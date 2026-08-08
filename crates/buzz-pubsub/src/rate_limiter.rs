//! Redis-backed rate limiter using atomic Lua script (INCR + EXPIRE).
//!
//! Implements the [`RateLimiter`] trait from `buzz-auth`.
//! Uses a single Lua script to atomically INCR and conditionally EXPIRE,
//! eliminating the crash window where a key could exist without a TTL.
//!
//! ⚠️ Fixed windows allow up to 2× burst at boundaries. Upgrade to sliding
//! window or token bucket for strict limiting.

use std::net::IpAddr;

use buzz_auth::{
    error::AuthError,
    rate_limit::{LimitType, RateLimitResult, RateLimiter},
};
use buzz_core::TenantContext;
use nostr::PublicKey;
use redis::Script;

/// Atomically INCR the key, set EXPIRE on first call, and return (count, ttl).
///
/// Using a Lua script ensures INCR and EXPIRE are executed atomically —
/// a crash between them can no longer leave a key without a TTL.
const RATE_LIMIT_SCRIPT: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
"#;

/// Atomically admit one optional client-status presentation across the exact
/// domain, authenticated actor, and canonical peer coordinates.
///
/// The three keys share one Redis Cluster hash tag. The script first validates
/// all counters and TTLs, then either increments all three or none. A denial
/// performs no writes and never refreshes an existing TTL.
const CLIENT_STATUS_ADMISSION_SCRIPT: &str = r#"
local window = tonumber(ARGV[1])
local limits = {tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])}
if not window or window < 1 then
  return {-1, -1}
end

local counts = {}
local ttls = {}
for i = 1, 3 do
  if not limits[i] or limits[i] < 1 then
    return {-1, -1}
  end
  local raw = redis.call('GET', KEYS[i])
  if raw then
    local count = tonumber(raw)
    local ttl = redis.call('TTL', KEYS[i])
    if not count or count < 0 or ttl < 0 then
      return {-1, -1}
    end
    counts[i] = count
    ttls[i] = ttl
  else
    counts[i] = 0
    ttls[i] = window
  end
end

local denied = false
local reset = 0
for i = 1, 3 do
  if counts[i] >= limits[i] then
    denied = true
    if ttls[i] > reset then
      reset = ttls[i]
    end
  end
end
if denied then
  return {0, reset}
end

for i = 1, 3 do
  local count = redis.call('INCR', KEYS[i])
  if count == 1 then
    redis.call('EXPIRE', KEYS[i], window)
  end
end
return {1, window}
"#;

/// Result of the optional three-coordinate client-status admission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientStatusAdmissionResult {
    /// Whether all three coordinates were atomically admitted.
    pub allowed: bool,
    /// Remaining fixed-window lifetime reported by Redis.
    pub reset_in_secs: u64,
}

/// Run the atomic rate-limit Lua script against `key` and return a
/// [`RateLimitResult`].
///
/// If the TTL comes back negative (key exists without expiry — broken state
/// from a prior crash), the key is repaired with a fresh EXPIRE and a warning
/// is logged.
async fn run_rate_limit(
    pool: &deadpool_redis::Pool,
    key: &str,
    window_secs: u64,
    limit: u64,
) -> Result<RateLimitResult, AuthError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AuthError::Internal(format!("Redis pool: {e}")))?;

    let script = Script::new(RATE_LIMIT_SCRIPT);
    let (count, ttl): (u64, i64) = script
        .key(key)
        .arg(window_secs as i64)
        .invoke_async(&mut *conn)
        .await
        .map_err(|e| AuthError::Internal(format!("Redis rate limit script: {e}")))?;

    // ttl == -1 means the key exists but has no expiry — broken state from a
    // prior crash between INCR and EXPIRE. Repair it now.
    let reset_in_secs = if ttl < 0 {
        tracing::warn!(key = %key, "rate limit key has no TTL — repairing");
        let _: () = redis::cmd("EXPIRE")
            .arg(key)
            .arg(window_secs as i64)
            .query_async(&mut *conn)
            .await
            .map_err(|e| AuthError::Internal(format!("Redis EXPIRE repair: {e}")))?;
        // After repair, the window resets to the full duration.
        window_secs
    } else {
        ttl.max(0) as u64
    };

    if count <= limit {
        Ok(RateLimitResult::allowed(count, limit, reset_in_secs))
    } else {
        Ok(RateLimitResult::denied(count, limit, reset_in_secs))
    }
}

/// Redis-backed rate limiter using fixed-window counters.
///
/// Pubkey keys are community-scoped via `&TenantContext`:
/// `buzz:{community}:ratelimit:{pubkey_hex}:{suffix}`. IP keys remain
/// operator-global: `buzz:ratelimit:ip:{ip}:conn`. The counter and its TTL are
/// managed atomically via a Lua script to prevent keys from persisting without
/// expiry.
pub struct RedisRateLimiter {
    pool: deadpool_redis::Pool,
}

impl RedisRateLimiter {
    /// Create a new `RedisRateLimiter` backed by the given connection pool.
    pub fn new(pool: deadpool_redis::Pool) -> Self {
        Self { pool }
    }

    /// Atomically check and increment the domain, actor, and peer coordinates
    /// for one optional current-binding presentation.
    #[allow(clippy::too_many_arguments)]
    pub async fn check_client_status_admission(
        &self,
        community_id: buzz_core::CommunityId,
        actor: &PublicKey,
        peer: IpAddr,
        max_presentations_per_domain: u64,
        max_presentations_per_actor: u64,
        max_presentations_per_peer: u64,
    ) -> Result<ClientStatusAdmissionResult, AuthError> {
        let window_secs = buzz_core::client_binding_status::MAX_CLIENT_BINDING_STATUS_LIFETIME_SECS;
        let window = i64::try_from(window_secs)
            .map_err(|_| AuthError::Internal("client status admission window is invalid".into()))?;
        let domain_limit = i64::try_from(max_presentations_per_domain)
            .map_err(|_| AuthError::Internal("client status domain admission is invalid".into()))?;
        let actor_limit = i64::try_from(max_presentations_per_actor)
            .map_err(|_| AuthError::Internal("client status actor admission is invalid".into()))?;
        let peer_limit = i64::try_from(max_presentations_per_peer)
            .map_err(|_| AuthError::Internal("client status peer admission is invalid".into()))?;
        if domain_limit < 1 || actor_limit < 1 || peer_limit < 1 {
            return Err(AuthError::Internal(
                "client status admission limits are invalid".into(),
            ));
        }
        let (domain_key, actor_key, peer_key) =
            client_status_admission_keys(community_id, actor, peer);
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|error| AuthError::Internal(format!("Redis pool: {error}")))?;
        let (decision, reset): (i64, i64) = Script::new(CLIENT_STATUS_ADMISSION_SCRIPT)
            .key(domain_key)
            .key(actor_key)
            .key(peer_key)
            .arg(window)
            .arg(domain_limit)
            .arg(actor_limit)
            .arg(peer_limit)
            .invoke_async(&mut *connection)
            .await
            .map_err(|error| {
                AuthError::Internal(format!("Redis client status admission script: {error}"))
            })?;
        if !matches!(decision, 0 | 1) || reset < 0 {
            return Err(AuthError::Internal(
                "Redis client status admission response is invalid".into(),
            ));
        }
        Ok(ClientStatusAdmissionResult {
            allowed: decision == 1,
            reset_in_secs: u64::try_from(reset).unwrap_or_default(),
        })
    }
}

fn client_status_admission_keys(
    community_id: buzz_core::CommunityId,
    actor: &PublicKey,
    peer: IpAddr,
) -> (String, String, String) {
    // Literal braces create one Redis Cluster hash tag for the atomic script.
    let prefix = format!("buzz:{{{community_id}}}:ratelimit:client-status");
    (
        format!("{prefix}:domain"),
        format!("{prefix}:actor:{}", actor.to_hex()),
        format!("{prefix}:peer:{peer}"),
    )
}

impl RateLimiter for RedisRateLimiter {
    async fn check_and_increment(
        &self,
        ctx: &TenantContext,
        pubkey: &PublicKey,
        limit_type: LimitType,
        window_secs: u64,
        limit: u64,
    ) -> Result<RateLimitResult, AuthError> {
        let key = buzz_auth::rate_limit::rate_limit_key(ctx, pubkey, &limit_type);
        run_rate_limit(&self.pool, &key, window_secs, limit).await
    }

    async fn check_ip_connection(
        &self,
        ip: &IpAddr,
        window_secs: u64,
        limit: u64,
    ) -> Result<RateLimitResult, AuthError> {
        let key = buzz_auth::rate_limit::ip_rate_limit_key(ip);
        run_rate_limit(&self.pool, &key, window_secs, limit).await
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use buzz_core::CommunityId;
    use nostr::Keys;
    use tokio::sync::Barrier;
    use uuid::Uuid;

    use super::*;

    fn redis_fixture() -> (deadpool_redis::Pool, Arc<RedisRateLimiter>) {
        let url = std::env::var("TEST_REDIS_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        let pool = deadpool_redis::Config::from_url(url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("create Redis test pool");
        (pool.clone(), Arc::new(RedisRateLimiter::new(pool)))
    }

    async fn redis_count(pool: &deadpool_redis::Pool, key: &str) -> Option<u64> {
        let mut connection = pool.get().await.expect("connect Redis test pool");
        redis::cmd("GET")
            .arg(key)
            .query_async(&mut *connection)
            .await
            .expect("read admission counter")
    }

    async fn redis_ttl(pool: &deadpool_redis::Pool, key: &str) -> i64 {
        let mut connection = pool.get().await.expect("connect Redis test pool");
        redis::cmd("TTL")
            .arg(key)
            .query_async(&mut *connection)
            .await
            .expect("read admission counter TTL")
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn client_status_admission_limits_each_coordinate_without_partial_consumption() {
        let (pool, limiter) = redis_fixture();
        let peer_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let peer_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        let actor_domain = CommunityId::from_uuid(Uuid::new_v4());
        let actor_a = Keys::generate().public_key();
        let actor_b = Keys::generate().public_key();
        assert!(
            limiter
                .check_client_status_admission(actor_domain, &actor_a, peer_a, 3, 1, 3)
                .await
                .expect("actor first admission")
                .allowed
        );
        let (domain_key, _, denied_peer_key) =
            client_status_admission_keys(actor_domain, &actor_a, peer_b);
        let domain_ttl_before_denial = redis_ttl(&pool, &domain_key).await;
        assert!(
            !limiter
                .check_client_status_admission(actor_domain, &actor_a, peer_b, 3, 1, 3)
                .await
                .expect("actor limit decision")
                .allowed
        );
        assert_eq!(redis_count(&pool, &domain_key).await, Some(1));
        assert_eq!(redis_count(&pool, &denied_peer_key).await, None);
        let domain_ttl_after_denial = redis_ttl(&pool, &domain_key).await;
        assert!(domain_ttl_before_denial > 0);
        assert!(
            domain_ttl_before_denial
                <= i64::try_from(
                    buzz_core::client_binding_status::MAX_CLIENT_BINDING_STATUS_LIFETIME_SECS
                )
                .expect("status lifetime fits Redis TTL")
        );
        assert!(
            domain_ttl_after_denial <= domain_ttl_before_denial,
            "denial must not refresh an admitted key's TTL",
        );

        let peer_domain = CommunityId::from_uuid(Uuid::new_v4());
        assert!(
            limiter
                .check_client_status_admission(peer_domain, &actor_a, peer_a, 3, 3, 1)
                .await
                .expect("peer first admission")
                .allowed
        );
        assert!(
            !limiter
                .check_client_status_admission(peer_domain, &actor_b, peer_a, 3, 3, 1)
                .await
                .expect("peer limit decision")
                .allowed
        );
        let (domain_key, denied_actor_key, _) =
            client_status_admission_keys(peer_domain, &actor_b, peer_a);
        assert_eq!(redis_count(&pool, &domain_key).await, Some(1));
        assert_eq!(redis_count(&pool, &denied_actor_key).await, None);

        let domain = CommunityId::from_uuid(Uuid::new_v4());
        assert!(
            limiter
                .check_client_status_admission(domain, &actor_a, peer_a, 1, 1, 1)
                .await
                .expect("domain first admission")
                .allowed
        );
        assert!(
            !limiter
                .check_client_status_admission(domain, &actor_b, peer_b, 1, 1, 1)
                .await
                .expect("domain limit decision")
                .allowed
        );
        let (_, denied_actor_key, denied_peer_key) =
            client_status_admission_keys(domain, &actor_b, peer_b);
        assert_eq!(redis_count(&pool, &denied_actor_key).await, None);
        assert_eq!(redis_count(&pool, &denied_peer_key).await, None);
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn client_status_admission_concurrent_boundary_allows_exactly_the_limit() {
        const CALLS: usize = 32;
        const LIMIT: u64 = 7;
        let (pool, limiter) = redis_fixture();
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let actor = Keys::generate().public_key();
        let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        let barrier = Arc::new(Barrier::new(CALLS));
        let mut tasks = Vec::with_capacity(CALLS);
        for _ in 0..CALLS {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                limiter
                    .check_client_status_admission(
                        domain,
                        &actor,
                        peer,
                        LIMIT,
                        CALLS as u64,
                        CALLS as u64,
                    )
                    .await
                    .expect("concurrent admission")
                    .allowed
            }));
        }
        let mut allowed = 0;
        for task in tasks {
            allowed += usize::from(task.await.expect("admission task joins"));
        }
        assert_eq!(allowed, LIMIT as usize);
        let (domain_key, actor_key, peer_key) = client_status_admission_keys(domain, &actor, peer);
        assert_eq!(redis_count(&pool, &domain_key).await, Some(LIMIT));
        assert_eq!(redis_count(&pool, &actor_key).await, Some(LIMIT));
        assert_eq!(redis_count(&pool, &peer_key).await, Some(LIMIT));
    }

    #[test]
    fn client_status_admission_keys_share_one_cluster_slot() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let actor = Keys::generate().public_key();
        let keys =
            client_status_admission_keys(domain, &actor, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
        let tag = format!("{{{domain}}}");
        assert!(keys.0.contains(&tag));
        assert!(keys.1.contains(&tag));
        assert!(keys.2.contains(&tag));
    }
}
