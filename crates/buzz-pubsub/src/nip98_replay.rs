//! Redis-backed NIP-98 replay seen-set.
//!
//! Implements the [`Nip98ReplayGuard`] trait from `buzz-auth`. Uses Redis
//! `SET NX EX` for single proofs and one Lua all-or-none transaction for
//! multi-proof sets — the §5 pre-build gate for multi-tenant HA replay
//! protection.

use buzz_auth::{
    error::AuthError,
    nip98_replay::{
        nip98_replay_key_for_scope, Nip98ReplayGuard, DEFAULT_REPLAY_TTL_SECS, MAX_REPLAY_TTL_SECS,
    },
};
use nostr::EventId;

const CLAIM_ALL_SCRIPT: &str = r#"
for _, key in ipairs(KEYS) do
  if redis.call('EXISTS', key) ~= 0 then
    return 0
  end
end
for _, key in ipairs(KEYS) do
  redis.call('SET', key, '1', 'EX', ARGV[1])
end
return 1
"#;

/// Redis-backed NIP-98 replay seen-set.
///
/// Each `try_mark(ctx, event_id, ttl)` issues a single
/// `SET buzz:{community}:nip98:{event_id_hex} 1 NX EX <ttl>` against Redis.
/// `NX` makes the operation atomic set-if-absent — the freshness proof comes
/// from Redis returning `OK` only on the first claim. Subsequent claims within
/// the TTL window return `nil`, which we surface as `Ok(false)` so the caller
/// rejects the request as replay.
pub struct RedisNip98ReplayGuard {
    pool: deadpool_redis::Pool,
}

impl RedisNip98ReplayGuard {
    /// Create a new replay guard backed by the given Redis connection pool.
    pub fn new(pool: deadpool_redis::Pool) -> Self {
        Self { pool }
    }
}

impl Nip98ReplayGuard for RedisNip98ReplayGuard {
    fn try_mark_in_scope<'a>(
        &'a self,
        scope: &'a str,
        event_id: &'a EventId,
        ttl_secs: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, AuthError>> + Send + 'a>>
    {
        Box::pin(async move {
            // §5 gate floor + safety ceiling. Sub-floor values are lifted to the
            // floor (contract permits clamping); above-ceiling values are pushed
            // down to MAX_REPLAY_TTL_SECS (contract REQUIRES clamping) so a buggy
            // caller cannot send a Redis-incompatible `EX` arg or pin a slot for
            // implausibly long.
            let ttl = ttl_secs.clamp(DEFAULT_REPLAY_TTL_SECS, MAX_REPLAY_TTL_SECS);

            let mut conn = self.pool.get().await.map_err(|e| {
                // Structured field for ops; the user-facing AuthError stays a
                // bounded category string.
                tracing::warn!(
                    scope = %scope,
                    error = %e,
                    "nip98 replay: redis pool acquire failed — caller MUST fail closed"
                );
                AuthError::Internal(format!("Redis pool: {e}"))
            })?;

            let key = nip98_replay_key_for_scope(scope, event_id);

            // SET key 1 NX EX <ttl>. redis-rs typed return: Some("OK") on first
            // claim, None on existing key. Any other value would be a Redis-side
            // bug; treat it as internal error.
            let result: Option<String> = redis::cmd("SET")
                .arg(&key)
                .arg("1")
                .arg("NX")
                .arg("EX")
                .arg(ttl)
                .query_async(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::warn!(
                        scope = %scope,
                        error = %e,
                        "nip98 replay: redis SET NX EX failed — caller MUST fail closed"
                    );
                    AuthError::Internal(format!("Redis SET NX EX: {e}"))
                })?;

            match result.as_deref() {
                Some("OK") => Ok(true),
                None => Ok(false),
                Some(other) => {
                    tracing::error!(
                        scope = %scope,
                        reply = %other,
                        "nip98 replay: redis SET NX EX returned an unexpected reply — investigate"
                    );
                    Err(AuthError::Internal(format!(
                        "unexpected SET NX EX reply: {other}"
                    )))
                }
            }
        })
    }

    fn try_mark_all_in_scope<'a>(
        &'a self,
        scope: &'a str,
        event_ids: &'a [EventId],
        ttl_secs: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, AuthError>> + Send + 'a>>
    {
        Box::pin(async move {
            let valid_cardinality = (1..=3).contains(&event_ids.len());
            let distinct = event_ids
                .iter()
                .enumerate()
                .all(|(index, event_id)| !event_ids[..index].contains(event_id));
            if !valid_cardinality || !distinct {
                return Err(AuthError::Internal(
                    "invalid NIP-98 proof-set replay claim".to_owned(),
                ));
            }

            let ttl = ttl_secs.clamp(DEFAULT_REPLAY_TTL_SECS, MAX_REPLAY_TTL_SECS);
            let keys: Vec<String> = event_ids
                .iter()
                .map(|event_id| nip98_replay_key_for_scope(scope, event_id))
                .collect();
            let mut conn = self.pool.get().await.map_err(|error| {
                tracing::warn!(
                    scope = %scope,
                    error = %error,
                    "nip98 replay: redis pool acquire failed for proof set — caller MUST fail closed"
                );
                AuthError::Internal(format!("Redis pool: {error}"))
            })?;

            let script = redis::Script::new(CLAIM_ALL_SCRIPT);
            let mut invocation = script.prepare_invoke();
            for key in &keys {
                invocation.key(key);
            }
            let result: i64 =
                invocation
                    .arg(ttl)
                    .invoke_async(&mut *conn)
                    .await
                    .map_err(|error| {
                        tracing::warn!(
                            scope = %scope,
                            proof_count = event_ids.len(),
                            error = %error,
                            "nip98 replay: atomic proof-set claim failed — caller MUST fail closed"
                        );
                        AuthError::Internal(format!("Redis atomic proof-set claim: {error}"))
                    })?;
            match result {
                1 => Ok(true),
                0 => Ok(false),
                other => {
                    tracing::error!(
                        scope = %scope,
                        reply = other,
                        "nip98 replay: atomic proof-set claim returned an unexpected reply"
                    );
                    Err(AuthError::Internal(format!(
                        "unexpected atomic proof-set reply: {other}"
                    )))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::{CommunityId, TenantContext};
    use deadpool_redis::{Config, Runtime};
    use nostr::{EventBuilder, Keys, Kind};
    use uuid::Uuid;

    #[test]
    fn redis_guard_implements_the_mandatory_atomic_batch_contract() {
        fn requires_mandatory_batch<T: Nip98ReplayGuard>() {}

        requires_mandatory_batch::<RedisNip98ReplayGuard>();
    }

    fn redis_pool() -> deadpool_redis::Pool {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        Config::from_url(url)
            .create_pool(Some(Runtime::Tokio1))
            .expect("create pool")
    }

    fn fresh_ctx() -> TenantContext {
        TenantContext::resolved(CommunityId::from_uuid(Uuid::new_v4()), "test.example")
    }

    fn fresh_event_id() -> EventId {
        EventBuilder::new(Kind::HttpAuth, "")
            .sign_with_keys(&Keys::generate())
            .expect("sign")
            .id
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn first_claim_succeeds_replay_fails() {
        let guard = RedisNip98ReplayGuard::new(redis_pool());
        let ctx = fresh_ctx();
        let eid = fresh_event_id();

        assert!(guard
            .try_mark(&ctx, &eid, DEFAULT_REPLAY_TTL_SECS)
            .await
            .expect("first mark"));
        assert!(!guard
            .try_mark(&ctx, &eid, DEFAULT_REPLAY_TTL_SECS)
            .await
            .expect("replay mark"));
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn isolation_between_communities() {
        let guard = RedisNip98ReplayGuard::new(redis_pool());
        let ctx_a = fresh_ctx();
        let ctx_b = fresh_ctx();
        let eid = fresh_event_id();

        assert!(guard
            .try_mark(&ctx_a, &eid, DEFAULT_REPLAY_TTL_SECS)
            .await
            .expect("mark in A"));
        // Same event id under ctx_b is still a first claim — communities are
        // independent seen-sets.
        assert!(guard
            .try_mark(&ctx_b, &eid, DEFAULT_REPLAY_TTL_SECS)
            .await
            .expect("mark in B"));
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn sub_floor_ttl_is_lifted_to_default() {
        let guard = RedisNip98ReplayGuard::new(redis_pool());
        let ctx = fresh_ctx();
        let eid = fresh_event_id();

        // Caller asks for 30s; impl lifts to ≥ DEFAULT_REPLAY_TTL_SECS.
        // Smoke-test the path: pass sub-floor TTL, claim once, then expect
        // replay rejection — the TTL lift kept the marker alive past 30s and
        // the contract holds.
        assert!(guard.try_mark(&ctx, &eid, 30).await.expect("mark"));
        assert!(!guard.try_mark(&ctx, &eid, 30).await.expect("replay"));
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn above_ceiling_ttl_is_clamped() {
        let guard = RedisNip98ReplayGuard::new(redis_pool());
        let ctx = fresh_ctx();
        let eid = fresh_event_id();

        // Caller asks for u64::MAX (well past Redis's i64::MAX `EX` limit).
        // Impl MUST clamp down to MAX_REPLAY_TTL_SECS so the SET succeeds; if
        // we instead forwarded u64::MAX, Redis would reject the EX arg and
        // try_mark would return Err — and per the trait contract, callers
        // fail closed on Err. That's correctness-preserving but UX-hostile:
        // every nip98 request errors. The clamp turns a foot-gun into a
        // contained warning.
        assert!(guard
            .try_mark(&ctx, &eid, u64::MAX)
            .await
            .expect("mark with extreme ttl must succeed via clamp"));
        assert!(!guard
            .try_mark(&ctx, &eid, u64::MAX)
            .await
            .expect("replay with extreme ttl must succeed via clamp"));
    }

    #[tokio::test]
    async fn malformed_proof_sets_fail_before_redis_io() {
        let guard = RedisNip98ReplayGuard::new(redis_pool());
        let event_id = fresh_event_id();
        assert!(guard
            .try_mark_all_in_scope("invalid-empty", &[], DEFAULT_REPLAY_TTL_SECS)
            .await
            .is_err());
        assert!(guard
            .try_mark_all_in_scope(
                "invalid-duplicate",
                &[event_id, event_id],
                DEFAULT_REPLAY_TTL_SECS,
            )
            .await
            .is_err());
        assert!(guard
            .try_mark_all_in_scope(
                "invalid-large",
                &[
                    fresh_event_id(),
                    fresh_event_id(),
                    fresh_event_id(),
                    fresh_event_id(),
                ],
                DEFAULT_REPLAY_TTL_SECS,
            )
            .await
            .is_err());
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn atomic_proof_sets_support_one_two_and_three_ids() {
        let guard = RedisNip98ReplayGuard::new(redis_pool());
        for count in 1..=3 {
            let scope = format!("proof-set-cardinality-{count}-{}", Uuid::new_v4());
            let event_ids: Vec<_> = (0..count).map(|_| fresh_event_id()).collect();
            assert!(guard
                .try_mark_all_in_scope(&scope, &event_ids, DEFAULT_REPLAY_TTL_SECS)
                .await
                .expect("first proof-set claim"));
            assert!(!guard
                .try_mark_all_in_scope(&scope, &event_ids, DEFAULT_REPLAY_TTL_SECS)
                .await
                .expect("replayed proof-set claim"));
        }
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn conflicting_proof_set_writes_no_partial_markers() {
        let guard = RedisNip98ReplayGuard::new(redis_pool());
        let scope = format!("proof-set-conflict-{}", Uuid::new_v4());
        let existing = fresh_event_id();
        let fresh = fresh_event_id();
        assert!(guard
            .try_mark_in_scope(&scope, &existing, DEFAULT_REPLAY_TTL_SECS)
            .await
            .expect("seed existing marker"));
        assert!(!guard
            .try_mark_all_in_scope(&scope, &[existing, fresh], DEFAULT_REPLAY_TTL_SECS,)
            .await
            .expect("conflicting batch"));
        assert!(guard
            .try_mark_in_scope(&scope, &fresh, DEFAULT_REPLAY_TTL_SECS)
            .await
            .expect("fresh marker was not partially written"));
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn concurrent_complete_proof_set_has_one_winner() {
        let pool = redis_pool();
        let first = RedisNip98ReplayGuard::new(pool.clone());
        let second = RedisNip98ReplayGuard::new(pool);
        let scope = format!("proof-set-race-{}", Uuid::new_v4());
        let event_ids = [fresh_event_id(), fresh_event_id(), fresh_event_id()];
        let (first_result, second_result) = tokio::join!(
            first.try_mark_all_in_scope(&scope, &event_ids, DEFAULT_REPLAY_TTL_SECS),
            second.try_mark_all_in_scope(&scope, &event_ids, DEFAULT_REPLAY_TTL_SECS),
        );
        let first_result = first_result.expect("first contender result");
        let second_result = second_result.expect("second contender result");
        assert_ne!(first_result, second_result);
    }
}
