use std::net::IpAddr;

use buzz_auth::{LimitType, RateLimiter};
use buzz_core::TenantContext;
use buzz_pubsub::rate_limiter::RedisRateLimiter;
use nostr::PublicKey;

use crate::authorization_runtime::ClientStatusAdmissionPolicy;

// Desktop startup establishes several independent live subscriptions at once.
// Preserve the configured average rate while allowing that bounded burst. This
// is still a fixed-window limiter, so a Redis-backed token bucket would be a
// better long-term fit for smoother refill behavior.
const WS_BURST_WINDOW_SECS: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    Exceeded { reset_in_secs: u64 },
    Unavailable,
}

pub(crate) async fn check_principal<L: RateLimiter>(
    limiter: &L,
    tenant: &TenantContext,
    pubkey: &PublicKey,
    limit_type: LimitType,
    window_secs: u64,
    limit: u64,
) -> Result<(), AdmissionError> {
    match limiter
        .check_and_increment(tenant, pubkey, limit_type, window_secs, limit)
        .await
    {
        Ok(result) if result.allowed => Ok(()),
        Ok(result) => Err(AdmissionError::Exceeded {
            reset_in_secs: result.reset_in_secs,
        }),
        Err(error) => {
            tracing::warn!(error = %error, "shared rate-limit admission unavailable");
            Err(AdmissionError::Unavailable)
        }
    }
}

/// Canonicalize peer identity before any shared admission key is derived.
pub(crate) fn canonical_peer_ip(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V6(peer) => peer.to_ipv4_mapped().map_or(IpAddr::V6(peer), IpAddr::V4),
        peer => peer,
    }
}

/// Admit optional status presentation without changing the completed AUTH
/// decision. A Redis denial or failure silently withholds presentation and is
/// never mapped to authorization/runtime health.
pub(crate) async fn check_client_status_presentation(
    limiter: &RedisRateLimiter,
    tenant: &TenantContext,
    actor: &PublicKey,
    peer: IpAddr,
    policy: ClientStatusAdmissionPolicy,
) -> Result<(), AdmissionError> {
    match limiter
        .check_client_status_admission(
            tenant.community(),
            actor,
            canonical_peer_ip(peer),
            policy.max_presentations_per_domain(),
            policy.max_presentations_per_actor(),
            policy.max_presentations_per_peer(),
        )
        .await
    {
        Ok(result) if result.allowed => Ok(()),
        Ok(result) => Err(AdmissionError::Exceeded {
            reset_in_secs: result.reset_in_secs,
        }),
        Err(error) => {
            tracing::warn!(error = %error, "client status admission unavailable");
            Err(AdmissionError::Unavailable)
        }
    }
}

pub(crate) fn ws_admission_budget(per_second_limit: u64) -> (u64, u64) {
    (
        WS_BURST_WINDOW_SECS,
        per_second_limit.saturating_mul(WS_BURST_WINDOW_SECS),
    )
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use buzz_auth::{AuthError, RateLimitResult, RateLimiter};
    use buzz_core::CommunityId;
    use nostr::Keys;
    use uuid::Uuid;

    use super::*;

    enum StubOutcome {
        Denied,
        Failed,
    }

    struct StubLimiter {
        outcome: StubOutcome,
        calls: AtomicUsize,
    }

    impl RateLimiter for StubLimiter {
        async fn check_and_increment(
            &self,
            _ctx: &TenantContext,
            _pubkey: &PublicKey,
            _limit_type: LimitType,
            _window_secs: u64,
            _limit: u64,
        ) -> Result<RateLimitResult, AuthError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            match self.outcome {
                StubOutcome::Denied => Ok(RateLimitResult::denied(11, 10, 1)),
                StubOutcome::Failed => Err(AuthError::Internal("redis unavailable".to_owned())),
            }
        }

        async fn check_ip_connection(
            &self,
            _ip: &IpAddr,
            _window_secs: u64,
            _limit: u64,
        ) -> Result<RateLimitResult, AuthError> {
            match self.outcome {
                StubOutcome::Denied => Ok(RateLimitResult::denied(11, 10, 1)),
                StubOutcome::Failed => Err(AuthError::Internal("redis unavailable".to_owned())),
            }
        }
    }

    fn tenant() -> TenantContext {
        TenantContext::resolved(
            CommunityId::from_uuid(Uuid::from_u128(1)),
            "relay.example.com",
        )
    }

    #[test]
    fn websocket_budget_preserves_rate_with_a_bounded_burst() {
        assert_eq!(ws_admission_budget(10), (5, 50));
    }

    #[test]
    fn websocket_budget_saturates_on_overflow() {
        assert_eq!(ws_admission_budget(u64::MAX), (5, u64::MAX));
    }

    #[test]
    fn ipv4_and_mapped_ipv6_share_one_canonical_peer() {
        let ipv4 = "192.0.2.44".parse::<IpAddr>().expect("IPv4 fixture");
        let mapped = "::ffff:192.0.2.44"
            .parse::<IpAddr>()
            .expect("mapped IPv6 fixture");
        assert_eq!(canonical_peer_ip(ipv4), canonical_peer_ip(mapped));
    }

    #[tokio::test]
    async fn denied_shared_counter_rejects_admission() {
        let limiter = StubLimiter {
            outcome: StubOutcome::Denied,
            calls: AtomicUsize::new(0),
        };
        let keys = Keys::generate();

        let result = check_principal(
            &limiter,
            &tenant(),
            &keys.public_key(),
            LimitType::WsEvents,
            1,
            10,
        )
        .await;

        assert_eq!(result, Err(AdmissionError::Exceeded { reset_in_secs: 1 }));
        assert_eq!(limiter.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn shared_counter_failure_rejects_admission() {
        let limiter = StubLimiter {
            outcome: StubOutcome::Failed,
            calls: AtomicUsize::new(0),
        };
        let keys = Keys::generate();

        let result = check_principal(
            &limiter,
            &tenant(),
            &keys.public_key(),
            LimitType::ApiCalls,
            60,
            300,
        )
        .await;

        assert_eq!(result, Err(AdmissionError::Unavailable));
        assert_eq!(limiter.calls.load(Ordering::Relaxed), 1);
    }
}
