//! Common in-memory bounded authorization lease for protected audio.
//!
//! Audio does not persist an admission ledger. A session combines separately
//! finalized `AudioJoin` and `AudioMedia` authority, registers both dependency
//! snapshots with the runtime observer, and retains only a monotonic deadline
//! plus a sticky cancellation token. Restart therefore discards every lease.

use std::{fmt, future::Future, pin::Pin};

use buzz_auth::{AuthContext, AuthorizationLeaseDependencySnapshot, RouteCapability};
use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Successful atomic registration of both audio lease dependency snapshots.
pub struct AudioLeaseObservation {
    authoritative_now: DateTime<Utc>,
    cancellation: CancellationToken,
}

impl AudioLeaseObservation {
    /// Construct the observer result after an atomic current-state recheck and subscription.
    pub fn current(authoritative_now: DateTime<Utc>, cancellation: CancellationToken) -> Self {
        Self {
            authoritative_now,
            cancellation,
        }
    }
}

impl fmt::Debug for AudioLeaseObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AudioLeaseObservation([REDACTED])")
    }
}

/// Runtime boundary that atomically rechecks and observes two audio leases.
///
/// Implementations must subscribe before their final recheck so an
/// invalidation cannot land between validation and observer registration.
/// Initial or continuing dependency loss must fail closed by returning an
/// error or cancelling the returned token.
pub trait AudioLeaseObserver: Send + Sync {
    /// Observer-specific fail-closed error.
    type Error: Send;

    /// Register the exact join and media dependency tuples together.
    fn register_audio_session<'a>(
        &'a self,
        join: &'a AuthorizationLeaseDependencySnapshot,
        media: &'a AuthorizationLeaseDependencySnapshot,
    ) -> Pin<Box<dyn Future<Output = Result<AudioLeaseObservation, Self::Error>> + Send + 'a>>;
}

/// Cloneable in-memory authority retained by one live audio connection.
#[derive(Clone)]
pub struct BoundedAudioSessionLease {
    cancellation: CancellationToken,
    deadline: Instant,
    expires_at: DateTime<Utc>,
}

impl BoundedAudioSessionLease {
    /// Validate an exact join/media pair and atomically register its dependencies.
    pub async fn register<O: AudioLeaseObserver>(
        join: &AuthContext,
        media: &AuthContext,
        observer: &O,
    ) -> Result<Self, AudioLeaseError> {
        let join_coordinates = AudioLeaseCoordinates::from_context(join);
        let media_coordinates = AudioLeaseCoordinates::from_context(media);
        // Request fingerprints, fences, dependency revisions, issue times, and
        // expiries remain independently authoritative for the two capabilities.
        // Only stable session identity coordinates must match here; the observer
        // atomically rechecks both complete snapshots below.
        validate_pair(&join_coordinates, &media_coordinates)?;

        let join_snapshot = join.lease().dependency_snapshot();
        let media_snapshot = media.lease().dependency_snapshot();
        // Anchor before observer I/O. PostgreSQL time is sampled during that
        // I/O, so adding the returned remaining duration to this earlier
        // monotonic instant is conservative rather than extending the lease.
        let local_anchor = Instant::now();
        let observation = observer
            .register_audio_session(&join_snapshot, &media_snapshot)
            .await
            .map_err(|_| AudioLeaseError::ObserverUnavailable)?;
        if observation.cancellation.is_cancelled() {
            return Err(AudioLeaseError::Invalidated);
        }
        let expires_at = join.lease().expires_at().min(media.lease().expires_at());
        let deadline = monotonic_deadline(local_anchor, observation.authoritative_now, expires_at)?;
        Ok(Self {
            cancellation: observation.cancellation,
            deadline,
            expires_at,
        })
    }

    /// Fail closed immediately before admission, publication, or disclosure.
    pub fn revalidate(&self) -> Result<(), AudioLeaseError> {
        self.revalidate_at(Instant::now())
    }

    /// Sticky token cancelled by invalidation or observer dependency loss.
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Wait until the exact session authority is invalidated.
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    /// Exclusive wall-clock expiry retained for diagnostics and scheduling.
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn revalidate_at(&self, now: Instant) -> Result<(), AudioLeaseError> {
        if self.cancellation.is_cancelled() {
            return Err(AudioLeaseError::Invalidated);
        }
        if now >= self.deadline {
            return Err(AudioLeaseError::Expired);
        }
        Ok(())
    }
}

impl fmt::Debug for BoundedAudioSessionLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedAudioSessionLease([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
struct AudioLeaseCoordinates {
    capability: RouteCapability,
    authorization_domain: buzz_core::CommunityId,
    actor_pubkey: nostr::PublicKey,
    owner_pubkey: Option<nostr::PublicKey>,
    binding: (uuid::Uuid, u64),
    delegated_relationship: Option<(uuid::Uuid, u64)>,
    transport: buzz_auth::ProofTransport,
    target_fingerprint: [u8; 32],
    transport_context_fingerprint: [u8; 32],
}

impl AudioLeaseCoordinates {
    fn from_context(context: &AuthContext) -> Self {
        let lease = context.lease();
        let (_, target, transport_context) = lease.request_binding();
        Self {
            capability: context.capability(),
            authorization_domain: context.authorization_domain(),
            actor_pubkey: context.actor_pubkey(),
            owner_pubkey: context.owner_pubkey(),
            binding: context.binding(),
            delegated_relationship: lease.delegated_relationship(),
            transport: context.transport(),
            target_fingerprint: *target,
            transport_context_fingerprint: *transport_context,
        }
    }
}

fn validate_pair(
    join: &AudioLeaseCoordinates,
    media: &AudioLeaseCoordinates,
) -> Result<(), AudioLeaseError> {
    if join.capability != RouteCapability::AudioJoin
        || media.capability != RouteCapability::AudioMedia
    {
        return Err(AudioLeaseError::CapabilityMismatch);
    }
    if join.authorization_domain != media.authorization_domain
        || join.actor_pubkey != media.actor_pubkey
        || join.owner_pubkey != media.owner_pubkey
        || join.binding != media.binding
        || join.delegated_relationship != media.delegated_relationship
        || join.transport != media.transport
        || join.target_fingerprint != media.target_fingerprint
        || join.transport_context_fingerprint != media.transport_context_fingerprint
    {
        return Err(AudioLeaseError::CoordinateMismatch);
    }
    Ok(())
}

fn monotonic_deadline(
    local_anchor: Instant,
    authoritative_now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<Instant, AudioLeaseError> {
    if expires_at <= authoritative_now {
        return Err(AudioLeaseError::Expired);
    }
    let remaining = (expires_at - authoritative_now)
        .to_std()
        .map_err(|_| AudioLeaseError::Expired)?;
    local_anchor
        .checked_add(remaining)
        .ok_or(AudioLeaseError::Expired)
}

/// Fail-closed common audio lease errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AudioLeaseError {
    /// The contexts were not exactly `AudioJoin` and `AudioMedia`.
    #[error("audio capability mismatch")]
    CapabilityMismatch,
    /// Join and media authority named different subjects or dependencies.
    #[error("audio authorization coordinates mismatch")]
    CoordinateMismatch,
    /// The observer could not establish current distributed authority.
    #[error("audio authorization observer unavailable")]
    ObserverUnavailable,
    /// The exclusive lease deadline was reached.
    #[error("audio authorization expired")]
    Expired,
    /// A dependency changed or its observer became unavailable.
    #[error("audio authorization invalidated")]
    Invalidated,
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;
    use std::time::Duration;

    fn coordinates(capability: RouteCapability) -> AudioLeaseCoordinates {
        AudioLeaseCoordinates {
            capability,
            authorization_domain: buzz_core::CommunityId::from_uuid(uuid::Uuid::from_u128(1)),
            actor_pubkey: Keys::generate().public_key(),
            owner_pubkey: None,
            binding: (uuid::Uuid::from_u128(2), 3),
            delegated_relationship: None,
            transport: buzz_auth::ProofTransport::Nip42,
            target_fingerprint: [5; 32],
            transport_context_fingerprint: [6; 32],
        }
    }

    fn pair() -> (AudioLeaseCoordinates, AudioLeaseCoordinates) {
        let join = coordinates(RouteCapability::AudioJoin);
        let mut media = join.clone();
        media.capability = RouteCapability::AudioMedia;
        (join, media)
    }

    #[test]
    fn exact_shared_session_pair_is_required() {
        let (join, media) = pair();
        assert_eq!(validate_pair(&join, &media), Ok(()));
        let mut wrong_actor = media.clone();
        wrong_actor.actor_pubkey = Keys::generate().public_key();
        assert_eq!(
            validate_pair(&join, &wrong_actor),
            Err(AudioLeaseError::CoordinateMismatch)
        );
        let mut wrong_capability = media;
        wrong_capability.capability = RouteCapability::GitRead;
        assert_eq!(
            validate_pair(&join, &wrong_capability),
            Err(AudioLeaseError::CapabilityMismatch)
        );
    }

    #[test]
    fn deadline_is_exclusive_without_rounding() {
        let local_anchor = Instant::now();
        let authoritative_now = fixture_time();
        let deadline = monotonic_deadline(
            local_anchor,
            authoritative_now,
            authoritative_now + chrono::TimeDelta::milliseconds(1500),
        )
        .expect("future deadline");
        let lease = BoundedAudioSessionLease {
            cancellation: CancellationToken::new(),
            deadline,
            expires_at: authoritative_now + chrono::TimeDelta::milliseconds(1500),
        };
        assert_eq!(lease.revalidate_at(local_anchor), Ok(()));
        assert_eq!(
            lease.revalidate_at(local_anchor + Duration::from_millis(1499)),
            Ok(())
        );
        assert_eq!(
            lease.revalidate_at(local_anchor + Duration::from_millis(1500)),
            Err(AudioLeaseError::Expired)
        );
    }

    #[test]
    fn cancellation_is_sticky_and_shared_by_clones() {
        let token = CancellationToken::new();
        let lease = BoundedAudioSessionLease {
            cancellation: token.clone(),
            deadline: Instant::now() + Duration::from_secs(30),
            expires_at: fixture_time() + chrono::TimeDelta::seconds(30),
        };
        let clone = lease.clone();
        assert_eq!(lease.revalidate(), Ok(()));
        token.cancel();
        assert_eq!(lease.revalidate(), Err(AudioLeaseError::Invalidated));
        assert_eq!(clone.revalidate(), Err(AudioLeaseError::Invalidated));
    }

    #[test]
    fn expired_authoritative_observation_fails_closed() {
        let now = fixture_time();
        assert_eq!(
            monotonic_deadline(Instant::now(), now, now),
            Err(AudioLeaseError::Expired)
        );
    }

    #[test]
    fn debug_output_contains_no_authority() {
        let lease = BoundedAudioSessionLease {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(30),
            expires_at: fixture_time() + chrono::TimeDelta::seconds(30),
        };
        assert_eq!(format!("{lease:?}"), "BoundedAudioSessionLease([REDACTED])");
    }

    fn fixture_time() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).expect("fixture time")
    }
}
