//! Live fail-closed observation for DB-authoritative immutable publications.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use buzz_core::CommunityId;
use buzz_db::{
    authorization_invalidation::{
        AuthorizationInvalidationNotice, AuthorizationInvalidationSubscription,
    },
    authorization_version::{
        ProtectedPublicationCoordinate, ProtectedPublicationDependency,
        ProtectedPublicationValidity, ProtectedPublicationWitness,
    },
    Db, DbError,
};
use thiserror::Error;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_LIVE_PUBLICATION_WITNESSES: usize = 100_000;

/// Sticky live authority for one immutable publication response.
#[derive(Clone)]
pub struct LiveProtectedPublicationWitness {
    inner: Arc<LiveWitnessInner>,
}

impl LiveProtectedPublicationWitness {
    /// Exact immutable digest committed by the canonical operation receipt.
    pub fn result_digest(&self) -> [u8; 32] {
        self.inner.witness.result_digest()
    }

    /// O(1) sticky cancellation check for each streamed chunk.
    pub fn is_cancelled(&self) -> bool {
        if Instant::now() >= self.inner.deadline {
            self.inner.cancellation.cancel();
        }
        self.inner.cancellation.is_cancelled()
    }

    /// Cancellation-safe wait for dependency loss, observer loss, or expiry.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        tokio::select! {
            _ = self.inner.cancellation.cancelled() => {}
            _ = tokio::time::sleep_until(self.inner.deadline) => {
                self.inner.cancellation.cancel();
            }
        }
    }

    /// Mandatory post-fetch DB recheck immediately before exposing refs,
    /// headers, ranges, or bytes.
    pub async fn revalidate(&self) -> Result<(), ProtectedPublicationObserverError> {
        if Instant::now() >= self.inner.deadline {
            self.inner.cancellation.cancel();
            return Err(ProtectedPublicationObserverError::Expired);
        }
        if self.inner.cancellation.is_cancelled() {
            return Err(ProtectedPublicationObserverError::Invalidated);
        }

        // The anchor precedes SQL. Adding PostgreSQL's remaining validity to
        // it can only shorten the DB lease by the query round trip.
        let anchor = Instant::now();
        let validity = match self
            .inner
            .db
            .recheck_protected_publication_validity(&self.inner.witness)
            .await
        {
            Ok(Some(validity)) => validity,
            Ok(None) => {
                self.inner.cancellation.cancel();
                return Err(ProtectedPublicationObserverError::Stale);
            }
            Err(error) => {
                self.inner.cancellation.cancel();
                return Err(ProtectedPublicationObserverError::Database(error));
            }
        };
        let checked_deadline = match monotonic_deadline(anchor, validity) {
            Ok(deadline) => deadline,
            Err(error) => {
                self.inner.cancellation.cancel();
                return Err(error);
            }
        };
        if Instant::now() >= checked_deadline {
            self.inner.cancellation.cancel();
            return Err(ProtectedPublicationObserverError::Expired);
        }
        if self.inner.cancellation.is_cancelled() {
            return Err(ProtectedPublicationObserverError::Invalidated);
        }
        Ok(())
    }
}

impl fmt::Debug for LiveProtectedPublicationWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveProtectedPublicationWitness([REDACTED])")
    }
}

struct LiveWitnessInner {
    db: Db,
    witness: ProtectedPublicationWitness,
    cancellation: CancellationToken,
    deadline: Instant,
    _registration: LiveRegistration,
}

/// Ready, independently connected live publication observer.
#[derive(Clone)]
pub struct ProtectedPublicationObserver {
    inner: Arc<ObserverInner>,
}

impl ProtectedPublicationObserver {
    /// Establish the dedicated PostgreSQL listener before returning a usable
    /// observer. A new observer is required after any listener loss.
    pub async fn start(db: Db) -> Result<Self, ProtectedPublicationObserverError> {
        let subscription = db
            .subscribe_authorization_invalidations()
            .await
            .map_err(ProtectedPublicationObserverError::Database)?;
        let hub = Arc::new(InvalidationHub::new());
        let shutdown = CancellationToken::new();
        tokio::spawn(run_subscription(
            subscription,
            Arc::clone(&hub),
            shutdown.clone(),
        ));
        Ok(Self {
            inner: Arc::new(ObserverInner { db, hub, shutdown }),
        })
    }

    /// Resolve, subscribe, and finally recheck the current exact publication.
    pub async fn observe_current(
        &self,
        coordinate: &ProtectedPublicationCoordinate,
    ) -> Result<Option<LiveProtectedPublicationWitness>, ProtectedPublicationObserverError> {
        let Some(witness) = self
            .inner
            .db
            .protected_publication_witness(coordinate)
            .await
            .map_err(ProtectedPublicationObserverError::Database)?
        else {
            return Ok(None);
        };
        self.observe_committed(witness).await.map(Some)
    }

    /// Upgrade the exact witness returned by a successful mutation without a
    /// second digest resolution window.
    pub async fn observe_committed(
        &self,
        witness: ProtectedPublicationWitness,
    ) -> Result<LiveProtectedPublicationWitness, ProtectedPublicationObserverError> {
        if witness.authoritative_now() >= witness.expires_at() {
            return Err(ProtectedPublicationObserverError::Expired);
        }
        let cancellation = CancellationToken::new();
        let registration = self.inner.hub.register(
            witness.dependency().clone(),
            witness.invalidation_generation(),
            witness.authority_epoch(),
            cancellation.clone(),
        )?;

        // Subscription is established and registration is visible before the
        // final query, closing both notice-before-register and register-before-
        // notice races.
        let anchor = Instant::now();
        let validity = match self
            .inner
            .db
            .recheck_protected_publication_validity(&witness)
            .await
        {
            Ok(Some(validity)) => validity,
            Ok(None) => {
                cancellation.cancel();
                return Err(ProtectedPublicationObserverError::Stale);
            }
            Err(error) => {
                cancellation.cancel();
                return Err(ProtectedPublicationObserverError::Database(error));
            }
        };
        let deadline = match monotonic_deadline(anchor, validity) {
            Ok(deadline) => deadline,
            Err(error) => {
                cancellation.cancel();
                return Err(error);
            }
        };
        if Instant::now() >= deadline {
            cancellation.cancel();
            return Err(ProtectedPublicationObserverError::Expired);
        }
        if cancellation.is_cancelled() {
            return Err(ProtectedPublicationObserverError::Invalidated);
        }

        Ok(LiveProtectedPublicationWitness {
            inner: Arc::new(LiveWitnessInner {
                db: self.inner.db.clone(),
                witness,
                cancellation,
                deadline,
                _registration: registration,
            }),
        })
    }

    /// Sticky listener health. A failed observer is never made healthy again.
    pub fn is_healthy(&self) -> bool {
        self.inner.hub.is_healthy()
    }
}

impl fmt::Debug for ProtectedPublicationObserver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedPublicationObserver")
            .field("healthy", &self.is_healthy())
            .finish()
    }
}

struct ObserverInner {
    db: Db,
    hub: Arc<InvalidationHub>,
    shutdown: CancellationToken,
}

impl Drop for ObserverInner {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.hub.fail_closed();
    }
}

/// Closed live-observation failure.
#[derive(Debug, Error)]
pub enum ProtectedPublicationObserverError {
    /// The publication dependency changed.
    #[error("authorization publication is stale")]
    Stale,
    /// The persisted exclusive authority expiry was reached.
    #[error("authorization publication authority expired")]
    Expired,
    /// A live invalidation or object-authority notice cancelled this guard.
    #[error("authorization publication was invalidated")]
    Invalidated,
    /// Listener capacity or health prevents a race-free registration.
    #[error("authorization publication observer is unavailable")]
    ObserverUnavailable,
    /// The authoritative final recheck failed.
    #[error("authorization publication database recheck failed")]
    Database(#[source] DbError),
}

async fn run_subscription(
    mut subscription: AuthorizationInvalidationSubscription,
    hub: Arc<InvalidationHub>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                hub.fail_closed();
                return;
            }
            notice = subscription.recv() => match notice {
                Ok(notice) => hub.apply(notice),
                Err(_) => {
                    hub.fail_closed();
                    return;
                }
            }
        }
    }
}

fn monotonic_deadline(
    anchor: Instant,
    validity: ProtectedPublicationValidity,
) -> Result<Instant, ProtectedPublicationObserverError> {
    monotonic_deadline_for_times(anchor, validity.authoritative_now(), validity.expires_at())
}

fn monotonic_deadline_for_times(
    anchor: Instant,
    authoritative_now: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<Instant, ProtectedPublicationObserverError> {
    let remaining = expires_at
        .signed_duration_since(authoritative_now)
        .to_std()
        .map_err(|_| ProtectedPublicationObserverError::Expired)?;
    if remaining.is_zero() {
        return Err(ProtectedPublicationObserverError::Expired);
    }
    anchor
        .checked_add(remaining)
        .ok_or(ProtectedPublicationObserverError::Expired)
}

struct InvalidationHub {
    healthy: AtomicBool,
    state: Mutex<HubState>,
}

struct HubState {
    latest_domains: HashMap<CommunityId, u64>,
    latest_objects: HashMap<ProtectedPublicationDependency, u64>,
    registrations: HashMap<Uuid, LiveDependencyRegistration>,
}

struct LiveDependencyRegistration {
    authorization_domain: CommunityId,
    invalidation_generation: u64,
    dependency: Option<ProtectedPublicationDependency>,
    authority_epoch: u64,
    cancellation: CancellationToken,
}

impl InvalidationHub {
    fn new() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            state: Mutex::new(HubState {
                latest_domains: HashMap::new(),
                latest_objects: HashMap::new(),
                registrations: HashMap::new(),
            }),
        }
    }

    fn register(
        self: &Arc<Self>,
        dependency: ProtectedPublicationDependency,
        invalidation_generation: u64,
        authority_epoch: u64,
        cancellation: CancellationToken,
    ) -> Result<LiveRegistration, ProtectedPublicationObserverError> {
        let authorization_domain = dependency.authorization_domain();
        self.register_parts(
            authorization_domain,
            Some(dependency),
            invalidation_generation,
            authority_epoch,
            cancellation,
        )
    }

    fn register_parts(
        self: &Arc<Self>,
        authorization_domain: CommunityId,
        dependency: Option<ProtectedPublicationDependency>,
        invalidation_generation: u64,
        authority_epoch: u64,
        cancellation: CancellationToken,
    ) -> Result<LiveRegistration, ProtectedPublicationObserverError> {
        if !self.is_healthy() || authority_epoch == 0 {
            cancellation.cancel();
            return Err(ProtectedPublicationObserverError::ObserverUnavailable);
        }
        let mut state = self.lock_state();
        if !self.is_healthy() || state.registrations.len() >= MAX_LIVE_PUBLICATION_WITNESSES {
            cancellation.cancel();
            return Err(ProtectedPublicationObserverError::ObserverUnavailable);
        }
        if state
            .latest_domains
            .get(&authorization_domain)
            .is_some_and(|latest| *latest > invalidation_generation)
            || dependency.as_ref().is_some_and(|dependency| {
                state
                    .latest_objects
                    .get(dependency)
                    .is_some_and(|latest| *latest > authority_epoch)
            })
        {
            cancellation.cancel();
            return Err(ProtectedPublicationObserverError::Invalidated);
        }
        let registration_id = loop {
            let candidate = Uuid::new_v4();
            if !state.registrations.contains_key(&candidate) {
                break candidate;
            }
        };
        state.registrations.insert(
            registration_id,
            LiveDependencyRegistration {
                authorization_domain,
                invalidation_generation,
                dependency,
                authority_epoch,
                cancellation,
            },
        );
        Ok(LiveRegistration {
            registration_id,
            hub: Arc::clone(self),
        })
    }

    #[cfg(test)]
    fn register_domain_for_test(
        self: &Arc<Self>,
        authorization_domain: CommunityId,
        invalidation_generation: u64,
        cancellation: CancellationToken,
    ) -> Result<LiveRegistration, ProtectedPublicationObserverError> {
        self.register_parts(
            authorization_domain,
            None,
            invalidation_generation,
            1,
            cancellation,
        )
    }

    fn apply(&self, notice: AuthorizationInvalidationNotice) {
        if !self.is_healthy() {
            return;
        }
        let mut state = self.lock_state();
        if !self.is_healthy() {
            return;
        }
        match notice {
            AuthorizationInvalidationNotice::DomainAdvanced {
                authorization_domain,
                generation,
            } => {
                if !state.latest_domains.contains_key(&authorization_domain)
                    && state.latest_domains.len() >= MAX_LIVE_PUBLICATION_WITNESSES
                {
                    self.fail_locked(&state);
                    return;
                }
                let latest = state
                    .latest_domains
                    .entry(authorization_domain)
                    .or_default();
                *latest = (*latest).max(generation);
                for registration in state.registrations.values() {
                    if registration.authorization_domain == authorization_domain
                        && registration.invalidation_generation < generation
                    {
                        registration.cancellation.cancel();
                    }
                }
            }
            AuthorizationInvalidationNotice::ProtectedPublicationAdvanced {
                dependency,
                authority_epoch,
            } => {
                if !state.latest_objects.contains_key(&dependency)
                    && state.latest_objects.len() >= MAX_LIVE_PUBLICATION_WITNESSES
                {
                    self.fail_locked(&state);
                    return;
                }
                let latest = state.latest_objects.entry(dependency.clone()).or_default();
                *latest = (*latest).max(authority_epoch);
                for registration in state.registrations.values() {
                    if registration.dependency.as_ref() == Some(&dependency)
                        && registration.authority_epoch < authority_epoch
                    {
                        registration.cancellation.cancel();
                    }
                }
            }
        }
    }

    fn fail_closed(&self) {
        if !self.healthy.swap(false, Ordering::AcqRel) {
            return;
        }
        let state = self.lock_state();
        self.cancel_locked(&state);
    }

    fn fail_locked(&self, state: &HubState) {
        self.healthy.store(false, Ordering::Release);
        self.cancel_locked(state);
    }

    fn cancel_locked(&self, state: &HubState) {
        for registration in state.registrations.values() {
            registration.cancellation.cancel();
        }
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    fn remove(&self, registration_id: Uuid) {
        self.lock_state().registrations.remove(&registration_id);
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, HubState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                self.healthy.store(false, Ordering::Release);
                let state = poisoned.into_inner();
                for registration in state.registrations.values() {
                    registration.cancellation.cancel();
                }
                state
            }
        }
    }

    #[cfg(test)]
    fn registration_count(&self) -> usize {
        self.lock_state().registrations.len()
    }
}

struct LiveRegistration {
    registration_id: Uuid,
    hub: Arc<InvalidationHub>,
}

impl Drop for LiveRegistration {
    fn drop(&mut self) {
        self.hub.remove(self.registration_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(value: u128) -> CommunityId {
        CommunityId::from_uuid(Uuid::from_u128(value))
    }

    #[test]
    fn notice_before_registration_and_listener_loss_fail_closed() {
        let hub = Arc::new(InvalidationHub::new());
        hub.apply(AuthorizationInvalidationNotice::DomainAdvanced {
            authorization_domain: domain(1),
            generation: 8,
        });
        let cancellation = CancellationToken::new();
        assert!(matches!(
            hub.register_domain_for_test(domain(1), 7, cancellation.clone()),
            Err(ProtectedPublicationObserverError::Invalidated)
        ));
        assert!(cancellation.is_cancelled());

        let current = CancellationToken::new();
        let _registration = hub
            .register_domain_for_test(domain(1), 8, current.clone())
            .expect("current registration");
        hub.fail_closed();
        assert!(current.is_cancelled());
        assert!(!hub.is_healthy());
        assert!(matches!(
            hub.register_domain_for_test(domain(1), 8, CancellationToken::new()),
            Err(ProtectedPublicationObserverError::ObserverUnavailable)
        ));
    }

    #[test]
    fn activated_generation_zero_is_a_valid_observation_baseline() {
        let hub = Arc::new(InvalidationHub::new());
        let cancellation = CancellationToken::new();
        let _registration = hub
            .register_domain_for_test(domain(4), 0, cancellation.clone())
            .expect("activated zero generation");
        assert!(!cancellation.is_cancelled());
        hub.apply(AuthorizationInvalidationNotice::DomainAdvanced {
            authorization_domain: domain(4),
            generation: 1,
        });
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn registration_before_notice_is_scoped_and_final_drop_cleans_up() {
        let hub = Arc::new(InvalidationHub::new());
        let cancelled = CancellationToken::new();
        let unrelated = CancellationToken::new();
        let registration = Arc::new(
            hub.register_domain_for_test(domain(1), 4, cancelled.clone())
                .expect("first registration"),
        );
        let registration_clone = Arc::clone(&registration);
        let unrelated_registration = hub
            .register_domain_for_test(domain(2), 4, unrelated.clone())
            .expect("unrelated registration");
        assert_eq!(hub.registration_count(), 2);

        hub.apply(AuthorizationInvalidationNotice::DomainAdvanced {
            authorization_domain: domain(1),
            generation: 5,
        });
        assert!(cancelled.is_cancelled());
        assert!(!unrelated.is_cancelled());

        drop(registration);
        assert_eq!(hub.registration_count(), 2, "a clone retains registration");
        drop(registration_clone);
        assert_eq!(hub.registration_count(), 1);
        drop(unrelated_registration);
        assert_eq!(hub.registration_count(), 0);
    }

    #[test]
    fn expiry_deadline_is_exclusive_and_anchored_before_io() {
        let anchor = Instant::now();
        let now = chrono::Utc::now();
        assert!(matches!(
            monotonic_deadline_for_times(anchor, now, now),
            Err(ProtectedPublicationObserverError::Expired)
        ));
        assert!(matches!(
            monotonic_deadline_for_times(anchor, now, now - chrono::Duration::nanoseconds(1)),
            Err(ProtectedPublicationObserverError::Expired)
        ));
        assert_eq!(
            monotonic_deadline_for_times(anchor, now, now + chrono::Duration::seconds(1))
                .expect("positive remaining validity"),
            anchor + std::time::Duration::from_secs(1)
        );
    }
}
