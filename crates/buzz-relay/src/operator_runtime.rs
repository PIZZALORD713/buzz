//! Transport-neutral deployment-operator identity lifecycle composition.
//!
//! Wire parsing remains in the existing deployment-operator HTTP module. This
//! module owns the exact policy-driven verifier call and the narrow persistence
//! trait. Durable deduplication, denial audit, domain existence, and canonical
//! transition execution remain one database-owned transaction boundary.

use std::{
    collections::HashMap,
    fmt,
    hash::Hash,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use buzz_auth::{
    Nip98ReplayGuard, NipFiMode, OperatorLifecycleGrantError, OperatorLifecycleVerifier,
    VerifiedOperatorLifecycleGrant, VerifiedProvisionBindingIntent,
};
use buzz_db::{
    authorization_resolver::ProviderFreeEnrollmentError,
    authorization_restore::{ProvisionBindingExecution, RestoredProvisionBindingError},
    identity_lifecycle::IdentityLifecycleObservation,
    operator_lifecycle::{
        OperatorAuthenticationDenialReason, OperatorLifecycleError, OperatorLifecycleIntent,
        OperatorPreauthDenialPersistenceError, OperatorPreauthDenialWrite,
    },
};
use url::{Position, Url};

pub(crate) const OPERATOR_RATE_LIMIT_MAX_REQUESTS: u32 = 60;
pub(crate) const OPERATOR_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const OPERATOR_RATE_LIMIT_MAX_KEYS: usize = 4096;

use crate::authorization_runtime::{ProviderFreeV1Composition, ProviderFreeV1CompositionError};

/// Persistence boundary for verified lifecycle execution and credential-free
/// denial audit. The production implementation delegates directly to the two
/// `buzz-db` operator methods and owns no lifecycle logic.
#[async_trait]
pub(crate) trait OperatorLifecycleExecutor: Send + Sync {
    /// Exact configured posture. This is an immutable in-memory lookup and
    /// must never perform credential, restore, or database I/O.
    fn mode(&self, domain: buzz_core::CommunityId) -> NipFiMode;

    /// Whether every dependency needed by this exact Enforce domain remains
    /// healthy. This is an in-memory latch check only.
    fn domain_healthy(&self, domain: buzz_core::CommunityId) -> bool;

    /// Recheck the grant, fail closed if its domain does not exist, and execute
    /// the canonical transition transaction. Every exact retry reaches this
    /// method so the durable DB receipt is the sole idempotency authority.
    async fn execute(
        &self,
        grant: &VerifiedOperatorLifecycleGrant,
        intent: &OperatorLifecycleIntent,
    ) -> Result<IdentityLifecycleObservation, OperatorLifecycleError>;

    /// Record one bounded credential-free denial without occupying canonical
    /// lifecycle receipt/history state.
    async fn record_preauth_denial(
        &self,
        intent: &OperatorLifecycleIntent,
        reason: OperatorAuthenticationDenialReason,
    ) -> Result<OperatorPreauthDenialWrite, OperatorPreauthDenialPersistenceError>;

    /// Record one bounded credential-free Provision denial without exposing
    /// private principal coordinates or occupying canonical operation state.
    async fn record_provision_preauth_denial(
        &self,
        domain: buzz_core::CommunityId,
        body: &[u8],
        reason: OperatorAuthenticationDenialReason,
    ) -> Result<OperatorPreauthDenialWrite, OperatorPreauthDenialPersistenceError>;

    /// Execute the separate verifier-sealed provision operation through the
    /// canonical resolver and operation-specific restore boundary.
    async fn provision(
        &self,
        intent: &VerifiedProvisionBindingIntent,
    ) -> Result<ProvisionBindingExecution, OperatorInvocationError>;

    /// Process-wide canonical persistence and denial-audit health latch.
    fn healthy(&self) -> bool;
}

/// Concrete production adapter over the one installed provider-free
/// composition. It owns no database handle and cannot bypass the canonical
/// resolver or operation-specific restore runtime.
pub(crate) struct ProductionOperatorLifecycleExecutor {
    authorization: ProviderFreeV1Composition,
}

impl ProductionOperatorLifecycleExecutor {
    pub(crate) fn new(authorization: ProviderFreeV1Composition) -> Self {
        Self { authorization }
    }

    fn enforced_runtimes(
        &self,
        domain: buzz_core::CommunityId,
    ) -> Result<
        (
            buzz_db::authorization_resolver::ProviderFreeEnrollmentRuntime,
            buzz_db::authorization_restore::OperationRestoreRuntime,
        ),
        OperatorInvocationError,
    > {
        let enrollment = self
            .authorization
            .enrollment_runtime(domain)
            .map_err(map_composition_error)?;
        let restore = self
            .authorization
            .operation_restore_runtime(domain)
            .map_err(map_composition_error)?;
        Ok((enrollment, restore))
    }
}

#[async_trait]
impl OperatorLifecycleExecutor for ProductionOperatorLifecycleExecutor {
    fn mode(&self, domain: buzz_core::CommunityId) -> NipFiMode {
        self.authorization.mode(domain)
    }

    fn domain_healthy(&self, domain: buzz_core::CommunityId) -> bool {
        self.enforced_runtimes(domain).is_ok()
    }

    async fn execute(
        &self,
        grant: &VerifiedOperatorLifecycleGrant,
        intent: &OperatorLifecycleIntent,
    ) -> Result<IdentityLifecycleObservation, OperatorLifecycleError> {
        let (_, restore) = self
            .enforced_runtimes(intent.authorization_domain())
            .map_err(|_| OperatorLifecycleError::AuditUnavailable)?;
        restore
            .execute_operator_lifecycle(grant, intent)
            .await
            .map_err(map_restored_operator_error)
    }

    async fn record_preauth_denial(
        &self,
        intent: &OperatorLifecycleIntent,
        reason: OperatorAuthenticationDenialReason,
    ) -> Result<OperatorPreauthDenialWrite, OperatorPreauthDenialPersistenceError> {
        let (enrollment, _) = self
            .enforced_runtimes(intent.authorization_domain())
            .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
        enrollment
            .record_operator_authentication_denial(intent, reason)
            .await
    }

    async fn record_provision_preauth_denial(
        &self,
        domain: buzz_core::CommunityId,
        body: &[u8],
        reason: OperatorAuthenticationDenialReason,
    ) -> Result<OperatorPreauthDenialWrite, OperatorPreauthDenialPersistenceError> {
        let (enrollment, _) = self
            .enforced_runtimes(domain)
            .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
        let attempt = enrollment.prepare_operator_provision_authentication_attempt(domain, body);
        attempt.persist_denial(reason).await
    }

    async fn provision(
        &self,
        intent: &VerifiedProvisionBindingIntent,
    ) -> Result<ProvisionBindingExecution, OperatorInvocationError> {
        let (enrollment, restore) = self.enforced_runtimes(intent.authorization_domain())?;
        let prepared = enrollment
            .prepare_provision_binding(intent)
            .await
            .map_err(map_provision_preparation_error)?;
        restore
            .execute_provision_binding(&prepared)
            .await
            .map_err(OperatorInvocationError::from)
    }

    fn healthy(&self) -> bool {
        // The immutable adapter owns no separate dependency. Per-domain
        // composition health is checked by `domain_healthy`; an unrelated
        // unhealthy Enforce domain must not disable this domain's operator
        // surface.
        true
    }
}

/// Exact verifier/executor composition installed by the existing operator API.
pub struct OperatorLifecycleRuntime {
    origin: OperatorOrigin,
    verifier: Arc<OperatorLifecycleVerifier>,
    replay_guard: Arc<dyn Nip98ReplayGuard>,
    executor: Arc<dyn OperatorLifecycleExecutor>,
    audit_healthy: AtomicBool,
    actor_rate_limit: OperatorRateLimit<OperatorActorRateKey>,
    peer_rate_limit: OperatorRateLimit<OperatorPeerRateKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperatorPrebodyGateError {
    Unavailable,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct OperatorActorRateKey {
    domain: buzz_core::CommunityId,
    actor: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct OperatorPeerRateKey {
    domain: buzz_core::CommunityId,
    peer: IpAddr,
}

struct OperatorRateLimit<K> {
    state: Mutex<OperatorRateLimitState<K>>,
}

struct OperatorRateLimitState<K> {
    entries: HashMap<K, OperatorRateLimitWindow>,
    next_touch: u64,
}

#[derive(Clone, Copy)]
struct OperatorRateLimitWindow {
    opened_at: tokio::time::Instant,
    accepted: u32,
    reserved: u32,
    touched_at: u64,
}

struct OperatorRateLimitReservation<'a, K>
where
    K: Copy + Eq + Hash,
{
    limiter: &'a OperatorRateLimit<K>,
    key: K,
    opened_at: tokio::time::Instant,
    active: bool,
}

impl<K> OperatorRateLimit<K>
where
    K: Copy + Eq + Hash,
{
    fn new() -> Self {
        Self {
            state: Mutex::new(OperatorRateLimitState {
                entries: HashMap::new(),
                next_touch: 0,
            }),
        }
    }

    fn admit(&self, key: K) -> bool {
        self.admit_at(key, tokio::time::Instant::now())
    }

    fn reserve(&self, key: K) -> Option<OperatorRateLimitReservation<'_, K>> {
        self.reserve_at(key, tokio::time::Instant::now())
    }

    fn make_room(state: &mut OperatorRateLimitState<K>, key: K, now: tokio::time::Instant) -> bool {
        if state.entries.contains_key(&key) {
            return true;
        }
        state.entries.retain(|_, window| {
            window.reserved > 0 || now < window.opened_at + OPERATOR_RATE_LIMIT_WINDOW
        });
        if state.entries.len() >= OPERATOR_RATE_LIMIT_MAX_KEYS {
            let least_recently_used = state
                .entries
                .iter()
                .filter(|(_, window)| window.reserved == 0)
                .min_by_key(|(_, window)| window.touched_at)
                .map(|(key, _)| *key);
            let Some(least_recently_used) = least_recently_used else {
                return false;
            };
            state.entries.remove(&least_recently_used);
        }
        true
    }

    fn admit_at(&self, key: K, now: tokio::time::Instant) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.next_touch = state.next_touch.wrapping_add(1);
        let touched_at = state.next_touch;

        if !Self::make_room(&mut state, key, now) {
            return false;
        }

        let window = state.entries.entry(key).or_insert(OperatorRateLimitWindow {
            opened_at: now,
            accepted: 0,
            reserved: 0,
            touched_at,
        });
        window.touched_at = touched_at;
        if now >= window.opened_at + OPERATOR_RATE_LIMIT_WINDOW {
            if window.reserved > 0 {
                return false;
            }
            *window = OperatorRateLimitWindow {
                opened_at: now,
                accepted: 0,
                reserved: 0,
                touched_at,
            };
        }
        if window.accepted + window.reserved >= OPERATOR_RATE_LIMIT_MAX_REQUESTS {
            return false;
        }
        window.accepted += 1;
        true
    }

    fn reserve_at(
        &self,
        key: K,
        now: tokio::time::Instant,
    ) -> Option<OperatorRateLimitReservation<'_, K>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.next_touch = state.next_touch.wrapping_add(1);
        let touched_at = state.next_touch;
        if !Self::make_room(&mut state, key, now) {
            return None;
        }
        let window = state.entries.entry(key).or_insert(OperatorRateLimitWindow {
            opened_at: now,
            accepted: 0,
            reserved: 0,
            touched_at,
        });
        window.touched_at = touched_at;
        if now >= window.opened_at + OPERATOR_RATE_LIMIT_WINDOW {
            if window.reserved > 0 {
                return None;
            }
            *window = OperatorRateLimitWindow {
                opened_at: now,
                accepted: 0,
                reserved: 0,
                touched_at,
            };
        }
        if window.accepted + window.reserved >= OPERATOR_RATE_LIMIT_MAX_REQUESTS {
            return None;
        }
        window.reserved += 1;
        Some(OperatorRateLimitReservation {
            limiter: self,
            key,
            opened_at: window.opened_at,
            active: true,
        })
    }

    fn finish_reservation(&self, key: K, opened_at: tokio::time::Instant, commit: bool) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(window) = state.entries.get_mut(&key) else {
            return false;
        };
        if window.opened_at != opened_at || window.reserved == 0 {
            return false;
        }
        window.reserved -= 1;
        if commit {
            window.accepted += 1;
        }
        true
    }
}

impl<K> OperatorRateLimitReservation<'_, K>
where
    K: Copy + Eq + Hash,
{
    fn commit(mut self) -> bool {
        let committed = self
            .limiter
            .finish_reservation(self.key, self.opened_at, true);
        if committed {
            self.active = false;
        }
        committed
    }
}

impl<K> Drop for OperatorRateLimitReservation<'_, K>
where
    K: Copy + Eq + Hash,
{
    fn drop(&mut self) {
        if self.active {
            let released = self
                .limiter
                .finish_reservation(self.key, self.opened_at, false);
            debug_assert!(released, "active operator quota reservation must exist");
        }
    }
}

/// Exact provisioning result paired with the verifier-bound operation ID.
pub(crate) struct OperatorProvisionObservation {
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) execution: ProvisionBindingExecution,
}

impl OperatorLifecycleRuntime {
    /// Install the sole production operator runtime over the immutable
    /// provider-free composition. Root passes only verifier policy, the shared
    /// replay guard, and the already-installed composition; no database,
    /// actor, fence, or lifecycle writer is exposed.
    pub fn production(
        origin: &str,
        verifier: Arc<OperatorLifecycleVerifier>,
        replay_guard: Arc<dyn Nip98ReplayGuard>,
        authorization: ProviderFreeV1Composition,
    ) -> Result<Self, OperatorRuntimeConfigurationError> {
        Self::new(
            origin,
            verifier,
            replay_guard,
            Arc::new(ProductionOperatorLifecycleExecutor::new(authorization)),
        )
    }

    /// Construct from one canonical configured operator origin and the exact
    /// verifier. Tests use this narrow boundary to prove zero-I/O gating.
    pub(crate) fn new(
        origin: &str,
        verifier: Arc<OperatorLifecycleVerifier>,
        replay_guard: Arc<dyn Nip98ReplayGuard>,
        executor: Arc<dyn OperatorLifecycleExecutor>,
    ) -> Result<Self, OperatorRuntimeConfigurationError> {
        Ok(Self {
            origin: OperatorOrigin::parse(origin)?,
            verifier,
            replay_guard,
            executor,
            audit_healthy: AtomicBool::new(true),
            actor_rate_limit: OperatorRateLimit::new(),
            peer_rate_limit: OperatorRateLimit::new(),
        })
    }

    /// Verify two exact NIP-98 events and execute the DB-owned bounded intent.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn invoke(
        &self,
        peer: IpAddr,
        authorization_event_json: &str,
        independent_approval_event_json: Option<&str>,
        replacement_proof_event_json: Option<&str>,
        path: &str,
        body: &[u8],
        intent: &OperatorLifecycleIntent,
    ) -> Result<IdentityLifecycleObservation, OperatorInvocationError> {
        self.preflight(intent.authorization_domain())?;
        let expected_url = self.origin.exact_url(path);
        let candidate = match self
            .verifier
            .verify_candidate(
                authorization_event_json,
                independent_approval_event_json,
                replacement_proof_event_json,
                &expected_url,
                body,
                intent.authorization_domain(),
                intent.action(),
                intent.operation_id(),
                intent.intent_digest(),
                intent.expected_revision(),
                intent.replacement_event_author_pubkey(),
                intent.replacement_expires_at(),
            )
            .await
        {
            Ok(grant) => grant,
            Err(error) => {
                if let Some(reason) = verifier_denial_reason(&error) {
                    if matches!(
                        self.record_preauth_denial(peer, intent, reason).await,
                        Err(OperatorInvocationError::RateLimited)
                    ) {
                        return Err(OperatorInvocationError::RateLimited);
                    }
                }
                return Err(OperatorInvocationError::from(error));
            }
        };
        let reservation = self
            .actor_rate_limit
            .reserve(OperatorActorRateKey {
                domain: candidate.authorization_domain(),
                actor: candidate.signer_attribution(),
            })
            .ok_or(OperatorInvocationError::RateLimited)?;
        let grant = match candidate.claim_replay(self.replay_guard.as_ref()).await {
            Ok(grant) => {
                if !reservation.commit() {
                    self.audit_healthy.store(false, Ordering::SeqCst);
                    return Err(OperatorInvocationError::Failed);
                }
                grant
            }
            Err(error) => {
                drop(reservation);
                if let Some(reason) = verifier_denial_reason(&error) {
                    let _ = self.persist_preauth_denial(intent, reason).await;
                }
                return Err(OperatorInvocationError::from(error));
            }
        };
        self.executor
            .execute(&grant, intent)
            .await
            .map_err(OperatorInvocationError::from)
    }

    /// Persist a denial discovered by the HTTP credential envelope preflight.
    pub(crate) async fn record_preauth_denial(
        &self,
        peer: IpAddr,
        intent: &OperatorLifecycleIntent,
        reason: OperatorAuthenticationDenialReason,
    ) -> Result<(), OperatorInvocationError> {
        self.preflight(intent.authorization_domain())?;
        if !self.peer_rate_limit.admit(OperatorPeerRateKey {
            domain: intent.authorization_domain(),
            peer: canonical_peer_ip(peer),
        }) {
            return Err(OperatorInvocationError::RateLimited);
        }
        self.persist_preauth_denial(intent, reason).await
    }

    async fn persist_preauth_denial(
        &self,
        intent: &OperatorLifecycleIntent,
        reason: OperatorAuthenticationDenialReason,
    ) -> Result<(), OperatorInvocationError> {
        let result = if self.executor.healthy() {
            self.executor.record_preauth_denial(intent, reason).await
        } else {
            Err(OperatorPreauthDenialPersistenceError::Unavailable)
        };
        let result = map_preauth_denial_write(result);
        if matches!(
            result,
            Err(OperatorInvocationError::Unavailable | OperatorInvocationError::Failed)
        ) {
            self.audit_healthy.store(false, Ordering::SeqCst);
        }
        result
    }

    /// Persist a Provision credential-envelope denial after the mode/health
    /// gate. The executor seals and discards private body coordinates before
    /// invoking the shared credential-free denial lane.
    pub(crate) async fn record_provision_preauth_denial(
        &self,
        peer: IpAddr,
        domain: buzz_core::CommunityId,
        body: &[u8],
        reason: OperatorAuthenticationDenialReason,
    ) -> Result<(), OperatorInvocationError> {
        self.preflight(domain)?;
        if !self.peer_rate_limit.admit(OperatorPeerRateKey {
            domain,
            peer: canonical_peer_ip(peer),
        }) {
            return Err(OperatorInvocationError::RateLimited);
        }
        self.persist_provision_preauth_denial(domain, body, reason)
            .await
    }

    async fn persist_provision_preauth_denial(
        &self,
        domain: buzz_core::CommunityId,
        body: &[u8],
        reason: OperatorAuthenticationDenialReason,
    ) -> Result<(), OperatorInvocationError> {
        let result = if self.executor.healthy() {
            self.executor
                .record_provision_preauth_denial(domain, body, reason)
                .await
        } else {
            Err(OperatorPreauthDenialPersistenceError::Unavailable)
        };
        let result = map_preauth_denial_write(result);
        if matches!(
            result,
            Err(OperatorInvocationError::Unavailable | OperatorInvocationError::Failed)
        ) {
            self.audit_healthy.store(false, Ordering::SeqCst);
        }
        result
    }

    /// Whether the installed immutable policy requires the approval header.
    pub(crate) fn requires_independent_approval(&self) -> bool {
        self.verifier.requires_independent_approval()
    }

    /// Verify and execute the separate production provisioning operation after
    /// the HTTP layer has resolved the request domain without reading proofs.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn provision(
        &self,
        peer: IpAddr,
        authorization_event_json: &str,
        independent_approval_event_json: Option<&str>,
        path: &str,
        body: &[u8],
        authorization_domain: buzz_core::CommunityId,
    ) -> Result<OperatorProvisionObservation, OperatorInvocationError> {
        self.preflight(authorization_domain)?;
        let expected_url = self.origin.exact_url(path);
        let candidate = match self
            .verifier
            .verify_provision_candidate(
                authorization_event_json,
                independent_approval_event_json,
                &expected_url,
                body,
                authorization_domain,
            )
            .await
        {
            Ok(intent) => intent,
            Err(error) => {
                if let Some(reason) = verifier_denial_reason(&error) {
                    if matches!(
                        self.record_provision_preauth_denial(
                            peer,
                            authorization_domain,
                            body,
                            reason,
                        )
                        .await,
                        Err(OperatorInvocationError::RateLimited)
                    ) {
                        return Err(OperatorInvocationError::RateLimited);
                    }
                }
                return Err(OperatorInvocationError::from(error));
            }
        };
        let reservation = self
            .actor_rate_limit
            .reserve(OperatorActorRateKey {
                domain: candidate.authorization_domain(),
                actor: candidate.signer_attribution(),
            })
            .ok_or(OperatorInvocationError::RateLimited)?;
        let intent = match candidate.claim_replay(self.replay_guard.as_ref()).await {
            Ok(intent) => {
                if !reservation.commit() {
                    self.audit_healthy.store(false, Ordering::SeqCst);
                    return Err(OperatorInvocationError::Failed);
                }
                intent
            }
            Err(error) => {
                drop(reservation);
                if let Some(reason) = verifier_denial_reason(&error) {
                    let _ = self
                        .persist_provision_preauth_denial(authorization_domain, body, reason)
                        .await;
                }
                return Err(OperatorInvocationError::from(error));
            }
        };
        let operation_id = intent.operation_id();
        let execution = self.executor.provision(&intent).await?;
        Ok(OperatorProvisionObservation {
            operation_id,
            execution,
        })
    }

    /// Exact mode and health gate. Callers must invoke this before parsing or
    /// recording any credential failure.
    pub(crate) fn preflight(
        &self,
        domain: buzz_core::CommunityId,
    ) -> Result<(), OperatorInvocationError> {
        match self.executor.mode(domain) {
            NipFiMode::Off => return Err(OperatorInvocationError::NotConfigured),
            NipFiMode::DenyProtected => return Err(OperatorInvocationError::PolicyDenied),
            NipFiMode::Enforce => {}
        }
        if !self.audit_healthy.load(Ordering::SeqCst)
            || !self.executor.healthy()
            || !self.executor.domain_healthy(domain)
        {
            return Err(OperatorInvocationError::Unavailable);
        }
        Ok(())
    }

    /// Validate the public transport boundary without parsing credentials or
    /// touching the request body. URI authority or Host may supply the
    /// authority; when both are present they must canonicalize to the same
    /// HTTPS authority. Origin remains optional and canonical when present.
    pub(crate) fn transport_matches(
        &self,
        uri_scheme: Option<&str>,
        uri_authority: Option<&str>,
        host_authority: Option<&str>,
        request_origin: Option<&str>,
    ) -> bool {
        self.origin
            .matches(uri_scheme, uri_authority, host_authority, request_origin)
    }

    /// Apply the in-memory domain posture/health gate. Callers invoke this only
    /// after the exact transport boundary and domain coordinate have been
    /// validated, and before polling the body or inspecting credentials.
    /// Quotas are deliberately applied later: failed verification is isolated
    /// by peer IP, while successful verification is isolated by sealed actor.
    pub(crate) fn admit_prebody(
        &self,
        domain: buzz_core::CommunityId,
    ) -> Result<(), OperatorPrebodyGateError> {
        self.preflight(domain)
            .map_err(|_| OperatorPrebodyGateError::Unavailable)
    }

    pub(crate) fn admit_failed_request(
        &self,
        domain: buzz_core::CommunityId,
        peer: IpAddr,
    ) -> Result<(), OperatorInvocationError> {
        self.preflight(domain)?;
        if self.peer_rate_limit.admit(OperatorPeerRateKey {
            domain,
            peer: canonical_peer_ip(peer),
        }) {
            Ok(())
        } else {
            Err(OperatorInvocationError::RateLimited)
        }
    }

    /// Exact verifier and persistence dependencies are installed and healthy.
    pub async fn healthy(&self) -> bool {
        self.audit_healthy.load(Ordering::SeqCst) && self.executor.healthy()
    }
}

impl fmt::Debug for OperatorLifecycleRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorLifecycleRuntime([REDACTED])")
    }
}

fn verifier_denial_reason(
    error: &OperatorLifecycleGrantError,
) -> Option<OperatorAuthenticationDenialReason> {
    match error {
        OperatorLifecycleGrantError::InvalidRequest
        | OperatorLifecycleGrantError::InvalidCredential
        | OperatorLifecycleGrantError::ApprovalNotIndependent
        | OperatorLifecycleGrantError::Replayed => {
            Some(OperatorAuthenticationDenialReason::InvalidCredential)
        }
        OperatorLifecycleGrantError::Unauthenticated => {
            Some(OperatorAuthenticationDenialReason::Unauthenticated)
        }
        OperatorLifecycleGrantError::InvalidConfiguration
        | OperatorLifecycleGrantError::ReplayUnavailable => None,
    }
}

#[derive(Clone)]
struct OperatorOrigin {
    canonical: String,
    authority: String,
}

impl OperatorOrigin {
    fn parse(value: &str) -> Result<Self, OperatorRuntimeConfigurationError> {
        let url = Url::parse(value).map_err(|_| OperatorRuntimeConfigurationError)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(OperatorRuntimeConfigurationError);
        }
        let authority = canonical_https_authority(&url[Position::BeforeHost..Position::AfterPort])
            .ok_or(OperatorRuntimeConfigurationError)?;
        Ok(Self {
            canonical: format!("https://{authority}"),
            authority,
        })
    }

    fn exact_url(&self, path: &str) -> String {
        format!("{}{path}", self.canonical)
    }

    fn matches(
        &self,
        uri_scheme: Option<&str>,
        uri_authority: Option<&str>,
        host_authority: Option<&str>,
        request_origin: Option<&str>,
    ) -> bool {
        if uri_authority.is_some() && uri_scheme != Some("https") {
            return false;
        }
        if uri_authority.is_none() && uri_scheme.is_some() {
            return false;
        }
        let uri_authority = uri_authority.and_then(canonical_https_authority);
        let host_authority = host_authority.and_then(canonical_https_authority);
        let request_authority = match (uri_authority, host_authority) {
            (Some(uri), Some(host)) if uri == host => uri,
            (Some(uri), None) => uri,
            (None, Some(host)) => host,
            _ => return false,
        };
        request_authority == self.authority
            && request_origin.is_none_or(|origin| {
                canonical_https_origin(origin).as_deref() == Some(self.canonical.as_str())
            })
    }
}

fn canonical_https_authority(value: &str) -> Option<String> {
    if value.contains('@') || value.contains(',') || value.chars().any(char::is_whitespace) {
        return None;
    }
    let authority = value.parse::<axum::http::uri::Authority>().ok()?;
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    match authority.port_u16() {
        None | Some(443) => Some(host),
        Some(_) => None,
    }
}

fn canonical_https_origin(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    canonical_https_authority(&url[Position::BeforeHost..Position::AfterPort])
        .map(|authority| format!("https://{authority}"))
}

fn canonical_peer_ip(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V6(peer) => peer.to_ipv4_mapped().map_or(IpAddr::V6(peer), IpAddr::V4),
        IpAddr::V4(peer) => IpAddr::V4(peer),
    }
}

/// Invalid canonical operator origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorRuntimeConfigurationError;

/// Closed runtime failure mapped by the existing operator HTTP module.
#[derive(Debug)]
pub(crate) enum OperatorInvocationError {
    /// The requested domain is absent or explicitly Off.
    NotConfigured,
    /// The requested domain is configured to deny protected operations.
    PolicyDenied,
    /// Typed invocation or exact grant was invalid.
    InvalidRequest,
    /// One or both credentials failed verification.
    AuthenticationRejected,
    /// A proof signer is not a configured operator.
    AuthenticationForbidden,
    /// Independent approval was absent or invalid.
    ApprovalDenied,
    /// Operation identity names different canonical semantics.
    IntentConflict,
    /// This exact verified actor or failed-verification peer exhausted its
    /// isolated bounded fixed window.
    RateLimited,
    /// Verifier, replay fence, audit, or persistence is unavailable.
    Unavailable,
    /// Stored canonical evidence was corrupt or execution otherwise failed.
    Failed,
}

fn map_composition_error(error: ProviderFreeV1CompositionError) -> OperatorInvocationError {
    match error {
        ProviderFreeV1CompositionError::NotEnforced => OperatorInvocationError::NotConfigured,
        ProviderFreeV1CompositionError::Unhealthy => OperatorInvocationError::Unavailable,
        _ => OperatorInvocationError::Unavailable,
    }
}

fn map_provision_preparation_error(error: ProviderFreeEnrollmentError) -> OperatorInvocationError {
    match error {
        ProviderFreeEnrollmentError::InvalidEvidence => OperatorInvocationError::InvalidRequest,
        ProviderFreeEnrollmentError::ProvisioningRequired
        | ProviderFreeEnrollmentError::PolicyUnavailable => OperatorInvocationError::PolicyDenied,
        ProviderFreeEnrollmentError::Lifecycle(error) => match error {
            buzz_db::identity_lifecycle::IdentityLifecycleFailure::InvalidRequest => {
                OperatorInvocationError::InvalidRequest
            }
            buzz_db::identity_lifecycle::IdentityLifecycleFailure::IntentConflict => {
                OperatorInvocationError::IntentConflict
            }
            buzz_db::identity_lifecycle::IdentityLifecycleFailure::AuditUnavailable
            | buzz_db::identity_lifecycle::IdentityLifecycleFailure::Storage(_) => {
                OperatorInvocationError::Unavailable
            }
            buzz_db::identity_lifecycle::IdentityLifecycleFailure::CorruptStoredResult => {
                OperatorInvocationError::Failed
            }
        },
        ProviderFreeEnrollmentError::Database(_) => OperatorInvocationError::Unavailable,
    }
}

fn map_preauth_denial_write(
    result: Result<OperatorPreauthDenialWrite, OperatorPreauthDenialPersistenceError>,
) -> Result<(), OperatorInvocationError> {
    match result {
        Ok(
            OperatorPreauthDenialWrite::Inserted
            | OperatorPreauthDenialWrite::ExactReplay
            | OperatorPreauthDenialWrite::CapacityExhausted,
        ) => Ok(()),
        Err(OperatorPreauthDenialPersistenceError::Unavailable) => {
            Err(OperatorInvocationError::Unavailable)
        }
        Err(OperatorPreauthDenialPersistenceError::CorruptStoredResult) => {
            Err(OperatorInvocationError::Failed)
        }
    }
}

fn map_restored_operator_error(
    error: buzz_db::authorization_restore::RestoredOperatorLifecycleError,
) -> OperatorLifecycleError {
    use buzz_db::authorization_restore::RestoredOperatorLifecycleError;
    match error {
        RestoredOperatorLifecycleError::InvalidRequest => OperatorLifecycleError::InvalidRequest,
        RestoredOperatorLifecycleError::IntentConflict => OperatorLifecycleError::IntentConflict,
        RestoredOperatorLifecycleError::AuditUnavailable => {
            OperatorLifecycleError::AuditUnavailable
        }
        RestoredOperatorLifecycleError::CorruptStoredResult => {
            OperatorLifecycleError::CorruptStoredResult
        }
        RestoredOperatorLifecycleError::Database(error)
        | RestoredOperatorLifecycleError::OutcomeUnknown(error) => {
            OperatorLifecycleError::Storage(error)
        }
        RestoredOperatorLifecycleError::Restore(error) => OperatorLifecycleError::Storage(
            buzz_db::DbError::InvalidData(format!("operator restore unavailable: {error}")),
        ),
    }
}

impl From<OperatorLifecycleGrantError> for OperatorInvocationError {
    fn from(value: OperatorLifecycleGrantError) -> Self {
        match value {
            OperatorLifecycleGrantError::InvalidRequest => Self::InvalidRequest,
            OperatorLifecycleGrantError::InvalidCredential
            | OperatorLifecycleGrantError::Replayed => Self::AuthenticationRejected,
            OperatorLifecycleGrantError::Unauthenticated => Self::AuthenticationForbidden,
            OperatorLifecycleGrantError::ApprovalNotIndependent => Self::ApprovalDenied,
            OperatorLifecycleGrantError::InvalidConfiguration
            | OperatorLifecycleGrantError::ReplayUnavailable => Self::Unavailable,
        }
    }
}

impl From<RestoredProvisionBindingError> for OperatorInvocationError {
    fn from(value: RestoredProvisionBindingError) -> Self {
        match value {
            RestoredProvisionBindingError::InvalidRequest => Self::InvalidRequest,
            RestoredProvisionBindingError::IntentConflict => Self::IntentConflict,
            RestoredProvisionBindingError::AuditUnavailable => Self::Unavailable,
            RestoredProvisionBindingError::CorruptStoredResult => Self::Failed,
            RestoredProvisionBindingError::Database(_)
            | RestoredProvisionBindingError::OutcomeUnknown(_)
            | RestoredProvisionBindingError::Restore(_) => Self::Unavailable,
        }
    }
}

impl From<OperatorLifecycleError> for OperatorInvocationError {
    fn from(value: OperatorLifecycleError) -> Self {
        match value {
            OperatorLifecycleError::InvalidRequest => Self::InvalidRequest,
            OperatorLifecycleError::IntentConflict => Self::IntentConflict,
            OperatorLifecycleError::AuditUnavailable | OperatorLifecycleError::Storage(_) => {
                Self::Unavailable
            }
            OperatorLifecycleError::CorruptStoredResult => Self::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier,
        },
    };

    use super::{
        canonical_peer_ip, map_preauth_denial_write, OperatorOrigin, OperatorRateLimit,
        OPERATOR_RATE_LIMIT_MAX_KEYS, OPERATOR_RATE_LIMIT_MAX_REQUESTS, OPERATOR_RATE_LIMIT_WINDOW,
    };
    use buzz_db::operator_lifecycle::{
        OperatorPreauthDenialPersistenceError, OperatorPreauthDenialWrite,
    };

    #[test]
    fn fixed_window_isolated_by_key_admits_sixty_and_resets_at_exact_equality() {
        let limiter = OperatorRateLimit::<u32>::new();
        let opened_at = tokio::time::Instant::now();
        for _ in 0..OPERATOR_RATE_LIMIT_MAX_REQUESTS {
            assert!(limiter.admit_at(7, opened_at));
        }
        assert!(!limiter.admit_at(7, opened_at));
        assert!(limiter.admit_at(8, opened_at));
        assert!(limiter.admit_at(7, opened_at + OPERATOR_RATE_LIMIT_WINDOW));
    }

    #[test]
    fn fixed_window_has_exactly_sixty_concurrent_winners() {
        let limiter = Arc::new(OperatorRateLimit::<u32>::new());
        let opened_at = tokio::time::Instant::now();
        let winners = std::thread::scope(|scope| {
            let attempts = (0..=OPERATOR_RATE_LIMIT_MAX_REQUESTS)
                .map(|_| {
                    let limiter = Arc::clone(&limiter);
                    scope.spawn(move || limiter.admit_at(7, opened_at))
                })
                .collect::<Vec<_>>();
            attempts
                .into_iter()
                .map(|attempt| attempt.join().expect("rate attempt"))
                .filter(|won| *won)
                .count()
        });
        assert_eq!(winners, OPERATOR_RATE_LIMIT_MAX_REQUESTS as usize);
    }

    #[test]
    fn actor_window_holds_exactly_sixty_concurrent_reservations() {
        let limiter = Arc::new(OperatorRateLimit::<u32>::new());
        let opened_at = tokio::time::Instant::now();
        let barrier = Arc::new(Barrier::new(OPERATOR_RATE_LIMIT_MAX_REQUESTS as usize + 2));
        let winners = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..=OPERATOR_RATE_LIMIT_MAX_REQUESTS {
                let limiter = Arc::clone(&limiter);
                let barrier = Arc::clone(&barrier);
                let winners = Arc::clone(&winners);
                scope.spawn(move || {
                    let reservation = limiter.reserve_at(7, opened_at);
                    if reservation.is_some() {
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                    barrier.wait();
                    drop(reservation);
                });
            }
            barrier.wait();
        });
        assert_eq!(
            winners.load(Ordering::SeqCst),
            OPERATOR_RATE_LIMIT_MAX_REQUESTS as usize
        );
        assert!(limiter.reserve_at(7, opened_at).is_some());
    }

    #[test]
    fn rate_limit_map_is_bounded_and_evicts_the_least_recently_used_key() {
        let limiter = OperatorRateLimit::<usize>::new();
        let now = tokio::time::Instant::now();
        for key in 0..OPERATOR_RATE_LIMIT_MAX_KEYS {
            assert!(limiter.admit_at(key, now));
        }
        assert!(limiter.admit_at(0, now));
        assert!(limiter.admit_at(OPERATOR_RATE_LIMIT_MAX_KEYS, now));

        let state = limiter.state.lock().expect("rate map");
        assert_eq!(state.entries.len(), OPERATOR_RATE_LIMIT_MAX_KEYS);
        assert!(state.entries.contains_key(&0));
        assert!(!state.entries.contains_key(&1));
        assert!(state.entries.contains_key(&OPERATOR_RATE_LIMIT_MAX_KEYS));
    }

    #[test]
    fn operator_origin_accepts_canonical_uri_host_and_origin_equivalence() {
        let origin = OperatorOrigin::parse("https://Operator.Example:443/").expect("origin");
        assert!(origin.matches(Some("https"), Some("OPERATOR.EXAMPLE:443"), None, None,));
        assert!(origin.matches(None, None, Some("operator.example"), None));
        assert!(origin.matches(
            Some("https"),
            Some("operator.example"),
            Some("OPERATOR.EXAMPLE:443"),
            Some("https://OPERATOR.EXAMPLE:443"),
        ));
        assert_eq!(
            origin.exact_url("/operator/test"),
            "https://operator.example/operator/test"
        );
    }

    #[test]
    fn operator_origin_rejects_missing_mismatched_or_non_https_authority() {
        let origin = OperatorOrigin::parse("https://operator.example").expect("origin");
        assert!(OperatorOrigin::parse("https://operator.example:444").is_err());
        for (scheme, uri, host) in [
            (None, None, None),
            (Some("http"), Some("operator.example"), None),
            (Some("https"), Some("wrong.example"), None),
            (None, None, Some("operator.example:444")),
            (
                Some("https"),
                Some("operator.example"),
                Some("wrong.example"),
            ),
            (None, None, Some("attacker@operator.example")),
            (None, None, Some("operator.example ")),
            (None, None, Some("operator.example,wrong.example")),
            (None, None, Some("[2001:db8::1")),
            (Some("https"), Some("attacker@operator.example"), None),
        ] {
            assert!(!origin.matches(scheme, uri, host, None));
        }
        assert!(!origin.matches(
            None,
            None,
            Some("operator.example"),
            Some("http://operator.example"),
        ));

        let ipv6 = OperatorOrigin::parse("https://[2001:db8::1]:443").expect("IPv6 origin");
        assert!(ipv6.matches(None, None, Some("[2001:DB8::1]"), None));
    }

    #[test]
    fn ipv4_mapped_peer_addresses_share_one_failure_identity() {
        let ipv4 = Ipv4Addr::new(192, 0, 2, 10);
        let mapped = IpAddr::V6(ipv4.to_ipv6_mapped());
        assert_eq!(canonical_peer_ip(mapped), IpAddr::V4(ipv4));
    }

    #[test]
    fn preauth_capacity_is_health_neutral_but_persistence_errors_are_not() {
        assert!(
            map_preauth_denial_write(Ok(OperatorPreauthDenialWrite::CapacityExhausted,)).is_ok()
        );
        for error in [
            OperatorPreauthDenialPersistenceError::Unavailable,
            OperatorPreauthDenialPersistenceError::CorruptStoredResult,
        ] {
            assert!(map_preauth_denial_write(Err(error)).is_err());
        }
    }
}
