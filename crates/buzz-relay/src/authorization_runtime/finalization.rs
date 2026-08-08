//! Concrete provider-free finalization for protected publication routes.
//!
//! Raw Git or Blossom credentials never cross this boundary. Their owning
//! extractors supply only origin-sealed evidence and one exact route seal.

use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use buzz_auth::{
    AuthContext, AuthorizationError, AuthorizationFinalizer, AuthorizationInput,
    BindingResolutionRequest, LocalBindingResolver, ProofTransport, RequestEvidenceBinding,
    TrustedProxyAssertionVerifier, VerifiedDelegatedEvidence, VerifiedDirectEvidence,
    VerifiedNostrProof,
};
use buzz_core::CommunityId;
use buzz_db::{
    authorization_resolver::{AuthorizationResolverError, PostgresLocalBindingResolver},
    authorization_version::{
        AuthorizationProtectedObjectKind, ProtectedPublicationCoordinate,
        ProtectedPublicationOperationIdentity,
    },
    DbError,
};
use nostr::PublicKey;
use thiserror::Error;
use uuid::Uuid;

use super::ProtectedPublicationObserver;

const MAX_PROTECTED_PUBLICATION_LEASE: Duration = Duration::from_secs(300);

/// Explicit V1 positive delegation-authority state.
///
/// V1 has no reviewed production grant source. Invalidation floors are
/// negative revocation facts and can never construct this authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedPublicationDelegationGrantSource {
    /// Delegated Git and Blossom authorization is unavailable and denied.
    Unavailable,
}

/// Whether the exact protected route reads or mutates its canonical object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedPublicationAuthorizationIntent {
    /// Read-only access; no operation identity is created.
    Read,
    /// A publication mutation requiring a server-generated operation identity.
    Mutation,
}

/// Origin-sealed evidence accepted by protected publication finalization.
pub enum ProtectedPublicationEvidence {
    /// Assertion plus direct Nostr transport proof.
    Direct(VerifiedDirectEvidence),
    /// Assertion-free owner-bound delegation. Explicitly unavailable in V1.
    Delegated(VerifiedDelegatedEvidence),
}

impl fmt::Debug for ProtectedPublicationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Direct(_) => "ProtectedPublicationEvidence::Direct([REDACTED])",
            Self::Delegated(_) => "ProtectedPublicationEvidence::Delegated([REDACTED])",
        })
    }
}

/// Exact server-resolved route joined to the transport verifier's fingerprints.
#[derive(Clone)]
pub struct VerifiedProtectedPublicationRoute {
    authorization_domain: CommunityId,
    expected_actor: PublicKey,
    correlation_id: Uuid,
    capability: buzz_auth::RouteCapability,
    object_kind: AuthorizationProtectedObjectKind,
    intent: ProtectedPublicationAuthorizationIntent,
    evidence_binding: RequestEvidenceBinding,
}

impl VerifiedProtectedPublicationRoute {
    /// Seal the canonical adapter output consumed by this runtime.
    ///
    /// This is crate-scoped so only reviewed relay transport adapters can join
    /// raw route parsing to origin-sealed evidence. The runtime independently
    /// compares every field to the proof and finalized lease.
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn from_verified_transport(
        authorization_domain: CommunityId,
        expected_actor: PublicKey,
        correlation_id: Uuid,
        capability: buzz_auth::RouteCapability,
        object_kind: AuthorizationProtectedObjectKind,
        intent: ProtectedPublicationAuthorizationIntent,
        evidence_binding: RequestEvidenceBinding,
    ) -> Result<Self, ProtectedPublicationAuthorizationError> {
        let capability_matches = match intent {
            ProtectedPublicationAuthorizationIntent::Read => object_kind.admits_read(capability),
            ProtectedPublicationAuthorizationIntent::Mutation => {
                object_kind.admits_mutation(capability)
            }
        };
        if authorization_domain.as_uuid().is_nil()
            || correlation_id.is_nil()
            || evidence_binding.authorization_domain() != authorization_domain
            || !capability_matches
        {
            return Err(ProtectedPublicationAuthorizationError::RouteMismatch);
        }
        Ok(Self {
            authorization_domain,
            expected_actor,
            correlation_id,
            capability,
            object_kind,
            intent,
            evidence_binding,
        })
    }

    fn accepts_proof(&self, proof: &VerifiedNostrProof) -> bool {
        let transport_matches = match self.object_kind {
            AuthorizationProtectedObjectKind::Repository => {
                proof.transport() == ProofTransport::GitSmartHttpSession
            }
            AuthorizationProtectedObjectKind::Media => proof.transport() == ProofTransport::Blossom,
            AuthorizationProtectedObjectKind::ModerationTarget => {
                proof.transport() == ProofTransport::Nip98
            }
            _ => false,
        };
        transport_matches
            && self.evidence_binding.accepts_proof(proof)
            && proof.authorization_domain() == self.authorization_domain
            && proof.actor_pubkey() == self.expected_actor
    }

    fn accepts_context(&self, context: &AuthContext) -> bool {
        context.authorization_domain() == self.authorization_domain
            && context.actor_pubkey() == self.expected_actor
            && context.correlation_id() == self.correlation_id
            && context.capability() == self.capability
    }

    fn coordinate(&self, context: &AuthContext) -> Result<ProtectedPublicationCoordinate, DbError> {
        match self.object_kind {
            AuthorizationProtectedObjectKind::Repository => {
                ProtectedPublicationCoordinate::repository(context)
            }
            AuthorizationProtectedObjectKind::Media => {
                ProtectedPublicationCoordinate::media(context)
            }
            AuthorizationProtectedObjectKind::ModerationTarget => {
                ProtectedPublicationCoordinate::moderation_target(context)
            }
            _ => Err(DbError::InvalidData(
                "authorization protected publication object is unsupported".to_owned(),
            )),
        }
    }
}

impl fmt::Debug for VerifiedProtectedPublicationRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedProtectedPublicationRoute")
            .field("object_kind", &self.object_kind)
            .field("intent", &self.intent)
            .field("coordinates", &"[REDACTED]")
            .finish()
    }
}

/// Final target-bound material consumed by S4's private access wrapper.
pub struct FinalizedProtectedPublicationAuthorization {
    context: AuthContext,
    coordinate: ProtectedPublicationCoordinate,
    operation: Option<ProtectedPublicationOperationIdentity>,
    observer: ProtectedPublicationObserver,
}

impl FinalizedProtectedPublicationAuthorization {
    /// Consume the target-bound result inside the reviewed transport adapter.
    #[allow(dead_code)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        AuthContext,
        ProtectedPublicationCoordinate,
        Option<ProtectedPublicationOperationIdentity>,
        ProtectedPublicationObserver,
    ) {
        (self.context, self.coordinate, self.operation, self.observer)
    }
}

impl fmt::Debug for FinalizedProtectedPublicationAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FinalizedProtectedPublicationAuthorization([REDACTED])")
    }
}

/// Concrete direct-only protected publication finalizer installed by root.
pub struct ProtectedPublicationAuthorizationRuntime {
    resolver: PostgresLocalBindingResolver,
    observer: ProtectedPublicationObserver,
    assertion_verifier: Arc<TrustedProxyAssertionVerifier>,
    maximum_lease: chrono::Duration,
    healthy: AtomicBool,
}

impl ProtectedPublicationAuthorizationRuntime {
    /// Construct a ready direct-only runtime. Delegation remains explicitly unavailable.
    pub fn new_direct_only(
        resolver: PostgresLocalBindingResolver,
        observer: ProtectedPublicationObserver,
        assertion_verifier: Arc<TrustedProxyAssertionVerifier>,
        maximum_lease: Duration,
    ) -> Result<Self, ProtectedPublicationAuthorizationError> {
        let maximum_lease = validate_startup(observer.is_healthy(), maximum_lease)?;
        Ok(Self {
            resolver,
            observer,
            assertion_verifier,
            maximum_lease,
            healthy: AtomicBool::new(true),
        })
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire) && self.observer.is_healthy()
    }

    fn latch_unhealthy(&self) {
        self.healthy.store(false, Ordering::Release);
    }

    async fn authorize(
        &self,
        evidence: ProtectedPublicationEvidence,
        route: VerifiedProtectedPublicationRoute,
    ) -> Result<FinalizedProtectedPublicationAuthorization, ProtectedPublicationAuthorizationError>
    {
        if !self.is_healthy() {
            return Err(ProtectedPublicationAuthorizationError::Unhealthy);
        }
        let (assertion, proof) = match evidence {
            ProtectedPublicationEvidence::Direct(evidence) => evidence.into_parts(),
            ProtectedPublicationEvidence::Delegated(_) => {
                return Err(ProtectedPublicationAuthorizationError::DelegationAuthorityUnavailable);
            }
        };
        if !route.accepts_proof(&proof) {
            return Err(ProtectedPublicationAuthorizationError::RouteMismatch);
        }
        let resolution_request = BindingResolutionRequest::Direct {
            assertion: assertion.clone(),
            proof: proof.clone(),
            capability: route.capability,
        };
        let resolution = self
            .resolver
            .resolve(&resolution_request)
            .await
            .map_err(|error| self.map_resolver_error(error))?;
        let (policy, authoritative_now) = self
            .resolver
            .protected_publication_policy(
                &resolution_request,
                route.object_kind,
                self.maximum_lease,
            )
            .await
            .map_err(|error| self.map_resolver_error(error))?;
        let input = AuthorizationInput::new(
            route.authorization_domain,
            route.correlation_id,
            proof,
            route.capability,
        )?;
        let context =
            AuthorizationFinalizer::finalize(input, resolution, policy, authoritative_now)?;
        if !route.accepts_context(&context) {
            return Err(ProtectedPublicationAuthorizationError::RouteMismatch);
        }
        let coordinate = route.coordinate(&context)?;
        match self
            .resolver
            .db()
            .recheck_protected_publication_authorization(&context, &coordinate)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Err(ProtectedPublicationAuthorizationError::Stale),
            Err(error) => {
                self.latch_unhealthy();
                return Err(ProtectedPublicationAuthorizationError::Database(error));
            }
        }
        if !self.is_healthy() {
            return Err(ProtectedPublicationAuthorizationError::Unhealthy);
        }
        let operation = match route.intent {
            ProtectedPublicationAuthorizationIntent::Read => None,
            ProtectedPublicationAuthorizationIntent::Mutation => {
                Some(ProtectedPublicationOperationIdentity::new(
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                )?)
            }
        };
        Ok(FinalizedProtectedPublicationAuthorization {
            context,
            coordinate,
            operation,
            observer: self.observer.clone(),
        })
    }

    fn map_resolver_error(
        &self,
        error: AuthorizationResolverError,
    ) -> ProtectedPublicationAuthorizationError {
        match error {
            AuthorizationResolverError::BindingUnavailable
            | AuthorizationResolverError::PolicyUnavailable
            | AuthorizationResolverError::StatusEvidenceStale => {
                ProtectedPublicationAuthorizationError::Denied
            }
            AuthorizationResolverError::DelegationAuthorityUnavailable => {
                ProtectedPublicationAuthorizationError::DelegationAuthorityUnavailable
            }
            AuthorizationResolverError::ContractUnavailable => {
                self.latch_unhealthy();
                ProtectedPublicationAuthorizationError::Unhealthy
            }
            AuthorizationResolverError::Database(error) => {
                self.latch_unhealthy();
                ProtectedPublicationAuthorizationError::Database(error)
            }
        }
    }
}

fn validate_startup(
    observer_healthy: bool,
    maximum_lease: Duration,
) -> Result<chrono::Duration, ProtectedPublicationAuthorizationError> {
    if !observer_healthy
        || maximum_lease.is_zero()
        || maximum_lease > MAX_PROTECTED_PUBLICATION_LEASE
    {
        return Err(ProtectedPublicationAuthorizationError::Unhealthy);
    }
    chrono::Duration::from_std(maximum_lease)
        .map_err(|_| ProtectedPublicationAuthorizationError::Unhealthy)
}

impl fmt::Debug for ProtectedPublicationAuthorizationRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedPublicationAuthorizationRuntime")
            .field("healthy", &self.is_healthy())
            .field(
                "delegation",
                &ProtectedPublicationDelegationGrantSource::Unavailable,
            )
            .finish()
    }
}

/// Cloneable concrete request-extension handle.
#[derive(Clone)]
pub struct ProtectedPublicationAuthorizationHandle(Arc<ProtectedPublicationAuthorizationRuntime>);

impl ProtectedPublicationAuthorizationHandle {
    /// Install one already validated direct-only runtime.
    pub fn new(runtime: ProtectedPublicationAuthorizationRuntime) -> Self {
        Self(Arc::new(runtime))
    }

    /// Finalize exact origin-sealed evidence for one target-bound route.
    pub async fn authorize(
        &self,
        evidence: ProtectedPublicationEvidence,
        route: VerifiedProtectedPublicationRoute,
    ) -> Result<FinalizedProtectedPublicationAuthorization, ProtectedPublicationAuthorizationError>
    {
        self.0.authorize(evidence, route).await
    }

    /// Clone the ready live publication observer.
    pub fn observer(
        &self,
    ) -> Result<ProtectedPublicationObserver, ProtectedPublicationAuthorizationError> {
        self.is_healthy()
            .then(|| self.0.observer.clone())
            .ok_or(ProtectedPublicationAuthorizationError::Unhealthy)
    }

    /// Clone the configured trusted-proxy assertion verifier for S4 extraction.
    pub fn trusted_proxy_assertion_verifier(&self) -> Arc<TrustedProxyAssertionVerifier> {
        Arc::clone(&self.0.assertion_verifier)
    }

    /// Explicit V1 delegation-source state.
    pub const fn delegation_grants(&self) -> ProtectedPublicationDelegationGrantSource {
        ProtectedPublicationDelegationGrantSource::Unavailable
    }

    /// Sticky runtime and observer health.
    pub fn is_healthy(&self) -> bool {
        self.0.is_healthy()
    }
}

impl fmt::Debug for ProtectedPublicationAuthorizationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedPublicationAuthorizationHandle")
            .field("healthy", &self.is_healthy())
            .field("delegation", &self.delegation_grants())
            .finish()
    }
}

/// Closed service failures; no credential or target bytes are exposed.
#[derive(Debug, Error)]
pub enum ProtectedPublicationAuthorizationError {
    /// The installed runtime or live observer is unhealthy.
    #[error("protected publication authorization is unavailable")]
    Unhealthy,
    /// V1 has no reviewed positive delegated relationship authority.
    #[error("delegated protected publication authorization is unavailable")]
    DelegationAuthorityUnavailable,
    /// The origin-sealed evidence and exact server route differ.
    #[error("protected publication route does not match verified evidence")]
    RouteMismatch,
    /// No exact active local authority exists.
    #[error("protected publication authorization denied")]
    Denied,
    /// A dependency changed before the final allow fence.
    #[error("protected publication authorization is stale")]
    Stale,
    /// The sole finalizer rejected the sealed evidence or policy.
    #[error(transparent)]
    Finalization(#[from] AuthorizationError),
    /// PostgreSQL was unavailable or returned malformed authority state.
    #[error(transparent)]
    Database(#[from] DbError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    fn domain() -> CommunityId {
        CommunityId::from_uuid(Uuid::from_u128(1))
    }

    fn binding(transport: ProofTransport) -> RequestEvidenceBinding {
        RequestEvidenceBinding::new(
            domain(),
            transport,
            b"canonical request",
            b"canonical target",
            b"canonical transport context",
        )
        .expect("valid binding")
    }

    #[test]
    fn route_seal_closes_object_capability_and_mutation_identity_shape() {
        let actor = Keys::generate().public_key();
        let read = VerifiedProtectedPublicationRoute::from_verified_transport(
            domain(),
            actor,
            Uuid::from_u128(2),
            buzz_auth::RouteCapability::GitRead,
            AuthorizationProtectedObjectKind::Repository,
            ProtectedPublicationAuthorizationIntent::Read,
            binding(ProofTransport::GitSmartHttpSession),
        )
        .expect("valid read route");
        assert_eq!(read.intent, ProtectedPublicationAuthorizationIntent::Read);
        assert!(matches!(
            VerifiedProtectedPublicationRoute::from_verified_transport(
                domain(),
                actor,
                Uuid::from_u128(2),
                buzz_auth::RouteCapability::GitRead,
                AuthorizationProtectedObjectKind::Repository,
                ProtectedPublicationAuthorizationIntent::Mutation,
                binding(ProofTransport::GitSmartHttpSession),
            ),
            Err(ProtectedPublicationAuthorizationError::RouteMismatch)
        ));
        assert!(matches!(
            VerifiedProtectedPublicationRoute::from_verified_transport(
                domain(),
                actor,
                Uuid::from_u128(2),
                buzz_auth::RouteCapability::MediaWrite,
                AuthorizationProtectedObjectKind::Repository,
                ProtectedPublicationAuthorizationIntent::Mutation,
                binding(ProofTransport::GitSmartHttpSession),
            ),
            Err(ProtectedPublicationAuthorizationError::RouteMismatch)
        ));
    }

    #[test]
    fn delegation_is_explicitly_unavailable_and_debug_is_redacted() {
        assert_eq!(
            ProtectedPublicationDelegationGrantSource::Unavailable,
            ProtectedPublicationDelegationGrantSource::Unavailable
        );
        let route = VerifiedProtectedPublicationRoute::from_verified_transport(
            domain(),
            Keys::generate().public_key(),
            Uuid::from_u128(2),
            buzz_auth::RouteCapability::MediaRead,
            AuthorizationProtectedObjectKind::Media,
            ProtectedPublicationAuthorizationIntent::Read,
            binding(ProofTransport::Blossom),
        )
        .expect("valid media route");
        let debug = format!("{route:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("canonical target"));
        assert!(!debug.contains("canonical request"));
    }

    #[test]
    fn lease_bound_is_finite_and_closed() {
        assert_eq!(MAX_PROTECTED_PUBLICATION_LEASE, Duration::from_secs(300));
        assert_eq!(
            validate_startup(true, Duration::from_secs(300)).expect("maximum is accepted"),
            chrono::Duration::seconds(300)
        );
        assert!(matches!(
            validate_startup(false, Duration::from_secs(60)),
            Err(ProtectedPublicationAuthorizationError::Unhealthy)
        ));
        assert!(matches!(
            validate_startup(true, Duration::ZERO),
            Err(ProtectedPublicationAuthorizationError::Unhealthy)
        ));
        assert!(matches!(
            validate_startup(true, Duration::from_secs(301)),
            Err(ProtectedPublicationAuthorizationError::Unhealthy)
        ));
    }
}
