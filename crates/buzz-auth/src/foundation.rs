//! Provider-free local authorization composition.
//!
//! Verified assertions and delegations are origin-sealed values: constructors
//! are crate-private so unverified claims cannot be promoted into authority.
//! Storage resolution and finalization are separate phases, and exactly one
//! finalizer creates [`AuthContext`].

use buzz_core::{AuthorizationLeaseFence, CanonicalCurrentBindingEvidence, CommunityId};
use chrono::{DateTime, Utc};
use nostr::PublicKey;
use std::fmt;
use std::future::Future;
use thiserror::Error;
use uuid::Uuid;

/// Hard implementation ceiling for one domain's retained audit events.
pub const HARD_MAX_AUTHORIZATION_EVENTS_PER_DOMAIN: u64 = 1_000_000;
/// Hard implementation ceiling for one domain's retained canonical bytes.
pub const HARD_MAX_AUTHORIZATION_EVENT_BYTES_PER_DOMAIN: u64 = 4_294_967_296;
/// Hard implementation ceiling for one canonical event envelope.
pub const HARD_MAX_AUTHORIZATION_EVENT_ENVELOPE_BYTES: u32 = 65_536;

/// Minimal stock NIP-FI operating modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NipFiMode {
    /// NIP-FI protected composition is absent. This is the stock default.
    Off,
    /// Protected routes require complete provider-free local composition.
    Enforce,
    /// Emergency mode denying protected routes before verifier setup.
    DenyProtected,
}

/// Validated immutable-capacity policy required by enabled composition.
///
/// V1 intentionally has no online prune, export, reset, claim, acknowledgement,
/// or retry workflow. Operators must size this policy for the installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationEventCapacityPolicy {
    max_events_per_domain: u64,
    max_bytes_per_domain: u64,
    max_envelope_bytes: u32,
}

impl AuthorizationEventCapacityPolicy {
    /// Validate an installation's explicit immutable-capacity bounds.
    pub fn new(
        max_events_per_domain: u64,
        max_bytes_per_domain: u64,
        max_envelope_bytes: u32,
    ) -> Result<Self, AuthorizationEventCapacityPolicyError> {
        if max_events_per_domain == 0
            || max_events_per_domain > HARD_MAX_AUTHORIZATION_EVENTS_PER_DOMAIN
        {
            return Err(AuthorizationEventCapacityPolicyError::EventCount);
        }
        if max_bytes_per_domain == 0
            || max_bytes_per_domain > HARD_MAX_AUTHORIZATION_EVENT_BYTES_PER_DOMAIN
        {
            return Err(AuthorizationEventCapacityPolicyError::DomainBytes);
        }
        if max_envelope_bytes == 0
            || max_envelope_bytes > HARD_MAX_AUTHORIZATION_EVENT_ENVELOPE_BYTES
            || u64::from(max_envelope_bytes) > max_bytes_per_domain
        {
            return Err(AuthorizationEventCapacityPolicyError::EnvelopeBytes);
        }
        Ok(Self {
            max_events_per_domain,
            max_bytes_per_domain,
            max_envelope_bytes,
        })
    }

    /// Maximum retained events in one authorization domain.
    pub const fn max_events_per_domain(self) -> u64 {
        self.max_events_per_domain
    }

    /// Maximum retained canonical envelope bytes in one domain.
    pub const fn max_bytes_per_domain(self) -> u64 {
        self.max_bytes_per_domain
    }

    /// Maximum canonical bytes in one event envelope.
    pub const fn max_envelope_bytes(self) -> u32 {
        self.max_envelope_bytes
    }
}

/// Capacity-policy validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthorizationEventCapacityPolicyError {
    /// The per-domain event count was zero or exceeded the implementation cap.
    #[error("invalid per-domain authorization event count")]
    EventCount,
    /// The per-domain byte limit was zero or exceeded the implementation cap.
    #[error("invalid per-domain authorization event byte limit")]
    DomainBytes,
    /// The envelope limit was zero, too large, or larger than domain capacity.
    #[error("invalid authorization event envelope byte limit")]
    EnvelopeBytes,
}

/// Audit-capacity portion of a domain's Base V1 configuration.
///
/// This is deliberately not the complete enabled configuration. Enforce mode
/// additionally requires verifier, audience, transport, enrollment, token-age,
/// clock-skew, and lease bounds owned by the composition layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationAuditConfig {
    mode: NipFiMode,
    event_capacity: Option<AuthorizationEventCapacityPolicy>,
}

impl AuthorizationAuditConfig {
    /// Validate the audit-capacity portion for one closed operating mode.
    pub fn new(
        mode: NipFiMode,
        event_capacity: Option<AuthorizationEventCapacityPolicy>,
    ) -> Result<Self, AuthorizationAuditConfigError> {
        match (mode, event_capacity) {
            (NipFiMode::Enforce, None) => Err(AuthorizationAuditConfigError::MissingEventCapacity),
            (NipFiMode::Off | NipFiMode::DenyProtected, Some(_)) => {
                Err(AuthorizationAuditConfigError::UnexpectedEventCapacity)
            }
            _ => Ok(Self {
                mode,
                event_capacity,
            }),
        }
    }

    /// The domain's closed operating mode.
    pub const fn mode(self) -> NipFiMode {
        self.mode
    }

    /// Enabled-mode audit capacity, absent for Off and emergency denial.
    pub const fn event_capacity(self) -> Option<AuthorizationEventCapacityPolicy> {
        self.event_capacity
    }
}

/// Domain-configuration validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthorizationAuditConfigError {
    /// Enforce mode must explicitly size the immutable audit store.
    #[error("enforce mode requires authorization event capacity")]
    MissingEventCapacity,
    /// Disabled and emergency-denial modes do not initialize an audit writer.
    #[error("authorization event capacity is only valid in enforce mode")]
    UnexpectedEventCapacity,
}

/// Transport on which the relay verified the Nostr proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofTransport {
    /// NIP-42 WebSocket AUTH.
    Nip42,
    /// Generic NIP-98 HTTP authorization.
    Nip98,
    /// Git smart-HTTP session authorization.
    GitSmartHttpSession,
    /// Blossom media HTTP authorization.
    Blossom,
}

/// Closed route capability used by local policy and delegation checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RouteCapability {
    /// Read messages.
    MessagesRead,
    /// Write messages.
    MessagesWrite,
    /// Read channel metadata.
    ChannelsRead,
    /// Mutate channels.
    ChannelsWrite,
    /// Perform channel administration.
    AdminChannels,
    /// Read user metadata.
    UsersRead,
    /// Mutate user metadata.
    UsersWrite,
    /// Perform user administration.
    AdminUsers,
    /// Read jobs.
    JobsRead,
    /// Mutate jobs.
    JobsWrite,
    /// Read subscriptions.
    SubscriptionsRead,
    /// Mutate subscriptions.
    SubscriptionsWrite,
    /// Read files.
    FilesRead,
    /// Write files.
    FilesWrite,
    /// Read repositories.
    ReposRead,
    /// Write repositories.
    ReposWrite,
    /// Read Git objects and refs.
    GitRead,
    /// Mutate Git objects and refs.
    GitWrite,
    /// Keep a bounded Git streaming operation alive.
    GitStream,
    /// Read media using GET or HEAD.
    MediaRead,
    /// Upload or mutate media.
    MediaWrite,
    /// Perform moderation operations.
    Moderation,
    /// Join an audio session.
    AudioJoin,
    /// Send or receive bounded audio media.
    AudioMedia,
    /// Read protected discovery data.
    Discovery,
    /// Read current local binding status.
    BindingStatus,
    /// Enroll a local binding.
    Enrollment,
}

/// Closed capability advertised by the concrete local binding resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalBindingResolverCapability {
    /// Direct active-binding resolution only.
    Direct,
    /// Direct resolution plus explicit owner-bound delegated resolution.
    DirectAndDelegatedOwnerBound,
}

/// Non-mutating request for current local binding status evidence.
#[derive(Clone)]
pub struct CurrentBindingStatusEvidenceRequest {
    authorization_domain: CommunityId,
    event_author_pubkey: PublicKey,
}

impl CurrentBindingStatusEvidenceRequest {
    /// Construct a status request from a server-resolved domain and exact key.
    pub fn new(
        authorization_domain: CommunityId,
        event_author_pubkey: PublicKey,
    ) -> Result<Self, AuthorizationError> {
        if authorization_domain.as_uuid().is_nil() {
            return Err(AuthorizationError::InvalidInput);
        }
        Ok(Self {
            authorization_domain,
            event_author_pubkey,
        })
    }

    /// Server-resolved authorization domain.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Exact Nostr author whose current binding is requested.
    pub const fn event_author_pubkey(&self) -> PublicKey {
        self.event_author_pubkey
    }
}

impl fmt::Debug for CurrentBindingStatusEvidenceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CurrentBindingStatusEvidenceRequest([REDACTED])")
    }
}

/// Cross-crate contract implemented by the concrete PostgreSQL local resolver.
///
/// This is a storage boundary, not a provider SPI. Resolution is limited to
/// exact local binding facts. Both status methods are read-only: implementations
/// must not enroll, consume selectors, append history, or update `last_seen`.
/// Public evidence construction validates data shape only. Composition trusts
/// the configured resolver implementation and must use its atomic recheck plus
/// `CanonicalCurrentBindingEvidence::accepts_exact_recheck` before delivery;
/// an arbitrary constructed tuple is never authority by itself.
pub trait LocalBindingResolver: Send + Sync {
    /// Storage/read failure returned fail closed to composition.
    type Error: Send;

    /// Whether this resolver supports direct-only or explicit owner-bound
    /// delegated resolution.
    fn capability(&self) -> LocalBindingResolverCapability;

    /// Resolve one origin-sealed direct, delegated, or enrollment request.
    fn resolve<'a>(
        &'a self,
        request: &'a BindingResolutionRequest,
    ) -> impl Future<Output = Result<LocalBindingResolution, Self::Error>> + Send + 'a;

    /// Read privacy-safe current status without mutating identity state.
    fn current_status_evidence<'a>(
        &'a self,
        request: &'a CurrentBindingStatusEvidenceRequest,
    ) -> impl Future<Output = Result<CanonicalCurrentBindingEvidence, Self::Error>> + Send + 'a;

    /// Recheck the complete evidence tuple atomically against PostgreSQL
    /// immediately before presentation. Error, staleness, or any tuple mismatch
    /// withholds presentation without changing authorization.
    fn recheck_current_status_evidence<'a>(
        &'a self,
        evidence: &'a CanonicalCurrentBindingEvidence,
    ) -> impl Future<Output = Result<CanonicalCurrentBindingEvidence, Self::Error>> + Send + 'a;
}

/// Whether a route participates in protected composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteProtection {
    /// Explicitly unprotected route; the only route accepting NotRequired.
    Unprotected,
    /// Protected route requiring the exact capability.
    Protected(RouteCapability),
}

/// Exact opaque federated identity admitted by a verifier.
#[derive(Clone, PartialEq, Eq)]
pub struct FederatedPrincipal {
    issuer: String,
    subject: String,
}

impl FederatedPrincipal {
    #[allow(dead_code)]
    pub(crate) fn from_verified_parts(issuer: String, subject: String) -> Option<Self> {
        if issuer.is_empty() || subject.is_empty() || issuer.len() > 2048 || subject.len() > 2048 {
            return None;
        }
        Some(Self { issuer, subject })
    }

    /// Borrow the exact opaque storage key without enabling construction from
    /// unverified claims.
    pub fn storage_key(&self) -> FederatedPrincipalStorageKey<'_> {
        FederatedPrincipalStorageKey {
            issuer: &self.issuer,
            subject: &self.subject,
        }
    }
}

/// Borrowed exact storage key for an origin-sealed principal.
#[derive(Clone, Copy)]
pub struct FederatedPrincipalStorageKey<'a> {
    issuer: &'a str,
    subject: &'a str,
}

impl<'a> FederatedPrincipalStorageKey<'a> {
    /// Exact validated issuer bytes for a parameterized database bind.
    pub const fn issuer(&self) -> &'a str {
        self.issuer
    }

    /// Exact opaque subject bytes for a parameterized database bind.
    pub const fn subject(&self) -> &'a str {
        self.subject
    }
}

impl fmt::Debug for FederatedPrincipalStorageKey<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FederatedPrincipalStorageKey([REDACTED])")
    }
}

impl fmt::Debug for FederatedPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FederatedPrincipal([REDACTED])")
    }
}

/// Origin-sealed result of federated assertion validation.
///
/// External callers cannot relabel an assertion with a claimed key:
///
/// ```compile_fail
/// # use buzz_auth::VerifiedFederatedAssertion;
/// fn relabel(assertion: &mut VerifiedFederatedAssertion) {
///     assertion.attested_event_author_pubkey = None;
/// }
/// ```
///
/// Nor can they reconstruct one with a substituted key:
///
/// ```compile_fail
/// # use buzz_auth::VerifiedFederatedAssertion;
/// fn remint(assertion: VerifiedFederatedAssertion) -> VerifiedFederatedAssertion {
///     VerifiedFederatedAssertion {
///         attested_event_author_pubkey: None,
///         ..assertion
///     }
/// }
/// ```
#[derive(Clone)]
pub struct VerifiedFederatedAssertion {
    authorization_domain: CommunityId,
    principal: FederatedPrincipal,
    attested_event_author_pubkey: Option<PublicKey>,
    transport: ProofTransport,
    assertion_fingerprint: [u8; 32],
    target_fingerprint: [u8; 32],
    request_fingerprint: [u8; 32],
    transport_context_fingerprint: [u8; 32],
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl VerifiedFederatedAssertion {
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn from_verifier(
        authorization_domain: CommunityId,
        principal: FederatedPrincipal,
        transport: ProofTransport,
        assertion_fingerprint: [u8; 32],
        target_fingerprint: [u8; 32],
        request_fingerprint: [u8; 32],
        transport_context_fingerprint: [u8; 32],
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Option<Self> {
        if authorization_domain.as_uuid().is_nil()
            || assertion_fingerprint == [0; 32]
            || target_fingerprint == [0; 32]
            || request_fingerprint == [0; 32]
            || transport_context_fingerprint == [0; 32]
            || not_before >= expires_at
        {
            return None;
        }
        Some(Self {
            authorization_domain,
            principal,
            attested_event_author_pubkey: None,
            transport,
            assertion_fingerprint,
            target_fingerprint,
            request_fingerprint,
            transport_context_fingerprint,
            not_before,
            expires_at,
        })
    }

    /// Server-resolved domain sealed by the verifier.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Clone the origin-sealed principal for an authoritative storage result.
    pub fn principal_for_storage(&self) -> FederatedPrincipal {
        self.principal.clone()
    }

    /// Exact principal lookup key for parameterized database reads.
    pub fn principal_storage_key(&self) -> FederatedPrincipalStorageKey<'_> {
        self.principal.storage_key()
    }

    /// Optional assertion key claim after exact Nostr-proof matching.
    ///
    /// `None` is valid for grandfathered existing-binding resolution and
    /// risk-labelled TOFU creation. Attested-key creation must require `Some`
    /// before mutation.
    pub const fn attested_event_author_pubkey(&self) -> Option<PublicKey> {
        self.attested_event_author_pubkey
    }

    // Consumed by the trusted-evidence layer introduced in the next stack PR.
    #[allow(dead_code)]
    pub(crate) fn bind_attested_event_author_pubkey(
        mut self,
        event_author_pubkey: PublicKey,
        proof: &VerifiedNostrProof,
    ) -> Option<Self> {
        if self.attested_event_author_pubkey.is_some()
            || event_author_pubkey != proof.actor_pubkey()
            || self.authorization_domain != proof.authorization_domain()
            || self.transport != proof.transport()
            || self.assertion_fingerprint != *proof.bound_assertion_fingerprint()?
            || self.request_fingerprint != *proof.request_fingerprint()
            || self.target_fingerprint != *proof.target_fingerprint()
            || self.transport_context_fingerprint != *proof.transport_context_fingerprint()
        {
            return None;
        }
        self.attested_event_author_pubkey = Some(event_author_pubkey);
        Some(self)
    }
}

impl fmt::Debug for VerifiedFederatedAssertion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedFederatedAssertion([REDACTED])")
    }
}

/// Origin-sealed Nostr proof bound to one server-resolved domain and request.
#[derive(Clone)]
pub struct VerifiedNostrProof {
    authorization_domain: CommunityId,
    actor_pubkey: PublicKey,
    transport: ProofTransport,
    request_fingerprint: [u8; 32],
    target_fingerprint: [u8; 32],
    transport_context_fingerprint: [u8; 32],
    bound_assertion_fingerprint: Option<[u8; 32]>,
    delegation_conditions_fingerprint: Option<[u8; 32]>,
    expires_at: DateTime<Utc>,
}

impl VerifiedNostrProof {
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn from_verifier(
        authorization_domain: CommunityId,
        actor_pubkey: PublicKey,
        transport: ProofTransport,
        request_fingerprint: [u8; 32],
        target_fingerprint: [u8; 32],
        transport_context_fingerprint: [u8; 32],
        bound_assertion_fingerprint: Option<[u8; 32]>,
        delegation_conditions_fingerprint: Option<[u8; 32]>,
        expires_at: DateTime<Utc>,
    ) -> Option<Self> {
        if authorization_domain.as_uuid().is_nil()
            || request_fingerprint == [0; 32]
            || target_fingerprint == [0; 32]
            || transport_context_fingerprint == [0; 32]
            || bound_assertion_fingerprint == Some([0; 32])
            || delegation_conditions_fingerprint == Some([0; 32])
        {
            return None;
        }
        Some(Self {
            authorization_domain,
            actor_pubkey,
            transport,
            request_fingerprint,
            target_fingerprint,
            transport_context_fingerprint,
            bound_assertion_fingerprint,
            delegation_conditions_fingerprint,
            expires_at,
        })
    }

    /// Server-resolved domain sealed by the proof verifier.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Exact verified Nostr actor.
    pub const fn actor_pubkey(&self) -> PublicKey {
        self.actor_pubkey
    }

    /// Transport whose verifier origin-sealed this proof.
    pub const fn transport(&self) -> ProofTransport {
        self.transport
    }

    /// Exact request fingerprint sealed by the verifier.
    pub const fn request_fingerprint(&self) -> &[u8; 32] {
        &self.request_fingerprint
    }

    /// Exact protected target fingerprint sealed by the verifier.
    pub const fn target_fingerprint(&self) -> &[u8; 32] {
        &self.target_fingerprint
    }

    /// Exact transport-context fingerprint sealed by the verifier.
    pub const fn transport_context_fingerprint(&self) -> &[u8; 32] {
        &self.transport_context_fingerprint
    }

    /// Optional assertion fingerprint co-located with this proof.
    pub const fn bound_assertion_fingerprint(&self) -> Option<&[u8; 32]> {
        self.bound_assertion_fingerprint.as_ref()
    }

    /// Optional delegated-conditions fingerprint co-located with this proof.
    pub const fn delegation_conditions_fingerprint(&self) -> Option<&[u8; 32]> {
        self.delegation_conditions_fingerprint.as_ref()
    }

    /// Exclusive verifier-owned proof expiry.
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl fmt::Debug for VerifiedNostrProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedNostrProof([REDACTED])")
    }
}

/// Origin-sealed, assertion-free delegated authority.
#[derive(Clone)]
pub struct VerifiedDelegation {
    authorization_domain: CommunityId,
    owner_pubkey: PublicKey,
    delegate_pubkey: PublicKey,
    transport: ProofTransport,
    relationship_id: Uuid,
    relationship_revision: u64,
    capabilities: Vec<RouteCapability>,
    conditions_fingerprint: [u8; 32],
    target_fingerprint: [u8; 32],
    request_fingerprint: [u8; 32],
    transport_context_fingerprint: [u8; 32],
    expires_at: DateTime<Utc>,
}

impl VerifiedDelegation {
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub(crate) fn from_verifier(
        authorization_domain: CommunityId,
        owner_pubkey: PublicKey,
        delegate_pubkey: PublicKey,
        transport: ProofTransport,
        relationship_id: Uuid,
        relationship_revision: u64,
        mut capabilities: Vec<RouteCapability>,
        conditions_fingerprint: [u8; 32],
        target_fingerprint: [u8; 32],
        request_fingerprint: [u8; 32],
        transport_context_fingerprint: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Option<Self> {
        capabilities.sort_unstable();
        capabilities.dedup();
        if authorization_domain.as_uuid().is_nil()
            || relationship_id.is_nil()
            || relationship_revision == 0
            || capabilities.is_empty()
            || conditions_fingerprint == [0; 32]
            || target_fingerprint == [0; 32]
            || request_fingerprint == [0; 32]
            || transport_context_fingerprint == [0; 32]
        {
            return None;
        }
        Some(Self {
            authorization_domain,
            owner_pubkey,
            delegate_pubkey,
            transport,
            relationship_id,
            relationship_revision,
            capabilities,
            conditions_fingerprint,
            target_fingerprint,
            request_fingerprint,
            transport_context_fingerprint,
            expires_at,
        })
    }

    /// Server-resolved domain sealed by the delegation verifier.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Exact owner key whose active binding must be resolved.
    pub const fn owner_pubkey(&self) -> PublicKey {
        self.owner_pubkey
    }

    /// Exact delegate key that must match the Nostr proof actor.
    pub const fn delegate_pubkey(&self) -> PublicKey {
        self.delegate_pubkey
    }
}

impl fmt::Debug for VerifiedDelegation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedDelegation([REDACTED])")
    }
}

/// Explicit request variants accepted by the one local binding resolver.
#[derive(Clone)]
pub enum BindingResolutionRequest {
    /// Resolve an existing binding for a verified assertion and Nostr proof.
    Direct {
        /// Origin-sealed federated assertion.
        assertion: VerifiedFederatedAssertion,
        /// Origin-sealed Nostr proof.
        proof: VerifiedNostrProof,
        /// Exact protected capability.
        capability: RouteCapability,
    },
    /// Resolve the exact active owner binding for an assertion-free delegate.
    Delegated {
        /// Origin-sealed delegation.
        delegation: VerifiedDelegation,
        /// Origin-sealed proof by the delegate.
        proof: VerifiedNostrProof,
        /// Exact owner-bound delegated capability.
        capability: RouteCapability,
    },
    /// Resolve or create a binding under the local enrollment policy.
    Enrollment {
        /// Origin-sealed federated assertion.
        assertion: VerifiedFederatedAssertion,
        /// Origin-sealed Nostr proof.
        proof: VerifiedNostrProof,
        /// Exact protected capability.
        capability: RouteCapability,
    },
}

/// One active, versioned local binding returned from authoritative storage.
#[derive(Clone)]
pub struct ActiveLocalBinding {
    authorization_domain: CommunityId,
    principal: FederatedPrincipal,
    binding_id: Uuid,
    binding_version: u64,
    event_author_pubkey: PublicKey,
    expires_at: Option<DateTime<Utc>>,
}

impl ActiveLocalBinding {
    /// Construct one exact active-binding row from raw authoritative storage
    /// columns.
    ///
    /// This adapter validates and seals the opaque issuer/subject pair without
    /// exposing a raw-claims principal constructor. It is intended only for the
    /// configured [`LocalBindingResolver`]; the returned storage fact is not
    /// authority until the finalizer matches it to independently verified
    /// inputs and policy.
    #[allow(clippy::too_many_arguments)]
    pub fn from_storage_parts(
        authorization_domain: CommunityId,
        issuer: String,
        subject: String,
        binding_id: Uuid,
        binding_version: u64,
        event_author_pubkey: PublicKey,
        expires_at: Option<DateTime<Utc>>,
    ) -> Option<Self> {
        let principal = FederatedPrincipal::from_verified_parts(issuer, subject)?;
        Self::from_storage(
            authorization_domain,
            principal,
            binding_id,
            binding_version,
            event_author_pubkey,
            expires_at,
        )
    }

    /// Construct one exact active-binding row returned by authoritative storage.
    pub fn from_storage(
        authorization_domain: CommunityId,
        principal: FederatedPrincipal,
        binding_id: Uuid,
        binding_version: u64,
        event_author_pubkey: PublicKey,
        expires_at: Option<DateTime<Utc>>,
    ) -> Option<Self> {
        if authorization_domain.as_uuid().is_nil() || binding_id.is_nil() || binding_version == 0 {
            return None;
        }
        Some(Self {
            authorization_domain,
            principal,
            binding_id,
            binding_version,
            event_author_pubkey,
            expires_at,
        })
    }
}

impl fmt::Debug for ActiveLocalBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveLocalBinding([REDACTED])")
    }
}

/// Authoritative local resolver result with origin-sealed authority inputs.
#[derive(Clone)]
pub struct LocalBindingResolution(LocalBindingResolutionKind);

#[derive(Clone)]
enum LocalBindingResolutionKind {
    Direct {
        assertion: VerifiedFederatedAssertion,
        binding: ActiveLocalBinding,
    },
    Enrollment {
        assertion: VerifiedFederatedAssertion,
        binding: ActiveLocalBinding,
    },
    Delegated {
        delegation: VerifiedDelegation,
        owner_binding: ActiveLocalBinding,
    },
}

impl LocalBindingResolution {
    /// Bind an origin-sealed direct assertion to an authoritative storage row.
    pub fn direct(assertion: VerifiedFederatedAssertion, binding: ActiveLocalBinding) -> Self {
        Self(LocalBindingResolutionKind::Direct { assertion, binding })
    }

    /// Bind caller-owned enrollment output to its origin-sealed assertion.
    pub fn enrollment(assertion: VerifiedFederatedAssertion, binding: ActiveLocalBinding) -> Self {
        Self(LocalBindingResolutionKind::Enrollment { assertion, binding })
    }

    /// Bind an assertion-free delegation to the exact authoritative owner row.
    pub fn delegated(delegation: VerifiedDelegation, owner_binding: ActiveLocalBinding) -> Self {
        Self(LocalBindingResolutionKind::Delegated {
            delegation,
            owner_binding,
        })
    }
}

impl fmt::Debug for LocalBindingResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match &self.0 {
            LocalBindingResolutionKind::Direct { .. } => "Direct([REDACTED])",
            LocalBindingResolutionKind::Enrollment { .. } => "Enrollment([REDACTED])",
            LocalBindingResolutionKind::Delegated { .. } => "Delegated([REDACTED])",
        };
        formatter.write_str(name)
    }
}

/// Database-derived final policy state for one exact capability.
#[derive(Clone)]
pub struct LocalAuthorizationPolicy {
    authorization_domain: CommunityId,
    lease_id: Uuid,
    policy_revision: u64,
    invalidation_generation: u64,
    authority_epoch: u64,
    fence: AuthorizationLeaseFence,
    capability: RouteCapability,
    expires_at: DateTime<Utc>,
    delegated_max_expires_at: Option<DateTime<Utc>>,
    stronger_owner_expires_at: Option<DateTime<Utc>>,
}

impl LocalAuthorizationPolicy {
    /// Construct a policy decision from an authoritative PostgreSQL result.
    #[allow(clippy::too_many_arguments)]
    pub fn from_database(
        authorization_domain: CommunityId,
        lease_id: Uuid,
        policy_revision: u64,
        invalidation_generation: u64,
        authority_epoch: u64,
        fence: AuthorizationLeaseFence,
        capability: RouteCapability,
        expires_at: DateTime<Utc>,
        delegated_max_expires_at: Option<DateTime<Utc>>,
        stronger_owner_expires_at: Option<DateTime<Utc>>,
    ) -> Option<Self> {
        if authorization_domain.as_uuid().is_nil()
            || lease_id.is_nil()
            || policy_revision == 0
            || authority_epoch == 0
        {
            return None;
        }
        Some(Self {
            authorization_domain,
            lease_id,
            policy_revision,
            invalidation_generation,
            authority_epoch,
            fence,
            capability,
            expires_at,
            delegated_max_expires_at,
            stronger_owner_expires_at,
        })
    }
}

impl fmt::Debug for LocalAuthorizationPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalAuthorizationPolicy([REDACTED])")
    }
}

/// Inputs already verified before local binding resolution.
#[derive(Clone)]
pub struct AuthorizationInput {
    authorization_domain: CommunityId,
    correlation_id: Uuid,
    proof: VerifiedNostrProof,
    capability: RouteCapability,
}

impl AuthorizationInput {
    /// Bind one verified proof to server-resolved route metadata.
    pub fn new(
        authorization_domain: CommunityId,
        correlation_id: Uuid,
        proof: VerifiedNostrProof,
        capability: RouteCapability,
    ) -> Result<Self, AuthorizationError> {
        if authorization_domain.as_uuid().is_nil() || correlation_id.is_nil() {
            return Err(AuthorizationError::InvalidInput);
        }
        if proof.authorization_domain != authorization_domain {
            return Err(AuthorizationError::DomainMismatch);
        }
        Ok(Self {
            authorization_domain,
            correlation_id,
            proof,
            capability,
        })
    }
}

/// Bounded authorization lease shared by request and audio use sites.
#[derive(Clone)]
pub struct BoundedAuthorizationLease {
    lease_id: Uuid,
    authorization_domain: CommunityId,
    capability: RouteCapability,
    actor_pubkey: PublicKey,
    owner_pubkey: Option<PublicKey>,
    binding_id: Uuid,
    binding_version: u64,
    relationship_id: Option<Uuid>,
    relationship_revision: Option<u64>,
    delegation_conditions_fingerprint: Option<[u8; 32]>,
    request_fingerprint: [u8; 32],
    target_fingerprint: [u8; 32],
    transport: ProofTransport,
    transport_context_fingerprint: [u8; 32],
    issued_at: DateTime<Utc>,
    fence: AuthorizationLeaseFence,
    policy_revision: u64,
    invalidation_generation: u64,
    authority_epoch: u64,
    expires_at: DateTime<Utc>,
}

impl BoundedAuthorizationLease {
    /// Exclusive validity check using an authoritative PostgreSQL-derived time.
    pub fn is_valid_at(&self, authoritative_now: DateTime<Utc>) -> bool {
        authoritative_now >= self.issued_at && authoritative_now < self.expires_at
    }

    /// Stable lease identifier allocated by the authoritative transaction.
    pub const fn lease_id(&self) -> Uuid {
        self.lease_id
    }

    /// Server-resolved authorization domain.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Exact closed capability guarded by this lease.
    pub const fn capability(&self) -> RouteCapability {
        self.capability
    }

    /// Exact Nostr actor.
    pub const fn actor_pubkey(&self) -> PublicKey {
        self.actor_pubkey
    }

    /// Exact delegated owner, when delegated authorization was used.
    pub const fn owner_pubkey(&self) -> Option<PublicKey> {
        self.owner_pubkey
    }

    /// Exact active owner/direct binding identifier and version.
    pub const fn binding(&self) -> (Uuid, u64) {
        (self.binding_id, self.binding_version)
    }

    /// Delegated relationship identity and revision, when present.
    pub const fn delegated_relationship(&self) -> Option<(Uuid, u64)> {
        match (self.relationship_id, self.relationship_revision) {
            (Some(id), Some(revision)) => Some((id, revision)),
            _ => None,
        }
    }

    /// Exact request, target, and transport-context binding.
    pub const fn request_binding(&self) -> (&[u8; 32], &[u8; 32], &[u8; 32]) {
        (
            &self.request_fingerprint,
            &self.target_fingerprint,
            &self.transport_context_fingerprint,
        )
    }

    /// Proof transport used for this lease.
    pub const fn transport(&self) -> ProofTransport {
        self.transport
    }

    /// Policy, invalidation, and authority versions captured by the lease.
    pub const fn dependency_versions(&self) -> (u64, u64, u64) {
        (
            self.policy_revision,
            self.invalidation_generation,
            self.authority_epoch,
        )
    }

    /// Authoritative PostgreSQL issue time.
    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    /// Observable dependency fence.
    pub const fn fence(&self) -> AuthorizationLeaseFence {
        self.fence
    }

    /// Exclusive lease expiry.
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Clone the complete sealed dependency tuple for a database re-fence.
    pub fn dependency_snapshot(&self) -> AuthorizationLeaseDependencySnapshot {
        AuthorizationLeaseDependencySnapshot {
            lease_id: self.lease_id,
            authorization_domain: self.authorization_domain,
            capability: self.capability,
            actor_pubkey: self.actor_pubkey,
            owner_pubkey: self.owner_pubkey,
            binding_id: self.binding_id,
            binding_version: self.binding_version,
            relationship_id: self.relationship_id,
            relationship_revision: self.relationship_revision,
            delegation_conditions_fingerprint: self.delegation_conditions_fingerprint,
            request_fingerprint: self.request_fingerprint,
            target_fingerprint: self.target_fingerprint,
            transport: self.transport,
            transport_context_fingerprint: self.transport_context_fingerprint,
            issued_at: self.issued_at,
            policy_revision: self.policy_revision,
            invalidation_generation: self.invalidation_generation,
            authority_epoch: self.authority_epoch,
            fence: self.fence,
            expires_at: self.expires_at,
        }
    }
}

impl fmt::Debug for BoundedAuthorizationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedAuthorizationLease([REDACTED])")
    }
}

/// Complete sealed input for re-fencing a cloned authorization lease.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationLeaseDependencySnapshot {
    lease_id: Uuid,
    authorization_domain: CommunityId,
    capability: RouteCapability,
    actor_pubkey: PublicKey,
    owner_pubkey: Option<PublicKey>,
    binding_id: Uuid,
    binding_version: u64,
    relationship_id: Option<Uuid>,
    relationship_revision: Option<u64>,
    delegation_conditions_fingerprint: Option<[u8; 32]>,
    request_fingerprint: [u8; 32],
    target_fingerprint: [u8; 32],
    transport: ProofTransport,
    transport_context_fingerprint: [u8; 32],
    issued_at: DateTime<Utc>,
    policy_revision: u64,
    invalidation_generation: u64,
    authority_epoch: u64,
    fence: AuthorizationLeaseFence,
    expires_at: DateTime<Utc>,
}

impl AuthorizationLeaseDependencySnapshot {
    /// Stable lease identifier and server-resolved domain.
    pub const fn identity(&self) -> (Uuid, CommunityId) {
        (self.lease_id, self.authorization_domain)
    }

    /// Exact capability, actor, and optional delegated owner.
    pub const fn authority(&self) -> (RouteCapability, PublicKey, Option<PublicKey>) {
        (self.capability, self.actor_pubkey, self.owner_pubkey)
    }

    /// Exact active direct/owner binding identifier and version.
    pub const fn binding(&self) -> (Uuid, u64) {
        (self.binding_id, self.binding_version)
    }

    /// Exact relationship identity/revision and conditions, when delegated.
    pub const fn delegated_relationship(&self) -> Option<(Uuid, u64, &[u8; 32])> {
        match (
            self.relationship_id,
            self.relationship_revision,
            &self.delegation_conditions_fingerprint,
        ) {
            (Some(id), Some(revision), Some(conditions)) => Some((id, revision, conditions)),
            _ => None,
        }
    }

    /// Exact request, target, transport, and transport-context coordinates.
    pub const fn request_binding(&self) -> (&[u8; 32], &[u8; 32], ProofTransport, &[u8; 32]) {
        (
            &self.request_fingerprint,
            &self.target_fingerprint,
            self.transport,
            &self.transport_context_fingerprint,
        )
    }

    /// Exact policy, invalidation, and authority versions.
    pub const fn dependency_versions(&self) -> (u64, u64, u64) {
        (
            self.policy_revision,
            self.invalidation_generation,
            self.authority_epoch,
        )
    }

    /// Opaque database-issued fence.
    pub const fn fence(&self) -> AuthorizationLeaseFence {
        self.fence
    }

    /// Authoritative issue time and exclusive expiry.
    pub const fn time_bounds(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        (self.issued_at, self.expires_at)
    }
}

impl fmt::Debug for AuthorizationLeaseDependencySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationLeaseDependencySnapshot([REDACTED])")
    }
}

/// Immutable post-policy authorization result.
#[derive(Clone)]
pub struct AuthContext {
    authorization_domain: CommunityId,
    correlation_id: Uuid,
    actor_pubkey: PublicKey,
    owner_pubkey: Option<PublicKey>,
    binding_id: Uuid,
    binding_version: u64,
    capability: RouteCapability,
    transport: ProofTransport,
    request_fingerprint: [u8; 32],
    lease: BoundedAuthorizationLease,
}

impl AuthContext {
    /// Server-resolved authorization domain.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Exact Nostr actor.
    pub const fn actor_pubkey(&self) -> PublicKey {
        self.actor_pubkey
    }

    /// Server-generated correlation identifier.
    pub const fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }

    /// Delegated owner, when the assertion-free delegated path was used.
    pub const fn owner_pubkey(&self) -> Option<PublicKey> {
        self.owner_pubkey
    }

    /// Exact protected capability.
    pub const fn capability(&self) -> RouteCapability {
        self.capability
    }

    /// Exact active direct/owner binding identifier and version.
    pub const fn binding(&self) -> (Uuid, u64) {
        (self.binding_id, self.binding_version)
    }

    /// Verified proof transport.
    pub const fn transport(&self) -> ProofTransport {
        self.transport
    }

    /// Exact request fingerprint bound by the finalized proof.
    pub const fn request_fingerprint(&self) -> &[u8; 32] {
        &self.request_fingerprint
    }

    /// Bounded shared lease.
    pub const fn lease(&self) -> &BoundedAuthorizationLease {
        &self.lease
    }
}

impl fmt::Debug for AuthContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthContext([REDACTED])")
    }
}

/// The one provider-free authorization finalizer.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuthorizationFinalizer;

impl AuthorizationFinalizer {
    /// Recheck one protected route and compute the earliest exclusive expiry.
    ///
    /// Explicitly unprotected routes bypass this API. They produce no
    /// [`AuthContext`], policy lookup, fence, or lease.
    pub fn finalize(
        input: AuthorizationInput,
        resolution: LocalBindingResolution,
        policy: LocalAuthorizationPolicy,
        authoritative_now: DateTime<Utc>,
    ) -> Result<AuthContext, AuthorizationError> {
        if policy.authorization_domain != input.authorization_domain {
            return Err(AuthorizationError::DomainMismatch);
        }
        if policy.capability != input.capability {
            return Err(AuthorizationError::BindingMismatch);
        }
        if policy.expires_at <= authoritative_now || input.proof.expires_at <= authoritative_now {
            return Err(AuthorizationError::Expired);
        }

        let (
            owner_pubkey,
            binding_id,
            binding_version,
            relationship_id,
            relationship_revision,
            expires_at,
        ) = match resolution.0 {
            LocalBindingResolutionKind::Direct { assertion, binding }
            | LocalBindingResolutionKind::Enrollment { assertion, binding } => {
                if assertion.authorization_domain != input.authorization_domain
                    || binding.authorization_domain != input.authorization_domain
                    || assertion.principal != binding.principal
                    || assertion.transport != input.proof.transport
                    || binding.event_author_pubkey != input.proof.actor_pubkey
                    || assertion.assertion_fingerprint
                        != input
                            .proof
                            .bound_assertion_fingerprint
                            .ok_or(AuthorizationError::BindingMismatch)?
                    || assertion.target_fingerprint != input.proof.target_fingerprint
                    || assertion.request_fingerprint != input.proof.request_fingerprint
                    || assertion.transport_context_fingerprint
                        != input.proof.transport_context_fingerprint
                    || input.proof.delegation_conditions_fingerprint.is_some()
                {
                    return Err(AuthorizationError::BindingMismatch);
                }
                if authoritative_now < assertion.not_before {
                    return Err(AuthorizationError::Expired);
                }
                let expires_at = Self::effective_lease_upper_bound(
                    authoritative_now,
                    &[
                        Some(input.proof.expires_at),
                        Some(assertion.expires_at),
                        binding.expires_at,
                        Some(policy.expires_at),
                    ],
                )?;
                (
                    None,
                    binding.binding_id,
                    binding.binding_version,
                    None,
                    None,
                    expires_at,
                )
            }
            LocalBindingResolutionKind::Delegated {
                delegation,
                owner_binding,
            } => {
                if delegation.authorization_domain != input.authorization_domain
                    || owner_binding.authorization_domain != input.authorization_domain
                    || delegation.transport != input.proof.transport
                    || delegation.delegate_pubkey != input.proof.actor_pubkey
                    || delegation.owner_pubkey != owner_binding.event_author_pubkey
                    || delegation.request_fingerprint != input.proof.request_fingerprint
                    || delegation.target_fingerprint != input.proof.target_fingerprint
                    || delegation.transport_context_fingerprint
                        != input.proof.transport_context_fingerprint
                    || input.proof.bound_assertion_fingerprint.is_some()
                    || input.proof.delegation_conditions_fingerprint
                        != Some(delegation.conditions_fingerprint)
                    || !delegation.capabilities.contains(&input.capability)
                {
                    return Err(AuthorizationError::DelegationMismatch);
                }
                let delegated_max = policy
                    .delegated_max_expires_at
                    .ok_or(AuthorizationError::DelegationMismatch)?;
                let expires_at = Self::effective_lease_upper_bound(
                    authoritative_now,
                    &[
                        Some(input.proof.expires_at),
                        Some(delegation.expires_at),
                        owner_binding.expires_at,
                        Some(policy.expires_at),
                        Some(delegated_max),
                        policy.stronger_owner_expires_at,
                    ],
                )?;
                (
                    Some(delegation.owner_pubkey),
                    owner_binding.binding_id,
                    owner_binding.binding_version,
                    Some(delegation.relationship_id),
                    Some(delegation.relationship_revision),
                    expires_at,
                )
            }
        };

        Ok(AuthContext {
            authorization_domain: input.authorization_domain,
            correlation_id: input.correlation_id,
            actor_pubkey: input.proof.actor_pubkey,
            owner_pubkey,
            binding_id,
            binding_version,
            capability: input.capability,
            transport: input.proof.transport,
            request_fingerprint: input.proof.request_fingerprint,
            lease: BoundedAuthorizationLease {
                lease_id: policy.lease_id,
                authorization_domain: input.authorization_domain,
                capability: input.capability,
                actor_pubkey: input.proof.actor_pubkey,
                owner_pubkey,
                binding_id,
                binding_version,
                relationship_id,
                relationship_revision,
                delegation_conditions_fingerprint: input.proof.delegation_conditions_fingerprint,
                request_fingerprint: input.proof.request_fingerprint,
                target_fingerprint: input.proof.target_fingerprint,
                transport: input.proof.transport,
                transport_context_fingerprint: input.proof.transport_context_fingerprint,
                issued_at: authoritative_now,
                fence: policy.fence,
                policy_revision: policy.policy_revision,
                invalidation_generation: policy.invalidation_generation,
                authority_epoch: policy.authority_epoch,
                expires_at,
            },
        })
    }

    fn effective_lease_upper_bound(
        authoritative_now: DateTime<Utc>,
        bounds: &[Option<DateTime<Utc>>],
    ) -> Result<DateTime<Utc>, AuthorizationError> {
        let expires_at = bounds
            .iter()
            .flatten()
            .copied()
            .min()
            .ok_or(AuthorizationError::Expired)?;
        if authoritative_now >= expires_at {
            return Err(AuthorizationError::Expired);
        }
        Ok(expires_at)
    }
}

/// Stable fail-closed authorization errors without credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthorizationError {
    /// Input identifiers were not valid server-generated identifiers.
    #[error("invalid authorization input")]
    InvalidInput,
    /// Two independently verified values named different domains.
    #[error("authorization domain mismatch")]
    DomainMismatch,
    /// Assertion, proof, or active binding did not match exactly.
    #[error("binding mismatch")]
    BindingMismatch,
    /// Delegation, actor, owner, request, or capability did not match exactly.
    #[error("delegation mismatch")]
    DelegationMismatch,
    /// A half-open time bound was no longer valid.
    #[error("authorization expired")]
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::AuthorizationLeaseFence;
    use chrono::{Duration, TimeZone};
    use nostr::Keys;

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000, 0).unwrap()
    }

    fn domain() -> CommunityId {
        CommunityId::from_uuid(Uuid::from_u128(1))
    }

    fn proof(
        actor_pubkey: PublicKey,
        bound_assertion_fingerprint: Option<[u8; 32]>,
        delegation_conditions_fingerprint: Option<[u8; 32]>,
        expires_at: DateTime<Utc>,
    ) -> VerifiedNostrProof {
        proof_for_transport(
            actor_pubkey,
            ProofTransport::Nip42,
            bound_assertion_fingerprint,
            delegation_conditions_fingerprint,
            expires_at,
        )
    }

    fn proof_for_transport(
        actor_pubkey: PublicKey,
        transport: ProofTransport,
        bound_assertion_fingerprint: Option<[u8; 32]>,
        delegation_conditions_fingerprint: Option<[u8; 32]>,
        expires_at: DateTime<Utc>,
    ) -> VerifiedNostrProof {
        VerifiedNostrProof::from_verifier(
            domain(),
            actor_pubkey,
            transport,
            [3; 32],
            [8; 32],
            [9; 32],
            bound_assertion_fingerprint,
            delegation_conditions_fingerprint,
            expires_at,
        )
        .unwrap()
    }

    fn policy(expires_at: DateTime<Utc>) -> LocalAuthorizationPolicy {
        LocalAuthorizationPolicy::from_database(
            domain(),
            Uuid::from_u128(10),
            1,
            0,
            1,
            AuthorizationLeaseFence::from_bytes([4; 32]).unwrap(),
            RouteCapability::MessagesRead,
            expires_at,
            Some(expires_at),
            None,
        )
        .unwrap()
    }

    #[test]
    fn enforce_requires_explicit_validated_audit_capacity() {
        let fixture = AuthorizationEventCapacityPolicy::new(10_000, 16 << 20, 16 << 10).unwrap();
        assert_eq!(
            AuthorizationAuditConfig::new(NipFiMode::Enforce, None),
            Err(AuthorizationAuditConfigError::MissingEventCapacity)
        );
        assert!(AuthorizationAuditConfig::new(NipFiMode::Enforce, Some(fixture)).is_ok());
        assert_eq!(
            AuthorizationAuditConfig::new(NipFiMode::Off, Some(fixture)),
            Err(AuthorizationAuditConfigError::UnexpectedEventCapacity)
        );
    }

    #[test]
    fn audit_capacity_accepts_exact_hard_maxima_and_rejects_each_successor() {
        let exact_maxima = AuthorizationEventCapacityPolicy::new(
            HARD_MAX_AUTHORIZATION_EVENTS_PER_DOMAIN,
            HARD_MAX_AUTHORIZATION_EVENT_BYTES_PER_DOMAIN,
            HARD_MAX_AUTHORIZATION_EVENT_ENVELOPE_BYTES,
        )
        .unwrap();
        assert_eq!(
            exact_maxima.max_events_per_domain(),
            HARD_MAX_AUTHORIZATION_EVENTS_PER_DOMAIN
        );
        assert_eq!(
            exact_maxima.max_bytes_per_domain(),
            HARD_MAX_AUTHORIZATION_EVENT_BYTES_PER_DOMAIN
        );
        assert_eq!(
            exact_maxima.max_envelope_bytes(),
            HARD_MAX_AUTHORIZATION_EVENT_ENVELOPE_BYTES
        );

        assert_eq!(
            AuthorizationEventCapacityPolicy::new(
                HARD_MAX_AUTHORIZATION_EVENTS_PER_DOMAIN + 1,
                HARD_MAX_AUTHORIZATION_EVENT_BYTES_PER_DOMAIN,
                HARD_MAX_AUTHORIZATION_EVENT_ENVELOPE_BYTES,
            ),
            Err(AuthorizationEventCapacityPolicyError::EventCount)
        );
        assert_eq!(
            AuthorizationEventCapacityPolicy::new(
                HARD_MAX_AUTHORIZATION_EVENTS_PER_DOMAIN,
                HARD_MAX_AUTHORIZATION_EVENT_BYTES_PER_DOMAIN + 1,
                HARD_MAX_AUTHORIZATION_EVENT_ENVELOPE_BYTES,
            ),
            Err(AuthorizationEventCapacityPolicyError::DomainBytes)
        );
        assert_eq!(
            AuthorizationEventCapacityPolicy::new(
                HARD_MAX_AUTHORIZATION_EVENTS_PER_DOMAIN,
                HARD_MAX_AUTHORIZATION_EVENT_BYTES_PER_DOMAIN,
                HARD_MAX_AUTHORIZATION_EVENT_ENVELOPE_BYTES + 1,
            ),
            Err(AuthorizationEventCapacityPolicyError::EnvelopeBytes)
        );
    }

    #[test]
    fn unprotected_routes_need_no_policy_or_lease_configuration() {
        assert!(AuthorizationAuditConfig::new(NipFiMode::Off, None).is_ok());
        assert_eq!(RouteProtection::Unprotected, RouteProtection::Unprotected);
    }

    #[test]
    fn direct_and_delegated_policies_reject_unallocated_authority_epoch() {
        for delegated_max_expires_at in [None, Some(now() + Duration::minutes(1))] {
            assert!(LocalAuthorizationPolicy::from_database(
                domain(),
                Uuid::from_u128(10),
                1,
                0,
                0,
                AuthorizationLeaseFence::from_bytes([4; 32]).unwrap(),
                RouteCapability::MessagesRead,
                now() + Duration::minutes(1),
                delegated_max_expires_at,
                None,
            )
            .is_none());
        }
    }

    #[test]
    fn direct_lease_uses_earliest_exclusive_expiry() {
        let actor = Keys::generate().public_key();
        let principal = FederatedPrincipal::from_verified_parts(
            "https://issuer.example".into(),
            "opaque-subject".into(),
        )
        .unwrap();
        let assertion = VerifiedFederatedAssertion::from_verifier(
            domain(),
            principal.clone(),
            ProofTransport::Nip42,
            [2; 32],
            [8; 32],
            [3; 32],
            [9; 32],
            now() - Duration::seconds(1),
            now() + Duration::seconds(90),
        )
        .unwrap();
        let binding = ActiveLocalBinding::from_storage(
            domain(),
            principal,
            Uuid::from_u128(6),
            1,
            actor,
            Some(now() + Duration::seconds(60)),
        )
        .unwrap();
        let input = AuthorizationInput::new(
            domain(),
            Uuid::from_u128(5),
            proof(actor, Some([2; 32]), None, now() + Duration::seconds(120)),
            RouteCapability::MessagesRead,
        )
        .unwrap();
        let context = AuthorizationFinalizer::finalize(
            input,
            LocalBindingResolution::direct(assertion, binding),
            policy(now() + Duration::seconds(180)),
            now(),
        )
        .unwrap();

        assert_eq!(context.lease().expires_at(), now() + Duration::seconds(60));
        assert!(context.lease().is_valid_at(now() + Duration::seconds(59)));
        assert!(!context.lease().is_valid_at(now() + Duration::seconds(60)));
    }

    #[test]
    fn root_http_transports_are_exact_and_non_substitutable() {
        let actor = Keys::generate().public_key();
        for (transport, substitutes) in [
            (
                ProofTransport::GitSmartHttpSession,
                [ProofTransport::Nip98, ProofTransport::Blossom],
            ),
            (
                ProofTransport::Blossom,
                [ProofTransport::Nip98, ProofTransport::GitSmartHttpSession],
            ),
        ] {
            let principal = FederatedPrincipal::from_verified_parts(
                "https://issuer.example".into(),
                "opaque-subject".into(),
            )
            .unwrap();
            let assertion = VerifiedFederatedAssertion::from_verifier(
                domain(),
                principal.clone(),
                transport,
                [2; 32],
                [8; 32],
                [3; 32],
                [9; 32],
                now() - Duration::seconds(1),
                now() + Duration::seconds(90),
            )
            .unwrap();
            let binding = ActiveLocalBinding::from_storage(
                domain(),
                principal,
                Uuid::from_u128(6),
                1,
                actor,
                None,
            )
            .unwrap();
            let finalize = |proof: VerifiedNostrProof| {
                AuthorizationFinalizer::finalize(
                    AuthorizationInput::new(
                        domain(),
                        Uuid::from_u128(5),
                        proof,
                        RouteCapability::MessagesRead,
                    )
                    .unwrap(),
                    LocalBindingResolution::direct(assertion.clone(), binding.clone()),
                    policy(now() + Duration::seconds(180)),
                    now(),
                )
            };
            let exact = proof_for_transport(
                actor,
                transport,
                Some([2; 32]),
                None,
                now() + Duration::seconds(120),
            );
            let context = finalize(exact.clone()).unwrap();
            assert_eq!(context.transport(), transport);
            assert_eq!(
                context.lease().request_binding(),
                (&[3; 32], &[8; 32], &[9; 32])
            );

            for substitute in substitutes {
                let mut changed = exact.clone();
                changed.transport = substitute;
                assert!(matches!(
                    finalize(changed),
                    Err(AuthorizationError::BindingMismatch)
                ));
            }
            for changed in [
                {
                    let mut changed = exact.clone();
                    changed.request_fingerprint = [12; 32];
                    changed
                },
                {
                    let mut changed = exact.clone();
                    changed.target_fingerprint = [12; 32];
                    changed
                },
                {
                    let mut changed = exact.clone();
                    changed.transport_context_fingerprint = [12; 32];
                    changed
                },
            ] {
                assert!(matches!(
                    finalize(changed),
                    Err(AuthorizationError::BindingMismatch)
                ));
            }
        }
    }

    #[test]
    fn delegated_path_is_assertion_free_and_actor_bound() {
        let owner = Keys::generate().public_key();
        let delegate = Keys::generate().public_key();
        let principal = FederatedPrincipal::from_verified_parts(
            "https://issuer.example".into(),
            "owner-subject".into(),
        )
        .unwrap();
        let owner_binding = ActiveLocalBinding::from_storage(
            domain(),
            principal,
            Uuid::from_u128(6),
            1,
            owner,
            Some(now() + Duration::seconds(100)),
        )
        .unwrap();
        let delegation = VerifiedDelegation::from_verifier(
            domain(),
            owner,
            delegate,
            ProofTransport::Nip42,
            Uuid::from_u128(7),
            1,
            vec![RouteCapability::MessagesRead],
            [11; 32],
            [8; 32],
            [3; 32],
            [9; 32],
            now() + Duration::seconds(80),
        )
        .unwrap();
        let input = AuthorizationInput::new(
            domain(),
            Uuid::from_u128(5),
            proof(
                delegate,
                None,
                Some([11; 32]),
                now() + Duration::seconds(120),
            ),
            RouteCapability::MessagesRead,
        )
        .unwrap();
        let context = AuthorizationFinalizer::finalize(
            input,
            LocalBindingResolution::delegated(delegation, owner_binding),
            policy(now() + Duration::seconds(180)),
            now(),
        )
        .unwrap();

        assert_eq!(context.owner_pubkey(), Some(owner));
        assert_eq!(context.lease().expires_at(), now() + Duration::seconds(80));
        let snapshot = context.lease().dependency_snapshot();
        assert_eq!(snapshot.binding(), (Uuid::from_u128(6), 1));
        assert_eq!(
            snapshot.delegated_relationship(),
            Some((Uuid::from_u128(7), 1, &[11; 32]))
        );
    }

    #[test]
    fn direct_fingerprints_and_optional_expiry_fail_closed() {
        let actor = Keys::generate().public_key();
        let principal = FederatedPrincipal::from_verified_parts(
            "https://issuer.example".into(),
            "opaque-subject".into(),
        )
        .unwrap();
        let base_assertion = VerifiedFederatedAssertion::from_verifier(
            domain(),
            principal.clone(),
            ProofTransport::Nip42,
            [2; 32],
            [8; 32],
            [3; 32],
            [9; 32],
            now() - Duration::seconds(1),
            now() + Duration::seconds(90),
        )
        .unwrap();
        let base_binding = ActiveLocalBinding::from_storage(
            domain(),
            principal,
            Uuid::from_u128(6),
            1,
            actor,
            None,
        )
        .unwrap();
        let base_proof = proof(actor, Some([2; 32]), None, now() + Duration::seconds(120));
        let finalize = |assertion: VerifiedFederatedAssertion,
                        binding: ActiveLocalBinding,
                        proof: VerifiedNostrProof| {
            AuthorizationFinalizer::finalize(
                AuthorizationInput::new(
                    domain(),
                    Uuid::from_u128(5),
                    proof,
                    RouteCapability::MessagesRead,
                )
                .unwrap(),
                LocalBindingResolution::direct(assertion, binding),
                policy(now() + Duration::seconds(180)),
                now(),
            )
        };

        let mut assertion = base_assertion.clone();
        assertion.target_fingerprint = [12; 32];
        assert!(matches!(
            finalize(assertion, base_binding.clone(), base_proof.clone()),
            Err(AuthorizationError::BindingMismatch)
        ));
        let mut assertion = base_assertion.clone();
        assertion.request_fingerprint = [12; 32];
        assert!(matches!(
            finalize(assertion, base_binding.clone(), base_proof.clone()),
            Err(AuthorizationError::BindingMismatch)
        ));
        let mut assertion = base_assertion.clone();
        assertion.transport_context_fingerprint = [12; 32];
        assert!(matches!(
            finalize(assertion, base_binding.clone(), base_proof.clone()),
            Err(AuthorizationError::BindingMismatch)
        ));
        let mut assertion = base_assertion.clone();
        assertion.assertion_fingerprint = [12; 32];
        assert!(matches!(
            finalize(assertion, base_binding.clone(), base_proof),
            Err(AuthorizationError::BindingMismatch)
        ));

        let mut expiring_binding = base_binding;
        expiring_binding.expires_at = Some(now());
        assert!(matches!(
            finalize(
                base_assertion,
                expiring_binding,
                proof(actor, Some([2; 32]), None, now() + Duration::seconds(120),)
            ),
            Err(AuthorizationError::Expired)
        ));
    }

    #[test]
    fn delegation_coordinates_each_deny_on_mismatch() {
        let owner = Keys::generate().public_key();
        let delegate = Keys::generate().public_key();
        let principal = FederatedPrincipal::from_verified_parts(
            "https://issuer.example".into(),
            "owner-subject".into(),
        )
        .unwrap();
        let owner_binding = ActiveLocalBinding::from_storage(
            domain(),
            principal,
            Uuid::from_u128(6),
            1,
            owner,
            None,
        )
        .unwrap();
        let delegation = VerifiedDelegation::from_verifier(
            domain(),
            owner,
            delegate,
            ProofTransport::Nip42,
            Uuid::from_u128(7),
            1,
            vec![RouteCapability::MessagesRead],
            [11; 32],
            [8; 32],
            [3; 32],
            [9; 32],
            now() + Duration::seconds(80),
        )
        .unwrap();
        let proof = proof(
            delegate,
            None,
            Some([11; 32]),
            now() + Duration::seconds(120),
        );
        let finalize = |delegation: VerifiedDelegation, proof: VerifiedNostrProof| {
            AuthorizationFinalizer::finalize(
                AuthorizationInput::new(
                    domain(),
                    Uuid::from_u128(5),
                    proof,
                    RouteCapability::MessagesRead,
                )
                .unwrap(),
                LocalBindingResolution::delegated(delegation, owner_binding.clone()),
                policy(now() + Duration::seconds(180)),
                now(),
            )
        };

        let mut changed = delegation.clone();
        changed.owner_pubkey = Keys::generate().public_key();
        assert!(matches!(
            finalize(changed, proof.clone()),
            Err(AuthorizationError::DelegationMismatch)
        ));
        let mut changed_proof = proof.clone();
        changed_proof.actor_pubkey = Keys::generate().public_key();
        assert!(matches!(
            finalize(delegation.clone(), changed_proof),
            Err(AuthorizationError::DelegationMismatch)
        ));
        let mut changed_proof = proof.clone();
        changed_proof.transport = ProofTransport::Nip98;
        assert!(matches!(
            finalize(delegation.clone(), changed_proof),
            Err(AuthorizationError::DelegationMismatch)
        ));
        let mut changed_proof = proof.clone();
        changed_proof.target_fingerprint = [12; 32];
        assert!(matches!(
            finalize(delegation.clone(), changed_proof),
            Err(AuthorizationError::DelegationMismatch)
        ));
        let mut changed_proof = proof.clone();
        changed_proof.request_fingerprint = [12; 32];
        assert!(matches!(
            finalize(delegation.clone(), changed_proof),
            Err(AuthorizationError::DelegationMismatch)
        ));
        let mut changed_proof = proof.clone();
        changed_proof.transport_context_fingerprint = [12; 32];
        assert!(matches!(
            finalize(delegation.clone(), changed_proof),
            Err(AuthorizationError::DelegationMismatch)
        ));
        let mut changed_proof = proof.clone();
        changed_proof.delegation_conditions_fingerprint = Some([12; 32]);
        assert!(matches!(
            finalize(delegation.clone(), changed_proof),
            Err(AuthorizationError::DelegationMismatch)
        ));
        let mut changed = delegation.clone();
        changed.capabilities = vec![RouteCapability::GitRead];
        assert!(matches!(
            finalize(changed, proof.clone()),
            Err(AuthorizationError::DelegationMismatch)
        ));
        let mut changed = delegation;
        changed.authorization_domain = CommunityId::from_uuid(Uuid::from_u128(99));
        assert!(matches!(
            finalize(changed, proof),
            Err(AuthorizationError::DelegationMismatch)
        ));

        assert!(VerifiedDelegation::from_verifier(
            domain(),
            owner,
            delegate,
            ProofTransport::Nip42,
            Uuid::from_u128(7),
            0,
            vec![RouteCapability::MessagesRead],
            [11; 32],
            [8; 32],
            [3; 32],
            [9; 32],
            now() + Duration::seconds(80),
        )
        .is_none());
    }
}
