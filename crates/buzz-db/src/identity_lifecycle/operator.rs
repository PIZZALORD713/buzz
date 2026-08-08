//! Canonical local identity lifecycle transaction engine.
//!
//! All binding, history, selector, consumption, receipt, and lifecycle audit
//! writes in this module are reachable only through the private non-`Deref`
//! [`PrelockedIdentityLifecycleTx`]. Public callers provide typed, already
//! verified coordinates; this module owns transaction and lock ordering.

// The resolver and operator adapters consume these crate-private entrypoints
// in later integration tranches. Keep the complete engine warning-clean while
// those callers remain intentionally absent from this isolated DB freeze.
#![allow(dead_code)]

use std::fmt;

use buzz_auth::{
    OperatorLifecycleAction, VerifiedFederatedAssertion, VerifiedNostrProof,
    VerifiedOperatorLifecycleGrant, VerifiedProvisionBindingIntent,
};
use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Connection, FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::authorization_events::{
    record_authorization_event_tx, record_authorization_operation_receipt_tx,
    resolve_local_admission_loss_actor_tx, AuthorizationEventActor, AuthorizationEventKind,
    AuthorizationEventOutcome, AuthorizationEventWriteError, AuthorizationOperationKind,
    AuthorizationOperationOutcome, AuthorizationOperationReceipt, AuthorizationReasonCode,
    AuthorizationReceiptWrite, LocalAdmissionLossCause, NewAuthorizationEvent,
};
use crate::authorization_invalidation::{
    apply_admission_loss_invalidation_tx, AuthorizationInvalidationSelector,
};
use crate::authorization_version::{
    advance_admission_loss_authority_tx, authorization_version_authority_epoch_component_key,
    authorization_version_binding_component_key,
    authorization_version_delegated_relationship_component_key,
    authorization_version_invalidation_generation_component_key,
    authorization_version_lifecycle_selector_component_key, load_manifest_connection,
    record_authorization_operation_version_delta_tx, AuthorizationOperationFence,
    AuthorizationOperationVersionDelta, AuthorizationOperationVersionDeltaManifest,
    AuthorizationProtectedObjectKind, AuthorizationVersionComponentKind,
};
use crate::operator_lifecycle::{
    ExactActiveOperatorTarget, ExactRetiredOperatorTarget, OperatorLifecycleError,
    OperatorLifecycleIntent, OperatorLifecyclePlan,
};
use crate::{Db, DbError};

const APPLIED_OUTCOME: i16 = 1;
const DENIED_OUTCOME: i16 = 2;
const NO_OP_OUTCOME: i16 = 3;

/// Canonical identity lifecycle transition kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub enum IdentityLifecycleTransition {
    /// Admit an assertion-backed identity/key binding.
    Enroll = 1,
    /// Admit a separately provisioned identity/key binding.
    Provision = 2,
    /// Permanently retire one exact identity/key pair.
    Retire = 3,
    /// Disable a principal identity.
    Disable = 4,
    /// Permanently revoke an event-author key.
    Revoke = 5,
    /// Retire one generation and create its direct successor.
    Rotate = 6,
    /// Consume a pending replacement and create a successor.
    Recover = 7,
    /// Consume a disabled-identity fact and create a successor.
    Enable = 8,
    /// Remove one exact binding after trusted local admission loss.
    AdmissionLoss = 9,
}

/// Closed binding provenance stored on an immutable binding generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub enum IdentityBindingProvenance {
    /// A local verifier accepted an assertion-bound event-author proof.
    AttestedKey = 1,
    /// A separately authorized provisioning workflow selected the key.
    Provisioned = 2,
    /// A local risk-labelled trust-on-first-use policy selected the key.
    RiskLabelledTofu = 3,
}

/// Origin-sealed actor attribution accepted by the lifecycle DB boundary.
#[derive(Clone)]
pub(crate) struct AuthenticatedLifecycleActor {
    request_attribution: [u8; 32],
    canonical: Option<AuthorizationEventActor>,
    operator_grant: Option<VerifiedOperatorLifecycleGrant>,
    operator_intent: Option<OperatorLifecycleIntent>,
}

impl AuthenticatedLifecycleActor {
    /// Bind an opaque S5 actor to its verifier-sealed request attribution.
    pub(crate) fn from_sealed_event_actor(
        request_attribution: [u8; 32],
        canonical: AuthorizationEventActor,
    ) -> Result<Self, IdentityLifecycleFailure> {
        if request_attribution == [0; 32] || !canonical.is_authenticated() {
            return Err(IdentityLifecycleFailure::InvalidRequest);
        }
        Ok(Self {
            request_attribution,
            canonical: Some(canonical),
            operator_grant: None,
            operator_intent: None,
        })
    }

    /// Bind lifecycle attribution to one verifier-sealed operator grant.
    pub(crate) fn from_verified_operator_grant(
        grant: &VerifiedOperatorLifecycleGrant,
        intent: &OperatorLifecycleIntent,
    ) -> Result<Self, IdentityLifecycleFailure> {
        let canonical = AuthorizationEventActor::from_verified_operator_grant(grant)
            .map_err(IdentityLifecycleFailure::Storage)?;
        if grant.request_attribution() == [0; 32]
            || !canonical.is_authenticated()
            || grant.authorization_domain() != intent.authorization_domain()
            || grant.operation_id() != intent.operation_id()
            || grant.action() != intent.action()
            || grant.expected_revision() != intent.expected_revision()
            || grant.intent_digest() != intent.intent_digest()
        {
            return Err(IdentityLifecycleFailure::InvalidRequest);
        }
        Ok(Self {
            request_attribution: grant.request_attribution(),
            canonical: Some(canonical),
            operator_grant: Some(grant.clone()),
            operator_intent: Some(intent.clone()),
        })
    }

    #[cfg(test)]
    fn test_only(request_attribution: [u8; 32]) -> Self {
        Self {
            request_attribution,
            canonical: None,
            operator_grant: None,
            operator_intent: None,
        }
    }

    fn canonical(
        &self,
        community_id: CommunityId,
    ) -> Result<&AuthorizationEventActor, IdentityLifecycleFailure> {
        self.canonical
            .as_ref()
            .filter(|actor| actor.is_authenticated() && actor.is_bound_to(community_id))
            .ok_or(IdentityLifecycleFailure::InvalidRequest)
    }

    fn denial_event_kind(&self) -> AuthorizationEventKind {
        if self.operator_grant.is_some() {
            AuthorizationEventKind::OperatorDenied
        } else {
            AuthorizationEventKind::ProtectedDenied
        }
    }
}

impl fmt::Debug for AuthenticatedLifecycleActor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedLifecycleActor([REDACTED])")
    }
}

/// Opaque authority to refence every protected object owned by one exact
/// active binding. It is minted only inside the locked Applied decision path
/// after the verifier-sealed operator grant has been matched again.
pub(crate) struct RetiringBindingAuthority {
    community_id: CommunityId,
    operation_id: Uuid,
    request_fingerprint: [u8; 32],
    binding_id: Uuid,
    binding_version: u64,
}

impl RetiringBindingAuthority {
    pub(crate) const fn community_id(&self) -> CommunityId {
        self.community_id
    }

    pub(crate) const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub(crate) const fn request_fingerprint(&self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub(crate) const fn binding(&self) -> (Uuid, u64) {
        (self.binding_id, self.binding_version)
    }
}

impl fmt::Debug for RetiringBindingAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetiringBindingAuthority([REDACTED])")
    }
}

/// Stable operation identity shared by receipt, history, and audit rows.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdentityLifecycleOperation {
    /// Server-selected domain.
    community_id: CommunityId,
    /// Caller-owned idempotency key.
    operation_id: Uuid,
    /// Canonical semantic request fingerprint.
    request_fingerprint: [u8; 32],
    /// Redaction-safe request correlation identifier.
    correlation_id: Uuid,
    /// Unique delivery/attempt identifier.
    attempt_id: Uuid,
}

impl fmt::Debug for IdentityLifecycleOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityLifecycleOperation([REDACTED])")
    }
}

/// Exact immutable binding-generation evidence returned to callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityBindingEvidence {
    /// Stable binding identity.
    pub binding_id: Uuid,
    /// Fresh, globally non-reused immutable generation version.
    pub binding_version: u64,
    /// Current lifecycle revision (one active, two retired).
    pub lifecycle_revision: u64,
}

/// Enrollment inputs extracted only after assertion and event-author proof
/// verification. Credential bytes are never accepted by this type.
#[derive(Clone)]
pub(crate) struct AuthoritativeEnrollmentRequest {
    /// Canonical operation identity.
    operation: IdentityLifecycleOperation,
    /// Enroll or Provision.
    transition: IdentityLifecycleTransition,
    /// Exact private issuer coordinate.
    issuer: String,
    /// Exact private subject coordinate.
    subject: String,
    /// Canonical principal selector fingerprint.
    principal_fingerprint: [u8; 32],
    /// Verified event-author public key bytes.
    event_author_pubkey: [u8; 32],
    /// Binding provenance selected by the local policy.
    provenance: IdentityBindingProvenance,
    /// Exact immutable policy revision.
    policy_revision: u64,
    /// Expected digest of that policy revision.
    policy_digest: [u8; 32],
    /// Redaction-safe digest of the accepted assertion/provisioning evidence.
    enrollment_evidence_digest: [u8; 32],
    /// Exclusive verifier-owned evidence expiry rechecked by PostgreSQL before
    /// any lifecycle mutation.
    evidence_expires_at: DateTime<Utc>,
    /// Exclusive binding expiry, if bounded.
    expires_at: Option<DateTime<Utc>>,
    /// Authenticated pseudonymous verifier/provisioner attribution.
    actor: AuthenticatedLifecycleActor,
}

/// Server-generated operation identity for one direct enrollment mutation.
/// Public callers never select these coordinates or the canonical request
/// fingerprint.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectEnrollmentOperationIdentity {
    community_id: CommunityId,
    operation_id: Uuid,
    correlation_id: Uuid,
    attempt_id: Uuid,
}

impl DirectEnrollmentOperationIdentity {
    pub(crate) fn generate(community_id: CommunityId) -> Result<Self, IdentityLifecycleFailure> {
        if community_id.as_uuid().is_nil() {
            return Err(IdentityLifecycleFailure::InvalidRequest);
        }
        Ok(Self {
            community_id,
            operation_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
        })
    }
}

impl fmt::Debug for DirectEnrollmentOperationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectEnrollmentOperationIdentity([REDACTED])")
    }
}

/// Opaque direct-enrollment mutation prepared only from origin-sealed
/// assertion/proof evidence and one authoritative policy row.
///
/// Public callers may pass this value only to the operation-specific restore
/// runtime; its private lifecycle command cannot be reconstructed:
///
/// ```compile_fail
/// use buzz_db::identity_lifecycle::PreparedDirectEnrollment;
/// let _ = PreparedDirectEnrollment {};
/// ```
#[derive(Clone)]
pub struct PreparedDirectEnrollment {
    request: AuthoritativeEnrollmentRequest,
    assertion: VerifiedFederatedAssertion,
    proof: VerifiedNostrProof,
}

/// Opaque provision-binding mutation prepared only from a verifier-sealed
/// operator intent and the exact authoritative Provisioned policy row.
///
/// ```compile_fail
/// use buzz_db::identity_lifecycle::PreparedProvisionBinding;
/// let _ = PreparedProvisionBinding {};
/// ```
#[derive(Clone)]
pub struct PreparedProvisionBinding {
    request: AuthoritativeEnrollmentRequest,
    intent: VerifiedProvisionBindingIntent,
}

impl PreparedProvisionBinding {
    fn seal(
        request: AuthoritativeEnrollmentRequest,
        intent: VerifiedProvisionBindingIntent,
    ) -> Result<Self, IdentityLifecycleFailure> {
        validate_enrollment_request(&request)?;
        if request.transition != IdentityLifecycleTransition::Provision
            || request.operation.community_id != intent.authorization_domain()
            || request.operation.operation_id != intent.operation_id()
            || request.policy_revision != intent.policy_revision()
            || request.policy_digest != intent.policy_digest()
            || request.event_author_pubkey != intent.selected_event_author_pubkey()
            || request.evidence_expires_at != intent.expires_at()
        {
            return Err(IdentityLifecycleFailure::InvalidRequest);
        }
        Ok(Self { request, intent })
    }

    /// Server-selected authorization domain.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.request.operation.community_id
    }

    /// Verifier-bound operation identity.
    pub const fn operation_id(&self) -> Uuid {
        self.request.operation.operation_id
    }

    /// Canonical semantic request fingerprint.
    pub const fn request_fingerprint(&self) -> [u8; 32] {
        self.request.operation.request_fingerprint
    }
}

impl fmt::Debug for PreparedProvisionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedProvisionBinding([REDACTED])")
    }
}

/// Seal a provision mutation only after the resolver has matched the exact
/// current Provisioned policy row to the verifier-owned intent.
pub(crate) fn prepare_provision_binding(
    intent: &VerifiedProvisionBindingIntent,
) -> Result<PreparedProvisionBinding, IdentityLifecycleFailure> {
    let principal = intent.principal_storage_key();
    if intent.authorization_domain().as_uuid().is_nil()
        || intent.operation_id().is_nil()
        || intent.policy_revision() == 0
        || intent.policy_digest() == [0; 32]
        || intent.selected_event_author_pubkey() == [0; 32]
        || intent.intent_digest() == [0; 32]
        || intent.request_attribution() == [0; 32]
        || intent.issued_at().timestamp_micros() <= 0
        || intent.expires_at() <= intent.issued_at()
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    let principal_fingerprint = identity_principal_fingerprint(
        intent.authorization_domain(),
        principal.issuer(),
        principal.subject(),
    );
    let enrollment_evidence_digest = lifecycle_digest(
        b"buzz:provision-binding-evidence:v1",
        &[
            intent.authorization_domain().as_uuid().as_bytes(),
            intent.operation_id().as_bytes(),
            &intent.policy_revision().to_be_bytes(),
            &intent.policy_digest(),
            principal.issuer().as_bytes(),
            principal.subject().as_bytes(),
            &intent.selected_event_author_pubkey(),
            &intent.intent_digest(),
            &intent.approval_policy_digest(),
            &intent.signer_attribution(),
            &intent.approval_attribution().unwrap_or([0; 32]),
            &intent.request_attribution(),
        ],
    );
    let canonical_actor = AuthorizationEventActor::from_verified_provision_intent(intent)
        .map_err(IdentityLifecycleFailure::Storage)?;
    let actor = AuthenticatedLifecycleActor::from_sealed_event_actor(
        intent.request_attribution(),
        canonical_actor,
    )?;
    let mut request = AuthoritativeEnrollmentRequest {
        operation: IdentityLifecycleOperation {
            community_id: intent.authorization_domain(),
            operation_id: intent.operation_id(),
            request_fingerprint: [1; 32],
            correlation_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
        },
        transition: IdentityLifecycleTransition::Provision,
        issuer: principal.issuer().to_owned(),
        subject: principal.subject().to_owned(),
        principal_fingerprint,
        event_author_pubkey: intent.selected_event_author_pubkey(),
        provenance: IdentityBindingProvenance::Provisioned,
        policy_revision: intent.policy_revision(),
        policy_digest: intent.policy_digest(),
        enrollment_evidence_digest,
        evidence_expires_at: intent.expires_at(),
        expires_at: None,
        actor,
    };
    request.operation.request_fingerprint = authoritative_enrollment_request_fingerprint(&request);
    PreparedProvisionBinding::seal(request, intent.clone())
}

impl PreparedDirectEnrollment {
    fn seal(
        request: AuthoritativeEnrollmentRequest,
        assertion: VerifiedFederatedAssertion,
        proof: VerifiedNostrProof,
    ) -> Result<Self, IdentityLifecycleFailure> {
        validate_enrollment_request(&request)?;
        Ok(Self {
            request,
            assertion,
            proof,
        })
    }

    /// Server-selected authorization domain.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.request.operation.community_id
    }

    /// Server-generated operation identity.
    pub const fn operation_id(&self) -> Uuid {
        self.request.operation.operation_id
    }

    /// Canonical semantic request fingerprint.
    pub const fn request_fingerprint(&self) -> [u8; 32] {
        self.request.operation.request_fingerprint
    }

    pub(crate) fn verified_evidence(&self) -> (&VerifiedFederatedAssertion, &VerifiedNostrProof) {
        (&self.assertion, &self.proof)
    }
}

impl fmt::Debug for PreparedDirectEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedDirectEnrollment([REDACTED])")
    }
}

/// Seal one direct enrollment after the resolver has loaded the exact current
/// policy. Attested enrollment requires the verifier-bound key claim; the
/// risk-labelled TOFU posture always records TOFU provenance even when the
/// optional claim is present.
pub(crate) fn prepare_direct_enrollment(
    operation: DirectEnrollmentOperationIdentity,
    assertion: &VerifiedFederatedAssertion,
    proof: &VerifiedNostrProof,
    authorization_expires_at: DateTime<Utc>,
    provenance: IdentityBindingProvenance,
    policy_revision: u64,
    policy_digest: [u8; 32],
) -> Result<PreparedDirectEnrollment, IdentityLifecycleFailure> {
    let principal = assertion.principal_storage_key();
    let actor_key = proof.actor_pubkey();
    if assertion.authorization_domain() != operation.community_id
        || proof.authorization_domain() != operation.community_id
        || proof.bound_assertion_fingerprint().is_none()
        || proof.delegation_conditions_fingerprint().is_some()
        || authorization_expires_at.timestamp_micros() <= 0
        || authorization_expires_at > proof.expires_at()
        || !matches!(
            provenance,
            IdentityBindingProvenance::AttestedKey | IdentityBindingProvenance::RiskLabelledTofu
        )
        || (provenance == IdentityBindingProvenance::AttestedKey
            && assertion.attested_event_author_pubkey() != Some(actor_key))
        || policy_revision == 0
        || policy_digest == [0; 32]
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    let principal_fingerprint = identity_principal_fingerprint(
        operation.community_id,
        principal.issuer(),
        principal.subject(),
    );
    let enrollment_evidence_digest =
        direct_enrollment_evidence_digest(assertion, proof, authorization_expires_at);
    let canonical_actor =
        AuthorizationEventActor::from_verified_direct_enrollment(assertion, proof)
            .map_err(IdentityLifecycleFailure::Storage)?;
    let actor = AuthenticatedLifecycleActor::from_sealed_event_actor(
        enrollment_evidence_digest,
        canonical_actor,
    )?;
    let mut request = AuthoritativeEnrollmentRequest {
        operation: IdentityLifecycleOperation {
            community_id: operation.community_id,
            operation_id: operation.operation_id,
            request_fingerprint: [1; 32],
            correlation_id: operation.correlation_id,
            attempt_id: operation.attempt_id,
        },
        transition: IdentityLifecycleTransition::Enroll,
        issuer: principal.issuer().to_owned(),
        subject: principal.subject().to_owned(),
        principal_fingerprint,
        event_author_pubkey: actor_key.to_bytes(),
        provenance,
        policy_revision,
        policy_digest,
        enrollment_evidence_digest,
        evidence_expires_at: authorization_expires_at,
        expires_at: None,
        actor,
    };
    request.operation.request_fingerprint = authoritative_enrollment_request_fingerprint(&request);
    PreparedDirectEnrollment::seal(request, assertion.clone(), proof.clone())
}

/// Canonical private principal coordinate shared by direct enrollment and
/// authoritative resolver reads.
pub(crate) fn identity_principal_fingerprint(
    community_id: CommunityId,
    issuer: &str,
    subject: &str,
) -> [u8; 32] {
    lifecycle_digest(
        b"buzz:identity-principal:v1",
        &[
            community_id.as_uuid().as_bytes(),
            issuer.as_bytes(),
            subject.as_bytes(),
        ],
    )
}

fn direct_enrollment_evidence_digest(
    assertion: &VerifiedFederatedAssertion,
    proof: &VerifiedNostrProof,
    authorization_expires_at: DateTime<Utc>,
) -> [u8; 32] {
    lifecycle_digest(
        b"buzz:direct-enrollment-evidence:v1",
        &[
            assertion.authorization_domain().as_uuid().as_bytes(),
            proof.bound_assertion_fingerprint().unwrap_or(&[0; 32]),
            &proof.actor_pubkey().to_bytes(),
            proof.request_fingerprint(),
            proof.target_fingerprint(),
            proof.transport_context_fingerprint(),
            &proof.expires_at().timestamp_micros().to_be_bytes(),
            &authorization_expires_at.timestamp_micros().to_be_bytes(),
        ],
    )
}

impl fmt::Debug for AuthoritativeEnrollmentRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthoritativeEnrollmentRequest")
            .field("operation", &self.operation)
            .field("transition", &self.transition)
            .field("private_coordinates", &"[REDACTED]")
            .field("policy_revision", &self.policy_revision)
            .field("expires_at", &self.expires_at)
            .field("actor", &self.actor)
            .finish()
    }
}

/// Compute the canonical semantic fingerprint that an authoritative
/// enrollment operation must carry. The digest binds private coordinates
/// without persisting them in the receipt or audit envelope.
pub(crate) fn authoritative_enrollment_request_fingerprint(
    request: &AuthoritativeEnrollmentRequest,
) -> [u8; 32] {
    let expires_at = request
        .expires_at
        .map(|value| value.timestamp_micros())
        .unwrap_or(0)
        .to_be_bytes();
    let evidence_expires_at = request.evidence_expires_at.timestamp_micros().to_be_bytes();
    lifecycle_digest(
        b"buzz:authoritative-enrollment-request:v1",
        &[
            request.operation.community_id.as_uuid().as_bytes(),
            request.operation.operation_id.as_bytes(),
            &(request.transition as i16).to_be_bytes(),
            request.issuer.as_bytes(),
            request.subject.as_bytes(),
            &request.principal_fingerprint,
            &request.event_author_pubkey,
            &(request.provenance as i16).to_be_bytes(),
            &request.policy_revision.to_be_bytes(),
            &request.policy_digest,
            &request.enrollment_evidence_digest,
            &evidence_expires_at,
            &expires_at,
            &request.actor.request_attribution,
        ],
    )
}

/// Trusted provider-free cause of a targeted local admission loss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrustedAdmissionLossCause {
    /// Local binding authority no longer admits the exact generation.
    LocalBinding,
    /// A specific local policy revision invalidated admission.
    LocalPolicy {
        /// Exact immutable local policy revision.
        revision: u64,
    },
    /// A specific local delegation relationship revision was withdrawn.
    DelegationAuthority {
        /// Stable local relationship identity.
        relationship_id: Uuid,
        /// Exact authoritative relationship revision.
        revision: u64,
    },
}

/// Typed request identity supplied by an authoritative local admission-loss
/// origin. It deliberately has no request-fingerprint field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdmissionLossOperationIdentity {
    community_id: CommunityId,
    operation_id: Uuid,
    correlation_id: Uuid,
    attempt_id: Uuid,
}

impl AdmissionLossOperationIdentity {
    /// Validate the server domain and redaction-safe operation coordinates.
    pub(crate) fn new(
        community_id: CommunityId,
        operation_id: Uuid,
        correlation_id: Uuid,
        attempt_id: Uuid,
    ) -> Result<Self, IdentityLifecycleFailure> {
        if community_id.as_uuid().is_nil()
            || operation_id.is_nil()
            || correlation_id.is_nil()
            || attempt_id.is_nil()
        {
            return Err(IdentityLifecycleFailure::InvalidRequest);
        }
        Ok(Self {
            community_id,
            operation_id,
            correlation_id,
            attempt_id,
        })
    }
}

impl fmt::Debug for AdmissionLossOperationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionLossOperationIdentity([REDACTED])")
    }
}

/// Exact active binding target for trusted admission loss.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExactAdmissionLossTarget {
    /// Exact binding identity.
    binding_id: Uuid,
    /// Exact immutable binding generation.
    binding_version: u64,
    /// Exact active lifecycle revision, currently one.
    expected_lifecycle_revision: u64,
    /// Principal coordinate to prelock and revalidate.
    principal_fingerprint: [u8; 32],
    /// Event-author key coordinate to prelock and revalidate.
    event_author_pubkey: [u8; 32],
}

impl ExactAdmissionLossTarget {
    /// Construct exact coordinates only after authoritative binding
    /// resolution supplied the immutable generation and active revision.
    pub(crate) fn from_authoritative_binding(
        binding_id: Uuid,
        binding_version: u64,
        expected_lifecycle_revision: u64,
        principal_fingerprint: [u8; 32],
        event_author_pubkey: [u8; 32],
    ) -> Result<Self, IdentityLifecycleFailure> {
        let target = Self {
            binding_id,
            binding_version,
            expected_lifecycle_revision,
            principal_fingerprint,
            event_author_pubkey,
        };
        if target.binding_id.is_nil()
            || target.binding_version == 0
            || target.expected_lifecycle_revision != 1
            || target.principal_fingerprint == [0; 32]
            || target.event_author_pubkey == [0; 32]
        {
            return Err(IdentityLifecycleFailure::InvalidRequest);
        }
        Ok(target)
    }
}

impl fmt::Debug for ExactAdmissionLossTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactAdmissionLossTarget([REDACTED])")
    }
}

/// Provider-free targeted admission-loss command.
#[derive(Clone)]
pub(crate) struct ExactAdmissionLossRequest {
    /// Canonical operation identity.
    operation: IdentityLifecycleOperation,
    /// Exact active binding target.
    target: ExactAdmissionLossTarget,
    /// Trusted server-local cause bound by the request fingerprint.
    cause: TrustedAdmissionLossCause,
    /// Authenticated pseudonymous local authority attribution.
    actor: AuthenticatedLifecycleActor,
}

impl fmt::Debug for ExactAdmissionLossRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactAdmissionLossRequest([REDACTED])")
    }
}

/// Opaque, canonical admission-loss command prepared by authoritative local
/// resolution before operation restore reserves its exact external intent.
///
/// The private command and its authority coordinates cannot be constructed or
/// inspected by public callers:
///
/// ```compile_fail
/// use buzz_db::identity_lifecycle::PreparedAdmissionLoss;
/// let _ = PreparedAdmissionLoss {};
/// ```
#[derive(Clone)]
pub struct PreparedAdmissionLoss {
    request: ExactAdmissionLossRequest,
}

impl PreparedAdmissionLoss {
    fn seal(request: ExactAdmissionLossRequest) -> Result<Self, IdentityLifecycleFailure> {
        validate_admission_loss_request(&request)?;
        Ok(Self { request })
    }

    /// Server-selected authorization domain.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.request.operation.community_id
    }

    /// Exact canonical operation identity.
    pub const fn operation_id(&self) -> Uuid {
        self.request.operation.operation_id
    }

    /// Canonical semantic fingerprint computed before the command was sealed.
    pub const fn request_fingerprint(&self) -> [u8; 32] {
        self.request.operation.request_fingerprint
    }
}

/// Assemble and seal the canonical command from an origin-sealed actor and
/// typed authoritative lifecycle coordinates. The request fingerprint is
/// computed here and cannot be selected by the caller.
pub(crate) fn prepare_admission_loss(
    operation: AdmissionLossOperationIdentity,
    target: ExactAdmissionLossTarget,
    cause: TrustedAdmissionLossCause,
    actor: AuthenticatedLifecycleActor,
) -> Result<PreparedAdmissionLoss, IdentityLifecycleFailure> {
    actor.canonical(operation.community_id)?;
    let mut request = ExactAdmissionLossRequest {
        operation: IdentityLifecycleOperation {
            community_id: operation.community_id,
            operation_id: operation.operation_id,
            request_fingerprint: [1; 32],
            correlation_id: operation.correlation_id,
            attempt_id: operation.attempt_id,
        },
        target,
        cause,
        actor,
    };
    request.operation.request_fingerprint = exact_admission_loss_request_fingerprint(&request);
    PreparedAdmissionLoss::seal(request)
}

impl fmt::Debug for PreparedAdmissionLoss {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedAdmissionLoss([REDACTED])")
    }
}

/// Compute the canonical semantic fingerprint for one exact targeted local
/// admission-loss operation.
pub(crate) fn exact_admission_loss_request_fingerprint(
    request: &ExactAdmissionLossRequest,
) -> [u8; 32] {
    lifecycle_digest(
        b"buzz:exact-admission-loss-request:v1",
        &[
            request.operation.community_id.as_uuid().as_bytes(),
            request.operation.operation_id.as_bytes(),
            request.target.binding_id.as_bytes(),
            &request.target.binding_version.to_be_bytes(),
            &request.target.expected_lifecycle_revision.to_be_bytes(),
            &request.target.principal_fingerprint,
            &request.target.event_author_pubkey,
            &admission_loss_cause_digest(request.cause),
            &request.actor.request_attribution,
        ],
    )
}

/// Exact immutable active-generation target for a binding lifecycle action.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExactActiveBindingTarget {
    /// Exact binding identity.
    binding_id: Uuid,
    /// Exact immutable binding generation.
    binding_version: u64,
    /// Expected active lifecycle revision, currently one.
    expected_lifecycle_revision: u64,
    /// Canonical principal coordinate.
    principal_fingerprint: [u8; 32],
    /// Exact event-author key coordinate.
    event_author_pubkey: [u8; 32],
}

impl fmt::Debug for ExactActiveBindingTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactActiveBindingTarget([REDACTED])")
    }
}

impl From<ExactAdmissionLossTarget> for ExactActiveBindingTarget {
    fn from(value: ExactAdmissionLossTarget) -> Self {
        Self {
            binding_id: value.binding_id,
            binding_version: value.binding_version,
            expected_lifecycle_revision: value.expected_lifecycle_revision,
            principal_fingerprint: value.principal_fingerprint,
            event_author_pubkey: value.event_author_pubkey,
        }
    }
}

/// Permanently retire one exact active identity/key pair.
#[derive(Clone)]
pub(crate) struct RetireIdentityPairRequest {
    /// Canonical operation identity.
    operation: IdentityLifecycleOperation,
    /// Exact active generation to retire.
    target: ExactActiveBindingTarget,
    /// Authenticated pseudonymous caller.
    actor: AuthenticatedLifecycleActor,
}

impl fmt::Debug for RetireIdentityPairRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetireIdentityPairRequest([REDACTED])")
    }
}

/// Disable one principal, optionally retiring its exact active generation.
#[derive(Clone)]
pub(crate) struct DisableIdentityPrincipalRequest {
    /// Canonical operation identity.
    operation: IdentityLifecycleOperation,
    /// Principal coordinate to disable.
    principal_fingerprint: [u8; 32],
    /// Exact active generation expected by the caller, or `None` when the
    /// principal is expected to have no active generation.
    expected_active_binding: Option<ExactActiveBindingTarget>,
    /// Authenticated pseudonymous caller.
    actor: AuthenticatedLifecycleActor,
}

impl fmt::Debug for DisableIdentityPrincipalRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DisableIdentityPrincipalRequest([REDACTED])")
    }
}

/// Permanently revoke one key, optionally retiring its exact active binding.
#[derive(Clone)]
pub(crate) struct RevokeIdentityKeyRequest {
    /// Canonical operation identity.
    operation: IdentityLifecycleOperation,
    /// Key coordinate to revoke permanently.
    event_author_pubkey: [u8; 32],
    /// Exact active generation expected by the caller, or `None` when the key
    /// is expected to be inactive.
    expected_active_binding: Option<ExactActiveBindingTarget>,
    /// Authenticated pseudonymous caller.
    actor: AuthenticatedLifecycleActor,
}

impl fmt::Debug for RevokeIdentityKeyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RevokeIdentityKeyRequest([REDACTED])")
    }
}

/// Exact retired generation referenced by a pending-replacement selector.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExactRetiredBindingTarget {
    binding_id: Uuid,
    binding_version: u64,
    expected_lifecycle_revision: u64,
    principal_fingerprint: [u8; 32],
    event_author_pubkey: [u8; 32],
}

impl fmt::Debug for ExactRetiredBindingTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactRetiredBindingTarget([REDACTED])")
    }
}

/// Exact open Q fact expected by Recover or Enable.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpectedPendingReplacement {
    target: ExactRetiredBindingTarget,
    fact_generation: u64,
}

impl fmt::Debug for ExpectedPendingReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedPendingReplacement([REDACTED])")
    }
}

/// Verifier-sealed fresh replacement-key proof.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifiedReplacementProof {
    community_id: CommunityId,
    operation_id: Uuid,
    intent_fingerprint: [u8; 32],
    principal_fingerprint: [u8; 32],
    event_author_pubkey: [u8; 32],
    proof_digest: [u8; 32],
    /// Exclusive expiry requested in the signed lifecycle body.
    expires_at: DateTime<Utc>,
    /// Exclusive verifier-computed bound across the operator and replacement
    /// credentials and the requested expiry.
    authorization_expires_at: DateTime<Utc>,
}

impl VerifiedReplacementProof {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verifier_sealed_receipt(
        community_id: CommunityId,
        operation_id: Uuid,
        intent_fingerprint: [u8; 32],
        principal_fingerprint: [u8; 32],
        event_author_pubkey: [u8; 32],
        proof_digest: [u8; 32],
        expires_at: DateTime<Utc>,
        authorization_expires_at: DateTime<Utc>,
    ) -> Result<Self, IdentityLifecycleFailure> {
        if community_id.as_uuid().is_nil()
            || operation_id.is_nil()
            || intent_fingerprint == [0; 32]
            || principal_fingerprint == [0; 32]
            || event_author_pubkey == [0; 32]
            || proof_digest == [0; 32]
            || expires_at.timestamp_micros() <= 0
            || authorization_expires_at.timestamp_micros() <= 0
            || authorization_expires_at > expires_at
        {
            return Err(IdentityLifecycleFailure::InvalidRequest);
        }
        Ok(Self {
            community_id,
            operation_id,
            intent_fingerprint,
            principal_fingerprint,
            event_author_pubkey,
            proof_digest,
            expires_at,
            authorization_expires_at,
        })
    }

    fn proof_fingerprint(&self) -> [u8; 32] {
        lifecycle_digest(
            b"buzz:verified-replacement-proof:v1",
            &[
                self.community_id.as_uuid().as_bytes(),
                self.operation_id.as_bytes(),
                &self.intent_fingerprint,
                &self.principal_fingerprint,
                &self.event_author_pubkey,
                &self.proof_digest,
                &self.expires_at.timestamp_micros().to_be_bytes(),
                &self
                    .authorization_expires_at
                    .timestamp_micros()
                    .to_be_bytes(),
            ],
        )
    }
}

impl fmt::Debug for VerifiedReplacementProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedReplacementProof([REDACTED])")
    }
}

/// Verifier-sealed private principal resolution required for Enable.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifiedPrincipalResolution {
    community_id: CommunityId,
    operation_id: Uuid,
    intent_fingerprint: [u8; 32],
    principal_fingerprint: [u8; 32],
    issuer: String,
    subject: String,
    provenance: IdentityBindingProvenance,
    policy_revision: u64,
    policy_digest: [u8; 32],
    proof_digest: [u8; 32],
    expires_at: DateTime<Utc>,
}

impl VerifiedPrincipalResolution {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verifier_sealed_receipt(
        community_id: CommunityId,
        operation_id: Uuid,
        intent_fingerprint: [u8; 32],
        principal_fingerprint: [u8; 32],
        issuer: String,
        subject: String,
        provenance: IdentityBindingProvenance,
        policy_revision: u64,
        policy_digest: [u8; 32],
        proof_digest: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<Self, IdentityLifecycleFailure> {
        if community_id.as_uuid().is_nil()
            || operation_id.is_nil()
            || intent_fingerprint == [0; 32]
            || principal_fingerprint == [0; 32]
            || issuer.is_empty()
            || subject.is_empty()
            || issuer.len() > 2048
            || subject.len() > 2048
            || policy_revision == 0
            || policy_digest == [0; 32]
            || proof_digest == [0; 32]
            || expires_at.timestamp_micros() <= 0
        {
            return Err(IdentityLifecycleFailure::InvalidRequest);
        }
        Ok(Self {
            community_id,
            operation_id,
            intent_fingerprint,
            principal_fingerprint,
            issuer,
            subject,
            provenance,
            policy_revision,
            policy_digest,
            proof_digest,
            expires_at,
        })
    }

    fn proof_fingerprint(&self) -> [u8; 32] {
        lifecycle_digest(
            b"buzz:verified-principal-resolution:v1",
            &[
                self.community_id.as_uuid().as_bytes(),
                self.operation_id.as_bytes(),
                &self.intent_fingerprint,
                &self.principal_fingerprint,
                self.issuer.as_bytes(),
                self.subject.as_bytes(),
                &(self.provenance as i16).to_be_bytes(),
                &self.policy_revision.to_be_bytes(),
                &self.policy_digest,
                &self.proof_digest,
                &self.expires_at.timestamp_micros().to_be_bytes(),
            ],
        )
    }
}

impl fmt::Debug for VerifiedPrincipalResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedPrincipalResolution([REDACTED])")
    }
}

/// Rotate one exact active generation to a fresh verified key.
#[derive(Clone)]
pub(crate) struct RotateIdentityBindingRequest {
    operation: IdentityLifecycleOperation,
    target: ExactActiveBindingTarget,
    replacement: VerifiedReplacementProof,
    actor: AuthenticatedLifecycleActor,
}

impl fmt::Debug for RotateIdentityBindingRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RotateIdentityBindingRequest([REDACTED])")
    }
}

/// Recover one exact pending lineage to a fresh verified key.
#[derive(Clone)]
pub(crate) struct RecoverIdentityBindingRequest {
    operation: IdentityLifecycleOperation,
    pending: ExpectedPendingReplacement,
    replacement: VerifiedReplacementProof,
    actor: AuthenticatedLifecycleActor,
}

impl fmt::Debug for RecoverIdentityBindingRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoverIdentityBindingRequest([REDACTED])")
    }
}

/// Enable one disabled principal by consuming its exact retired-lineage Q.
#[derive(Clone)]
pub(crate) struct EnableIdentityPrincipalRequest {
    operation: IdentityLifecycleOperation,
    principal_fingerprint: [u8; 32],
    disabled_fact_generation: u64,
    pending: ExpectedPendingReplacement,
    replacement: VerifiedReplacementProof,
    principal_resolution: Option<VerifiedPrincipalResolution>,
    actor: AuthenticatedLifecycleActor,
}

impl fmt::Debug for EnableIdentityPrincipalRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnableIdentityPrincipalRequest([REDACTED])")
    }
}

/// Compute the canonical fingerprint for exact pair retirement.
pub(crate) fn retire_identity_pair_request_fingerprint(
    request: &RetireIdentityPairRequest,
) -> [u8; 32] {
    destructive_request_fingerprint(
        b"buzz:retire-identity-pair-request:v1",
        &request.operation,
        Some(request.target.principal_fingerprint),
        request.target.event_author_pubkey,
        Some(request.target),
        &request.actor,
    )
}

/// Compute the canonical fingerprint for principal disablement.
pub(crate) fn disable_identity_principal_request_fingerprint(
    request: &DisableIdentityPrincipalRequest,
) -> [u8; 32] {
    destructive_request_fingerprint(
        b"buzz:disable-identity-principal-request:v1",
        &request.operation,
        Some(request.principal_fingerprint),
        request
            .expected_active_binding
            .map(|target| target.event_author_pubkey)
            .unwrap_or([0; 32]),
        request.expected_active_binding,
        &request.actor,
    )
}

/// Compute the canonical fingerprint for permanent key revocation.
pub(crate) fn revoke_identity_key_request_fingerprint(
    request: &RevokeIdentityKeyRequest,
) -> [u8; 32] {
    destructive_request_fingerprint(
        b"buzz:revoke-identity-key-request:v1",
        &request.operation,
        request
            .expected_active_binding
            .map(|target| target.principal_fingerprint),
        request.event_author_pubkey,
        request.expected_active_binding,
        &request.actor,
    )
}

fn rotate_identity_intent_fingerprint(request: &RotateIdentityBindingRequest) -> [u8; 32] {
    lifecycle_digest(
        b"buzz:rotate-identity-intent:v1",
        &[
            request.operation.community_id.as_uuid().as_bytes(),
            request.operation.operation_id.as_bytes(),
            request.target.binding_id.as_bytes(),
            &request.target.binding_version.to_be_bytes(),
            &request.target.expected_lifecycle_revision.to_be_bytes(),
            &request.target.principal_fingerprint,
            &request.target.event_author_pubkey,
            &request.replacement.event_author_pubkey,
            &request
                .replacement
                .expires_at
                .timestamp_micros()
                .to_be_bytes(),
        ],
    )
}

fn recover_identity_intent_fingerprint(request: &RecoverIdentityBindingRequest) -> [u8; 32] {
    lifecycle_digest(
        b"buzz:recover-identity-intent:v1",
        &[
            request.operation.community_id.as_uuid().as_bytes(),
            request.operation.operation_id.as_bytes(),
            request.pending.target.binding_id.as_bytes(),
            &request.pending.target.binding_version.to_be_bytes(),
            &request
                .pending
                .target
                .expected_lifecycle_revision
                .to_be_bytes(),
            &request.pending.target.principal_fingerprint,
            &request.pending.target.event_author_pubkey,
            &request.pending.fact_generation.to_be_bytes(),
            &request.replacement.event_author_pubkey,
            &request
                .replacement
                .expires_at
                .timestamp_micros()
                .to_be_bytes(),
        ],
    )
}

fn enable_identity_intent_fingerprint(request: &EnableIdentityPrincipalRequest) -> [u8; 32] {
    let pending_id = *request.pending.target.binding_id.as_bytes();
    let pending_version = request.pending.target.binding_version;
    let pending_revision = request.pending.target.expected_lifecycle_revision;
    let pending_generation = request.pending.fact_generation;
    let pending_key = request.pending.target.event_author_pubkey;
    match &request.principal_resolution {
        Some(resolution) => lifecycle_digest(
            b"buzz:enable-identity-intent:v1",
            &[
                request.operation.community_id.as_uuid().as_bytes(),
                request.operation.operation_id.as_bytes(),
                &request.principal_fingerprint,
                &request.disabled_fact_generation.to_be_bytes(),
                &pending_id,
                &pending_version.to_be_bytes(),
                &pending_revision.to_be_bytes(),
                &pending_generation.to_be_bytes(),
                &pending_key,
                &request.replacement.event_author_pubkey,
                &request
                    .replacement
                    .expires_at
                    .timestamp_micros()
                    .to_be_bytes(),
                resolution.issuer.as_bytes(),
                resolution.subject.as_bytes(),
                &(resolution.provenance as i16).to_be_bytes(),
                &resolution.policy_revision.to_be_bytes(),
                &resolution.policy_digest,
                &resolution.expires_at.timestamp_micros().to_be_bytes(),
            ],
        ),
        None => lifecycle_digest(
            b"buzz:operator-enable-db-resolution:v1",
            &[
                request.operation.community_id.as_uuid().as_bytes(),
                request.operation.operation_id.as_bytes(),
                &request.principal_fingerprint,
                &request.disabled_fact_generation.to_be_bytes(),
                &pending_id,
                &pending_version.to_be_bytes(),
                &pending_revision.to_be_bytes(),
                &pending_generation.to_be_bytes(),
                &pending_key,
                &request.replacement.event_author_pubkey,
                &request
                    .replacement
                    .expires_at
                    .timestamp_micros()
                    .to_be_bytes(),
            ],
        ),
    }
}

fn enable_principal_proof_fingerprint(request: &EnableIdentityPrincipalRequest) -> [u8; 32] {
    request
        .principal_resolution
        .as_ref()
        .map(VerifiedPrincipalResolution::proof_fingerprint)
        .unwrap_or_else(|| {
            lifecycle_digest(
                b"buzz:operator-enable-db-resolved-principal:v1",
                &[
                    request.operation.community_id.as_uuid().as_bytes(),
                    request.operation.operation_id.as_bytes(),
                    &request.principal_fingerprint,
                ],
            )
        })
}

pub(crate) fn rotate_identity_binding_request_fingerprint(
    request: &RotateIdentityBindingRequest,
) -> [u8; 32] {
    proof_bound_lifecycle_request_fingerprint(
        b"buzz:rotate-identity-request:v1",
        &request.operation,
        rotate_identity_intent_fingerprint(request),
        request.replacement.proof_fingerprint(),
        None,
        &request.actor,
    )
}

pub(crate) fn recover_identity_binding_request_fingerprint(
    request: &RecoverIdentityBindingRequest,
) -> [u8; 32] {
    proof_bound_lifecycle_request_fingerprint(
        b"buzz:recover-identity-request:v1",
        &request.operation,
        recover_identity_intent_fingerprint(request),
        request.replacement.proof_fingerprint(),
        None,
        &request.actor,
    )
}

pub(crate) fn enable_identity_principal_request_fingerprint(
    request: &EnableIdentityPrincipalRequest,
) -> [u8; 32] {
    proof_bound_lifecycle_request_fingerprint(
        b"buzz:enable-identity-request:v1",
        &request.operation,
        enable_identity_intent_fingerprint(request),
        request.replacement.proof_fingerprint(),
        Some(enable_principal_proof_fingerprint(request)),
        &request.actor,
    )
}

#[derive(Clone)]
enum CanonicalOperatorLifecycleRequest {
    Retire(Box<RetireIdentityPairRequest>),
    Disable(Box<DisableIdentityPrincipalRequest>),
    Revoke(Box<RevokeIdentityKeyRequest>),
    Rotate(Box<RotateIdentityBindingRequest>),
    Recover(Box<RecoverIdentityBindingRequest>),
    Enable(Box<EnableIdentityPrincipalRequest>),
}

impl CanonicalOperatorLifecycleRequest {
    const fn operation(&self) -> IdentityLifecycleOperation {
        match self {
            Self::Retire(request) => request.operation,
            Self::Disable(request) => request.operation,
            Self::Revoke(request) => request.operation,
            Self::Rotate(request) => request.operation,
            Self::Recover(request) => request.operation,
            Self::Enable(request) => request.operation,
        }
    }
}

/// Opaque operator transition consumed only by operation restore.
pub(crate) struct PreparedVerifiedOperatorTransition {
    canonical: CanonicalOperatorLifecycleRequest,
    grant_issued_at: DateTime<Utc>,
    grant_expires_at: DateTime<Utc>,
}

impl PreparedVerifiedOperatorTransition {
    pub(crate) const fn authorization_domain(&self) -> CommunityId {
        self.canonical.operation().community_id
    }

    pub(crate) const fn operation_id(&self) -> Uuid {
        self.canonical.operation().operation_id
    }

    pub(crate) const fn request_fingerprint(&self) -> [u8; 32] {
        self.canonical.operation().request_fingerprint
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedOperatorLifecycleRejection {
    InvalidRequest,
    IntentConflict,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PreparedOperatorLifecycleWriteFailure {
    #[error("operator lifecycle audit unavailable")]
    AuditUnavailable,
    #[error("operator lifecycle request rejected: {0:?}")]
    Rejected(PreparedOperatorLifecycleRejection),
    #[error("operator lifecycle canonical evidence is corrupt")]
    CorruptStoredResult,
    #[error("operator lifecycle database failure")]
    Database(#[source] DbError),
    #[error("operator lifecycle outcome is unknown")]
    OutcomeUnknown(#[source] DbError),
}

struct GrantBoundReplacementProof {
    event_author_pubkey: [u8; 32],
    proof_attribution: [u8; 32],
    requested_expires_at: DateTime<Utc>,
    authorization_expires_at: DateTime<Utc>,
}

/// Match one origin-sealed grant to the sole canonical intent and prepare the
/// private lifecycle request. The locked target is rejoined inside execution.
pub(crate) fn prepare_verified_operator_transition(
    grant: &VerifiedOperatorLifecycleGrant,
    intent: &OperatorLifecycleIntent,
) -> Result<PreparedVerifiedOperatorTransition, OperatorLifecycleError> {
    let replacement_proof = validate_operator_grant(grant, intent)?;
    let actor = AuthenticatedLifecycleActor::from_verified_operator_grant(grant, intent)
        .map_err(map_operator_lifecycle_failure)?;
    let operation = IdentityLifecycleOperation {
        community_id: intent.authorization_domain(),
        operation_id: intent.operation_id(),
        request_fingerprint: [1; 32],
        correlation_id: intent.correlation_id(),
        attempt_id: intent.attempt_id(),
    };
    let canonical = match intent.plan().clone() {
        OperatorLifecyclePlan::Retire { target } => {
            let mut request = RetireIdentityPairRequest {
                operation,
                target: operator_active_target(target),
                actor,
            };
            request.operation.request_fingerprint =
                retire_identity_pair_request_fingerprint(&request);
            validate_retire_request(&request).map_err(map_operator_lifecycle_failure)?;
            CanonicalOperatorLifecycleRequest::Retire(Box::new(request))
        }
        OperatorLifecyclePlan::Disable {
            principal_fingerprint,
            expected_active_binding,
        } => {
            let mut request = DisableIdentityPrincipalRequest {
                operation,
                principal_fingerprint,
                expected_active_binding: expected_active_binding.map(operator_active_target),
                actor,
            };
            request.operation.request_fingerprint =
                disable_identity_principal_request_fingerprint(&request);
            validate_disable_request(&request).map_err(map_operator_lifecycle_failure)?;
            CanonicalOperatorLifecycleRequest::Disable(Box::new(request))
        }
        OperatorLifecyclePlan::Revoke {
            event_author_pubkey,
            expected_active_binding,
        } => {
            let mut request = RevokeIdentityKeyRequest {
                operation,
                event_author_pubkey,
                expected_active_binding: expected_active_binding.map(operator_active_target),
                actor,
            };
            request.operation.request_fingerprint =
                revoke_identity_key_request_fingerprint(&request);
            validate_revoke_request(&request).map_err(map_operator_lifecycle_failure)?;
            CanonicalOperatorLifecycleRequest::Revoke(Box::new(request))
        }
        OperatorLifecyclePlan::Rotate { target, .. } => {
            let target = operator_active_target(target);
            let replacement = operator_replacement_proof(
                operation,
                target.principal_fingerprint,
                replacement_proof.ok_or(OperatorLifecycleError::InvalidRequest)?,
            )?;
            let mut request = RotateIdentityBindingRequest {
                operation,
                target,
                replacement,
                actor,
            };
            request.replacement.intent_fingerprint = rotate_identity_intent_fingerprint(&request);
            request.operation.request_fingerprint =
                rotate_identity_binding_request_fingerprint(&request);
            validate_rotate_request(&request).map_err(map_operator_lifecycle_failure)?;
            CanonicalOperatorLifecycleRequest::Rotate(Box::new(request))
        }
        OperatorLifecyclePlan::Recover { pending, .. } => {
            let pending = ExpectedPendingReplacement {
                target: operator_retired_target(pending.target()),
                fact_generation: pending.fact_generation(),
            };
            let replacement = operator_replacement_proof(
                operation,
                pending.target.principal_fingerprint,
                replacement_proof.ok_or(OperatorLifecycleError::InvalidRequest)?,
            )?;
            let mut request = RecoverIdentityBindingRequest {
                operation,
                pending,
                replacement,
                actor,
            };
            request.replacement.intent_fingerprint = recover_identity_intent_fingerprint(&request);
            request.operation.request_fingerprint =
                recover_identity_binding_request_fingerprint(&request);
            validate_recover_request(&request).map_err(map_operator_lifecycle_failure)?;
            CanonicalOperatorLifecycleRequest::Recover(Box::new(request))
        }
        OperatorLifecyclePlan::Enable {
            principal_fingerprint,
            disabled_fact_generation,
            pending,
            ..
        } => {
            let pending = ExpectedPendingReplacement {
                target: operator_retired_target(pending.target()),
                fact_generation: pending.fact_generation(),
            };
            let replacement = operator_replacement_proof(
                operation,
                principal_fingerprint,
                replacement_proof.ok_or(OperatorLifecycleError::InvalidRequest)?,
            )?;
            let mut request = EnableIdentityPrincipalRequest {
                operation,
                principal_fingerprint,
                disabled_fact_generation,
                pending,
                replacement,
                principal_resolution: None,
                actor,
            };
            request.replacement.intent_fingerprint = enable_identity_intent_fingerprint(&request);
            request.operation.request_fingerprint =
                enable_identity_principal_request_fingerprint(&request);
            validate_enable_request(&request).map_err(map_operator_lifecycle_failure)?;
            CanonicalOperatorLifecycleRequest::Enable(Box::new(request))
        }
    };
    Ok(PreparedVerifiedOperatorTransition {
        canonical,
        grant_issued_at: grant.issued_at(),
        grant_expires_at: grant.expires_at(),
    })
}

fn validate_operator_grant(
    grant: &VerifiedOperatorLifecycleGrant,
    intent: &OperatorLifecycleIntent,
) -> Result<Option<GrantBoundReplacementProof>, OperatorLifecycleError> {
    if grant.authorization_domain() != intent.authorization_domain()
        || grant.action() != intent.action()
        || grant.operation_id() != intent.operation_id()
        || grant.intent_digest() != intent.intent_digest()
        || grant.expected_revision() != intent.expected_revision()
        || grant.request_attribution() == [0; 32]
        || grant.approval_policy_digest() == [0; 32]
        || grant.signer_attribution() == [0; 32]
        || grant
            .approval_attribution()
            .is_some_and(|approval| approval == [0; 32] || approval == grant.signer_attribution())
    {
        return Err(OperatorLifecycleError::InvalidRequest);
    }
    match (
        intent.replacement_event_author_pubkey(),
        intent.replacement_expires_at(),
        grant.replacement_event_author_pubkey(),
        grant.replacement_expires_at(),
        grant.replacement_proof_attribution(),
    ) {
        (None, None, None, None, None) => Ok(None),
        (
            Some(requested_key),
            Some(requested_expiry),
            Some(proven_key),
            Some(proven_expiry),
            Some(proof_attribution),
        ) if requested_key == proven_key
            && requested_expiry == proven_expiry
            && proven_key != [0; 32]
            && proof_attribution != [0; 32]
            && proven_expiry.timestamp_micros() > 0 =>
        {
            Ok(Some(GrantBoundReplacementProof {
                event_author_pubkey: proven_key,
                proof_attribution,
                requested_expires_at: proven_expiry,
                authorization_expires_at: grant.expires_at(),
            }))
        }
        _ => Err(OperatorLifecycleError::InvalidRequest),
    }
}

const fn operator_active_target(target: ExactActiveOperatorTarget) -> ExactActiveBindingTarget {
    ExactActiveBindingTarget {
        binding_id: target.binding_id(),
        binding_version: target.binding_version(),
        expected_lifecycle_revision: target.expected_lifecycle_revision(),
        principal_fingerprint: target.principal_fingerprint(),
        event_author_pubkey: target.event_author_pubkey(),
    }
}

const fn operator_retired_target(target: ExactRetiredOperatorTarget) -> ExactRetiredBindingTarget {
    ExactRetiredBindingTarget {
        binding_id: target.binding_id(),
        binding_version: target.binding_version(),
        expected_lifecycle_revision: target.expected_lifecycle_revision(),
        principal_fingerprint: target.principal_fingerprint(),
        event_author_pubkey: target.event_author_pubkey(),
    }
}

fn operator_replacement_proof(
    operation: IdentityLifecycleOperation,
    principal_fingerprint: [u8; 32],
    proof: GrantBoundReplacementProof,
) -> Result<VerifiedReplacementProof, OperatorLifecycleError> {
    VerifiedReplacementProof::from_verifier_sealed_receipt(
        operation.community_id,
        operation.operation_id,
        [1; 32],
        principal_fingerprint,
        proof.event_author_pubkey,
        proof.proof_attribution,
        proof.requested_expires_at,
        proof.authorization_expires_at,
    )
    .map_err(map_operator_lifecycle_failure)
}

fn map_operator_lifecycle_failure(error: IdentityLifecycleFailure) -> OperatorLifecycleError {
    match error {
        IdentityLifecycleFailure::InvalidRequest => OperatorLifecycleError::InvalidRequest,
        IdentityLifecycleFailure::IntentConflict => OperatorLifecycleError::IntentConflict,
        IdentityLifecycleFailure::AuditUnavailable => OperatorLifecycleError::AuditUnavailable,
        IdentityLifecycleFailure::CorruptStoredResult => {
            OperatorLifecycleError::CorruptStoredResult
        }
        IdentityLifecycleFailure::Storage(error) => OperatorLifecycleError::Storage(error),
    }
}

fn proof_bound_lifecycle_request_fingerprint(
    domain: &[u8],
    operation: &IdentityLifecycleOperation,
    intent_fingerprint: [u8; 32],
    replacement_proof_fingerprint: [u8; 32],
    principal_proof_fingerprint: Option<[u8; 32]>,
    actor: &AuthenticatedLifecycleActor,
) -> [u8; 32] {
    lifecycle_digest(
        domain,
        &[
            operation.community_id.as_uuid().as_bytes(),
            operation.operation_id.as_bytes(),
            &intent_fingerprint,
            &replacement_proof_fingerprint,
            &principal_proof_fingerprint.unwrap_or([0; 32]),
            &actor.request_attribution,
        ],
    )
}

/// Closed lifecycle denial reasons persisted only after authenticated
/// validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub enum IdentityLifecycleDenial {
    /// The selected policy is missing, mismatched, inactive, or expired.
    PolicyUnavailable = 3,
    /// A binding's exclusive expiry has passed at authoritative DB time.
    BindingExpired = 4,
    /// The principal is already active under incompatible coordinates.
    PrincipalAlreadyBound = 5,
    /// The event-author key is already active or permanently revoked.
    EventAuthorUnavailable = 6,
    /// A permanent or open lifecycle selector prevents admission.
    LifecycleSelectorConflict = 7,
    /// The exact expected binding generation/revision/state no longer matches.
    StaleExpectedState = 8,
}

impl IdentityLifecycleDenial {
    fn from_reason_code(value: i16) -> Result<Self, IdentityLifecycleFailure> {
        match value {
            3 => Ok(Self::PolicyUnavailable),
            4 => Ok(Self::BindingExpired),
            5 => Ok(Self::PrincipalAlreadyBound),
            6 => Ok(Self::EventAuthorUnavailable),
            7 => Ok(Self::LifecycleSelectorConflict),
            8 => Ok(Self::StaleExpectedState),
            _ => Err(IdentityLifecycleFailure::CorruptStoredResult),
        }
    }
}

/// Original persisted operation outcome represented by an exact replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistedIdentityLifecycleOutcome {
    /// The original operation applied.
    Applied,
    /// The original operation was an explicit semantic no-op.
    NoOp,
    /// The original authenticated operation was denied.
    Denied(IdentityLifecycleDenial),
}

/// Canonical lifecycle execution observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityLifecycleObservation {
    /// This invocation committed the transition.
    Applied {
        /// Transition that was applied.
        transition: IdentityLifecycleTransition,
        /// Successor or existing binding evidence where applicable.
        binding: Option<IdentityBindingEvidence>,
    },
    /// This invocation committed a canonical no-op receipt/history/event.
    NoOp {
        /// Transition that was observed as a no-op.
        transition: IdentityLifecycleTransition,
        /// Exact already-active binding, if applicable.
        binding: Option<IdentityBindingEvidence>,
    },
    /// This invocation observed an exact prior receipt without writing again.
    ExactReplay {
        /// Transition bound by the original receipt.
        transition: IdentityLifecycleTransition,
        /// Original persisted outcome.
        original_outcome: PersistedIdentityLifecycleOutcome,
        /// Original successor/existing binding evidence, if applicable.
        binding: Option<IdentityBindingEvidence>,
    },
    /// This invocation durably committed an authenticated denial and audit.
    Denied {
        /// Attempted transition.
        transition: IdentityLifecycleTransition,
        /// Closed denial reason.
        reason: IdentityLifecycleDenial,
    },
}

/// Lifecycle transaction failures distinct from durable closed denials.
#[derive(Debug, thiserror::Error)]
pub enum IdentityLifecycleFailure {
    /// Typed request validation failed before DB mutation.
    #[error("invalid identity lifecycle request")]
    InvalidRequest,
    /// An operation ID already exists with different canonical semantics.
    #[error("identity lifecycle operation intent conflict")]
    IntentConflict,
    /// Audit could not be appended; the complete transaction was rolled back.
    #[error("authorization audit unavailable")]
    AuditUnavailable,
    /// Stored immutable result data does not satisfy the closed model.
    #[error("corrupt stored identity lifecycle result")]
    CorruptStoredResult,
    /// Ordinary database failure.
    #[error(transparent)]
    Storage(#[from] DbError),
}

impl From<AuthorizationEventWriteError> for IdentityLifecycleFailure {
    fn from(value: AuthorizationEventWriteError) -> Self {
        match value {
            AuthorizationEventWriteError::CapacityUnavailable => Self::AuditUnavailable,
            AuthorizationEventWriteError::Database(error) => Self::Storage(error),
        }
    }
}

/// Canonical result returned only to the crate-local restore wrapper after a
/// fenced admission-loss transaction commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedAdmissionLossObservation {
    /// This invocation applied the exact targeted loss.
    Applied {
        /// Exact invalidation generation attributed to this operation.
        invalidation_generation: u64,
    },
    /// This invocation durably committed an authenticated denial.
    Denied {
        /// Closed lifecycle denial reason.
        reason: IdentityLifecycleDenial,
    },
    /// This invocation reproduced an exact prior canonical result.
    ExactReplay {
        /// Outcome stored by the original canonical invocation.
        original_outcome: PersistedIdentityLifecycleOutcome,
        /// Original invalidation generation for an applied result.
        invalidation_generation: Option<u64>,
    },
}

/// Deterministic request failures for which restore may abort its pending
/// external intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedAdmissionLossRejection {
    /// The sealed command failed closed validation.
    InvalidRequest,
    /// The operation ID is already bound to different canonical semantics.
    IntentConflict,
}

/// Closed writer failures consumed by the future high-level restore wrapper.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PreparedAdmissionLossWriteFailure {
    /// Canonical audit capacity or append was unavailable; all SQL rolled back.
    #[error("admission-loss audit unavailable")]
    AuditUnavailable,
    /// The command was deterministically rejected before a canonical result.
    #[error("admission-loss request rejected: {0:?}")]
    Rejected(PreparedAdmissionLossRejection),
    /// Stored canonical evidence was inconsistent; restore may abort its
    /// pending intent and the caller must latch unhealthy.
    #[error("admission-loss canonical evidence is corrupt")]
    CorruptStoredResult,
    /// A deterministic database failure occurred before commit and rollback
    /// completed, so restore may abort its pending intent.
    #[error("admission-loss database failure")]
    Database(#[source] DbError),
    /// PostgreSQL commit or rollback failed, so restore must reconcile rather
    /// than abort because the canonical outcome is unknown.
    #[error("admission-loss outcome is unknown")]
    OutcomeUnknown(#[source] DbError),
}

/// Deterministic direct-enrollment request failures for which restore may
/// abort the owned external Pending intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedDirectEnrollmentRejection {
    /// The sealed request failed canonical validation.
    InvalidRequest,
    /// The operation identity is already bound to different semantics.
    IntentConflict,
}

/// Same-session canonical writer failures consumed by the operation-specific
/// restore wrapper.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PreparedDirectEnrollmentWriteFailure {
    /// Canonical audit capacity or append was unavailable; SQL rolled back.
    #[error("direct-enrollment audit unavailable")]
    AuditUnavailable,
    /// The sealed request was deterministically rejected.
    #[error("direct-enrollment request rejected: {0:?}")]
    Rejected(PreparedDirectEnrollmentRejection),
    /// Stored canonical evidence was internally inconsistent.
    #[error("direct-enrollment canonical evidence is corrupt")]
    CorruptStoredResult,
    /// A deterministic database failure occurred and rollback completed.
    #[error("direct-enrollment database failure")]
    Database(#[source] DbError),
    /// Commit or rollback failed, so the canonical outcome is unknown.
    #[error("direct-enrollment outcome is unknown")]
    OutcomeUnknown(#[source] DbError),
}

#[derive(Clone, Copy)]
enum IdentityLifecycleLockPlan {
    Enroll {
        principal: [u8; 32],
        new_key: [u8; 32],
    },
    AdmissionLoss {
        principal: [u8; 32],
        old_key: [u8; 32],
    },
    Retire {
        principal: [u8; 32],
        old_key: [u8; 32],
    },
    Disable {
        principal: [u8; 32],
        old_key: Option<[u8; 32]>,
    },
    Revoke {
        principal: Option<[u8; 32]>,
        old_key: [u8; 32],
    },
    Rotate {
        principal: [u8; 32],
        old_key: [u8; 32],
        new_key: [u8; 32],
    },
    Recover {
        principal: [u8; 32],
        old_key: [u8; 32],
        new_key: [u8; 32],
    },
    Enable {
        principal: [u8; 32],
        old_key: Option<[u8; 32]>,
        new_key: [u8; 32],
    },
}

/// Proof that the operation and complete coordinate plan were locked in
/// canonical order. It deliberately exposes neither `Deref` nor raw access.
struct PrelockedIdentityLifecycleTx<'borrow, 'connection> {
    transaction: &'borrow mut Transaction<'connection, Postgres>,
    community_id: CommunityId,
    database_owned_version_deltas: Vec<AuthorizationOperationVersionDelta>,
}

// Migration integration tests intentionally exercise the SQL trigger lock
// namespace directly. Keep this test-only bridge out of production builds so
// application callers cannot bypass the private lifecycle executor.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct IdentityLifecycleLockCoordinates {
    community_id: CommunityId,
    principal_fingerprint: Option<[u8; 32]>,
    old_event_author_pubkey: Option<nostr::PublicKey>,
    new_event_author_pubkey: Option<nostr::PublicKey>,
}

#[cfg(test)]
impl IdentityLifecycleLockCoordinates {
    pub(crate) fn new(
        community_id: CommunityId,
        principal_fingerprint: Option<[u8; 32]>,
        old_event_author_pubkey: Option<nostr::PublicKey>,
        new_event_author_pubkey: Option<nostr::PublicKey>,
    ) -> Result<Self, DbError> {
        if community_id.as_uuid().is_nil()
            || (principal_fingerprint.is_none()
                && old_event_author_pubkey.is_none()
                && new_event_author_pubkey.is_none())
        {
            return Err(DbError::InvalidData(
                "invalid lifecycle test lock coordinates".to_owned(),
            ));
        }
        Ok(Self {
            community_id,
            principal_fingerprint,
            old_event_author_pubkey,
            new_event_author_pubkey,
        })
    }
}

#[cfg(test)]
pub(crate) async fn lock_identity_lifecycle_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    coordinates: &IdentityLifecycleLockCoordinates,
) -> Result<(), DbError> {
    let operation = IdentityLifecycleOperation {
        community_id: coordinates.community_id,
        operation_id: Uuid::new_v4(),
        request_fingerprint: [1; 32],
        correlation_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
    };
    let keys: Vec<i64> = sqlx::query_scalar(
        "WITH coordinates(scope,fingerprint) AS (VALUES \
           ('principal'::text,$2::bytea),('key'::text,$3::bytea),('key'::text,$4::bytea)) \
         SELECT DISTINCT hashtextextended( \
           'buzz:identity-lifecycle-coordinate:v1:' || scope || ':' || \
           $1::uuid::text || ':' || encode(fingerprint,'hex'),0) AS lock_key \
         FROM coordinates WHERE fingerprint IS NOT NULL ORDER BY lock_key",
    )
    .bind(operation.community_id.as_uuid())
    .bind(
        coordinates
            .principal_fingerprint
            .map(|value| value.to_vec()),
    )
    .bind(
        coordinates
            .old_event_author_pubkey
            .map(|value| value.to_bytes().to_vec()),
    )
    .bind(
        coordinates
            .new_event_author_pubkey
            .map(|value| value.to_bytes().to_vec()),
    )
    .fetch_all(&mut **transaction)
    .await?;
    for key in keys {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(key)
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

#[derive(FromRow)]
struct StoredReceipt {
    request_fingerprint: Vec<u8>,
    operation_kind: i16,
    outcome_code: i16,
    result_digest: Vec<u8>,
}

#[derive(FromRow)]
struct StoredLifecycleHistory {
    transition_kind: i16,
    outcome_code: i16,
    old_binding_id: Option<Uuid>,
    old_binding_version: Option<i64>,
    old_prior_lifecycle_revision: Option<i64>,
    old_prior_state: Option<i16>,
    old_resulting_lifecycle_revision: Option<i64>,
    old_resulting_state: Option<i16>,
    successor_binding_id: Option<Uuid>,
    successor_binding_version: Option<i64>,
    successor_lifecycle_revision: Option<i64>,
    successor_state: Option<i16>,
    request_fingerprint: Vec<u8>,
    transition_digest: Vec<u8>,
}

#[derive(FromRow)]
struct StoredBindingGeneration {
    binding_id: Uuid,
    binding_version: i64,
}

#[derive(FromRow)]
struct ActiveBinding {
    binding_id: Uuid,
    binding_version: i64,
    issuer: String,
    subject: String,
    principal_fingerprint: Vec<u8>,
    event_author_pubkey: Vec<u8>,
    binding_state: i16,
    lifecycle_revision: i64,
    binding_provenance: i16,
    policy_revision: i64,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
struct OpenLifecycleSelector {
    selector_id: Uuid,
    selector_kind: i16,
    fact_generation: i64,
    principal_fingerprint: Vec<u8>,
    event_author_pubkey: Option<Vec<u8>>,
    binding_id: Option<Uuid>,
    binding_version: Option<i64>,
}

enum EnrollmentDecision {
    Apply,
    NoOp(IdentityBindingEvidence),
    Deny(IdentityLifecycleDenial),
}

#[derive(Clone, Copy)]
enum LifecycleReplayRequest<'request> {
    Enrollment(&'request AuthoritativeEnrollmentRequest),
    AdmissionLoss(&'request ExactAdmissionLossRequest),
    Retire(&'request RetireIdentityPairRequest),
    Disable(&'request DisableIdentityPrincipalRequest),
    Revoke(&'request RevokeIdentityKeyRequest),
    Rotate(&'request RotateIdentityBindingRequest),
    Recover(&'request RecoverIdentityBindingRequest),
    Enable(&'request EnableIdentityPrincipalRequest),
}

impl<'request> LifecycleReplayRequest<'request> {
    fn operation(self) -> IdentityLifecycleOperation {
        match self {
            Self::Enrollment(request) => request.operation,
            Self::AdmissionLoss(request) => request.operation,
            Self::Retire(request) => request.operation,
            Self::Disable(request) => request.operation,
            Self::Revoke(request) => request.operation,
            Self::Rotate(request) => request.operation,
            Self::Recover(request) => request.operation,
            Self::Enable(request) => request.operation,
        }
    }

    fn transition(self) -> IdentityLifecycleTransition {
        match self {
            Self::Enrollment(request) => request.transition,
            Self::AdmissionLoss(_) => IdentityLifecycleTransition::AdmissionLoss,
            Self::Retire(_) => IdentityLifecycleTransition::Retire,
            Self::Disable(_) => IdentityLifecycleTransition::Disable,
            Self::Revoke(_) => IdentityLifecycleTransition::Revoke,
            Self::Rotate(_) => IdentityLifecycleTransition::Rotate,
            Self::Recover(_) => IdentityLifecycleTransition::Recover,
            Self::Enable(_) => IdentityLifecycleTransition::Enable,
        }
    }

    fn actor(self) -> &'request AuthenticatedLifecycleActor {
        match self {
            Self::Enrollment(request) => &request.actor,
            Self::AdmissionLoss(request) => &request.actor,
            Self::Retire(request) => &request.actor,
            Self::Disable(request) => &request.actor,
            Self::Revoke(request) => &request.actor,
            Self::Rotate(request) => &request.actor,
            Self::Recover(request) => &request.actor,
            Self::Enable(request) => &request.actor,
        }
    }

    fn subject_fingerprint(self) -> Option<[u8; 32]> {
        match self {
            Self::Enrollment(request) => Some(request.principal_fingerprint),
            Self::AdmissionLoss(request) => Some(request.target.principal_fingerprint),
            Self::Retire(request) => Some(request.target.principal_fingerprint),
            Self::Disable(request) => Some(request.principal_fingerprint),
            Self::Revoke(request) => request
                .expected_active_binding
                .map(|target| target.principal_fingerprint),
            Self::Rotate(request) => Some(request.target.principal_fingerprint),
            Self::Recover(request) => Some(request.pending.target.principal_fingerprint),
            Self::Enable(request) => Some(request.principal_fingerprint),
        }
    }
}

impl Db {
    /// Execute authoritative local enrollment/provisioning through the single
    /// canonical lifecycle transaction engine.
    pub(crate) async fn execute_authoritative_enrollment(
        &self,
        request: &AuthoritativeEnrollmentRequest,
    ) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
        validate_enrollment_request(request)?;
        let mut transaction = self.pool.begin().await.map_err(DbError::from)?;
        let observation = execute_enrollment_tx(&mut transaction, request).await?;
        transaction.commit().await.map_err(DbError::from)?;
        Ok(observation)
    }

    /// Execute one sealed direct enrollment on the exact primary session
    /// owned by operation restore. Canonical lifecycle SQL remains solely in
    /// `execute_enrollment_tx`.
    pub(crate) async fn execute_prepared_direct_enrollment_fenced(
        &self,
        fence: &mut AuthorizationOperationFence,
        prepared: &PreparedDirectEnrollment,
    ) -> Result<IdentityLifecycleObservation, PreparedDirectEnrollmentWriteFailure> {
        let request = &prepared.request;
        validate_enrollment_request(request).map_err(map_prepared_direct_enrollment_failure)?;
        let connection = fence
            .connection_for(
                prepared.authorization_domain(),
                prepared.operation_id(),
                prepared.request_fingerprint(),
            )
            .map_err(PreparedDirectEnrollmentWriteFailure::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(DbError::from)
            .map_err(PreparedDirectEnrollmentWriteFailure::Database)?;
        let observation = match execute_enrollment_tx(&mut transaction, request).await {
            Ok(observation) => observation,
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    return Err(PreparedDirectEnrollmentWriteFailure::OutcomeUnknown(
                        rollback_error.into(),
                    ));
                }
                return Err(map_prepared_direct_enrollment_failure(error));
            }
        };
        transaction
            .commit()
            .await
            .map_err(DbError::from)
            .map_err(PreparedDirectEnrollmentWriteFailure::OutcomeUnknown)?;
        Ok(observation)
    }

    /// Execute one verifier-sealed provision binding on the exact primary
    /// session owned by operation restore. Canonical enrollment SQL remains
    /// solely in `execute_enrollment_tx`.
    pub(crate) async fn execute_prepared_provision_binding_fenced(
        &self,
        fence: &mut AuthorizationOperationFence,
        prepared: &PreparedProvisionBinding,
    ) -> Result<IdentityLifecycleObservation, PreparedDirectEnrollmentWriteFailure> {
        let request = &prepared.request;
        validate_enrollment_request(request).map_err(map_prepared_direct_enrollment_failure)?;
        if request.transition != IdentityLifecycleTransition::Provision
            || request.operation.community_id != prepared.intent.authorization_domain()
            || request.operation.operation_id != prepared.intent.operation_id()
            || request.policy_revision != prepared.intent.policy_revision()
            || request.policy_digest != prepared.intent.policy_digest()
            || request.event_author_pubkey != prepared.intent.selected_event_author_pubkey()
            || request.evidence_expires_at != prepared.intent.expires_at()
        {
            return Err(PreparedDirectEnrollmentWriteFailure::Rejected(
                PreparedDirectEnrollmentRejection::InvalidRequest,
            ));
        }
        let connection = fence
            .connection_for(
                prepared.authorization_domain(),
                prepared.operation_id(),
                prepared.request_fingerprint(),
            )
            .map_err(PreparedDirectEnrollmentWriteFailure::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(DbError::from)
            .map_err(PreparedDirectEnrollmentWriteFailure::Database)?;
        let observation = match execute_enrollment_tx(&mut transaction, request).await {
            Ok(observation) => observation,
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    return Err(PreparedDirectEnrollmentWriteFailure::OutcomeUnknown(
                        rollback_error.into(),
                    ));
                }
                return Err(map_prepared_direct_enrollment_failure(error));
            }
        };
        transaction
            .commit()
            .await
            .map_err(DbError::from)
            .map_err(PreparedDirectEnrollmentWriteFailure::OutcomeUnknown)?;
        Ok(observation)
    }

    /// Apply one exact provider-free local admission loss through the same
    /// canonical lifecycle transaction engine used by authenticated commands.
    #[cfg(test)]
    pub(crate) async fn apply_exact_admission_loss(
        &self,
        request: &ExactAdmissionLossRequest,
    ) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
        validate_admission_loss_request(request)?;
        let mut transaction = self.pool.begin().await.map_err(DbError::from)?;
        let observation = execute_admission_loss_tx(&mut transaction, request).await?;
        transaction.commit().await.map_err(DbError::from)?;
        Ok(observation)
    }

    /// Execute one sealed admission loss on the exact primary session owned
    /// by operation restore. The fence identity and SQL transaction therefore
    /// cannot be split across connections.
    pub(crate) async fn execute_prepared_admission_loss_fenced(
        &self,
        fence: &mut AuthorizationOperationFence,
        prepared: &PreparedAdmissionLoss,
    ) -> Result<PreparedAdmissionLossObservation, PreparedAdmissionLossWriteFailure> {
        let request = &prepared.request;
        validate_admission_loss_request(request).map_err(map_prepared_admission_loss_failure)?;
        let connection = fence
            .connection_for(
                prepared.authorization_domain(),
                prepared.operation_id(),
                prepared.request_fingerprint(),
            )
            .map_err(PreparedAdmissionLossWriteFailure::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(DbError::from)
            .map_err(PreparedAdmissionLossWriteFailure::Database)?;
        let observation = match execute_admission_loss_tx(&mut transaction, request).await {
            Ok(observation) => observation,
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    return Err(PreparedAdmissionLossWriteFailure::OutcomeUnknown(
                        rollback_error.into(),
                    ));
                }
                return Err(map_prepared_admission_loss_failure(error));
            }
        };
        let observation =
            match map_prepared_admission_loss_observation(&mut transaction, request, observation)
                .await
            {
                Ok(observation) => observation,
                Err(error) => {
                    if let Err(rollback_error) = transaction.rollback().await {
                        return Err(PreparedAdmissionLossWriteFailure::OutcomeUnknown(
                            rollback_error.into(),
                        ));
                    }
                    return Err(map_prepared_admission_loss_failure(error));
                }
            };
        transaction
            .commit()
            .await
            .map_err(DbError::from)
            .map_err(PreparedAdmissionLossWriteFailure::OutcomeUnknown)?;
        Ok(observation)
    }

    /// Permanently retire one exact active identity/key pair.
    #[cfg(test)]
    pub(crate) async fn retire_identity_pair(
        &self,
        request: &RetireIdentityPairRequest,
    ) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
        validate_retire_request(request)?;
        let mut transaction = self.pool.begin().await.map_err(DbError::from)?;
        let observation = execute_retire_tx(&mut transaction, request, None).await?;
        transaction.commit().await.map_err(DbError::from)?;
        Ok(observation)
    }

    /// Disable a principal, retiring its exact active generation when present.
    #[cfg(test)]
    pub(crate) async fn disable_identity_principal(
        &self,
        request: &DisableIdentityPrincipalRequest,
    ) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
        validate_disable_request(request)?;
        let mut transaction = self.pool.begin().await.map_err(DbError::from)?;
        let observation = execute_disable_tx(&mut transaction, request, None).await?;
        transaction.commit().await.map_err(DbError::from)?;
        Ok(observation)
    }

    /// Permanently revoke a key, retiring its exact active binding when present.
    #[cfg(test)]
    pub(crate) async fn revoke_identity_key(
        &self,
        request: &RevokeIdentityKeyRequest,
    ) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
        validate_revoke_request(request)?;
        let mut transaction = self.pool.begin().await.map_err(DbError::from)?;
        let observation = execute_revoke_tx(&mut transaction, request, None).await?;
        transaction.commit().await.map_err(DbError::from)?;
        Ok(observation)
    }

    /// Rotate one exact active generation to a verifier-proven fresh key.
    #[cfg(test)]
    pub(crate) async fn rotate_identity_binding(
        &self,
        request: &RotateIdentityBindingRequest,
    ) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
        validate_rotate_request(request)?;
        let mut transaction = self.pool.begin().await.map_err(DbError::from)?;
        let observation = execute_rotate_tx(&mut transaction, request, None).await?;
        transaction.commit().await.map_err(DbError::from)?;
        Ok(observation)
    }

    /// Recover one exact open pending lineage to a verifier-proven fresh key.
    #[cfg(test)]
    pub(crate) async fn recover_identity_binding(
        &self,
        request: &RecoverIdentityBindingRequest,
    ) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
        validate_recover_request(request)?;
        let mut transaction = self.pool.begin().await.map_err(DbError::from)?;
        let observation = execute_recover_tx(&mut transaction, request, None).await?;
        transaction.commit().await.map_err(DbError::from)?;
        Ok(observation)
    }

    /// Enable one disabled principal through one exact pending lineage.
    #[cfg(test)]
    pub(crate) async fn enable_identity_principal(
        &self,
        request: &EnableIdentityPrincipalRequest,
    ) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
        validate_enable_request(request)?;
        let mut transaction = self.pool.begin().await.map_err(DbError::from)?;
        let observation = execute_enable_tx(&mut transaction, request, None).await?;
        transaction.commit().await.map_err(DbError::from)?;
        Ok(observation)
    }

    /// Execute one verifier-sealed operator transition on the physical
    /// session owned by operation restore. Canonical lifecycle SQL remains in
    /// the six private transaction functions below.
    pub(crate) async fn execute_prepared_operator_transition_fenced(
        &self,
        fence: &mut AuthorizationOperationFence,
        prepared: &PreparedVerifiedOperatorTransition,
    ) -> Result<IdentityLifecycleObservation, PreparedOperatorLifecycleWriteFailure> {
        let connection = fence
            .connection_for(
                prepared.authorization_domain(),
                prepared.operation_id(),
                prepared.request_fingerprint(),
            )
            .map_err(PreparedOperatorLifecycleWriteFailure::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(DbError::from)
            .map_err(PreparedOperatorLifecycleWriteFailure::Database)?;
        let eligibility = OperatorFirstExecutionEligibility {
            issued_at: prepared.grant_issued_at,
            expires_at: prepared.grant_expires_at,
        };
        let observation = match execute_operator_canonical_tx(
            &mut transaction,
            &prepared.canonical,
            &eligibility,
        )
        .await
        {
            Ok(observation) => observation,
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    return Err(PreparedOperatorLifecycleWriteFailure::OutcomeUnknown(
                        rollback_error.into(),
                    ));
                }
                return Err(map_prepared_operator_lifecycle_failure(error));
            }
        };
        transaction
            .commit()
            .await
            .map_err(DbError::from)
            .map_err(PreparedOperatorLifecycleWriteFailure::OutcomeUnknown)?;
        Ok(observation)
    }
}

#[derive(Clone, Copy)]
struct OperatorFirstExecutionEligibility {
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

async fn validate_operator_first_execution_eligibility_tx(
    transaction: &mut Transaction<'_, Postgres>,
    eligibility: Option<&OperatorFirstExecutionEligibility>,
) -> Result<(), IdentityLifecycleFailure> {
    let Some(eligibility) = eligibility else {
        return Ok(());
    };
    let fresh: bool =
        sqlx::query_scalar("SELECT clock_timestamp() >= $1 AND clock_timestamp() < $2")
            .bind(eligibility.issued_at)
            .bind(eligibility.expires_at)
            .fetch_one(&mut **transaction)
            .await
            .map_err(DbError::from)?;
    if !fresh {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

async fn execute_operator_canonical_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &CanonicalOperatorLifecycleRequest,
    eligibility: &OperatorFirstExecutionEligibility,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    match request {
        CanonicalOperatorLifecycleRequest::Retire(request) => {
            execute_retire_tx(transaction, request, Some(eligibility)).await
        }
        CanonicalOperatorLifecycleRequest::Disable(request) => {
            execute_disable_tx(transaction, request, Some(eligibility)).await
        }
        CanonicalOperatorLifecycleRequest::Revoke(request) => {
            execute_revoke_tx(transaction, request, Some(eligibility)).await
        }
        CanonicalOperatorLifecycleRequest::Rotate(request) => {
            execute_rotate_tx(transaction, request, Some(eligibility)).await
        }
        CanonicalOperatorLifecycleRequest::Recover(request) => {
            execute_recover_tx(transaction, request, Some(eligibility)).await
        }
        CanonicalOperatorLifecycleRequest::Enable(request) => {
            execute_enable_tx(transaction, request, Some(eligibility)).await
        }
    }
}

fn map_prepared_operator_lifecycle_failure(
    error: IdentityLifecycleFailure,
) -> PreparedOperatorLifecycleWriteFailure {
    match error {
        IdentityLifecycleFailure::InvalidRequest => {
            PreparedOperatorLifecycleWriteFailure::Rejected(
                PreparedOperatorLifecycleRejection::InvalidRequest,
            )
        }
        IdentityLifecycleFailure::IntentConflict => {
            PreparedOperatorLifecycleWriteFailure::Rejected(
                PreparedOperatorLifecycleRejection::IntentConflict,
            )
        }
        IdentityLifecycleFailure::AuditUnavailable => {
            PreparedOperatorLifecycleWriteFailure::AuditUnavailable
        }
        IdentityLifecycleFailure::CorruptStoredResult => {
            PreparedOperatorLifecycleWriteFailure::CorruptStoredResult
        }
        IdentityLifecycleFailure::Storage(error) => {
            PreparedOperatorLifecycleWriteFailure::Database(error)
        }
    }
}

fn map_prepared_direct_enrollment_failure(
    failure: IdentityLifecycleFailure,
) -> PreparedDirectEnrollmentWriteFailure {
    match failure {
        IdentityLifecycleFailure::InvalidRequest => PreparedDirectEnrollmentWriteFailure::Rejected(
            PreparedDirectEnrollmentRejection::InvalidRequest,
        ),
        IdentityLifecycleFailure::IntentConflict => PreparedDirectEnrollmentWriteFailure::Rejected(
            PreparedDirectEnrollmentRejection::IntentConflict,
        ),
        IdentityLifecycleFailure::AuditUnavailable => {
            PreparedDirectEnrollmentWriteFailure::AuditUnavailable
        }
        IdentityLifecycleFailure::CorruptStoredResult => {
            PreparedDirectEnrollmentWriteFailure::CorruptStoredResult
        }
        IdentityLifecycleFailure::Storage(error) => {
            PreparedDirectEnrollmentWriteFailure::Database(error)
        }
    }
}

fn map_prepared_admission_loss_failure(
    failure: IdentityLifecycleFailure,
) -> PreparedAdmissionLossWriteFailure {
    match failure {
        IdentityLifecycleFailure::InvalidRequest => PreparedAdmissionLossWriteFailure::Rejected(
            PreparedAdmissionLossRejection::InvalidRequest,
        ),
        IdentityLifecycleFailure::IntentConflict => PreparedAdmissionLossWriteFailure::Rejected(
            PreparedAdmissionLossRejection::IntentConflict,
        ),
        IdentityLifecycleFailure::AuditUnavailable => {
            PreparedAdmissionLossWriteFailure::AuditUnavailable
        }
        IdentityLifecycleFailure::CorruptStoredResult => {
            PreparedAdmissionLossWriteFailure::CorruptStoredResult
        }
        IdentityLifecycleFailure::Storage(error) => {
            PreparedAdmissionLossWriteFailure::Database(error)
        }
    }
}

async fn map_prepared_admission_loss_observation(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ExactAdmissionLossRequest,
    observation: IdentityLifecycleObservation,
) -> Result<PreparedAdmissionLossObservation, IdentityLifecycleFailure> {
    match observation {
        IdentityLifecycleObservation::Applied {
            transition: IdentityLifecycleTransition::AdmissionLoss,
            binding: None,
        } => Ok(PreparedAdmissionLossObservation::Applied {
            invalidation_generation: admission_loss_invalidation_generation_tx(
                transaction,
                request,
            )
            .await?,
        }),
        IdentityLifecycleObservation::Denied {
            transition: IdentityLifecycleTransition::AdmissionLoss,
            reason,
        } => Ok(PreparedAdmissionLossObservation::Denied { reason }),
        IdentityLifecycleObservation::ExactReplay {
            transition: IdentityLifecycleTransition::AdmissionLoss,
            original_outcome,
            binding: None,
        } => {
            let invalidation_generation = match original_outcome {
                PersistedIdentityLifecycleOutcome::Applied => {
                    Some(admission_loss_invalidation_generation_tx(transaction, request).await?)
                }
                PersistedIdentityLifecycleOutcome::Denied(_) => None,
                PersistedIdentityLifecycleOutcome::NoOp => {
                    return Err(IdentityLifecycleFailure::CorruptStoredResult)
                }
            };
            Ok(PreparedAdmissionLossObservation::ExactReplay {
                original_outcome,
                invalidation_generation,
            })
        }
        _ => Err(IdentityLifecycleFailure::CorruptStoredResult),
    }
}

async fn admission_loss_invalidation_generation_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ExactAdmissionLossRequest,
) -> Result<u64, IdentityLifecycleFailure> {
    let manifest = load_manifest_connection(
        transaction,
        request.operation.community_id,
        request.operation.operation_id,
    )
    .await
    .map_err(IdentityLifecycleFailure::Storage)?
    .ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
    if manifest.request_fingerprint() != request.operation.request_fingerprint {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    let expected_key =
        authorization_version_invalidation_generation_component_key(request.operation.community_id);
    let mut generations = manifest.components().iter().filter(|component| {
        component.component_kind() == AuthorizationVersionComponentKind::InvalidationGeneration
            && component.component_key() == expected_key
    });
    let generation = generations
        .next()
        .ok_or(IdentityLifecycleFailure::CorruptStoredResult)?
        .after_version();
    if generations.next().is_some() {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    Ok(generation)
}

async fn execute_enrollment_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AuthoritativeEnrollmentRequest,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    lock_operation_tx(transaction, &request.operation).await?;
    if let Some(replay) =
        replay_observation_tx(transaction, LifecycleReplayRequest::Enrollment(request)).await?
    {
        return Ok(replay);
    }
    let mut locked = prelock_identity_lifecycle_tx(
        transaction,
        &request.operation,
        IdentityLifecycleLockPlan::Enroll {
            principal: request.principal_fingerprint,
            new_key: request.event_author_pubkey,
        },
    )
    .await?;
    let decision = enrollment_decision_tx(&mut locked, request).await?;
    match decision {
        EnrollmentDecision::Apply => apply_enrollment_tx(&mut locked, request).await,
        EnrollmentDecision::NoOp(binding) => commit_no_op_tx(&mut locked, request, binding).await,
        EnrollmentDecision::Deny(reason) => {
            commit_denial_tx(
                &mut locked,
                &request.operation,
                request.transition,
                &request.actor,
                Some(request.principal_fingerprint),
                event_kind_for_transition(request.transition),
                reason,
            )
            .await
        }
    }
}

async fn execute_admission_loss_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ExactAdmissionLossRequest,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    lock_operation_tx(transaction, &request.operation).await?;
    if let Some(replay) =
        replay_observation_tx(transaction, LifecycleReplayRequest::AdmissionLoss(request)).await?
    {
        return Ok(replay);
    }
    let mut locked = prelock_identity_lifecycle_tx(
        transaction,
        &request.operation,
        IdentityLifecycleLockPlan::AdmissionLoss {
            principal: request.target.principal_fingerprint,
            old_key: request.target.event_author_pubkey,
        },
    )
    .await?;
    let target = load_exact_binding_tx(&mut locked, request.target.binding_id).await?;
    if !admission_target_matches(target.as_ref(), &request.target) {
        return commit_denial_tx(
            &mut locked,
            &request.operation,
            IdentityLifecycleTransition::AdmissionLoss,
            &request.actor,
            Some(request.target.principal_fingerprint),
            event_kind_for_transition(IdentityLifecycleTransition::AdmissionLoss),
            IdentityLifecycleDenial::StaleExpectedState,
        )
        .await;
    }
    apply_admission_loss_tx(&mut locked, request, target.expect("matched target")).await
}

async fn execute_retire_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RetireIdentityPairRequest,
    operator_eligibility: Option<&OperatorFirstExecutionEligibility>,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    lock_operation_tx(transaction, &request.operation).await?;
    if let Some(replay) =
        replay_observation_tx(transaction, LifecycleReplayRequest::Retire(request)).await?
    {
        return Ok(replay);
    }
    validate_operator_first_execution_eligibility_tx(transaction, operator_eligibility).await?;
    let mut locked = prelock_identity_lifecycle_tx(
        transaction,
        &request.operation,
        IdentityLifecycleLockPlan::Retire {
            principal: request.target.principal_fingerprint,
            old_key: request.target.event_author_pubkey,
        },
    )
    .await?;
    let target = load_exact_binding_tx(&mut locked, request.target.binding_id).await?;
    if !active_target_matches(target.as_ref(), &request.target) {
        return commit_denial_tx(
            &mut locked,
            &request.operation,
            IdentityLifecycleTransition::Retire,
            &request.actor,
            Some(request.target.principal_fingerprint),
            event_kind_for_transition(IdentityLifecycleTransition::Retire),
            IdentityLifecycleDenial::StaleExpectedState,
        )
        .await;
    }
    apply_active_retirement_tx(
        &mut locked,
        &request.operation,
        IdentityLifecycleTransition::Retire,
        &request.actor,
        target.expect("matched target"),
        RetirementCompanions::Retire,
    )
    .await
}

async fn execute_disable_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &DisableIdentityPrincipalRequest,
    operator_eligibility: Option<&OperatorFirstExecutionEligibility>,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    lock_operation_tx(transaction, &request.operation).await?;
    if let Some(replay) =
        replay_observation_tx(transaction, LifecycleReplayRequest::Disable(request)).await?
    {
        return Ok(replay);
    }
    validate_operator_first_execution_eligibility_tx(transaction, operator_eligibility).await?;
    let mut locked = prelock_identity_lifecycle_tx(
        transaction,
        &request.operation,
        IdentityLifecycleLockPlan::Disable {
            principal: request.principal_fingerprint,
            old_key: request
                .expected_active_binding
                .map(|target| target.event_author_pubkey),
        },
    )
    .await?;
    let active =
        load_active_binding_by_principal_tx(&mut locked, request.principal_fingerprint).await?;
    match (request.expected_active_binding, active) {
        (Some(expected), Some(active)) if active_target_matches(Some(&active), &expected) => {
            apply_active_retirement_tx(
                &mut locked,
                &request.operation,
                IdentityLifecycleTransition::Disable,
                &request.actor,
                active,
                RetirementCompanions::Disable,
            )
            .await
        }
        (None, None) => apply_inactive_disable_tx(&mut locked, request).await,
        _ => {
            commit_denial_tx(
                &mut locked,
                &request.operation,
                IdentityLifecycleTransition::Disable,
                &request.actor,
                Some(request.principal_fingerprint),
                event_kind_for_transition(IdentityLifecycleTransition::Disable),
                IdentityLifecycleDenial::StaleExpectedState,
            )
            .await
        }
    }
}

async fn execute_revoke_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RevokeIdentityKeyRequest,
    operator_eligibility: Option<&OperatorFirstExecutionEligibility>,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    lock_operation_tx(transaction, &request.operation).await?;
    if let Some(replay) =
        replay_observation_tx(transaction, LifecycleReplayRequest::Revoke(request)).await?
    {
        return Ok(replay);
    }
    validate_operator_first_execution_eligibility_tx(transaction, operator_eligibility).await?;
    let mut locked = prelock_identity_lifecycle_tx(
        transaction,
        &request.operation,
        IdentityLifecycleLockPlan::Revoke {
            principal: request
                .expected_active_binding
                .map(|target| target.principal_fingerprint),
            old_key: request.event_author_pubkey,
        },
    )
    .await?;
    let active = load_active_binding_by_key_tx(&mut locked, request.event_author_pubkey).await?;
    match (request.expected_active_binding, active) {
        (Some(expected), Some(active)) if active_target_matches(Some(&active), &expected) => {
            apply_active_retirement_tx(
                &mut locked,
                &request.operation,
                IdentityLifecycleTransition::Revoke,
                &request.actor,
                active,
                RetirementCompanions::Revoke,
            )
            .await
        }
        (None, None) => apply_inactive_revoke_tx(&mut locked, request).await,
        _ => {
            commit_denial_tx(
                &mut locked,
                &request.operation,
                IdentityLifecycleTransition::Revoke,
                &request.actor,
                request
                    .expected_active_binding
                    .map(|target| target.principal_fingerprint),
                event_kind_for_transition(IdentityLifecycleTransition::Revoke),
                IdentityLifecycleDenial::StaleExpectedState,
            )
            .await
        }
    }
}

async fn execute_rotate_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RotateIdentityBindingRequest,
    operator_eligibility: Option<&OperatorFirstExecutionEligibility>,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    lock_operation_tx(transaction, &request.operation).await?;
    if let Some(replay) =
        replay_observation_tx(transaction, LifecycleReplayRequest::Rotate(request)).await?
    {
        return Ok(replay);
    }
    validate_operator_first_execution_eligibility_tx(transaction, operator_eligibility).await?;
    let mut locked = prelock_identity_lifecycle_tx(
        transaction,
        &request.operation,
        IdentityLifecycleLockPlan::Rotate {
            principal: request.target.principal_fingerprint,
            old_key: request.target.event_author_pubkey,
            new_key: request.replacement.event_author_pubkey,
        },
    )
    .await?;
    let target = load_exact_binding_tx(&mut locked, request.target.binding_id).await?;
    if !active_target_matches(target.as_ref(), &request.target) {
        return commit_denial_tx(
            &mut locked,
            &request.operation,
            IdentityLifecycleTransition::Rotate,
            &request.actor,
            Some(request.target.principal_fingerprint),
            event_kind_for_transition(IdentityLifecycleTransition::Rotate),
            IdentityLifecycleDenial::StaleExpectedState,
        )
        .await;
    }
    validate_replacement_freshness_tx(&mut locked, &request.replacement).await?;
    if !replacement_key_available_tx(&mut locked, request.replacement.event_author_pubkey).await? {
        return commit_denial_tx(
            &mut locked,
            &request.operation,
            IdentityLifecycleTransition::Rotate,
            &request.actor,
            Some(request.target.principal_fingerprint),
            event_kind_for_transition(IdentityLifecycleTransition::Rotate),
            IdentityLifecycleDenial::EventAuthorUnavailable,
        )
        .await;
    }
    let target = target.expect("matched target");
    let Some(policy) = load_current_policy_expiry_tx(
        &mut locked,
        target.policy_revision,
        target.binding_provenance,
    )
    .await?
    else {
        return commit_denial_tx(
            &mut locked,
            &request.operation,
            IdentityLifecycleTransition::Rotate,
            &request.actor,
            Some(request.target.principal_fingerprint),
            event_kind_for_transition(IdentityLifecycleTransition::Rotate),
            IdentityLifecycleDenial::PolicyUnavailable,
        )
        .await;
    };
    apply_successor_transition_tx(
        &mut locked,
        &request.operation,
        IdentityLifecycleTransition::Rotate,
        &request.actor,
        target,
        &request.replacement,
        policy.expires_at,
        None,
        None,
    )
    .await
}

async fn execute_recover_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RecoverIdentityBindingRequest,
    operator_eligibility: Option<&OperatorFirstExecutionEligibility>,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    lock_operation_tx(transaction, &request.operation).await?;
    if let Some(replay) =
        replay_observation_tx(transaction, LifecycleReplayRequest::Recover(request)).await?
    {
        return Ok(replay);
    }
    validate_operator_first_execution_eligibility_tx(transaction, operator_eligibility).await?;
    let mut locked = prelock_identity_lifecycle_tx(
        transaction,
        &request.operation,
        IdentityLifecycleLockPlan::Recover {
            principal: request.pending.target.principal_fingerprint,
            old_key: request.pending.target.event_author_pubkey,
            new_key: request.replacement.event_author_pubkey,
        },
    )
    .await?;
    let target = load_exact_binding_tx(&mut locked, request.pending.target.binding_id).await?;
    let pending = load_open_lifecycle_selector_tx(
        &mut locked,
        4,
        request.pending.target.principal_fingerprint,
    )
    .await?;
    if !retired_target_matches(target.as_ref(), &request.pending.target)
        || !pending_selector_matches(pending.as_ref(), &request.pending)
    {
        return commit_denial_tx(
            &mut locked,
            &request.operation,
            IdentityLifecycleTransition::Recover,
            &request.actor,
            Some(request.pending.target.principal_fingerprint),
            event_kind_for_transition(IdentityLifecycleTransition::Recover),
            IdentityLifecycleDenial::StaleExpectedState,
        )
        .await;
    }
    validate_replacement_freshness_tx(&mut locked, &request.replacement).await?;
    if !replacement_key_available_tx(&mut locked, request.replacement.event_author_pubkey).await? {
        return commit_denial_tx(
            &mut locked,
            &request.operation,
            IdentityLifecycleTransition::Recover,
            &request.actor,
            Some(request.pending.target.principal_fingerprint),
            event_kind_for_transition(IdentityLifecycleTransition::Recover),
            IdentityLifecycleDenial::EventAuthorUnavailable,
        )
        .await;
    }
    let target = target.expect("matched target");
    let Some(policy) = load_current_policy_expiry_tx(
        &mut locked,
        target.policy_revision,
        target.binding_provenance,
    )
    .await?
    else {
        return commit_denial_tx(
            &mut locked,
            &request.operation,
            IdentityLifecycleTransition::Recover,
            &request.actor,
            Some(request.pending.target.principal_fingerprint),
            event_kind_for_transition(IdentityLifecycleTransition::Recover),
            IdentityLifecycleDenial::PolicyUnavailable,
        )
        .await;
    };
    apply_successor_transition_tx(
        &mut locked,
        &request.operation,
        IdentityLifecycleTransition::Recover,
        &request.actor,
        target,
        &request.replacement,
        policy.expires_at,
        Some(pending.expect("matched pending selector")),
        None,
    )
    .await
}

async fn execute_enable_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &EnableIdentityPrincipalRequest,
    operator_eligibility: Option<&OperatorFirstExecutionEligibility>,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    lock_operation_tx(transaction, &request.operation).await?;
    if let Some(replay) =
        replay_observation_tx(transaction, LifecycleReplayRequest::Enable(request)).await?
    {
        return Ok(replay);
    }
    validate_operator_first_execution_eligibility_tx(transaction, operator_eligibility).await?;
    let mut locked = prelock_identity_lifecycle_tx(
        transaction,
        &request.operation,
        IdentityLifecycleLockPlan::Enable {
            principal: request.principal_fingerprint,
            old_key: Some(request.pending.target.event_author_pubkey),
            new_key: request.replacement.event_author_pubkey,
        },
    )
    .await?;
    validate_replacement_freshness_tx(&mut locked, &request.replacement).await?;
    if let Some(resolution) = &request.principal_resolution {
        validate_principal_resolution_freshness_tx(&mut locked, resolution).await?;
    }
    let disabled =
        load_open_lifecycle_selector_tx(&mut locked, 2, request.principal_fingerprint).await?;
    let pending =
        load_open_lifecycle_selector_tx(&mut locked, 4, request.principal_fingerprint).await?;
    let active =
        load_active_binding_by_principal_tx(&mut locked, request.principal_fingerprint).await?;
    let disabled_matches = disabled.as_ref().is_some_and(|selector| {
        selector.fact_generation == i64::try_from(request.disabled_fact_generation).unwrap_or(-1)
    });
    let pending_matches = pending_selector_matches(pending.as_ref(), &request.pending);
    let old_binding = load_exact_binding_tx(&mut locked, request.pending.target.binding_id).await?;
    let old_matches = retired_target_matches(old_binding.as_ref(), &request.pending.target);
    if active.is_some() || !disabled_matches || !pending_matches || !old_matches {
        return commit_denial_tx(
            &mut locked,
            &request.operation,
            IdentityLifecycleTransition::Enable,
            &request.actor,
            Some(request.principal_fingerprint),
            event_kind_for_transition(IdentityLifecycleTransition::Enable),
            IdentityLifecycleDenial::StaleExpectedState,
        )
        .await;
    }
    if !replacement_key_available_tx(&mut locked, request.replacement.event_author_pubkey).await? {
        return commit_denial_tx(
            &mut locked,
            &request.operation,
            IdentityLifecycleTransition::Enable,
            &request.actor,
            Some(request.principal_fingerprint),
            event_kind_for_transition(IdentityLifecycleTransition::Enable),
            IdentityLifecycleDenial::LifecycleSelectorConflict,
        )
        .await;
    }
    let resolution = match resolve_enable_principal_tx(
        &mut locked,
        request,
        old_binding.as_ref().expect("matched exact retired binding"),
    )
    .await?
    {
        EnablePrincipalResolution::Resolved(resolution) => resolution,
        EnablePrincipalResolution::MissingCanonicalIdentity => {
            return commit_denial_tx(
                &mut locked,
                &request.operation,
                IdentityLifecycleTransition::Enable,
                &request.actor,
                Some(request.principal_fingerprint),
                event_kind_for_transition(IdentityLifecycleTransition::Enable),
                IdentityLifecycleDenial::LifecycleSelectorConflict,
            )
            .await;
        }
        EnablePrincipalResolution::PolicyUnavailable => {
            return commit_denial_tx(
                &mut locked,
                &request.operation,
                IdentityLifecycleTransition::Enable,
                &request.actor,
                Some(request.principal_fingerprint),
                event_kind_for_transition(IdentityLifecycleTransition::Enable),
                IdentityLifecycleDenial::PolicyUnavailable,
            )
            .await;
        }
    };
    apply_enable_transition_tx(
        &mut locked,
        request,
        &resolution,
        old_binding.expect("matched exact retired binding"),
        disabled.expect("matched disabled selector"),
        pending.expect("matched pending selector"),
    )
    .await
}

async fn prelock_identity_lifecycle_tx<'borrow, 'connection>(
    transaction: &'borrow mut Transaction<'connection, Postgres>,
    operation: &IdentityLifecycleOperation,
    plan: IdentityLifecycleLockPlan,
) -> Result<PrelockedIdentityLifecycleTx<'borrow, 'connection>, IdentityLifecycleFailure> {
    let (principal, old_key, new_key) = match plan {
        IdentityLifecycleLockPlan::Enroll { principal, new_key } => {
            (Some(principal), None, Some(new_key))
        }
        IdentityLifecycleLockPlan::AdmissionLoss { principal, old_key } => {
            (Some(principal), Some(old_key), None)
        }
        IdentityLifecycleLockPlan::Retire { principal, old_key } => {
            (Some(principal), Some(old_key), None)
        }
        IdentityLifecycleLockPlan::Disable { principal, old_key } => {
            (Some(principal), old_key, None)
        }
        IdentityLifecycleLockPlan::Revoke { principal, old_key } => {
            (principal, Some(old_key), None)
        }
        IdentityLifecycleLockPlan::Rotate {
            principal,
            old_key,
            new_key,
        }
        | IdentityLifecycleLockPlan::Recover {
            principal,
            old_key,
            new_key,
        } => (Some(principal), Some(old_key), Some(new_key)),
        IdentityLifecycleLockPlan::Enable {
            principal,
            old_key,
            new_key,
        } => (Some(principal), old_key, Some(new_key)),
    };
    let keys: Vec<i64> = sqlx::query_scalar(
        "WITH coordinates(scope,fingerprint) AS (VALUES \
           ('principal'::text,$2::bytea),('key'::text,$3::bytea),('key'::text,$4::bytea)) \
         SELECT DISTINCT hashtextextended( \
           'buzz:identity-lifecycle-coordinate:v1:' || scope || ':' || \
           $1::uuid::text || ':' || encode(fingerprint,'hex'),0) AS lock_key \
         FROM coordinates WHERE fingerprint IS NOT NULL ORDER BY lock_key",
    )
    .bind(operation.community_id.as_uuid())
    .bind(principal.map(|value| value.to_vec()))
    .bind(old_key.map(|value| value.to_vec()))
    .bind(new_key.map(|value| value.to_vec()))
    .fetch_all(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    for key in keys {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(key)
            .execute(&mut **transaction)
            .await
            .map_err(DbError::from)?;
    }
    Ok(PrelockedIdentityLifecycleTx {
        transaction,
        community_id: operation.community_id,
        database_owned_version_deltas: Vec::new(),
    })
}

async fn lock_operation_tx(
    transaction: &mut Transaction<'_, Postgres>,
    operation: &IdentityLifecycleOperation,
) -> Result<(), IdentityLifecycleFailure> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended( \
         'buzz:authorization-operation:v1:' || $1::uuid::text || ':' || $2::uuid::text,0))",
    )
    .bind(operation.community_id.as_uuid())
    .bind(operation.operation_id)
    .execute(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

async fn enrollment_decision_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    request: &AuthoritativeEnrollmentRequest,
) -> Result<EnrollmentDecision, IdentityLifecycleFailure> {
    let expected_mode = request.provenance as i16;
    let policy_ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM identity_enrollment_policies \
         WHERE community_id=$1 AND policy_revision=$2 AND enrollment_mode=$3 \
           AND policy_digest=$4 AND effective_at<=clock_timestamp() \
           AND (expires_at IS NULL OR expires_at>clock_timestamp()) \
           AND policy_revision=(SELECT MAX(current.policy_revision) \
             FROM identity_enrollment_policies current \
             WHERE current.community_id=$1 \
               AND current.effective_at<=clock_timestamp() \
               AND (current.expires_at IS NULL OR current.expires_at>clock_timestamp())) \
           AND $5>clock_timestamp())",
    )
    .bind(locked.community_id.as_uuid())
    .bind(i64_from_u64(request.policy_revision)?)
    .bind(expected_mode)
    .bind(request.policy_digest.as_slice())
    .bind(request.evidence_expires_at)
    .fetch_one(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    if !policy_ok {
        return Ok(EnrollmentDecision::Deny(
            IdentityLifecycleDenial::PolicyUnavailable,
        ));
    }

    let active: Vec<ActiveBinding> = sqlx::query_as(
        "SELECT binding_id,binding_version,issuer,subject,principal_fingerprint, \
                event_author_pubkey,binding_state,lifecycle_revision,binding_provenance, \
                policy_revision,expires_at \
         FROM identity_bindings \
         WHERE community_id=$1 AND binding_state=1 \
           AND ((issuer=$2 AND subject=$3) OR event_author_pubkey=$4) \
         ORDER BY binding_version FOR UPDATE",
    )
    .bind(locked.community_id.as_uuid())
    .bind(&request.issuer)
    .bind(&request.subject)
    .bind(request.event_author_pubkey.as_slice())
    .fetch_all(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    for binding in active {
        let same_principal = binding.issuer == request.issuer && binding.subject == request.subject;
        let same_key = binding.event_author_pubkey == request.event_author_pubkey;
        if same_principal && same_key {
            if binding.principal_fingerprint != request.principal_fingerprint {
                return Ok(EnrollmentDecision::Deny(
                    IdentityLifecycleDenial::PrincipalAlreadyBound,
                ));
            }
            let still_fresh: bool = sqlx::query_scalar(
                "SELECT $1::timestamptz IS NULL OR $1::timestamptz>clock_timestamp()",
            )
            .bind(binding.expires_at)
            .fetch_one(&mut **locked.transaction)
            .await
            .map_err(DbError::from)?;
            if !still_fresh {
                return Ok(EnrollmentDecision::Deny(
                    IdentityLifecycleDenial::BindingExpired,
                ));
            }
            return Ok(EnrollmentDecision::NoOp(binding_evidence(&binding)?));
        }
        if same_principal {
            return Ok(EnrollmentDecision::Deny(
                IdentityLifecycleDenial::PrincipalAlreadyBound,
            ));
        }
        if same_key {
            return Ok(EnrollmentDecision::Deny(
                IdentityLifecycleDenial::EventAuthorUnavailable,
            ));
        }
    }

    let conflict: Option<i16> = sqlx::query_scalar(
        "SELECT selector.selector_kind \
         FROM identity_lifecycle_selectors selector \
         LEFT JOIN identity_lifecycle_selector_consumptions consumption \
           ON consumption.community_id=selector.community_id \
          AND consumption.selector_id=selector.selector_id \
         WHERE selector.community_id=$1 AND ( \
           (selector.selector_kind=1 AND selector.principal_fingerprint=$2 \
             AND selector.event_author_pubkey=$3) \
           OR (selector.selector_kind=3 AND selector.event_author_pubkey=$3) \
           OR (selector.selector_kind IN (2,4) \
             AND selector.principal_fingerprint=$2 AND consumption.selector_id IS NULL)) \
         ORDER BY selector.selector_kind LIMIT 1 FOR UPDATE OF selector",
    )
    .bind(locked.community_id.as_uuid())
    .bind(request.principal_fingerprint.as_slice())
    .bind(request.event_author_pubkey.as_slice())
    .fetch_optional(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    match conflict {
        Some(3) => Ok(EnrollmentDecision::Deny(
            IdentityLifecycleDenial::EventAuthorUnavailable,
        )),
        Some(_) => Ok(EnrollmentDecision::Deny(
            IdentityLifecycleDenial::LifecycleSelectorConflict,
        )),
        None => Ok(EnrollmentDecision::Apply),
    }
}

async fn apply_enrollment_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    request: &AuthoritativeEnrollmentRequest,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    let binding_id = Uuid::new_v4();
    let history_id = Uuid::new_v4();
    let result_digest = lifecycle_digest(
        b"buzz:identity-lifecycle-result:v1",
        &[
            request.operation.community_id.as_uuid().as_bytes(),
            request.operation.operation_id.as_bytes(),
            &[request.transition as u8],
            binding_id.as_bytes(),
            &request.principal_fingerprint,
            &request.event_author_pubkey,
        ],
    );
    insert_receipt_tx(
        locked,
        &request.operation,
        request.transition,
        &request.actor,
        APPLIED_OUTCOME,
        result_digest,
    )
    .await?;
    let binding_version: i64 = sqlx::query_scalar(
        "INSERT INTO identity_bindings \
         (community_id,binding_id,issuer,subject,principal_fingerprint,event_author_pubkey, \
          binding_state,lifecycle_revision,binding_provenance,policy_revision, \
          enrollment_evidence_digest,expires_at,birth_history_id,creation_operation_id, \
          creation_request_fingerprint) \
         VALUES ($1,$2,$3,$4,$5,$6,1,1,$7,$8,$9,$10,$11,$12,$13) \
         RETURNING binding_version",
    )
    .bind(locked.community_id.as_uuid())
    .bind(binding_id)
    .bind(&request.issuer)
    .bind(&request.subject)
    .bind(request.principal_fingerprint.as_slice())
    .bind(request.event_author_pubkey.as_slice())
    .bind(request.provenance as i16)
    .bind(i64_from_u64(request.policy_revision)?)
    .bind(request.enrollment_evidence_digest.as_slice())
    .bind(request.expires_at)
    .bind(history_id)
    .bind(request.operation.operation_id)
    .bind(request.operation.request_fingerprint.as_slice())
    .fetch_one(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    let transition_digest = transition_digest(
        &request.operation,
        request.transition,
        None,
        Some((binding_id, binding_version)),
    );
    insert_history_tx(
        locked,
        history_id,
        &request.operation,
        request.transition,
        APPLIED_OUTCOME,
        None,
        Some((binding_id, binding_version)),
        transition_digest,
    )
    .await?;
    append_lifecycle_audit_tx(
        locked,
        &request.operation,
        &request.actor,
        event_kind_for_transition(request.transition),
        AuthorizationEventOutcome::Allowed,
        1,
        Some(request.principal_fingerprint),
        false,
    )
    .await?;
    Ok(IdentityLifecycleObservation::Applied {
        transition: request.transition,
        binding: Some(IdentityBindingEvidence {
            binding_id,
            binding_version: u64_from_i64(binding_version)?,
            lifecycle_revision: 1,
        }),
    })
}

async fn commit_no_op_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    request: &AuthoritativeEnrollmentRequest,
    binding: IdentityBindingEvidence,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    let history_id = Uuid::new_v4();
    let result_digest = lifecycle_digest(
        b"buzz:identity-lifecycle-result:v1",
        &[
            request.operation.community_id.as_uuid().as_bytes(),
            request.operation.operation_id.as_bytes(),
            &[request.transition as u8],
            b"no-op",
            binding.binding_id.as_bytes(),
            &binding.binding_version.to_be_bytes(),
        ],
    );
    insert_receipt_tx(
        locked,
        &request.operation,
        request.transition,
        &request.actor,
        NO_OP_OUTCOME,
        result_digest,
    )
    .await?;
    let transition_digest = transition_digest(&request.operation, request.transition, None, None);
    insert_history_tx(
        locked,
        history_id,
        &request.operation,
        request.transition,
        NO_OP_OUTCOME,
        None,
        None,
        transition_digest,
    )
    .await?;
    append_lifecycle_audit_tx(
        locked,
        &request.operation,
        &request.actor,
        event_kind_for_transition(request.transition),
        AuthorizationEventOutcome::NoOp,
        2,
        Some(request.principal_fingerprint),
        false,
    )
    .await?;
    Ok(IdentityLifecycleObservation::NoOp {
        transition: request.transition,
        binding: Some(binding),
    })
}

async fn apply_admission_loss_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    request: &ExactAdmissionLossRequest,
    target: ActiveBinding,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    let (cause, selector) = admission_loss_invalidation_coordinates(request)?;
    let resolved_actor = resolve_local_admission_loss_actor_tx(
        locked.transaction,
        request.operation.community_id,
        cause,
    )
    .await
    .map_err(IdentityLifecycleFailure::Storage)?;
    if request.actor.canonical(request.operation.community_id)? != &resolved_actor {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    let authority_advance = advance_admission_loss_authority_tx(
        locked.transaction,
        request.operation.community_id,
        request.operation.operation_id,
        request.operation.request_fingerprint,
        &resolved_actor,
    )
    .await
    .map_err(IdentityLifecycleFailure::Storage)?;
    let invalidation_advance = apply_admission_loss_invalidation_tx(
        locked.transaction,
        request.operation.community_id,
        request.operation.operation_id,
        request.operation.request_fingerprint,
        &[selector],
        authority_advance,
    )
    .await
    .map_err(IdentityLifecycleFailure::Storage)?;
    locked
        .database_owned_version_deltas
        .extend(invalidation_advance.into_deltas());
    let history_id = Uuid::new_v4();
    let transition_digest = transition_digest(
        &request.operation,
        IdentityLifecycleTransition::AdmissionLoss,
        Some((target.binding_id, target.binding_version)),
        None,
    );
    insert_history_tx(
        locked,
        history_id,
        &request.operation,
        IdentityLifecycleTransition::AdmissionLoss,
        APPLIED_OUTCOME,
        Some((target.binding_id, target.binding_version)),
        None,
        transition_digest,
    )
    .await?;
    let updated = sqlx::query(
        "UPDATE identity_bindings SET binding_state=2,lifecycle_revision=2, \
         retirement_history_id=$4 WHERE community_id=$1 AND binding_id=$2 \
         AND binding_version=$3 AND binding_state=1 AND lifecycle_revision=1",
    )
    .bind(locked.community_id.as_uuid())
    .bind(target.binding_id)
    .bind(target.binding_version)
    .bind(history_id)
    .execute(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    if updated.rows_affected() != 1 {
        return Err(IdentityLifecycleFailure::Storage(DbError::InvalidData(
            "binding changed after lifecycle prelock".to_owned(),
        )));
    }
    insert_retired_pair_selector_tx(locked, history_id, &request.operation, &target).await?;
    insert_pending_replacement_selector_tx(locked, history_id, &request.operation, &target).await?;
    let manifest = record_lifecycle_version_manifest_tx(locked, &request.operation).await?;
    validate_admission_loss_version_manifest_tx(locked.transaction, request, &manifest).await?;
    let result_digest = admission_loss_result_digest(request, manifest.manifest_digest());
    insert_receipt_tx(
        locked,
        &request.operation,
        IdentityLifecycleTransition::AdmissionLoss,
        &request.actor,
        APPLIED_OUTCOME,
        result_digest,
    )
    .await?;
    append_lifecycle_audit_tx(
        locked,
        &request.operation,
        &request.actor,
        event_kind_for_transition(IdentityLifecycleTransition::AdmissionLoss),
        AuthorizationEventOutcome::Allowed,
        1,
        Some(request.target.principal_fingerprint),
        true,
    )
    .await?;
    Ok(IdentityLifecycleObservation::Applied {
        transition: IdentityLifecycleTransition::AdmissionLoss,
        binding: None,
    })
}

fn admission_loss_invalidation_coordinates(
    request: &ExactAdmissionLossRequest,
) -> Result<(LocalAdmissionLossCause, AuthorizationInvalidationSelector), IdentityLifecycleFailure>
{
    Ok(match request.cause {
        TrustedAdmissionLossCause::LocalBinding => (
            LocalAdmissionLossCause::Binding {
                binding_id: request.target.binding_id,
                binding_version: request.target.binding_version,
            },
            AuthorizationInvalidationSelector::binding(
                request.target.binding_id,
                request.target.binding_version,
            )
            .map_err(IdentityLifecycleFailure::Storage)?,
        ),
        TrustedAdmissionLossCause::LocalPolicy { revision } => (
            LocalAdmissionLossCause::Policy {
                policy_revision: revision,
            },
            AuthorizationInvalidationSelector::configuration_revision(revision)
                .map_err(IdentityLifecycleFailure::Storage)?,
        ),
        TrustedAdmissionLossCause::DelegationAuthority {
            relationship_id,
            revision,
        } => (
            LocalAdmissionLossCause::DelegatedRelationship {
                relationship_id,
                relationship_revision: revision,
            },
            AuthorizationInvalidationSelector::delegated_relationship(relationship_id, revision)
                .map_err(IdentityLifecycleFailure::Storage)?,
        ),
    })
}

#[derive(Clone, Copy)]
enum RetirementCompanions {
    Retire,
    Disable,
    Revoke,
}

struct SuccessorBindingMaterial<'material> {
    issuer: &'material str,
    subject: &'material str,
    principal_fingerprint: [u8; 32],
    provenance: i16,
    policy_revision: i64,
    enrollment_evidence_digest: [u8; 32],
    expires_at: Option<DateTime<Utc>>,
}

#[allow(clippy::too_many_arguments)]
async fn apply_successor_transition_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    operation: &IdentityLifecycleOperation,
    transition: IdentityLifecycleTransition,
    actor: &AuthenticatedLifecycleActor,
    old_binding: ActiveBinding,
    replacement: &VerifiedReplacementProof,
    policy_expires_at: Option<DateTime<Utc>>,
    pending: Option<OpenLifecycleSelector>,
    disabled: Option<OpenLifecycleSelector>,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    debug_assert!(matches!(
        transition,
        IdentityLifecycleTransition::Rotate | IdentityLifecycleTransition::Recover
    ));
    let history_id = Uuid::new_v4();
    let successor_expires_at = validate_successor_expiry_tx(
        locked,
        replacement.authorization_expires_at,
        policy_expires_at,
    )
    .await?;
    let old_pair = (old_binding.binding_id, old_binding.binding_version);
    if transition == IdentityLifecycleTransition::Rotate {
        if let Some(authority) = seal_retiring_binding_authority_tx(
            locked,
            operation,
            transition,
            actor,
            &old_binding,
            Some(replacement),
        )
        .await?
        {
            let advance = crate::authorization_invalidation::apply_retiring_binding_authority_tx(
                locked.transaction,
                authority,
            )
            .await
            .map_err(IdentityLifecycleFailure::Storage)?;
            locked
                .database_owned_version_deltas
                .extend(advance.into_deltas());
        }
        // Retire the old generation before inserting its successor so the
        // partial unique active-principal index cannot observe two active
        // generations. The deferred history FK keeps this atomic.
        retire_binding_tx(locked, &old_binding, history_id).await?;
    }
    let material = SuccessorBindingMaterial {
        issuer: &old_binding.issuer,
        subject: &old_binding.subject,
        principal_fingerprint: exact_32(&old_binding.principal_fingerprint)?,
        provenance: old_binding.binding_provenance,
        policy_revision: old_binding.policy_revision,
        enrollment_evidence_digest: replacement.proof_digest,
        expires_at: Some(successor_expires_at),
    };
    let successor = insert_successor_binding_tx(
        locked,
        history_id,
        operation,
        replacement.event_author_pubkey,
        &material,
    )
    .await?;
    let base_result_digest = successor_result_digest(
        operation,
        transition,
        Some(old_pair),
        successor,
        replacement.proof_fingerprint(),
        None,
        successor_expires_at,
    );
    insert_history_tx(
        locked,
        history_id,
        operation,
        transition,
        APPLIED_OUTCOME,
        Some(old_pair),
        Some(successor),
        transition_digest(operation, transition, Some(old_pair), Some(successor)),
    )
    .await?;
    match transition {
        IdentityLifecycleTransition::Rotate => {
            insert_retired_pair_selector_tx(locked, history_id, operation, &old_binding).await?;
        }
        IdentityLifecycleTransition::Recover => {
            consume_lifecycle_selector_tx(
                locked,
                pending.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?,
                history_id,
                operation,
                successor,
            )
            .await?;
        }
        _ => return Err(IdentityLifecycleFailure::InvalidRequest),
    }
    if let Some(disabled) = disabled {
        consume_lifecycle_selector_tx(locked, disabled, history_id, operation, successor).await?;
    }
    let manifest_digest =
        if transition == IdentityLifecycleTransition::Rotate && actor.operator_grant.is_some() {
            Some(
                record_lifecycle_version_manifest_tx(locked, operation)
                    .await?
                    .manifest_digest(),
            )
        } else {
            None
        };
    let result_digest = manifest_digest
        .map(|digest| operator_manifest_result_digest(base_result_digest, digest))
        .unwrap_or(base_result_digest);
    insert_receipt_tx(
        locked,
        operation,
        transition,
        actor,
        APPLIED_OUTCOME,
        result_digest,
    )
    .await?;
    append_lifecycle_audit_tx(
        locked,
        operation,
        actor,
        event_kind_for_transition(transition),
        AuthorizationEventOutcome::Allowed,
        1,
        Some(material.principal_fingerprint),
        manifest_digest.is_some(),
    )
    .await?;
    Ok(IdentityLifecycleObservation::Applied {
        transition,
        binding: Some(IdentityBindingEvidence {
            binding_id: successor.0,
            binding_version: u64_from_i64(successor.1)?,
            lifecycle_revision: 1,
        }),
    })
}

async fn apply_enable_transition_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    request: &EnableIdentityPrincipalRequest,
    resolution: &ResolvedEnablePrincipal,
    old_binding: ActiveBinding,
    disabled: OpenLifecycleSelector,
    pending: OpenLifecycleSelector,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    let history_id = Uuid::new_v4();
    let successor_expires_at = validate_successor_expiry_tx(
        locked,
        request.replacement.authorization_expires_at,
        resolution.policy_expires_at,
    )
    .await?;
    let old_pair = Some((old_binding.binding_id, old_binding.binding_version));
    let material = SuccessorBindingMaterial {
        issuer: &resolution.issuer,
        subject: &resolution.subject,
        principal_fingerprint: request.principal_fingerprint,
        provenance: resolution.provenance,
        policy_revision: resolution.policy_revision,
        enrollment_evidence_digest: request.replacement.proof_digest,
        expires_at: Some(successor_expires_at),
    };
    let successor = insert_successor_binding_tx(
        locked,
        history_id,
        &request.operation,
        request.replacement.event_author_pubkey,
        &material,
    )
    .await?;
    let result_digest = successor_result_digest(
        &request.operation,
        IdentityLifecycleTransition::Enable,
        old_pair,
        successor,
        request.replacement.proof_fingerprint(),
        Some(enable_principal_proof_fingerprint(request)),
        successor_expires_at,
    );
    insert_receipt_tx(
        locked,
        &request.operation,
        IdentityLifecycleTransition::Enable,
        &request.actor,
        APPLIED_OUTCOME,
        result_digest,
    )
    .await?;
    insert_history_tx(
        locked,
        history_id,
        &request.operation,
        IdentityLifecycleTransition::Enable,
        APPLIED_OUTCOME,
        old_pair,
        Some(successor),
        transition_digest(
            &request.operation,
            IdentityLifecycleTransition::Enable,
            old_pair,
            Some(successor),
        ),
    )
    .await?;
    consume_lifecycle_selector_tx(locked, disabled, history_id, &request.operation, successor)
        .await?;
    consume_lifecycle_selector_tx(locked, pending, history_id, &request.operation, successor)
        .await?;
    append_lifecycle_audit_tx(
        locked,
        &request.operation,
        &request.actor,
        event_kind_for_transition(IdentityLifecycleTransition::Enable),
        AuthorizationEventOutcome::Allowed,
        1,
        Some(request.principal_fingerprint),
        false,
    )
    .await?;
    Ok(IdentityLifecycleObservation::Applied {
        transition: IdentityLifecycleTransition::Enable,
        binding: Some(IdentityBindingEvidence {
            binding_id: successor.0,
            binding_version: u64_from_i64(successor.1)?,
            lifecycle_revision: 1,
        }),
    })
}

async fn insert_successor_binding_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    history_id: Uuid,
    operation: &IdentityLifecycleOperation,
    replacement_key: [u8; 32],
    material: &SuccessorBindingMaterial<'_>,
) -> Result<(Uuid, i64), IdentityLifecycleFailure> {
    let binding_id = Uuid::new_v4();
    let binding_version: i64 = sqlx::query_scalar(
        "INSERT INTO identity_bindings \
         (community_id,binding_id,issuer,subject,principal_fingerprint,event_author_pubkey, \
          binding_state,lifecycle_revision,binding_provenance,policy_revision, \
          enrollment_evidence_digest,expires_at,birth_history_id,creation_operation_id, \
          creation_request_fingerprint) \
         VALUES ($1,$2,$3,$4,$5,$6,1,1,$7,$8,$9,$10,$11,$12,$13) \
         RETURNING binding_version",
    )
    .bind(locked.community_id.as_uuid())
    .bind(binding_id)
    .bind(material.issuer)
    .bind(material.subject)
    .bind(material.principal_fingerprint.as_slice())
    .bind(replacement_key.as_slice())
    .bind(material.provenance)
    .bind(material.policy_revision)
    .bind(material.enrollment_evidence_digest.as_slice())
    .bind(material.expires_at)
    .bind(history_id)
    .bind(operation.operation_id)
    .bind(operation.request_fingerprint.as_slice())
    .fetch_one(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    Ok((binding_id, binding_version))
}

async fn consume_lifecycle_selector_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    selector: OpenLifecycleSelector,
    history_id: Uuid,
    operation: &IdentityLifecycleOperation,
    successor: (Uuid, i64),
) -> Result<(), IdentityLifecycleFailure> {
    if !matches!(selector.selector_kind, 2 | 4) {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    sqlx::query(
        "INSERT INTO identity_lifecycle_selector_consumptions \
         (community_id,selector_id,selector_kind,history_id,operation_id,request_fingerprint, \
          successor_binding_id,successor_binding_version) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(locked.community_id.as_uuid())
    .bind(selector.selector_id)
    .bind(selector.selector_kind)
    .bind(history_id)
    .bind(operation.operation_id)
    .bind(operation.request_fingerprint.as_slice())
    .bind(successor.0)
    .bind(successor.1)
    .execute(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

fn successor_result_digest(
    operation: &IdentityLifecycleOperation,
    transition: IdentityLifecycleTransition,
    old: Option<(Uuid, i64)>,
    successor: (Uuid, i64),
    replacement_proof_fingerprint: [u8; 32],
    principal_proof_fingerprint: Option<[u8; 32]>,
    successor_expires_at: DateTime<Utc>,
) -> [u8; 32] {
    let old_id = old.map(|value| *value.0.as_bytes()).unwrap_or([0; 16]);
    let old_version = old.map(|value| value.1).unwrap_or(0).to_be_bytes();
    lifecycle_digest(
        b"buzz:identity-lifecycle-successor-result:v1",
        &[
            operation.community_id.as_uuid().as_bytes(),
            operation.operation_id.as_bytes(),
            &[transition as u8],
            &old_id,
            &old_version,
            successor.0.as_bytes(),
            &successor.1.to_be_bytes(),
            &replacement_proof_fingerprint,
            &principal_proof_fingerprint.unwrap_or([0; 32]),
            &successor_expires_at.timestamp_micros().to_be_bytes(),
        ],
    )
}

fn operator_manifest_result_digest(
    lifecycle_result_digest: [u8; 32],
    manifest_digest: [u8; 32],
) -> [u8; 32] {
    lifecycle_digest(
        b"buzz:identity-lifecycle-operator-manifest-result:v1",
        &[&lifecycle_result_digest, &manifest_digest],
    )
}

async fn seal_retiring_binding_authority_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    operation: &IdentityLifecycleOperation,
    transition: IdentityLifecycleTransition,
    actor: &AuthenticatedLifecycleActor,
    target: &ActiveBinding,
    replacement: Option<&VerifiedReplacementProof>,
) -> Result<Option<RetiringBindingAuthority>, IdentityLifecycleFailure> {
    let Some(grant) = actor.operator_grant.as_ref() else {
        return Ok(None);
    };
    let intent = actor
        .operator_intent
        .as_ref()
        .ok_or(IdentityLifecycleFailure::InvalidRequest)?;
    let expected_action = match transition {
        IdentityLifecycleTransition::Retire => OperatorLifecycleAction::Retire,
        IdentityLifecycleTransition::Disable => OperatorLifecycleAction::Disable,
        IdentityLifecycleTransition::Revoke => OperatorLifecycleAction::Revoke,
        IdentityLifecycleTransition::Rotate => OperatorLifecycleAction::Rotate,
        _ => return Err(IdentityLifecycleFailure::InvalidRequest),
    };
    let canonical = AuthorizationEventActor::from_verified_operator_grant(grant)
        .map_err(IdentityLifecycleFailure::Storage)?;
    let replacement_coordinates =
        replacement.map(|replacement| (replacement.event_author_pubkey, replacement.expires_at));
    let grant_replacement_coordinates = grant
        .replacement_event_author_pubkey()
        .zip(grant.replacement_expires_at());
    let locked_intent_matches = intent.matches_locked_retiring_binding(
        expected_action,
        target.binding_id,
        u64_from_i64(target.binding_version)?,
        exact_32(&target.principal_fingerprint)?,
        exact_32(&target.event_author_pubkey)?,
        u64_from_i64(target.lifecycle_revision)?,
        replacement_coordinates,
    );
    if grant.authorization_domain() != operation.community_id
        || grant.operation_id() != operation.operation_id
        || grant.action() != expected_action
        || grant.expected_revision() != u64_from_i64(target.lifecycle_revision)?
        || grant.intent_digest() != intent.intent_digest()
        || !locked_intent_matches
        || grant_replacement_coordinates != replacement_coordinates
        || grant.request_attribution() != actor.request_attribution
        || actor.canonical(operation.community_id)? != &canonical
        || target.binding_state != 1
        || target.lifecycle_revision != 1
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    let fresh: bool =
        sqlx::query_scalar("SELECT clock_timestamp() >= $1 AND clock_timestamp() < $2")
            .bind(grant.issued_at())
            .bind(grant.expires_at())
            .fetch_one(&mut **locked.transaction)
            .await
            .map_err(DbError::from)?;
    if !fresh {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(Some(RetiringBindingAuthority {
        community_id: operation.community_id,
        operation_id: operation.operation_id,
        request_fingerprint: operation.request_fingerprint,
        binding_id: target.binding_id,
        binding_version: u64_from_i64(target.binding_version)?,
    }))
}

async fn apply_active_retirement_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    operation: &IdentityLifecycleOperation,
    transition: IdentityLifecycleTransition,
    actor: &AuthenticatedLifecycleActor,
    target: ActiveBinding,
    companions: RetirementCompanions,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    if let Some(authority) =
        seal_retiring_binding_authority_tx(locked, operation, transition, actor, &target, None)
            .await?
    {
        let advance = crate::authorization_invalidation::apply_retiring_binding_authority_tx(
            locked.transaction,
            authority,
        )
        .await
        .map_err(IdentityLifecycleFailure::Storage)?;
        locked
            .database_owned_version_deltas
            .extend(advance.into_deltas());
    }
    let history_id = Uuid::new_v4();
    let base_result_digest = lifecycle_digest(
        b"buzz:identity-lifecycle-result:v1",
        &[
            operation.community_id.as_uuid().as_bytes(),
            operation.operation_id.as_bytes(),
            &[transition as u8],
            target.binding_id.as_bytes(),
            &target.binding_version.to_be_bytes(),
        ],
    );
    let digest = transition_digest(
        operation,
        transition,
        Some((target.binding_id, target.binding_version)),
        None,
    );
    insert_history_tx(
        locked,
        history_id,
        operation,
        transition,
        APPLIED_OUTCOME,
        Some((target.binding_id, target.binding_version)),
        None,
        digest,
    )
    .await?;
    retire_binding_tx(locked, &target, history_id).await?;
    insert_retired_pair_selector_tx(locked, history_id, operation, &target).await?;
    match companions {
        RetirementCompanions::Retire => {}
        RetirementCompanions::Disable => {
            insert_disabled_identity_selector_tx(locked, history_id, operation, &target).await?;
        }
        RetirementCompanions::Revoke => {
            insert_revoked_key_selector_tx(
                locked,
                history_id,
                operation,
                exact_32(&target.event_author_pubkey)?,
            )
            .await?;
        }
    }
    insert_pending_replacement_selector_tx(locked, history_id, operation, &target).await?;
    let manifest_digest = if actor.operator_grant.is_some() {
        Some(
            record_lifecycle_version_manifest_tx(locked, operation)
                .await?
                .manifest_digest(),
        )
    } else {
        None
    };
    let result_digest = manifest_digest
        .map(|digest| operator_manifest_result_digest(base_result_digest, digest))
        .unwrap_or(base_result_digest);
    insert_receipt_tx(
        locked,
        operation,
        transition,
        actor,
        APPLIED_OUTCOME,
        result_digest,
    )
    .await?;
    append_lifecycle_audit_tx(
        locked,
        operation,
        actor,
        event_kind_for_transition(transition),
        AuthorizationEventOutcome::Allowed,
        1,
        Some(exact_32(&target.principal_fingerprint)?),
        manifest_digest.is_some(),
    )
    .await?;
    Ok(IdentityLifecycleObservation::Applied {
        transition,
        binding: None,
    })
}

async fn apply_inactive_disable_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    request: &DisableIdentityPrincipalRequest,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    if open_selector_exists_tx(locked, 2, request.principal_fingerprint).await? {
        return commit_semantic_no_op_tx(
            locked,
            &request.operation,
            IdentityLifecycleTransition::Disable,
            &request.actor,
            Some(request.principal_fingerprint),
        )
        .await;
    }
    let history_id = Uuid::new_v4();
    insert_applied_empty_transition_tx(
        locked,
        history_id,
        &request.operation,
        IdentityLifecycleTransition::Disable,
        &request.actor,
    )
    .await?;
    insert_disabled_identity_selector_without_binding_tx(
        locked,
        history_id,
        &request.operation,
        request.principal_fingerprint,
    )
    .await?;
    append_lifecycle_audit_tx(
        locked,
        &request.operation,
        &request.actor,
        event_kind_for_transition(IdentityLifecycleTransition::Disable),
        AuthorizationEventOutcome::Allowed,
        1,
        Some(request.principal_fingerprint),
        false,
    )
    .await?;
    Ok(IdentityLifecycleObservation::Applied {
        transition: IdentityLifecycleTransition::Disable,
        binding: None,
    })
}

async fn apply_inactive_revoke_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    request: &RevokeIdentityKeyRequest,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    let already_revoked: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM identity_lifecycle_selectors \
         WHERE community_id=$1 AND selector_kind=3 AND event_author_pubkey=$2)",
    )
    .bind(locked.community_id.as_uuid())
    .bind(request.event_author_pubkey.as_slice())
    .fetch_one(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    if already_revoked {
        return commit_semantic_no_op_tx(
            locked,
            &request.operation,
            IdentityLifecycleTransition::Revoke,
            &request.actor,
            None,
        )
        .await;
    }
    let history_id = Uuid::new_v4();
    insert_applied_empty_transition_tx(
        locked,
        history_id,
        &request.operation,
        IdentityLifecycleTransition::Revoke,
        &request.actor,
    )
    .await?;
    insert_revoked_key_selector_tx(
        locked,
        history_id,
        &request.operation,
        request.event_author_pubkey,
    )
    .await?;
    append_lifecycle_audit_tx(
        locked,
        &request.operation,
        &request.actor,
        event_kind_for_transition(IdentityLifecycleTransition::Revoke),
        AuthorizationEventOutcome::Allowed,
        1,
        None,
        false,
    )
    .await?;
    Ok(IdentityLifecycleObservation::Applied {
        transition: IdentityLifecycleTransition::Revoke,
        binding: None,
    })
}

async fn insert_applied_empty_transition_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    history_id: Uuid,
    operation: &IdentityLifecycleOperation,
    transition: IdentityLifecycleTransition,
    actor: &AuthenticatedLifecycleActor,
) -> Result<(), IdentityLifecycleFailure> {
    let result_digest = lifecycle_digest(
        b"buzz:identity-lifecycle-result:v1",
        &[
            operation.community_id.as_uuid().as_bytes(),
            operation.operation_id.as_bytes(),
            &[transition as u8],
            b"inactive-target",
        ],
    );
    insert_receipt_tx(
        locked,
        operation,
        transition,
        actor,
        APPLIED_OUTCOME,
        result_digest,
    )
    .await?;
    insert_history_tx(
        locked,
        history_id,
        operation,
        transition,
        APPLIED_OUTCOME,
        None,
        None,
        transition_digest(operation, transition, None, None),
    )
    .await
}

async fn commit_semantic_no_op_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    operation: &IdentityLifecycleOperation,
    transition: IdentityLifecycleTransition,
    actor: &AuthenticatedLifecycleActor,
    subject: Option<[u8; 32]>,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    let history_id = Uuid::new_v4();
    let result_digest = lifecycle_digest(
        b"buzz:identity-lifecycle-result:v1",
        &[
            operation.community_id.as_uuid().as_bytes(),
            operation.operation_id.as_bytes(),
            &[transition as u8],
            b"no-op",
        ],
    );
    insert_receipt_tx(
        locked,
        operation,
        transition,
        actor,
        NO_OP_OUTCOME,
        result_digest,
    )
    .await?;
    insert_history_tx(
        locked,
        history_id,
        operation,
        transition,
        NO_OP_OUTCOME,
        None,
        None,
        transition_digest(operation, transition, None, None),
    )
    .await?;
    append_lifecycle_audit_tx(
        locked,
        operation,
        actor,
        event_kind_for_transition(transition),
        AuthorizationEventOutcome::NoOp,
        2,
        subject,
        false,
    )
    .await?;
    Ok(IdentityLifecycleObservation::NoOp {
        transition,
        binding: None,
    })
}

async fn retire_binding_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    target: &ActiveBinding,
    history_id: Uuid,
) -> Result<(), IdentityLifecycleFailure> {
    let updated = sqlx::query(
        "UPDATE identity_bindings SET binding_state=2,lifecycle_revision=2, \
         retirement_history_id=$4 WHERE community_id=$1 AND binding_id=$2 \
         AND binding_version=$3 AND binding_state=1 AND lifecycle_revision=1",
    )
    .bind(locked.community_id.as_uuid())
    .bind(target.binding_id)
    .bind(target.binding_version)
    .bind(history_id)
    .execute(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    if updated.rows_affected() != 1 {
        return Err(IdentityLifecycleFailure::Storage(DbError::InvalidData(
            "binding changed after lifecycle prelock".to_owned(),
        )));
    }
    Ok(())
}

async fn insert_receipt_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    operation: &IdentityLifecycleOperation,
    transition: IdentityLifecycleTransition,
    actor: &AuthenticatedLifecycleActor,
    outcome: i16,
    result_digest: [u8; 32],
) -> Result<(), IdentityLifecycleFailure> {
    let outcome = match outcome {
        APPLIED_OUTCOME => AuthorizationOperationOutcome::Applied,
        DENIED_OUTCOME => AuthorizationOperationOutcome::Denied,
        NO_OP_OUTCOME => AuthorizationOperationOutcome::NoOp,
        _ => return Err(IdentityLifecycleFailure::CorruptStoredResult),
    };
    let receipt = AuthorizationOperationReceipt::new(
        operation.community_id,
        operation.operation_id,
        operation.request_fingerprint,
        operation_kind_for_transition(transition),
        actor.canonical(operation.community_id)?.clone(),
        outcome,
        result_digest,
    )
    .map_err(IdentityLifecycleFailure::Storage)?;
    match record_authorization_operation_receipt_tx(locked.transaction, &receipt).await? {
        AuthorizationReceiptWrite::Inserted => Ok(()),
        AuthorizationReceiptWrite::ExactReplay => {
            Err(IdentityLifecycleFailure::CorruptStoredResult)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_history_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    history_id: Uuid,
    operation: &IdentityLifecycleOperation,
    transition: IdentityLifecycleTransition,
    outcome: i16,
    old_binding: Option<(Uuid, i64)>,
    successor: Option<(Uuid, i64)>,
    transition_digest: [u8; 32],
) -> Result<(), IdentityLifecycleFailure> {
    let (old_id, old_version) = old_binding.unzip();
    let (successor_id, successor_version) = successor.unzip();
    sqlx::query(
        "INSERT INTO identity_lifecycle_history \
         (community_id,history_id,transition_kind,outcome_code, \
          old_binding_id,old_binding_version,old_prior_lifecycle_revision,old_prior_state, \
          old_resulting_lifecycle_revision,old_resulting_state,successor_binding_id, \
          successor_binding_version,successor_lifecycle_revision,successor_state, \
          operation_id,request_fingerprint,transition_digest) \
         VALUES ($1,$2,$3,$4,$5,$6, \
          CASE WHEN $5::uuid IS NULL THEN NULL \
               WHEN $3::smallint IN (7,8) THEN 2 ELSE 1 END, \
          CASE WHEN $5::uuid IS NULL THEN NULL \
               WHEN $3::smallint IN (7,8) THEN 2 ELSE 1 END, \
          CASE WHEN $5::uuid IS NULL THEN NULL ELSE 2 END, \
          CASE WHEN $5::uuid IS NULL THEN NULL ELSE 2 END, \
          $7,$8,CASE WHEN $7::uuid IS NULL THEN NULL ELSE 1 END, \
          CASE WHEN $7::uuid IS NULL THEN NULL ELSE 1 END,$9,$10,$11)",
    )
    .bind(operation.community_id.as_uuid())
    .bind(history_id)
    .bind(transition as i16)
    .bind(outcome)
    .bind(old_id)
    .bind(old_version)
    .bind(successor_id)
    .bind(successor_version)
    .bind(operation.operation_id)
    .bind(operation.request_fingerprint.as_slice())
    .bind(transition_digest.as_slice())
    .execute(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

async fn insert_retired_pair_selector_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    history_id: Uuid,
    operation: &IdentityLifecycleOperation,
    target: &ActiveBinding,
) -> Result<(), IdentityLifecycleFailure> {
    let principal = exact_32(&target.principal_fingerprint)?;
    let key = exact_32(&target.event_author_pubkey)?;
    let fingerprint = selector_fingerprint(
        b"retired-pair",
        locked.community_id,
        &[
            &principal,
            &key,
            target.binding_id.as_bytes(),
            &target.binding_version.to_be_bytes(),
        ],
    );
    insert_selector_tx(
        locked,
        Uuid::new_v4(),
        1,
        fingerprint,
        1,
        Some(principal),
        Some(key),
        Some((target.binding_id, target.binding_version)),
        history_id,
        operation,
    )
    .await
}

async fn insert_pending_replacement_selector_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    history_id: Uuid,
    operation: &IdentityLifecycleOperation,
    target: &ActiveBinding,
) -> Result<(), IdentityLifecycleFailure> {
    let principal = exact_32(&target.principal_fingerprint)?;
    let key = exact_32(&target.event_author_pubkey)?;
    let generation: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(fact_generation),0)+1 FROM identity_lifecycle_selectors \
         WHERE community_id=$1 AND selector_kind=4 AND principal_fingerprint=$2",
    )
    .bind(locked.community_id.as_uuid())
    .bind(principal.as_slice())
    .fetch_one(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    let fingerprint = selector_fingerprint(
        b"pending-replacement",
        locked.community_id,
        &[&principal, &key],
    );
    insert_selector_tx(
        locked,
        Uuid::new_v4(),
        4,
        fingerprint,
        generation,
        Some(principal),
        Some(key),
        Some((target.binding_id, target.binding_version)),
        history_id,
        operation,
    )
    .await
}

async fn insert_disabled_identity_selector_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    history_id: Uuid,
    operation: &IdentityLifecycleOperation,
    target: &ActiveBinding,
) -> Result<(), IdentityLifecycleFailure> {
    insert_disabled_identity_selector_without_binding_tx(
        locked,
        history_id,
        operation,
        exact_32(&target.principal_fingerprint)?,
    )
    .await
}

async fn insert_disabled_identity_selector_without_binding_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    history_id: Uuid,
    operation: &IdentityLifecycleOperation,
    principal: [u8; 32],
) -> Result<(), IdentityLifecycleFailure> {
    let generation: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(fact_generation),0)+1 FROM identity_lifecycle_selectors \
         WHERE community_id=$1 AND selector_kind=2 AND principal_fingerprint=$2",
    )
    .bind(locked.community_id.as_uuid())
    .bind(principal.as_slice())
    .fetch_one(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    let fingerprint =
        selector_fingerprint(b"disabled-identity", locked.community_id, &[&principal]);
    insert_selector_tx(
        locked,
        Uuid::new_v4(),
        2,
        fingerprint,
        generation,
        Some(principal),
        None,
        None,
        history_id,
        operation,
    )
    .await
}

async fn insert_revoked_key_selector_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    history_id: Uuid,
    operation: &IdentityLifecycleOperation,
    key: [u8; 32],
) -> Result<(), IdentityLifecycleFailure> {
    let fingerprint = selector_fingerprint(b"revoked-key", locked.community_id, &[&key]);
    insert_selector_tx(
        locked,
        Uuid::new_v4(),
        3,
        fingerprint,
        1,
        None,
        Some(key),
        None,
        history_id,
        operation,
    )
    .await
}

async fn open_selector_exists_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    selector_kind: i16,
    principal: [u8; 32],
) -> Result<bool, IdentityLifecycleFailure> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM identity_lifecycle_selectors selector \
         LEFT JOIN identity_lifecycle_selector_consumptions consumption \
           ON consumption.community_id=selector.community_id \
          AND consumption.selector_id=selector.selector_id \
         WHERE selector.community_id=$1 AND selector.selector_kind=$2 \
           AND selector.principal_fingerprint=$3 AND consumption.selector_id IS NULL)",
    )
    .bind(locked.community_id.as_uuid())
    .bind(selector_kind)
    .bind(principal.as_slice())
    .fetch_one(&mut **locked.transaction)
    .await
    .map_err(DbError::from)
    .map_err(IdentityLifecycleFailure::from)
}

#[allow(clippy::too_many_arguments)]
async fn insert_selector_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    selector_id: Uuid,
    kind: i16,
    fingerprint: [u8; 32],
    generation: i64,
    principal: Option<[u8; 32]>,
    key: Option<[u8; 32]>,
    binding: Option<(Uuid, i64)>,
    history_id: Uuid,
    operation: &IdentityLifecycleOperation,
) -> Result<(), IdentityLifecycleFailure> {
    let (binding_id, binding_version) = binding.unzip();
    sqlx::query(
        "INSERT INTO identity_lifecycle_selectors \
         (community_id,selector_id,selector_kind,selector_fingerprint,fact_generation, \
          principal_fingerprint,event_author_pubkey,binding_id,binding_version, \
          asserted_history_id,selected_by_operation_id,selected_by_request_fingerprint) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(locked.community_id.as_uuid())
    .bind(selector_id)
    .bind(kind)
    .bind(fingerprint.as_slice())
    .bind(generation)
    .bind(principal.map(|value| value.to_vec()))
    .bind(key.map(|value| value.to_vec()))
    .bind(binding_id)
    .bind(binding_version)
    .bind(history_id)
    .bind(operation.operation_id)
    .bind(operation.request_fingerprint.as_slice())
    .execute(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

async fn commit_denial_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    operation: &IdentityLifecycleOperation,
    transition: IdentityLifecycleTransition,
    actor: &AuthenticatedLifecycleActor,
    subject: Option<[u8; 32]>,
    event_kind: AuthorizationEventKind,
    reason: IdentityLifecycleDenial,
) -> Result<IdentityLifecycleObservation, IdentityLifecycleFailure> {
    let result_digest = lifecycle_digest(
        b"buzz:identity-lifecycle-denial:v1",
        &[
            operation.community_id.as_uuid().as_bytes(),
            operation.operation_id.as_bytes(),
            &[transition as u8],
            &(reason as i16).to_be_bytes(),
        ],
    );
    insert_receipt_tx(
        locked,
        operation,
        transition,
        actor,
        DENIED_OUTCOME,
        result_digest,
    )
    .await?;
    append_lifecycle_audit_tx(
        locked,
        operation,
        actor,
        event_kind,
        AuthorizationEventOutcome::Denied,
        reason as i16,
        subject,
        false,
    )
    .await?;
    Ok(IdentityLifecycleObservation::Denied { transition, reason })
}

#[allow(clippy::too_many_arguments)]
async fn append_lifecycle_audit_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    operation: &IdentityLifecycleOperation,
    actor: &AuthenticatedLifecycleActor,
    event_kind: AuthorizationEventKind,
    outcome: AuthorizationEventOutcome,
    reason_code: i16,
    subject_fingerprint: Option<[u8; 32]>,
    manifest_already_recorded: bool,
) -> Result<(), IdentityLifecycleFailure> {
    let event_kind = if outcome == AuthorizationEventOutcome::Denied {
        actor.denial_event_kind()
    } else {
        event_kind
    };
    let denial = if outcome == AuthorizationEventOutcome::Denied {
        Some(IdentityLifecycleDenial::from_reason_code(reason_code)?)
    } else {
        None
    };
    let reason = authorization_reason(outcome, event_kind, denial)?;
    let event = NewAuthorizationEvent::new(
        operation.community_id,
        operation.attempt_id,
        event_kind,
        outcome,
        reason,
        actor.canonical(operation.community_id)?.clone(),
        subject_fingerprint,
        operation.operation_id,
        Some(operation.request_fingerprint),
        operation.correlation_id,
        operation.attempt_id,
    )
    .map_err(IdentityLifecycleFailure::Storage)?;
    match record_authorization_event_tx(locked.transaction, &event).await? {
        AuthorizationReceiptWrite::Inserted if manifest_already_recorded => Ok(()),
        AuthorizationReceiptWrite::Inserted => {
            record_lifecycle_version_manifest_tx(locked, operation)
                .await
                .map(|_| ())
        }
        AuthorizationReceiptWrite::ExactReplay => {
            Err(IdentityLifecycleFailure::CorruptStoredResult)
        }
    }
}

async fn record_lifecycle_version_manifest_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    operation: &IdentityLifecycleOperation,
) -> Result<AuthorizationOperationVersionDeltaManifest, IdentityLifecycleFailure> {
    let mut components = std::mem::take(&mut locked.database_owned_version_deltas);
    let successors: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT successor_binding_id,successor_binding_version \
         FROM identity_lifecycle_history \
         WHERE community_id=$1 AND operation_id=$2 AND successor_binding_id IS NOT NULL",
    )
    .bind(operation.community_id.as_uuid())
    .bind(operation.operation_id)
    .fetch_all(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    if successors.len() > 1 {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    for (binding_id, binding_version) in successors {
        components.push(
            AuthorizationOperationVersionDelta::new(
                AuthorizationVersionComponentKind::Binding,
                authorization_version_binding_component_key(operation.community_id, binding_id),
                0,
                u64_from_i64(binding_version)?,
            )
            .map_err(IdentityLifecycleFailure::Storage)?,
        );
    }
    let selectors: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT selector_id,fact_generation FROM identity_lifecycle_selectors \
         WHERE community_id=$1 AND selected_by_operation_id=$2 ORDER BY selector_id",
    )
    .bind(operation.community_id.as_uuid())
    .bind(operation.operation_id)
    .fetch_all(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    for (selector_id, fact_generation) in selectors {
        components.push(
            AuthorizationOperationVersionDelta::new(
                AuthorizationVersionComponentKind::LifecycleSelector,
                authorization_version_lifecycle_selector_component_key(
                    operation.community_id,
                    selector_id,
                ),
                0,
                u64_from_i64(fact_generation)?,
            )
            .map_err(IdentityLifecycleFailure::Storage)?,
        );
    }
    record_authorization_operation_version_delta_tx(
        locked.transaction,
        operation.community_id,
        operation.operation_id,
        operation.request_fingerprint,
        components,
    )
    .await
    .map_err(IdentityLifecycleFailure::Storage)
}

async fn load_exact_binding_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    binding_id: Uuid,
) -> Result<Option<ActiveBinding>, IdentityLifecycleFailure> {
    sqlx::query_as(
        "SELECT binding_id,binding_version,issuer,subject,principal_fingerprint, \
                event_author_pubkey,binding_state,lifecycle_revision,binding_provenance, \
                policy_revision,expires_at \
         FROM identity_bindings WHERE community_id=$1 AND binding_id=$2 FOR UPDATE",
    )
    .bind(locked.community_id.as_uuid())
    .bind(binding_id)
    .fetch_optional(&mut **locked.transaction)
    .await
    .map_err(DbError::from)
    .map_err(IdentityLifecycleFailure::from)
}

async fn load_active_binding_by_principal_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    principal: [u8; 32],
) -> Result<Option<ActiveBinding>, IdentityLifecycleFailure> {
    let bindings: Vec<ActiveBinding> = sqlx::query_as(
        "SELECT binding_id,binding_version,issuer,subject,principal_fingerprint, \
                event_author_pubkey,binding_state,lifecycle_revision,binding_provenance, \
                policy_revision,expires_at \
         FROM identity_bindings WHERE community_id=$1 AND principal_fingerprint=$2 \
           AND binding_state=1 ORDER BY binding_version FOR UPDATE",
    )
    .bind(locked.community_id.as_uuid())
    .bind(principal.as_slice())
    .fetch_all(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    match bindings.len() {
        0 => Ok(None),
        1 => Ok(bindings.into_iter().next()),
        _ => Err(IdentityLifecycleFailure::CorruptStoredResult),
    }
}

async fn load_active_binding_by_key_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    key: [u8; 32],
) -> Result<Option<ActiveBinding>, IdentityLifecycleFailure> {
    sqlx::query_as(
        "SELECT binding_id,binding_version,issuer,subject,principal_fingerprint, \
                event_author_pubkey,binding_state,lifecycle_revision,binding_provenance, \
                policy_revision,expires_at \
         FROM identity_bindings WHERE community_id=$1 AND event_author_pubkey=$2 \
           AND binding_state=1 FOR UPDATE",
    )
    .bind(locked.community_id.as_uuid())
    .bind(key.as_slice())
    .fetch_optional(&mut **locked.transaction)
    .await
    .map_err(DbError::from)
    .map_err(IdentityLifecycleFailure::from)
}

async fn load_open_lifecycle_selector_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    selector_kind: i16,
    principal: [u8; 32],
) -> Result<Option<OpenLifecycleSelector>, IdentityLifecycleFailure> {
    let selectors: Vec<OpenLifecycleSelector> = sqlx::query_as(
        "SELECT selector.selector_id,selector.selector_kind,selector.fact_generation, \
                selector.principal_fingerprint,selector.event_author_pubkey, \
                selector.binding_id,selector.binding_version \
         FROM identity_lifecycle_selectors selector \
         LEFT JOIN identity_lifecycle_selector_consumptions consumption \
           ON consumption.community_id=selector.community_id \
          AND consumption.selector_id=selector.selector_id \
         WHERE selector.community_id=$1 AND selector.selector_kind=$2 \
           AND selector.principal_fingerprint=$3 AND consumption.selector_id IS NULL \
         ORDER BY selector.fact_generation FOR UPDATE OF selector",
    )
    .bind(locked.community_id.as_uuid())
    .bind(selector_kind)
    .bind(principal.as_slice())
    .fetch_all(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    match selectors.as_slice() {
        [] => Ok(None),
        [selector] => Ok(Some(OpenLifecycleSelector {
            selector_id: selector.selector_id,
            selector_kind: selector.selector_kind,
            fact_generation: selector.fact_generation,
            principal_fingerprint: selector.principal_fingerprint.clone(),
            event_author_pubkey: selector.event_author_pubkey.clone(),
            binding_id: selector.binding_id,
            binding_version: selector.binding_version,
        })),
        _ => Err(IdentityLifecycleFailure::CorruptStoredResult),
    }
}

async fn validate_replacement_freshness_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    proof: &VerifiedReplacementProof,
) -> Result<(), IdentityLifecycleFailure> {
    let fresh: bool = sqlx::query_scalar("SELECT $1::timestamptz > clock_timestamp()")
        .bind(proof.expires_at)
        .fetch_one(&mut **locked.transaction)
        .await
        .map_err(DbError::from)?;
    if !fresh {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

async fn validate_successor_expiry_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    authorization_expires_at: DateTime<Utc>,
    policy_expires_at: Option<DateTime<Utc>>,
) -> Result<DateTime<Utc>, IdentityLifecycleFailure> {
    let successor_expires_at = policy_expires_at
        .map(|expires_at| expires_at.min(authorization_expires_at))
        .unwrap_or(authorization_expires_at);
    let fresh: bool = sqlx::query_scalar("SELECT clock_timestamp() < $1::timestamptz")
        .bind(successor_expires_at)
        .fetch_one(&mut **locked.transaction)
        .await
        .map_err(DbError::from)?;
    if !fresh {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(successor_expires_at)
}

async fn validate_principal_resolution_freshness_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    resolution: &VerifiedPrincipalResolution,
) -> Result<(), IdentityLifecycleFailure> {
    let valid: bool = sqlx::query_scalar(
        "SELECT $1::timestamptz > clock_timestamp() AND EXISTS( \
           SELECT 1 FROM identity_enrollment_policies \
           WHERE community_id=$2 AND policy_revision=$3 AND enrollment_mode=$4 \
             AND policy_digest=$5 AND effective_at<=clock_timestamp() \
             AND (expires_at IS NULL OR expires_at>clock_timestamp()))",
    )
    .bind(resolution.expires_at)
    .bind(locked.community_id.as_uuid())
    .bind(i64_from_u64(resolution.policy_revision)?)
    .bind(resolution.provenance as i16)
    .bind(resolution.policy_digest.as_slice())
    .fetch_one(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    if !valid {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

async fn replacement_key_available_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    replacement_key: [u8; 32],
) -> Result<bool, IdentityLifecycleFailure> {
    sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM identity_bindings \
           WHERE community_id=$1 AND event_author_pubkey=$2 AND binding_state=1) \
         AND NOT EXISTS(SELECT 1 FROM identity_lifecycle_selectors \
           WHERE community_id=$1 AND selector_kind=3 AND event_author_pubkey=$2)",
    )
    .bind(locked.community_id.as_uuid())
    .bind(replacement_key.as_slice())
    .fetch_one(&mut **locked.transaction)
    .await
    .map_err(DbError::from)
    .map_err(IdentityLifecycleFailure::from)
}

fn retired_target_matches(
    binding: Option<&ActiveBinding>,
    target: &ExactRetiredBindingTarget,
) -> bool {
    binding.is_some_and(|binding| {
        binding.binding_id == target.binding_id
            && binding.binding_version == i64::try_from(target.binding_version).unwrap_or(-1)
            && binding.lifecycle_revision
                == i64::try_from(target.expected_lifecycle_revision).unwrap_or(-1)
            && binding.binding_state == 2
            && binding.lifecycle_revision == 2
            && binding.principal_fingerprint == target.principal_fingerprint
            && binding.event_author_pubkey == target.event_author_pubkey
    })
}

fn pending_selector_matches(
    selector: Option<&OpenLifecycleSelector>,
    expected: &ExpectedPendingReplacement,
) -> bool {
    selector.is_some_and(|selector| {
        selector.selector_kind == 4
            && selector.fact_generation == i64::try_from(expected.fact_generation).unwrap_or(-1)
            && selector.principal_fingerprint == expected.target.principal_fingerprint
            && selector.event_author_pubkey.as_deref()
                == Some(expected.target.event_author_pubkey.as_slice())
            && selector.binding_id == Some(expected.target.binding_id)
            && selector.binding_version == i64::try_from(expected.target.binding_version).ok()
    })
}

struct ResolvedEnablePrincipal {
    issuer: String,
    subject: String,
    provenance: i16,
    policy_revision: i64,
    policy_expires_at: Option<DateTime<Utc>>,
}

struct CurrentPolicyExpiry {
    expires_at: Option<DateTime<Utc>>,
}

async fn load_current_policy_expiry_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    policy_revision: i64,
    provenance: i16,
) -> Result<Option<CurrentPolicyExpiry>, IdentityLifecycleFailure> {
    let expires_at = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        "SELECT expires_at FROM identity_enrollment_policies \
         WHERE community_id=$1 AND policy_revision=$2 AND enrollment_mode=$3 \
           AND effective_at<=clock_timestamp() \
           AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE",
    )
    .bind(locked.community_id.as_uuid())
    .bind(policy_revision)
    .bind(provenance)
    .fetch_optional(&mut **locked.transaction)
    .await
    .map_err(DbError::from)?;
    Ok(expires_at.map(|expires_at| CurrentPolicyExpiry { expires_at }))
}

enum EnablePrincipalResolution {
    Resolved(ResolvedEnablePrincipal),
    MissingCanonicalIdentity,
    PolicyUnavailable,
}

async fn resolve_enable_principal_tx(
    locked: &mut PrelockedIdentityLifecycleTx<'_, '_>,
    request: &EnableIdentityPrincipalRequest,
    old_binding: &ActiveBinding,
) -> Result<EnablePrincipalResolution, IdentityLifecycleFailure> {
    if let Some(resolution) = &request.principal_resolution {
        if !principal_resolution_matches_enable(request, old_binding) {
            return Ok(EnablePrincipalResolution::MissingCanonicalIdentity);
        }
        let policy_revision = i64_from_u64(resolution.policy_revision)?;
        let Some(policy) =
            load_current_policy_expiry_tx(locked, policy_revision, resolution.provenance as i16)
                .await?
        else {
            return Ok(EnablePrincipalResolution::PolicyUnavailable);
        };
        return Ok(EnablePrincipalResolution::Resolved(
            ResolvedEnablePrincipal {
                issuer: resolution.issuer.clone(),
                subject: resolution.subject.clone(),
                provenance: resolution.provenance as i16,
                policy_revision,
                policy_expires_at: policy.expires_at,
            },
        ));
    }

    let source = old_binding;
    if source.principal_fingerprint != request.principal_fingerprint
        || source.binding_state != 2
        || source.lifecycle_revision != 2
    {
        return Ok(EnablePrincipalResolution::MissingCanonicalIdentity);
    }
    let Some(policy) =
        load_current_policy_expiry_tx(locked, source.policy_revision, source.binding_provenance)
            .await?
    else {
        return Ok(EnablePrincipalResolution::PolicyUnavailable);
    };
    Ok(EnablePrincipalResolution::Resolved(
        ResolvedEnablePrincipal {
            issuer: source.issuer.clone(),
            subject: source.subject.clone(),
            provenance: source.binding_provenance,
            policy_revision: source.policy_revision,
            policy_expires_at: policy.expires_at,
        },
    ))
}

fn principal_resolution_matches_enable(
    request: &EnableIdentityPrincipalRequest,
    old_binding: &ActiveBinding,
) -> bool {
    let Some(resolution) = &request.principal_resolution else {
        return request.actor.operator_grant.is_some();
    };
    resolution.community_id == request.operation.community_id
        && resolution.operation_id == request.operation.operation_id
        && resolution.intent_fingerprint == enable_identity_intent_fingerprint(request)
        && resolution.principal_fingerprint == request.principal_fingerprint
        && request.replacement.principal_fingerprint == request.principal_fingerprint
        && old_binding.issuer == resolution.issuer
        && old_binding.subject == resolution.subject
        && old_binding.principal_fingerprint == request.principal_fingerprint
}

fn active_target_matches(
    binding: Option<&ActiveBinding>,
    target: &ExactActiveBindingTarget,
) -> bool {
    binding.is_some_and(|binding| {
        binding.binding_id == target.binding_id
            && binding.binding_version == i64::try_from(target.binding_version).unwrap_or(-1)
            && binding.lifecycle_revision
                == i64::try_from(target.expected_lifecycle_revision).unwrap_or(-1)
            && binding.binding_state == 1
            && binding.lifecycle_revision == 1
            && binding.principal_fingerprint == target.principal_fingerprint
            && binding.event_author_pubkey == target.event_author_pubkey
    })
}

fn admission_target_matches(
    binding: Option<&ActiveBinding>,
    target: &ExactAdmissionLossTarget,
) -> bool {
    binding.is_some_and(|binding| {
        binding.binding_id == target.binding_id
            && binding.binding_version == i64::try_from(target.binding_version).unwrap_or(-1)
            && binding.lifecycle_revision
                == i64::try_from(target.expected_lifecycle_revision).unwrap_or(-1)
            && binding.binding_state == 1
            && binding.lifecycle_revision == 1
            && binding.principal_fingerprint == target.principal_fingerprint
            && binding.event_author_pubkey == target.event_author_pubkey
    })
}

fn destructive_request_fingerprint(
    domain: &[u8],
    operation: &IdentityLifecycleOperation,
    principal: Option<[u8; 32]>,
    key: [u8; 32],
    target: Option<ExactActiveBindingTarget>,
    actor: &AuthenticatedLifecycleActor,
) -> [u8; 32] {
    let principal = principal.unwrap_or([0; 32]);
    let target_id = target
        .map(|value| *value.binding_id.as_bytes())
        .unwrap_or([0; 16]);
    let target_version = target
        .map(|value| value.binding_version)
        .unwrap_or(0)
        .to_be_bytes();
    let target_revision = target
        .map(|value| value.expected_lifecycle_revision)
        .unwrap_or(0)
        .to_be_bytes();
    lifecycle_digest(
        domain,
        &[
            operation.community_id.as_uuid().as_bytes(),
            operation.operation_id.as_bytes(),
            &principal,
            &key,
            &target_id,
            &target_version,
            &target_revision,
            &actor.request_attribution,
        ],
    )
}

async fn replay_observation_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: LifecycleReplayRequest<'_>,
) -> Result<Option<IdentityLifecycleObservation>, IdentityLifecycleFailure> {
    let operation = request.operation();
    let transition = request.transition();
    let receipt: Option<StoredReceipt> = sqlx::query_as(
        "SELECT request_fingerprint,operation_kind,outcome_code,result_digest \
         FROM authorization_operation_receipts WHERE community_id=$1 AND operation_id=$2",
    )
    .bind(operation.community_id.as_uuid())
    .bind(operation.operation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    if receipt.request_fingerprint != operation.request_fingerprint
        || receipt.operation_kind != transition as i16
    {
        return Err(IdentityLifecycleFailure::IntentConflict);
    }
    let histories: Vec<StoredLifecycleHistory> = sqlx::query_as(
        "SELECT transition_kind,outcome_code,old_binding_id,old_binding_version, \
                old_prior_lifecycle_revision,old_prior_state, \
                old_resulting_lifecycle_revision,old_resulting_state, \
                successor_binding_id,successor_binding_version, \
                successor_lifecycle_revision,successor_state,request_fingerprint, \
                transition_digest \
         FROM identity_lifecycle_history WHERE community_id=$1 AND operation_id=$2",
    )
    .bind(operation.community_id.as_uuid())
    .bind(operation.operation_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    let history = match receipt.outcome_code {
        APPLIED_OUTCOME | NO_OP_OUTCOME if histories.len() == 1 => histories.first(),
        DENIED_OUTCOME if histories.is_empty() => None,
        APPLIED_OUTCOME | NO_OP_OUTCOME | DENIED_OUTCOME => {
            return Err(IdentityLifecycleFailure::CorruptStoredResult);
        }
        _ => return Err(IdentityLifecycleFailure::CorruptStoredResult),
    };
    if let Some(history) = history {
        validate_replay_history(&operation, transition, receipt.outcome_code, history)?;
        validate_replay_target(request, history)?;
    }
    let manifest = validate_lifecycle_version_manifest_tx(transaction, request, history).await?;

    let denial =
        validate_shared_replay_event_tx(transaction, request, receipt.outcome_code).await?;
    let binding =
        replay_binding_evidence_tx(transaction, request, receipt.outcome_code, history).await?;
    let successor_expires_at =
        replay_successor_expiry_tx(transaction, request, receipt.outcome_code, history).await?;
    let expected_result_digest = replay_result_digest(
        request,
        receipt.outcome_code,
        history,
        binding,
        denial,
        manifest.manifest_digest(),
        successor_expires_at,
    )?;
    if exact_32(&receipt.result_digest)? != expected_result_digest {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    let receipt_outcome = operation_outcome(receipt.outcome_code)?;
    let candidate = AuthorizationOperationReceipt::new(
        operation.community_id,
        operation.operation_id,
        operation.request_fingerprint,
        operation_kind_for_transition(transition),
        request.actor().canonical(operation.community_id)?.clone(),
        receipt_outcome,
        expected_result_digest,
    )
    .map_err(IdentityLifecycleFailure::Storage)?;
    if record_authorization_operation_receipt_tx(transaction, &candidate).await?
        != AuthorizationReceiptWrite::ExactReplay
    {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    let original_outcome = match receipt.outcome_code {
        APPLIED_OUTCOME => PersistedIdentityLifecycleOutcome::Applied,
        NO_OP_OUTCOME => PersistedIdentityLifecycleOutcome::NoOp,
        DENIED_OUTCOME => PersistedIdentityLifecycleOutcome::Denied(
            denial.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?,
        ),
        _ => return Err(IdentityLifecycleFailure::CorruptStoredResult),
    };
    Ok(Some(IdentityLifecycleObservation::ExactReplay {
        transition,
        original_outcome,
        binding,
    }))
}

async fn validate_lifecycle_version_manifest_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: LifecycleReplayRequest<'_>,
    history: Option<&StoredLifecycleHistory>,
) -> Result<AuthorizationOperationVersionDeltaManifest, IdentityLifecycleFailure> {
    let operation = request.operation();
    let manifest =
        load_manifest_connection(transaction, operation.community_id, operation.operation_id)
            .await
            .map_err(IdentityLifecycleFailure::Storage)?
            .ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
    if manifest.request_fingerprint() != operation.request_fingerprint {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    let expected =
        expected_lifecycle_version_components_tx(transaction, operation, history).await?;
    if let (LifecycleReplayRequest::AdmissionLoss(admission_loss), Some(history)) =
        (request, history)
    {
        if history.outcome_code == APPLIED_OUTCOME {
            // Fresh application validated this complete AuthorityEpoch set
            // against the authoritative protected-object membership before
            // inserting the receipt. Replay must use that immutable,
            // digest-validated operation manifest: a later protected head is
            // allowed to replace the mutable current authority rows.
            let authority_count = manifest
                .components()
                .iter()
                .filter(|component| {
                    component.component_kind() == AuthorizationVersionComponentKind::AuthorityEpoch
                })
                .count();
            validate_admission_loss_manifest_shape(
                operation.community_id,
                admission_loss.cause,
                authority_count,
                &expected,
                manifest.components(),
            )?;
        } else {
            validate_exact_version_components(manifest.components(), &expected)?;
        }
    } else if history.is_some_and(|history| history.outcome_code == APPLIED_OUTCOME)
        && request.actor().operator_grant.is_some()
        && matches!(
            request.transition(),
            IdentityLifecycleTransition::Retire
                | IdentityLifecycleTransition::Disable
                | IdentityLifecycleTransition::Revoke
                | IdentityLifecycleTransition::Rotate
        )
    {
        validate_retiring_binding_manifest_shape(
            operation.community_id,
            &expected,
            manifest.components(),
        )?;
    } else {
        validate_exact_version_components(manifest.components(), &expected)?;
    }
    Ok(manifest)
}

fn validate_retiring_binding_manifest_shape(
    community_id: CommunityId,
    lifecycle: &[AuthorizationOperationVersionDelta],
    actual: &[AuthorizationOperationVersionDelta],
) -> Result<(), IdentityLifecycleFailure> {
    let actual_lifecycle: Vec<_> = actual
        .iter()
        .filter(|component| {
            matches!(
                component.component_kind(),
                AuthorizationVersionComponentKind::Binding
                    | AuthorizationVersionComponentKind::LifecycleSelector
            )
        })
        .cloned()
        .collect();
    if actual_lifecycle != lifecycle {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    let invalidation: Vec<_> = actual
        .iter()
        .filter(|component| {
            component.component_kind() == AuthorizationVersionComponentKind::InvalidationGeneration
        })
        .collect();
    if invalidation.len() != 1
        || invalidation[0].component_key()
            != authorization_version_invalidation_generation_component_key(community_id)
        || invalidation[0].after_version() != invalidation[0].before_version().saturating_add(1)
    {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    let authority_count = actual
        .iter()
        .filter(|component| {
            component.component_kind() == AuthorizationVersionComponentKind::AuthorityEpoch
        })
        .inspect(|component| {
            debug_assert!(component.after_version() > component.before_version());
        })
        .count();
    if actual.iter().any(|component| {
        !matches!(
            component.component_kind(),
            AuthorizationVersionComponentKind::Binding
                | AuthorizationVersionComponentKind::LifecycleSelector
                | AuthorizationVersionComponentKind::InvalidationGeneration
                | AuthorizationVersionComponentKind::AuthorityEpoch
        ) || (component.component_kind() == AuthorizationVersionComponentKind::AuthorityEpoch
            && component.after_version() != component.before_version().saturating_add(1))
    }) || actual.len() != lifecycle.len() + authority_count + 1
    {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    Ok(())
}

async fn expected_lifecycle_version_components_tx(
    transaction: &mut Transaction<'_, Postgres>,
    operation: IdentityLifecycleOperation,
    history: Option<&StoredLifecycleHistory>,
) -> Result<Vec<AuthorizationOperationVersionDelta>, IdentityLifecycleFailure> {
    let mut expected = Vec::new();
    if let Some(history) = history {
        if let Some((binding_id, binding_version)) = optional_binding_pair(
            history.successor_binding_id,
            history.successor_binding_version,
        )? {
            expected.push(
                AuthorizationOperationVersionDelta::new(
                    AuthorizationVersionComponentKind::Binding,
                    authorization_version_binding_component_key(operation.community_id, binding_id),
                    0,
                    u64_from_i64(binding_version)?,
                )
                .map_err(IdentityLifecycleFailure::Storage)?,
            );
        }
    }
    let selectors: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT selector_id,fact_generation FROM identity_lifecycle_selectors \
         WHERE community_id=$1 AND selected_by_operation_id=$2 ORDER BY selector_id",
    )
    .bind(operation.community_id.as_uuid())
    .bind(operation.operation_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    for (selector_id, fact_generation) in selectors {
        expected.push(
            AuthorizationOperationVersionDelta::new(
                AuthorizationVersionComponentKind::LifecycleSelector,
                authorization_version_lifecycle_selector_component_key(
                    operation.community_id,
                    selector_id,
                ),
                0,
                u64_from_i64(fact_generation)?,
            )
            .map_err(IdentityLifecycleFailure::Storage)?,
        );
    }
    expected.sort_by_key(|component| (component.component_kind(), component.component_key()));
    Ok(expected)
}

async fn validate_admission_loss_version_manifest_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ExactAdmissionLossRequest,
    manifest: &AuthorizationOperationVersionDeltaManifest,
) -> Result<(), IdentityLifecycleFailure> {
    let histories: Vec<StoredLifecycleHistory> = sqlx::query_as(
        "SELECT transition_kind,outcome_code,old_binding_id,old_binding_version, \
                old_prior_lifecycle_revision,old_prior_state, \
                old_resulting_lifecycle_revision,old_resulting_state, \
                successor_binding_id,successor_binding_version, \
                successor_lifecycle_revision,successor_state,request_fingerprint, \
                transition_digest \
         FROM identity_lifecycle_history WHERE community_id=$1 AND operation_id=$2",
    )
    .bind(request.operation.community_id.as_uuid())
    .bind(request.operation.operation_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    let [history] = histories.as_slice() else {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    };
    let lifecycle =
        expected_lifecycle_version_components_tx(transaction, request.operation, Some(history))
            .await?;
    let authority_count = admission_loss_authority_target_count_tx(transaction, request).await?;
    validate_admission_loss_manifest_shape(
        request.operation.community_id,
        request.cause,
        authority_count,
        &lifecycle,
        manifest.components(),
    )?;
    let expected =
        reconstruct_current_admission_loss_components_tx(transaction, request, lifecycle)
            .await?
            .ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
    validate_exact_version_components(manifest.components(), &expected)
}

fn validate_exact_version_components(
    actual: &[AuthorizationOperationVersionDelta],
    expected: &[AuthorizationOperationVersionDelta],
) -> Result<(), IdentityLifecycleFailure> {
    if actual != expected {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    Ok(())
}

fn validate_admission_loss_manifest_shape(
    community_id: CommunityId,
    cause: TrustedAdmissionLossCause,
    authoritative_object_count: usize,
    lifecycle: &[AuthorizationOperationVersionDelta],
    actual: &[AuthorizationOperationVersionDelta],
) -> Result<(), IdentityLifecycleFailure> {
    let actual_lifecycle: Vec<_> = actual
        .iter()
        .filter(|component| {
            matches!(
                component.component_kind(),
                AuthorizationVersionComponentKind::Binding
                    | AuthorizationVersionComponentKind::LifecycleSelector
            )
        })
        .cloned()
        .collect();
    if actual_lifecycle != lifecycle {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    let invalidation: Vec<_> = actual
        .iter()
        .filter(|component| {
            component.component_kind() == AuthorizationVersionComponentKind::InvalidationGeneration
        })
        .collect();
    if invalidation.len() != 1
        || invalidation[0].component_key()
            != authorization_version_invalidation_generation_component_key(community_id)
        || invalidation[0].after_version() != invalidation[0].before_version().saturating_add(1)
    {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    let authority: Vec<_> = actual
        .iter()
        .filter(|component| {
            component.component_kind() == AuthorizationVersionComponentKind::AuthorityEpoch
        })
        .collect();
    if authority.len() != authoritative_object_count
        || authority.iter().any(|component| {
            component.after_version() != component.before_version().saturating_add(1)
        })
    {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    let relationship: Vec<_> = actual
        .iter()
        .filter(|component| {
            component.component_kind() == AuthorizationVersionComponentKind::DelegatedRelationship
        })
        .collect();
    match (cause, relationship.as_slice()) {
        (TrustedAdmissionLossCause::DelegationAuthority { .. }, [])
        | (TrustedAdmissionLossCause::LocalBinding, [])
        | (TrustedAdmissionLossCause::LocalPolicy { .. }, []) => {}
        (
            TrustedAdmissionLossCause::DelegationAuthority {
                relationship_id,
                revision,
            },
            [component],
        ) if component.component_key()
            == authorization_version_delegated_relationship_component_key(
                community_id,
                relationship_id,
            )
            && component.after_version() == revision
            && component.before_version() < component.after_version() => {}
        _ => return Err(IdentityLifecycleFailure::CorruptStoredResult),
    }
    let expected_count =
        actual_lifecycle.len() + invalidation.len() + authority.len() + relationship.len();
    if actual.len() != expected_count {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    Ok(())
}

async fn admission_loss_authority_target_count_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ExactAdmissionLossRequest,
) -> Result<usize, IdentityLifecycleFailure> {
    let count: i64 = match request.cause {
        TrustedAdmissionLossCause::LocalBinding => sqlx::query_scalar(
            "SELECT count(*) FROM protected_object_authority \
             WHERE community_id=$1 AND binding_id=$2 AND binding_version=$3",
        )
        .bind(request.operation.community_id.as_uuid())
        .bind(request.target.binding_id)
        .bind(i64_from_u64(request.target.binding_version)?)
        .fetch_one(&mut **transaction)
        .await
        .map_err(DbError::from)?,
        TrustedAdmissionLossCause::LocalPolicy { revision } => sqlx::query_scalar(
            "SELECT count(*) FROM protected_object_authority \
             WHERE community_id=$1 AND policy_revision=$2",
        )
        .bind(request.operation.community_id.as_uuid())
        .bind(i64_from_u64(revision)?)
        .fetch_one(&mut **transaction)
        .await
        .map_err(DbError::from)?,
        TrustedAdmissionLossCause::DelegationAuthority {
            relationship_id,
            revision,
        } => sqlx::query_scalar(
            "SELECT count(*) FROM protected_object_authority \
             WHERE community_id=$1 AND delegated_relationship_id=$2 \
               AND delegated_relationship_revision=$3",
        )
        .bind(request.operation.community_id.as_uuid())
        .bind(relationship_id)
        .bind(i64_from_u64(revision)?)
        .fetch_one(&mut **transaction)
        .await
        .map_err(DbError::from)?,
    };
    let count =
        usize::try_from(count).map_err(|_| IdentityLifecycleFailure::CorruptStoredResult)?;
    if count > 1_024 {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    Ok(count)
}

async fn reconstruct_current_admission_loss_components_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ExactAdmissionLossRequest,
    mut expected: Vec<AuthorizationOperationVersionDelta>,
) -> Result<Option<Vec<AuthorizationOperationVersionDelta>>, IdentityLifecycleFailure> {
    type StoredInvalidationFloorAttribution = (i16, Vec<u8>, i64, Option<i64>, Option<i64>);

    let (_, selector) = admission_loss_invalidation_coordinates(request)?;
    let floors: Vec<StoredInvalidationFloorAttribution> = sqlx::query_as(
        "SELECT selector_kind,selector_fingerprint,floor_generation, \
                binding_version_floor,relationship_revision_floor \
         FROM authorization_invalidation_floors \
         WHERE community_id=$1 AND operation_id=$2 AND request_fingerprint=$3",
    )
    .bind(request.operation.community_id.as_uuid())
    .bind(request.operation.operation_id)
    .bind(request.operation.request_fingerprint.as_slice())
    .fetch_all(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    let [floor] = floors.as_slice() else {
        return if floors.is_empty() {
            Ok(None)
        } else {
            Err(IdentityLifecycleFailure::CorruptStoredResult)
        };
    };
    let selector_fingerprint = selector.fingerprint(request.operation.community_id);
    let floor_binding = floor.3.map(u64_from_i64).transpose()?;
    let floor_relationship = floor.4.map(u64_from_i64).transpose()?;
    let floor_coordinates_match = match selector {
        AuthorizationInvalidationSelector::Binding {
            invalid_through, ..
        } => floor_binding == Some(invalid_through) && floor_relationship.is_none(),
        AuthorizationInvalidationSelector::DelegatedRelationship {
            invalid_through, ..
        } => floor_binding.is_none() && floor_relationship == Some(invalid_through),
        AuthorizationInvalidationSelector::ConfigurationRevision(_) => {
            floor_binding.is_none() && floor_relationship.is_none()
        }
        _ => false,
    };
    if floor.0 != selector.kind() as i16
        || exact_32(&floor.1)? != selector_fingerprint
        || !floor_coordinates_match
    {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    let generation = u64_from_i64(floor.2)?;
    let before_generation = generation
        .checked_sub(1)
        .ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
    expected.push(
        AuthorizationOperationVersionDelta::new(
            AuthorizationVersionComponentKind::InvalidationGeneration,
            authorization_version_invalidation_generation_component_key(
                request.operation.community_id,
            ),
            before_generation,
            generation,
        )
        .map_err(IdentityLifecycleFailure::Storage)?,
    );
    if let TrustedAdmissionLossCause::DelegationAuthority {
        relationship_id,
        revision,
    } = request.cause
    {
        let key = authorization_version_delegated_relationship_component_key(
            request.operation.community_id,
            relationship_id,
        );
        let prior: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(after_version) FROM authorization_operation_version_deltas \
             WHERE community_id=$1 AND operation_id<>$2 AND component_kind=6 \
               AND component_key=$3 AND after_version<=$4",
        )
        .bind(request.operation.community_id.as_uuid())
        .bind(request.operation.operation_id)
        .bind(key.as_slice())
        .bind(i64_from_u64(revision)?)
        .fetch_one(&mut **transaction)
        .await
        .map_err(DbError::from)?;
        let prior = prior.map(u64_from_i64).transpose()?.unwrap_or(0);
        if prior < revision {
            expected.push(
                AuthorizationOperationVersionDelta::new(
                    AuthorizationVersionComponentKind::DelegatedRelationship,
                    key,
                    prior,
                    revision,
                )
                .map_err(IdentityLifecycleFailure::Storage)?,
            );
        }
    }
    let authority_rows: Vec<(i16, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT epoch.object_kind,epoch.object_key,epoch.authority_epoch \
         FROM authorization_authority_epochs epoch \
         JOIN protected_object_authority protected \
           ON protected.community_id=epoch.community_id \
          AND protected.object_kind=epoch.object_kind \
          AND protected.object_key=epoch.object_key \
          AND protected.authority_epoch=epoch.authority_epoch \
          AND protected.operation_id=epoch.operation_id \
          AND protected.request_fingerprint=epoch.request_fingerprint \
         WHERE epoch.community_id=$1 AND epoch.operation_id=$2 \
           AND epoch.request_fingerprint=$3 \
         ORDER BY epoch.object_kind,epoch.object_key",
    )
    .bind(request.operation.community_id.as_uuid())
    .bind(request.operation.operation_id)
    .bind(request.operation.request_fingerprint.as_slice())
    .fetch_all(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    for (kind, key, authority_epoch) in authority_rows {
        let kind = protected_object_kind_from_database(kind)?;
        let key = exact_32(&key)?;
        let after = u64_from_i64(authority_epoch)?;
        let before = after
            .checked_sub(1)
            .ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
        expected.push(
            AuthorizationOperationVersionDelta::new(
                AuthorizationVersionComponentKind::AuthorityEpoch,
                authorization_version_authority_epoch_component_key(
                    request.operation.community_id,
                    kind,
                    key,
                ),
                before,
                after,
            )
            .map_err(IdentityLifecycleFailure::Storage)?,
        );
    }
    expected.sort_by_key(|component| (component.component_kind(), component.component_key()));
    Ok(Some(expected))
}

fn protected_object_kind_from_database(
    value: i16,
) -> Result<AuthorizationProtectedObjectKind, IdentityLifecycleFailure> {
    match value {
        1 => Ok(AuthorizationProtectedObjectKind::Domain),
        2 => Ok(AuthorizationProtectedObjectKind::Channel),
        3 => Ok(AuthorizationProtectedObjectKind::Repository),
        4 => Ok(AuthorizationProtectedObjectKind::Media),
        5 => Ok(AuthorizationProtectedObjectKind::ModerationTarget),
        6 => Ok(AuthorizationProtectedObjectKind::AudioSession),
        7 => Ok(AuthorizationProtectedObjectKind::BindingStatus),
        _ => Err(IdentityLifecycleFailure::CorruptStoredResult),
    }
}

fn validate_replay_history(
    operation: &IdentityLifecycleOperation,
    transition: IdentityLifecycleTransition,
    outcome: i16,
    history: &StoredLifecycleHistory,
) -> Result<(), IdentityLifecycleFailure> {
    let old = optional_binding_pair(history.old_binding_id, history.old_binding_version)?;
    let successor = optional_binding_pair(
        history.successor_binding_id,
        history.successor_binding_version,
    )?;
    let old_state_is_valid = match old {
        None => {
            history.old_prior_lifecycle_revision.is_none()
                && history.old_prior_state.is_none()
                && history.old_resulting_lifecycle_revision.is_none()
                && history.old_resulting_state.is_none()
        }
        Some(_)
            if matches!(
                transition,
                IdentityLifecycleTransition::Recover | IdentityLifecycleTransition::Enable
            ) =>
        {
            history.old_prior_lifecycle_revision == Some(2)
                && history.old_prior_state == Some(2)
                && history.old_resulting_lifecycle_revision == Some(2)
                && history.old_resulting_state == Some(2)
        }
        Some(_) => {
            history.old_prior_lifecycle_revision == Some(1)
                && history.old_prior_state == Some(1)
                && history.old_resulting_lifecycle_revision == Some(2)
                && history.old_resulting_state == Some(2)
        }
    };
    let successor_state_is_valid = match successor {
        None => history.successor_lifecycle_revision.is_none() && history.successor_state.is_none(),
        Some(_) => {
            history.successor_lifecycle_revision == Some(1) && history.successor_state == Some(1)
        }
    };
    let no_op_is_empty = outcome != NO_OP_OUTCOME || (old.is_none() && successor.is_none());
    let expected_digest = transition_digest(operation, transition, old, successor);
    if history.transition_kind != transition as i16
        || history.outcome_code != outcome
        || history.request_fingerprint != operation.request_fingerprint
        || !old_state_is_valid
        || !successor_state_is_valid
        || !no_op_is_empty
        || exact_32(&history.transition_digest)? != expected_digest
    {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    Ok(())
}

fn validate_replay_target(
    request: LifecycleReplayRequest<'_>,
    history: &StoredLifecycleHistory,
) -> Result<(), IdentityLifecycleFailure> {
    let old = optional_binding_pair(history.old_binding_id, history.old_binding_version)?;
    match request {
        LifecycleReplayRequest::Enrollment(_) if history.outcome_code == APPLIED_OUTCOME => {
            if old.is_some() || history.successor_binding_id.is_none() {
                return Err(IdentityLifecycleFailure::CorruptStoredResult);
            }
        }
        LifecycleReplayRequest::Enrollment(_) => {}
        LifecycleReplayRequest::AdmissionLoss(request) => {
            if history.outcome_code == APPLIED_OUTCOME
                && old
                    != Some((
                        request.target.binding_id,
                        i64_from_u64(request.target.binding_version)?,
                    ))
            {
                return Err(IdentityLifecycleFailure::CorruptStoredResult);
            }
        }
        LifecycleReplayRequest::Retire(request) => {
            if history.outcome_code == APPLIED_OUTCOME
                && old
                    != Some((
                        request.target.binding_id,
                        i64_from_u64(request.target.binding_version)?,
                    ))
            {
                return Err(IdentityLifecycleFailure::CorruptStoredResult);
            }
        }
        LifecycleReplayRequest::Disable(request) => {
            let expected = match request.expected_active_binding {
                Some(target) => Some((target.binding_id, i64_from_u64(target.binding_version)?)),
                None => None,
            };
            if history.outcome_code == APPLIED_OUTCOME && old != expected {
                return Err(IdentityLifecycleFailure::CorruptStoredResult);
            }
        }
        LifecycleReplayRequest::Revoke(request) => {
            let expected = match request.expected_active_binding {
                Some(target) => Some((target.binding_id, i64_from_u64(target.binding_version)?)),
                None => None,
            };
            if history.outcome_code == APPLIED_OUTCOME && old != expected {
                return Err(IdentityLifecycleFailure::CorruptStoredResult);
            }
        }
        LifecycleReplayRequest::Rotate(request) => {
            let expected = Some((
                request.target.binding_id,
                i64_from_u64(request.target.binding_version)?,
            ));
            if history.outcome_code == APPLIED_OUTCOME
                && (old != expected || history.successor_binding_id.is_none())
            {
                return Err(IdentityLifecycleFailure::CorruptStoredResult);
            }
        }
        LifecycleReplayRequest::Recover(request) => {
            let expected = Some((
                request.pending.target.binding_id,
                i64_from_u64(request.pending.target.binding_version)?,
            ));
            if history.outcome_code == APPLIED_OUTCOME
                && (old != expected || history.successor_binding_id.is_none())
            {
                return Err(IdentityLifecycleFailure::CorruptStoredResult);
            }
        }
        LifecycleReplayRequest::Enable(request) => {
            let expected = Some((
                request.pending.target.binding_id,
                i64_from_u64(request.pending.target.binding_version)?,
            ));
            if history.outcome_code == APPLIED_OUTCOME
                && (old != expected || history.successor_binding_id.is_none())
            {
                return Err(IdentityLifecycleFailure::CorruptStoredResult);
            }
        }
    }
    Ok(())
}

async fn validate_shared_replay_event_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: LifecycleReplayRequest<'_>,
    outcome: i16,
) -> Result<Option<IdentityLifecycleDenial>, IdentityLifecycleFailure> {
    let operation = request.operation();
    let transition = request.transition();
    let event_kind = if outcome == DENIED_OUTCOME {
        request.actor().denial_event_kind()
    } else {
        event_kind_for_transition(transition)
    };
    let stored_events: Vec<(Uuid, i16, Uuid, Uuid)> = sqlx::query_as(
        "SELECT event_id,reason_code,correlation_id,attempt_id FROM authorization_events \
         WHERE community_id=$1 AND operation_id=$2 AND event_kind=$3 ORDER BY event_id",
    )
    .bind(operation.community_id.as_uuid())
    .bind(operation.operation_id)
    .bind(event_kind as i16)
    .fetch_all(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    let [(event_id, stored_reason, correlation_id, attempt_id)] = stored_events.as_slice() else {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    };
    let denial = match outcome {
        DENIED_OUTCOME => Some(denial_from_authorization_reason(*stored_reason)?),
        APPLIED_OUTCOME | NO_OP_OUTCOME => None,
        _ => return Err(IdentityLifecycleFailure::CorruptStoredResult),
    };
    let event_outcome = event_outcome(outcome)?;
    let reason = authorization_reason(event_outcome, event_kind, denial)?;
    if *stored_reason != reason as i16 {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    let event = NewAuthorizationEvent::new(
        operation.community_id,
        *event_id,
        event_kind,
        event_outcome,
        reason,
        request.actor().canonical(operation.community_id)?.clone(),
        request.subject_fingerprint(),
        operation.operation_id,
        Some(operation.request_fingerprint),
        *correlation_id,
        *attempt_id,
    )
    .map_err(IdentityLifecycleFailure::Storage)?;
    if record_authorization_event_tx(transaction, &event).await?
        != AuthorizationReceiptWrite::ExactReplay
    {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    Ok(denial)
}

async fn replay_binding_evidence_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: LifecycleReplayRequest<'_>,
    outcome: i16,
    history: Option<&StoredLifecycleHistory>,
) -> Result<Option<IdentityBindingEvidence>, IdentityLifecycleFailure> {
    if let Some(history) = history {
        if let Some((binding_id, binding_version)) = optional_binding_pair(
            history.successor_binding_id,
            history.successor_binding_version,
        )? {
            return Ok(Some(IdentityBindingEvidence {
                binding_id,
                binding_version: u64_from_i64(binding_version)?,
                lifecycle_revision: 1,
            }));
        }
    }
    let LifecycleReplayRequest::Enrollment(request) = request else {
        return Ok(None);
    };
    if outcome != NO_OP_OUTCOME {
        return Ok(None);
    }
    let bindings: Vec<StoredBindingGeneration> = sqlx::query_as(
        "SELECT binding_id,binding_version FROM identity_bindings \
         WHERE community_id=$1 AND issuer=$2 AND subject=$3 \
           AND principal_fingerprint=$4 AND event_author_pubkey=$5",
    )
    .bind(request.operation.community_id.as_uuid())
    .bind(&request.issuer)
    .bind(&request.subject)
    .bind(request.principal_fingerprint.as_slice())
    .bind(request.event_author_pubkey.as_slice())
    .fetch_all(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    let [binding] = bindings.as_slice() else {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    };
    Ok(Some(IdentityBindingEvidence {
        binding_id: binding.binding_id,
        binding_version: u64_from_i64(binding.binding_version)?,
        lifecycle_revision: 1,
    }))
}

async fn replay_successor_expiry_tx(
    transaction: &mut Transaction<'_, Postgres>,
    request: LifecycleReplayRequest<'_>,
    outcome: i16,
    history: Option<&StoredLifecycleHistory>,
) -> Result<Option<DateTime<Utc>>, IdentityLifecycleFailure> {
    if outcome != APPLIED_OUTCOME
        || !matches!(
            request,
            LifecycleReplayRequest::Rotate(_)
                | LifecycleReplayRequest::Recover(_)
                | LifecycleReplayRequest::Enable(_)
        )
    {
        return Ok(None);
    }
    let history = history.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
    let (old_binding_id, _) =
        optional_binding_pair(history.old_binding_id, history.old_binding_version)?
            .ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
    let (successor_binding_id, _) = optional_binding_pair(
        history.successor_binding_id,
        history.successor_binding_version,
    )?
    .ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
    let stored_expires_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT expires_at FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
    )
    .bind(request.operation().community_id.as_uuid())
    .bind(successor_binding_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(DbError::from)?
    .flatten();
    let stored_expires_at =
        stored_expires_at.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
    let policy_expires_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT policy.expires_at FROM identity_bindings binding \
         JOIN identity_enrollment_policies policy \
           ON policy.community_id=binding.community_id \
          AND policy.policy_revision=binding.policy_revision \
          AND policy.enrollment_mode=binding.binding_provenance \
         WHERE binding.community_id=$1 AND binding.binding_id=$2",
    )
    .bind(request.operation().community_id.as_uuid())
    .bind(old_binding_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(DbError::from)?
    .ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
    let authorization_expires_at = match request {
        LifecycleReplayRequest::Rotate(request) => request.replacement.authorization_expires_at,
        LifecycleReplayRequest::Recover(request) => request.replacement.authorization_expires_at,
        LifecycleReplayRequest::Enable(request) => request.replacement.authorization_expires_at,
        _ => return Err(IdentityLifecycleFailure::CorruptStoredResult),
    };
    let expected_expires_at = policy_expires_at
        .map(|expires_at| expires_at.min(authorization_expires_at))
        .unwrap_or(authorization_expires_at);
    if stored_expires_at != expected_expires_at {
        return Err(IdentityLifecycleFailure::CorruptStoredResult);
    }
    Ok(Some(stored_expires_at))
}

fn replay_result_digest(
    request: LifecycleReplayRequest<'_>,
    outcome: i16,
    history: Option<&StoredLifecycleHistory>,
    binding: Option<IdentityBindingEvidence>,
    denial: Option<IdentityLifecycleDenial>,
    manifest_digest: [u8; 32],
    successor_expires_at: Option<DateTime<Utc>>,
) -> Result<[u8; 32], IdentityLifecycleFailure> {
    let operation = request.operation();
    let transition = request.transition();
    if outcome == DENIED_OUTCOME {
        let reason = denial.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
        return Ok(lifecycle_digest(
            b"buzz:identity-lifecycle-denial:v1",
            &[
                operation.community_id.as_uuid().as_bytes(),
                operation.operation_id.as_bytes(),
                &[transition as u8],
                &(reason as i16).to_be_bytes(),
            ],
        ));
    }
    match (request, outcome) {
        (LifecycleReplayRequest::Enrollment(request), APPLIED_OUTCOME) => {
            let binding = binding.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
            Ok(lifecycle_digest(
                b"buzz:identity-lifecycle-result:v1",
                &[
                    operation.community_id.as_uuid().as_bytes(),
                    operation.operation_id.as_bytes(),
                    &[transition as u8],
                    binding.binding_id.as_bytes(),
                    &request.principal_fingerprint,
                    &request.event_author_pubkey,
                ],
            ))
        }
        (LifecycleReplayRequest::Enrollment(_), NO_OP_OUTCOME) => {
            let binding = binding.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
            Ok(lifecycle_digest(
                b"buzz:identity-lifecycle-result:v1",
                &[
                    operation.community_id.as_uuid().as_bytes(),
                    operation.operation_id.as_bytes(),
                    &[transition as u8],
                    b"no-op",
                    binding.binding_id.as_bytes(),
                    &binding.binding_version.to_be_bytes(),
                ],
            ))
        }
        (LifecycleReplayRequest::AdmissionLoss(request), APPLIED_OUTCOME) => {
            Ok(admission_loss_result_digest(request, manifest_digest))
        }
        (LifecycleReplayRequest::Rotate(request), APPLIED_OUTCOME) => {
            let history = history.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
            let old = optional_binding_pair(history.old_binding_id, history.old_binding_version)?;
            let successor = binding.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
            let base_result_digest = successor_result_digest(
                &operation,
                transition,
                old,
                (
                    successor.binding_id,
                    i64_from_u64(successor.binding_version)?,
                ),
                request.replacement.proof_fingerprint(),
                None,
                successor_expires_at.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?,
            );
            Ok(if request.actor.operator_grant.is_some() {
                operator_manifest_result_digest(base_result_digest, manifest_digest)
            } else {
                base_result_digest
            })
        }
        (LifecycleReplayRequest::Recover(request), APPLIED_OUTCOME) => {
            let history = history.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
            let old = optional_binding_pair(history.old_binding_id, history.old_binding_version)?;
            let successor = binding.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
            Ok(successor_result_digest(
                &operation,
                transition,
                old,
                (
                    successor.binding_id,
                    i64_from_u64(successor.binding_version)?,
                ),
                request.replacement.proof_fingerprint(),
                None,
                successor_expires_at.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?,
            ))
        }
        (LifecycleReplayRequest::Enable(request), APPLIED_OUTCOME) => {
            let history = history.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
            let old = optional_binding_pair(history.old_binding_id, history.old_binding_version)?;
            let successor = binding.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
            Ok(successor_result_digest(
                &operation,
                transition,
                old,
                (
                    successor.binding_id,
                    i64_from_u64(successor.binding_version)?,
                ),
                request.replacement.proof_fingerprint(),
                Some(enable_principal_proof_fingerprint(request)),
                successor_expires_at.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?,
            ))
        }
        (request, APPLIED_OUTCOME) => {
            let history = history.ok_or(IdentityLifecycleFailure::CorruptStoredResult)?;
            let old = optional_binding_pair(history.old_binding_id, history.old_binding_version)?;
            let suffix: &[u8] = if old.is_some() {
                &[]
            } else {
                b"inactive-target"
            };
            let old_id = old.map(|value| *value.0.as_bytes()).unwrap_or([0; 16]);
            let old_version = old.map(|value| value.1).unwrap_or(0).to_be_bytes();
            let transition_code = [transition as u8];
            let mut parts: Vec<&[u8]> = vec![
                operation.community_id.as_uuid().as_bytes(),
                operation.operation_id.as_bytes(),
                &transition_code,
            ];
            if old.is_some() {
                parts.push(&old_id);
                parts.push(&old_version);
            } else {
                parts.push(suffix);
            }
            let base_result_digest = lifecycle_digest(b"buzz:identity-lifecycle-result:v1", &parts);
            let binds_operator_manifest = request.actor().operator_grant.is_some()
                && old.is_some()
                && matches!(
                    transition,
                    IdentityLifecycleTransition::Retire
                        | IdentityLifecycleTransition::Disable
                        | IdentityLifecycleTransition::Revoke
                );
            Ok(if binds_operator_manifest {
                operator_manifest_result_digest(base_result_digest, manifest_digest)
            } else {
                base_result_digest
            })
        }
        (_, NO_OP_OUTCOME) => Ok(lifecycle_digest(
            b"buzz:identity-lifecycle-result:v1",
            &[
                operation.community_id.as_uuid().as_bytes(),
                operation.operation_id.as_bytes(),
                &[transition as u8],
                b"no-op",
            ],
        )),
        _ => Err(IdentityLifecycleFailure::CorruptStoredResult),
    }
}

fn optional_binding_pair(
    binding_id: Option<Uuid>,
    binding_version: Option<i64>,
) -> Result<Option<(Uuid, i64)>, IdentityLifecycleFailure> {
    match (binding_id, binding_version) {
        (None, None) => Ok(None),
        (Some(binding_id), Some(binding_version)) if binding_version > 0 => {
            Ok(Some((binding_id, binding_version)))
        }
        _ => Err(IdentityLifecycleFailure::CorruptStoredResult),
    }
}

fn validate_enrollment_request(
    request: &AuthoritativeEnrollmentRequest,
) -> Result<(), IdentityLifecycleFailure> {
    validate_operation(&request.operation)?;
    if !matches!(
        request.transition,
        IdentityLifecycleTransition::Enroll | IdentityLifecycleTransition::Provision
    ) || request.issuer.is_empty()
        || request.subject.is_empty()
        || request.issuer.len() > 2048
        || request.subject.len() > 2048
        || request.principal_fingerprint == [0; 32]
        || request.event_author_pubkey == [0; 32]
        || request.policy_revision == 0
        || request.policy_digest == [0; 32]
        || request.enrollment_evidence_digest == [0; 32]
        || request.evidence_expires_at.timestamp_micros() <= 0
        || (request.transition == IdentityLifecycleTransition::Provision
            && request.provenance != IdentityBindingProvenance::Provisioned)
        || (request.transition == IdentityLifecycleTransition::Enroll
            && request.provenance == IdentityBindingProvenance::Provisioned)
        || request.operation.request_fingerprint
            != authoritative_enrollment_request_fingerprint(request)
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

fn validate_admission_loss_request(
    request: &ExactAdmissionLossRequest,
) -> Result<(), IdentityLifecycleFailure> {
    validate_operation(&request.operation)?;
    if request.target.binding_id.is_nil()
        || request.target.binding_version == 0
        || request.target.expected_lifecycle_revision != 1
        || request.target.principal_fingerprint == [0; 32]
        || request.target.event_author_pubkey == [0; 32]
        || matches!(
            request.cause,
            TrustedAdmissionLossCause::LocalPolicy { revision: 0 }
                | TrustedAdmissionLossCause::DelegationAuthority { revision: 0, .. }
        )
        || matches!(
            request.cause,
            TrustedAdmissionLossCause::DelegationAuthority {
                relationship_id,
                ..
            } if relationship_id.is_nil()
        )
        || request.operation.request_fingerprint
            != exact_admission_loss_request_fingerprint(request)
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

fn validate_active_target(
    target: &ExactActiveBindingTarget,
) -> Result<(), IdentityLifecycleFailure> {
    if target.binding_id.is_nil()
        || target.binding_version == 0
        || target.expected_lifecycle_revision != 1
        || target.principal_fingerprint == [0; 32]
        || target.event_author_pubkey == [0; 32]
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

fn validate_retire_request(
    request: &RetireIdentityPairRequest,
) -> Result<(), IdentityLifecycleFailure> {
    validate_operation(&request.operation)?;
    validate_active_target(&request.target)?;
    if request.operation.request_fingerprint != retire_identity_pair_request_fingerprint(request) {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

fn validate_disable_request(
    request: &DisableIdentityPrincipalRequest,
) -> Result<(), IdentityLifecycleFailure> {
    validate_operation(&request.operation)?;
    if request.principal_fingerprint == [0; 32]
        || request
            .expected_active_binding
            .is_some_and(|target| target.principal_fingerprint != request.principal_fingerprint)
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    if let Some(target) = &request.expected_active_binding {
        validate_active_target(target)?;
    }
    if request.operation.request_fingerprint
        != disable_identity_principal_request_fingerprint(request)
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

fn validate_revoke_request(
    request: &RevokeIdentityKeyRequest,
) -> Result<(), IdentityLifecycleFailure> {
    validate_operation(&request.operation)?;
    if request.event_author_pubkey == [0; 32]
        || request
            .expected_active_binding
            .is_some_and(|target| target.event_author_pubkey != request.event_author_pubkey)
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    if let Some(target) = &request.expected_active_binding {
        validate_active_target(target)?;
    }
    if request.operation.request_fingerprint != revoke_identity_key_request_fingerprint(request) {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

fn validate_retired_target(
    target: &ExactRetiredBindingTarget,
) -> Result<(), IdentityLifecycleFailure> {
    if target.binding_id.is_nil()
        || target.binding_version == 0
        || target.expected_lifecycle_revision != 2
        || target.principal_fingerprint == [0; 32]
        || target.event_author_pubkey == [0; 32]
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

fn replacement_proof_matches(
    operation: &IdentityLifecycleOperation,
    principal_fingerprint: [u8; 32],
    expected_intent: [u8; 32],
    proof: &VerifiedReplacementProof,
) -> bool {
    proof.community_id == operation.community_id
        && proof.operation_id == operation.operation_id
        && proof.intent_fingerprint == expected_intent
        && proof.principal_fingerprint == principal_fingerprint
}

fn validate_rotate_request(
    request: &RotateIdentityBindingRequest,
) -> Result<(), IdentityLifecycleFailure> {
    validate_operation(&request.operation)?;
    validate_active_target(&request.target)?;
    if request.replacement.event_author_pubkey == request.target.event_author_pubkey
        || !replacement_proof_matches(
            &request.operation,
            request.target.principal_fingerprint,
            rotate_identity_intent_fingerprint(request),
            &request.replacement,
        )
        || request.operation.request_fingerprint
            != rotate_identity_binding_request_fingerprint(request)
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

fn validate_recover_request(
    request: &RecoverIdentityBindingRequest,
) -> Result<(), IdentityLifecycleFailure> {
    validate_operation(&request.operation)?;
    validate_retired_target(&request.pending.target)?;
    if request.pending.fact_generation == 0
        || request.replacement.event_author_pubkey == request.pending.target.event_author_pubkey
        || !replacement_proof_matches(
            &request.operation,
            request.pending.target.principal_fingerprint,
            recover_identity_intent_fingerprint(request),
            &request.replacement,
        )
        || request.operation.request_fingerprint
            != recover_identity_binding_request_fingerprint(request)
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

fn validate_enable_request(
    request: &EnableIdentityPrincipalRequest,
) -> Result<(), IdentityLifecycleFailure> {
    validate_operation(&request.operation)?;
    validate_retired_target(&request.pending.target)?;
    if request.pending.fact_generation == 0
        || request.pending.target.principal_fingerprint != request.principal_fingerprint
        || request.pending.target.event_author_pubkey == request.replacement.event_author_pubkey
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    let intent = enable_identity_intent_fingerprint(request);
    let resolution_matches = request.principal_resolution.as_ref().map_or(
        request.actor.operator_grant.is_some(),
        |resolution| {
            resolution.community_id == request.operation.community_id
                && resolution.operation_id == request.operation.operation_id
                && resolution.intent_fingerprint == intent
                && resolution.principal_fingerprint == request.principal_fingerprint
        },
    );
    if request.principal_fingerprint == [0; 32]
        || request.disabled_fact_generation == 0
        || !replacement_proof_matches(
            &request.operation,
            request.principal_fingerprint,
            intent,
            &request.replacement,
        )
        || !resolution_matches
        || request.operation.request_fingerprint
            != enable_identity_principal_request_fingerprint(request)
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

fn validate_operation(
    operation: &IdentityLifecycleOperation,
) -> Result<(), IdentityLifecycleFailure> {
    if operation.community_id.as_uuid().is_nil()
        || operation.operation_id.is_nil()
        || operation.correlation_id.is_nil()
        || operation.attempt_id.is_nil()
        || operation.request_fingerprint == [0; 32]
    {
        return Err(IdentityLifecycleFailure::InvalidRequest);
    }
    Ok(())
}

fn binding_evidence(
    binding: &ActiveBinding,
) -> Result<IdentityBindingEvidence, IdentityLifecycleFailure> {
    Ok(IdentityBindingEvidence {
        binding_id: binding.binding_id,
        binding_version: u64_from_i64(binding.binding_version)?,
        lifecycle_revision: u64_from_i64(binding.lifecycle_revision)?,
    })
}

fn i64_from_u64(value: u64) -> Result<i64, IdentityLifecycleFailure> {
    i64::try_from(value).map_err(|_| IdentityLifecycleFailure::InvalidRequest)
}

fn u64_from_i64(value: i64) -> Result<u64, IdentityLifecycleFailure> {
    u64::try_from(value).map_err(|_| IdentityLifecycleFailure::CorruptStoredResult)
}

fn exact_32(value: &[u8]) -> Result<[u8; 32], IdentityLifecycleFailure> {
    value
        .try_into()
        .map_err(|_| IdentityLifecycleFailure::CorruptStoredResult)
}

fn operation_kind_for_transition(
    transition: IdentityLifecycleTransition,
) -> AuthorizationOperationKind {
    match transition {
        IdentityLifecycleTransition::Enroll => AuthorizationOperationKind::Enroll,
        IdentityLifecycleTransition::Provision => AuthorizationOperationKind::Provision,
        IdentityLifecycleTransition::Retire => AuthorizationOperationKind::Retire,
        IdentityLifecycleTransition::Disable => AuthorizationOperationKind::Disable,
        IdentityLifecycleTransition::Revoke => AuthorizationOperationKind::Revoke,
        IdentityLifecycleTransition::Rotate => AuthorizationOperationKind::Rotate,
        IdentityLifecycleTransition::Recover => AuthorizationOperationKind::Recover,
        IdentityLifecycleTransition::Enable => AuthorizationOperationKind::Enable,
        IdentityLifecycleTransition::AdmissionLoss => AuthorizationOperationKind::AdmissionLoss,
    }
}

fn operation_outcome(
    value: i16,
) -> Result<AuthorizationOperationOutcome, IdentityLifecycleFailure> {
    match value {
        APPLIED_OUTCOME => Ok(AuthorizationOperationOutcome::Applied),
        DENIED_OUTCOME => Ok(AuthorizationOperationOutcome::Denied),
        NO_OP_OUTCOME => Ok(AuthorizationOperationOutcome::NoOp),
        _ => Err(IdentityLifecycleFailure::CorruptStoredResult),
    }
}

fn event_outcome(value: i16) -> Result<AuthorizationEventOutcome, IdentityLifecycleFailure> {
    match value {
        APPLIED_OUTCOME => Ok(AuthorizationEventOutcome::Allowed),
        DENIED_OUTCOME => Ok(AuthorizationEventOutcome::Denied),
        NO_OP_OUTCOME => Ok(AuthorizationEventOutcome::NoOp),
        _ => Err(IdentityLifecycleFailure::CorruptStoredResult),
    }
}

fn authorization_reason(
    outcome: AuthorizationEventOutcome,
    event_kind: AuthorizationEventKind,
    denial: Option<IdentityLifecycleDenial>,
) -> Result<AuthorizationReasonCode, IdentityLifecycleFailure> {
    match (outcome, event_kind, denial) {
        (AuthorizationEventOutcome::Allowed, AuthorizationEventKind::AdmissionLost, None) => {
            Ok(AuthorizationReasonCode::Invalidated)
        }
        (AuthorizationEventOutcome::Allowed, _, None) => Ok(AuthorizationReasonCode::Current),
        (AuthorizationEventOutcome::NoOp, _, None) => Ok(AuthorizationReasonCode::Replay),
        (
            AuthorizationEventOutcome::Denied,
            _,
            Some(IdentityLifecycleDenial::PolicyUnavailable),
        ) => Ok(AuthorizationReasonCode::PolicyDenied),
        (AuthorizationEventOutcome::Denied, _, Some(IdentityLifecycleDenial::BindingExpired)) => {
            Ok(AuthorizationReasonCode::Expired)
        }
        (
            AuthorizationEventOutcome::Denied,
            _,
            Some(IdentityLifecycleDenial::PrincipalAlreadyBound),
        ) => Ok(AuthorizationReasonCode::BindingMismatch),
        (
            AuthorizationEventOutcome::Denied,
            _,
            Some(IdentityLifecycleDenial::EventAuthorUnavailable),
        ) => Ok(AuthorizationReasonCode::Invalid),
        (
            AuthorizationEventOutcome::Denied,
            _,
            Some(IdentityLifecycleDenial::LifecycleSelectorConflict),
        ) => Ok(AuthorizationReasonCode::Invalidated),
        (
            AuthorizationEventOutcome::Denied,
            _,
            Some(IdentityLifecycleDenial::StaleExpectedState),
        ) => Ok(AuthorizationReasonCode::StaleAuthority),
        _ => Err(IdentityLifecycleFailure::CorruptStoredResult),
    }
}

fn denial_from_authorization_reason(
    value: i16,
) -> Result<IdentityLifecycleDenial, IdentityLifecycleFailure> {
    match value {
        value if value == AuthorizationReasonCode::PolicyDenied as i16 => {
            Ok(IdentityLifecycleDenial::PolicyUnavailable)
        }
        value if value == AuthorizationReasonCode::Expired as i16 => {
            Ok(IdentityLifecycleDenial::BindingExpired)
        }
        value if value == AuthorizationReasonCode::BindingMismatch as i16 => {
            Ok(IdentityLifecycleDenial::PrincipalAlreadyBound)
        }
        value if value == AuthorizationReasonCode::Invalid as i16 => {
            Ok(IdentityLifecycleDenial::EventAuthorUnavailable)
        }
        value if value == AuthorizationReasonCode::Invalidated as i16 => {
            Ok(IdentityLifecycleDenial::LifecycleSelectorConflict)
        }
        value if value == AuthorizationReasonCode::StaleAuthority as i16 => {
            Ok(IdentityLifecycleDenial::StaleExpectedState)
        }
        _ => Err(IdentityLifecycleFailure::CorruptStoredResult),
    }
}

fn event_kind_for_transition(transition: IdentityLifecycleTransition) -> AuthorizationEventKind {
    match transition {
        IdentityLifecycleTransition::Enroll | IdentityLifecycleTransition::Provision => {
            AuthorizationEventKind::Enrolled
        }
        IdentityLifecycleTransition::Revoke => AuthorizationEventKind::Revoked,
        IdentityLifecycleTransition::Rotate => AuthorizationEventKind::Rotated,
        IdentityLifecycleTransition::Recover => AuthorizationEventKind::Recovered,
        IdentityLifecycleTransition::Enable => AuthorizationEventKind::PrincipalEnabled,
        IdentityLifecycleTransition::Retire => AuthorizationEventKind::Retired,
        IdentityLifecycleTransition::Disable => AuthorizationEventKind::PrincipalDisabled,
        IdentityLifecycleTransition::AdmissionLoss => AuthorizationEventKind::AdmissionLost,
    }
}

fn selector_fingerprint(scope: &[u8], community_id: CommunityId, parts: &[&[u8]]) -> [u8; 32] {
    let mut all = Vec::with_capacity(parts.len() + 2);
    all.push(scope);
    all.push(community_id.as_uuid().as_bytes().as_slice());
    all.extend_from_slice(parts);
    lifecycle_digest(b"buzz:identity-lifecycle-selector:v1", &all)
}

fn transition_digest(
    operation: &IdentityLifecycleOperation,
    transition: IdentityLifecycleTransition,
    old: Option<(Uuid, i64)>,
    successor: Option<(Uuid, i64)>,
) -> [u8; 32] {
    let old_id = old.map(|value| *value.0.as_bytes()).unwrap_or([0; 16]);
    let old_version = old.map(|value| value.1).unwrap_or(0).to_be_bytes();
    let successor_id = successor
        .map(|value| *value.0.as_bytes())
        .unwrap_or([0; 16]);
    let successor_version = successor.map(|value| value.1).unwrap_or(0).to_be_bytes();
    lifecycle_digest(
        b"buzz:identity-lifecycle-transition:v1",
        &[
            operation.community_id.as_uuid().as_bytes(),
            operation.operation_id.as_bytes(),
            &operation.request_fingerprint,
            &[transition as u8],
            &old_id,
            &old_version,
            &successor_id,
            &successor_version,
        ],
    )
}

fn admission_loss_cause_digest(cause: TrustedAdmissionLossCause) -> [u8; 32] {
    match cause {
        TrustedAdmissionLossCause::LocalBinding => lifecycle_digest(
            b"buzz:identity-admission-loss-cause:v1",
            &[b"local-binding"],
        ),
        TrustedAdmissionLossCause::LocalPolicy { revision } => lifecycle_digest(
            b"buzz:identity-admission-loss-cause:v1",
            &[b"local-policy", &revision.to_be_bytes()],
        ),
        TrustedAdmissionLossCause::DelegationAuthority {
            relationship_id,
            revision,
        } => lifecycle_digest(
            b"buzz:identity-admission-loss-cause:v1",
            &[
                b"delegation-authority",
                relationship_id.as_bytes(),
                &revision.to_be_bytes(),
            ],
        ),
    }
}

fn admission_loss_result_digest(
    request: &ExactAdmissionLossRequest,
    manifest_digest: [u8; 32],
) -> [u8; 32] {
    lifecycle_digest(
        b"buzz:identity-lifecycle-result:admission-loss:v2",
        &[
            request.operation.community_id.as_uuid().as_bytes(),
            request.operation.operation_id.as_bytes(),
            &[IdentityLifecycleTransition::AdmissionLoss as u8],
            request.target.binding_id.as_bytes(),
            &request.target.binding_version.to_be_bytes(),
            &admission_loss_cause_digest(request.cause),
            &manifest_digest,
        ],
    )
}

fn lifecycle_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

/// Production-sealed PostgreSQL fixture shared by crate-local restore tests.
/// All authoritative actor, cause, target, and raw request construction stays
/// inside this module; callers receive only the opaque prepared command and
/// its immutable binding identity.
#[cfg(test)]
pub(crate) mod admission_loss_test_fixture {
    use super::*;

    pub(crate) struct PreparedAdmissionLossPgFixture {
        pub(crate) prepared: PreparedAdmissionLoss,
        pub(crate) binding_id: Uuid,
    }

    pub(crate) async fn provision(db: &Db, domain: CommunityId) -> PreparedAdmissionLossPgFixture {
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(domain.as_uuid())
            .bind(format!(
                "s3-admission-fixture-{}.example",
                domain.as_uuid().simple()
            ))
            .execute(&db.pool)
            .await
            .expect("insert admission-loss fixture community");
        sqlx::query(
            "INSERT INTO identity_enrollment_policies \
             (community_id,policy_revision,enrollment_mode,policy_digest,effective_at) \
             VALUES ($1,1,1,$2,clock_timestamp()-INTERVAL '1 second')",
        )
        .bind(domain.as_uuid())
        .bind([201_u8; 32].as_slice())
        .execute(&db.pool)
        .await
        .expect("insert admission-loss fixture policy");
        sqlx::query(
            "INSERT INTO authorization_event_capacity \
             (community_id,max_events_per_domain,max_bytes_per_domain,max_envelope_bytes) \
             VALUES ($1,100,1048576,16384)",
        )
        .bind(domain.as_uuid())
        .execute(&db.pool)
        .await
        .expect("install admission-loss fixture audit capacity");
        sqlx::query(
            "INSERT INTO authorization_invalidation_domains (community_id,current_generation) \
             VALUES ($1,0)",
        )
        .bind(domain.as_uuid())
        .execute(&db.pool)
        .await
        .expect("activate admission-loss fixture invalidation");

        let principal_fingerprint = lifecycle_digest(
            b"buzz:s3-admission-loss-fixture:principal:v1",
            &[domain.as_uuid().as_bytes()],
        );
        let event_author_pubkey = lifecycle_digest(
            b"buzz:s3-admission-loss-fixture:event-author:v1",
            &[domain.as_uuid().as_bytes()],
        );
        let actor = resolve_actor(db, domain).await;
        let mut enrollment = AuthoritativeEnrollmentRequest {
            operation: operation(domain),
            transition: IdentityLifecycleTransition::Enroll,
            issuer: "https://fixture.issuer.example".to_owned(),
            subject: format!("fixture-subject-{}", domain.as_uuid().simple()),
            principal_fingerprint,
            event_author_pubkey,
            provenance: IdentityBindingProvenance::AttestedKey,
            policy_revision: 1,
            policy_digest: [201; 32],
            enrollment_evidence_digest: [202; 32],
            evidence_expires_at: Utc::now() + chrono::Duration::minutes(5),
            expires_at: None,
            actor,
        };
        enrollment.operation.request_fingerprint =
            authoritative_enrollment_request_fingerprint(&enrollment);
        let binding = match db
            .execute_authoritative_enrollment(&enrollment)
            .await
            .expect("enroll admission-loss fixture binding")
        {
            IdentityLifecycleObservation::Applied {
                binding: Some(binding),
                ..
            } => binding,
            observation => panic!("unexpected fixture enrollment observation: {observation:?}"),
        };

        seed_authority(db, domain, binding, event_author_pubkey).await;
        let prepared = prepare_admission_loss(
            AdmissionLossOperationIdentity::new(
                domain,
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
            )
            .expect("valid fixture operation identity"),
            ExactAdmissionLossTarget::from_authoritative_binding(
                binding.binding_id,
                binding.binding_version,
                binding.lifecycle_revision,
                principal_fingerprint,
                event_author_pubkey,
            )
            .expect("valid fixture admission-loss target"),
            TrustedAdmissionLossCause::LocalPolicy { revision: 1 },
            resolve_actor(db, domain).await,
        )
        .expect("prepare production-sealed admission loss");

        PreparedAdmissionLossPgFixture {
            prepared,
            binding_id: binding.binding_id,
        }
    }

    fn operation(domain: CommunityId) -> IdentityLifecycleOperation {
        IdentityLifecycleOperation {
            community_id: domain,
            operation_id: Uuid::new_v4(),
            request_fingerprint: [1; 32],
            correlation_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
        }
    }

    async fn resolve_actor(db: &Db, domain: CommunityId) -> AuthenticatedLifecycleActor {
        let mut transaction = db.pool.begin().await.expect("begin fixture actor lookup");
        let canonical = resolve_local_admission_loss_actor_tx(
            &mut transaction,
            domain,
            LocalAdmissionLossCause::Policy { policy_revision: 1 },
        )
        .await
        .expect("resolve fixture lifecycle actor");
        transaction
            .commit()
            .await
            .expect("commit fixture actor lookup");
        AuthenticatedLifecycleActor::from_sealed_event_actor([2; 32], canonical)
            .expect("seal fixture lifecycle actor")
    }

    async fn seed_authority(
        db: &Db,
        domain: CommunityId,
        binding: IdentityBindingEvidence,
        event_author_pubkey: [u8; 32],
    ) {
        let (creation_operation, creation_fingerprint): (Uuid, Vec<u8>) = sqlx::query_as(
            "SELECT creation_operation_id,creation_request_fingerprint \
             FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(domain.as_uuid())
        .bind(binding.binding_id)
        .fetch_one(&db.pool)
        .await
        .expect("load fixture binding receipt");
        let authority_object: [u8; 32] = Sha256::digest(binding.binding_id.as_bytes()).into();
        let authority_fence: [u8; 32] = Sha256::digest(authority_object).into();
        sqlx::query(
            "INSERT INTO authorization_authority_epochs \
             (community_id,object_kind,object_key,authority_epoch,fence,operation_id,request_fingerprint) \
             VALUES ($1,2,$2,1,$3,$4,$5)",
        )
        .bind(domain.as_uuid())
        .bind(authority_object.as_slice())
        .bind(authority_fence.as_slice())
        .bind(creation_operation)
        .bind(&creation_fingerprint)
        .execute(&db.pool)
        .await
        .expect("seed fixture authority epoch");
        sqlx::query(
            "INSERT INTO protected_object_authority \
             (community_id,object_kind,object_key,capability,actor_pubkey,binding_id, \
              binding_version,policy_revision,invalidation_generation,authority_epoch,fence, \
              issued_at,expires_at,operation_id,request_fingerprint) \
             VALUES ($1,2,$2,1,$3,$4,$5,1,0,1,$6,clock_timestamp()-INTERVAL '1 second', \
                     clock_timestamp()+INTERVAL '1 hour',$7,$8)",
        )
        .bind(domain.as_uuid())
        .bind(authority_object.as_slice())
        .bind(event_author_pubkey.as_slice())
        .bind(binding.binding_id)
        .bind(i64_from_u64(binding.binding_version).expect("fixture binding version"))
        .bind(authority_fence.as_slice())
        .bind(creation_operation)
        .bind(&creation_fingerprint)
        .execute(&db.pool)
        .await
        .expect("seed fixture protected authority");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DbConfig;
    use buzz_auth::{
        AuthError, AuthorizationEventCapacityPolicy, Nip98ReplayGuard, OperatorLifecycleVerifier,
    };
    use chrono::Duration;
    use nostr::{EventBuilder, Keys, Kind, Tag};

    struct AlwaysFreshOperatorReplay;

    impl Nip98ReplayGuard for AlwaysFreshOperatorReplay {
        fn try_mark_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            _event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, AuthError>> + Send + 'a>>
        {
            Box::pin(async { Ok(true) })
        }

        fn try_mark_all_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            event_ids: &'a [nostr::EventId],
            _ttl_secs: u64,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, AuthError>> + Send + 'a>>
        {
            Box::pin(async move {
                let valid_cardinality = (1..=3).contains(&event_ids.len());
                let distinct = event_ids
                    .iter()
                    .enumerate()
                    .all(|(index, event_id)| !event_ids[..index].contains(event_id));
                Ok(valid_cardinality && distinct)
            })
        }
    }

    #[tokio::test]
    async fn operator_replay_fixture_accepts_only_distinct_bounded_proof_sets() {
        let replay = AlwaysFreshOperatorReplay;
        let first = nostr::EventId::from_byte_array([1; 32]);
        let second = nostr::EventId::from_byte_array([2; 32]);
        let third = nostr::EventId::from_byte_array([3; 32]);
        let fourth = nostr::EventId::from_byte_array([4; 32]);

        assert!(replay
            .try_mark_all_in_scope("operator", &[first], 60)
            .await
            .expect("single proof set"));
        assert!(replay
            .try_mark_all_in_scope("operator", &[first, second, third], 60)
            .await
            .expect("three-proof set"));
        assert!(!replay
            .try_mark_all_in_scope("operator", &[], 60)
            .await
            .expect("empty proof set"));
        assert!(!replay
            .try_mark_all_in_scope("operator", &[first, first], 60)
            .await
            .expect("duplicate proof set"));
        assert!(!replay
            .try_mark_all_in_scope("operator", &[first, second, third, fourth], 60)
            .await
            .expect("four-proof set"));
    }

    async fn verified_operator_actor(
        domain: CommunityId,
        operation_id: Uuid,
        action: OperatorLifecycleAction,
        target: ExactActiveBindingTarget,
        replacement: Option<(&Keys, DateTime<Utc>)>,
    ) -> AuthenticatedLifecycleActor {
        let signer = Keys::generate();
        let verifier =
            OperatorLifecycleVerifier::new(vec![signer.public_key()]).expect("operator verifier");
        let replacement_coordinates =
            replacement.map(|(keys, expires_at)| (keys.public_key().to_bytes(), expires_at));
        let intent_operation = crate::operator_lifecycle::OperatorLifecycleOperation::new(
            domain,
            operation_id,
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .expect("operator operation");
        let intent_target = ExactActiveOperatorTarget::new(
            target.binding_id,
            target.binding_version,
            target.expected_lifecycle_revision,
            target.principal_fingerprint,
            target.event_author_pubkey,
        )
        .expect("operator target");
        let intent = match action {
            OperatorLifecycleAction::Retire => OperatorLifecycleIntent::retire(
                intent_operation,
                target.expected_lifecycle_revision,
                intent_target,
            ),
            OperatorLifecycleAction::Disable => OperatorLifecycleIntent::disable(
                intent_operation,
                target.expected_lifecycle_revision,
                target.principal_fingerprint,
                Some(intent_target),
            ),
            OperatorLifecycleAction::Revoke => OperatorLifecycleIntent::revoke(
                intent_operation,
                target.expected_lifecycle_revision,
                target.event_author_pubkey,
                Some(intent_target),
            ),
            OperatorLifecycleAction::Rotate => {
                let (event_author_pubkey, expires_at) =
                    replacement_coordinates.expect("rotate replacement");
                OperatorLifecycleIntent::rotate(
                    intent_operation,
                    target.expected_lifecycle_revision,
                    intent_target,
                    crate::operator_lifecycle::RequestedOperatorReplacement::new(
                        event_author_pubkey,
                        expires_at,
                    )
                    .expect("operator replacement"),
                )
            }
            _ => Err(OperatorLifecycleError::InvalidRequest),
        }
        .expect("operator intent");
        let intent_digest = intent.intent_digest();
        let mut body = serde_json::json!({
            "operation": { "operation_id": operation_id },
            "expected_revision": target.expected_lifecycle_revision,
            "target": {
                "binding_id": target.binding_id,
                "binding_version": target.binding_version,
                "principal_fingerprint": hex::encode(target.principal_fingerprint),
                "event_author_pubkey": hex::encode(target.event_author_pubkey),
            },
        });
        if let Some((keys, expires_at)) = replacement {
            body["replacement"] = serde_json::json!({
                "event_author_pubkey": hex::encode(keys.public_key().to_bytes()),
                "expires_at": expires_at,
            });
        }
        let body = serde_json::to_vec(&body).expect("serialize operator lifecycle body");
        let url = format!(
            "https://operator.example/operator/communities/{}/identity-lifecycle/{}",
            domain.as_uuid(),
            action.as_path_segment()
        );
        let payload = hex::encode(<[u8; 32]>::from(Sha256::digest(&body)));
        let intent_tag = hex::encode(intent_digest);
        let proof = EventBuilder::new(Kind::HttpAuth, "")
            .tags([
                Tag::parse(["u", url.as_str()]).expect("operator URL tag"),
                Tag::parse(["method", "POST"]).expect("operator method tag"),
                Tag::parse(["payload", payload.as_str()]).expect("operator payload tag"),
                Tag::parse(["buzz-intent", intent_tag.as_str()]).expect("operator intent tag"),
            ])
            .sign_with_keys(&signer)
            .expect("sign operator lifecycle proof");
        let replacement_proof = replacement.map(|(keys, _)| {
            EventBuilder::new(Kind::HttpAuth, "")
                .tags([
                    Tag::parse(["u", url.as_str()]).expect("replacement URL tag"),
                    Tag::parse(["method", "POST"]).expect("replacement method tag"),
                    Tag::parse(["payload", payload.as_str()]).expect("replacement payload tag"),
                    Tag::parse(["buzz-intent", intent_tag.as_str()])
                        .expect("replacement intent tag"),
                ])
                .sign_with_keys(keys)
                .expect("sign replacement proof")
        });
        let replacement_proof_json = replacement_proof
            .as_ref()
            .map(|proof| serde_json::to_string(proof).expect("serialize replacement proof"));
        let grant = verifier
            .verify_candidate(
                &serde_json::to_string(&proof).expect("serialize operator lifecycle proof"),
                None,
                replacement_proof_json.as_deref(),
                &url,
                &body,
                domain,
                action,
                operation_id,
                intent_digest,
                target.expected_lifecycle_revision,
                replacement_coordinates.map(|value| value.0),
                replacement_coordinates.map(|value| value.1),
            )
            .await
            .expect("verify operator lifecycle candidate")
            .claim_replay(&AlwaysFreshOperatorReplay)
            .await
            .expect("verify operator lifecycle grant");
        AuthenticatedLifecycleActor::from_verified_operator_grant(&grant, &intent)
            .expect("seal operator lifecycle actor")
    }

    fn operation() -> IdentityLifecycleOperation {
        IdentityLifecycleOperation {
            community_id: CommunityId::from_uuid(Uuid::new_v4()),
            operation_id: Uuid::new_v4(),
            request_fingerprint: [1; 32],
            correlation_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
        }
    }

    fn domain_operation(community_id: CommunityId) -> IdentityLifecycleOperation {
        let mut operation = operation();
        operation.community_id = community_id;
        operation
    }

    fn actor() -> AuthenticatedLifecycleActor {
        AuthenticatedLifecycleActor::test_only([2; 32])
    }

    async fn actor_for_postgres(db: &Db, community_id: CommunityId) -> AuthenticatedLifecycleActor {
        let mut transaction = db.pool.begin().await.expect("begin actor resolution");
        let canonical = resolve_local_admission_loss_actor_tx(
            &mut transaction,
            community_id,
            LocalAdmissionLossCause::Policy { policy_revision: 1 },
        )
        .await
        .expect("resolve database-bound lifecycle actor");
        transaction.commit().await.expect("commit actor resolution");
        AuthenticatedLifecycleActor::from_sealed_event_actor([2; 32], canonical)
            .expect("seal lifecycle actor")
    }

    async fn advance_protected_publication_head_for_postgres(
        db: &Db,
        community_id: CommunityId,
        object_kind: AuthorizationProtectedObjectKind,
        object_key: [u8; 32],
    ) -> Uuid {
        let mut transaction = db.pool.begin().await.expect("begin later protected head");
        let (before_epoch, before_fence): (i64, Vec<u8>) = sqlx::query_as(
            "SELECT authority_epoch,fence FROM authorization_authority_epochs \
             WHERE community_id=$1 AND object_kind=$2 AND object_key=$3 FOR UPDATE",
        )
        .bind(community_id.as_uuid())
        .bind(object_kind as i16)
        .bind(object_key.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .expect("lock prior protected head");
        let before_epoch = u64_from_i64(before_epoch).expect("valid prior authority epoch");
        let after_epoch = before_epoch
            .checked_add(1)
            .expect("advance authority epoch");
        let operation_id = Uuid::new_v4();
        let request_fingerprint = lifecycle_digest(
            b"buzz:test:later-protected-publication-request:v1",
            &[
                community_id.as_uuid().as_bytes(),
                operation_id.as_bytes(),
                &object_key,
            ],
        );
        let result_digest = lifecycle_digest(
            b"buzz:test:later-protected-publication-result:v1",
            &[operation_id.as_bytes(), &object_key],
        );
        let actor = AuthorizationEventActor::test_direct(community_id);
        let receipt = AuthorizationOperationReceipt::new(
            community_id,
            operation_id,
            request_fingerprint,
            AuthorizationOperationKind::ProtectedMutation,
            actor.clone(),
            AuthorizationOperationOutcome::Applied,
            result_digest,
        )
        .expect("construct later protected receipt");
        assert_eq!(
            record_authorization_operation_receipt_tx(&mut transaction, &receipt)
                .await
                .expect("record later protected receipt"),
            AuthorizationReceiptWrite::Inserted
        );
        let next_fence = lifecycle_digest(
            b"buzz:test:later-protected-publication-fence:v1",
            &[before_fence.as_slice(), operation_id.as_bytes()],
        );
        let epoch_update = sqlx::query(
            "UPDATE authorization_authority_epochs \
             SET authority_epoch=$4,fence=$5,operation_id=$6,request_fingerprint=$7, \
                 updated_at=GREATEST(clock_timestamp(),updated_at + INTERVAL '1 microsecond') \
             WHERE community_id=$1 AND object_kind=$2 AND object_key=$3 \
               AND authority_epoch=$8 AND fence=$9",
        )
        .bind(community_id.as_uuid())
        .bind(object_kind as i16)
        .bind(object_key.as_slice())
        .bind(i64_from_u64(after_epoch).expect("database after epoch"))
        .bind(next_fence.as_slice())
        .bind(operation_id)
        .bind(request_fingerprint.as_slice())
        .bind(i64_from_u64(before_epoch).expect("database before epoch"))
        .bind(before_fence.as_slice())
        .execute(&mut *transaction)
        .await
        .expect("advance later authority epoch");
        assert_eq!(epoch_update.rows_affected(), 1);
        let protected_update = sqlx::query(
            "UPDATE protected_object_authority \
             SET authority_epoch=$4,fence=$5,operation_id=$6,request_fingerprint=$7, \
                 issued_at=GREATEST(clock_timestamp(),issued_at + INTERVAL '1 microsecond'), \
                 expires_at=GREATEST(expires_at,clock_timestamp() + INTERVAL '1 hour') \
             WHERE community_id=$1 AND object_kind=$2 AND object_key=$3 \
               AND authority_epoch=$8 AND fence=$9",
        )
        .bind(community_id.as_uuid())
        .bind(object_kind as i16)
        .bind(object_key.as_slice())
        .bind(i64_from_u64(after_epoch).expect("database after epoch"))
        .bind(next_fence.as_slice())
        .bind(operation_id)
        .bind(request_fingerprint.as_slice())
        .bind(i64_from_u64(before_epoch).expect("database before epoch"))
        .bind(before_fence.as_slice())
        .execute(&mut *transaction)
        .await
        .expect("advance later protected authority");
        assert_eq!(protected_update.rows_affected(), 1);
        let delta = AuthorizationOperationVersionDelta::new(
            AuthorizationVersionComponentKind::AuthorityEpoch,
            authorization_version_authority_epoch_component_key(
                community_id,
                object_kind,
                object_key,
            ),
            before_epoch,
            after_epoch,
        )
        .expect("construct later protected delta");
        record_authorization_operation_version_delta_tx(
            &mut transaction,
            community_id,
            operation_id,
            request_fingerprint,
            vec![delta],
        )
        .await
        .expect("record later protected manifest");
        let event = NewAuthorizationEvent::new(
            community_id,
            Uuid::new_v4(),
            AuthorizationEventKind::ProtectedAllowed,
            AuthorizationEventOutcome::Allowed,
            AuthorizationReasonCode::Current,
            actor,
            Some(object_key),
            operation_id,
            Some(request_fingerprint),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .expect("construct later protected event");
        assert_eq!(
            record_authorization_event_tx(&mut transaction, &event)
                .await
                .expect("record later protected event"),
            AuthorizationReceiptWrite::Inserted
        );
        transaction
            .commit()
            .await
            .expect("commit later protected head");
        operation_id
    }

    fn replacement_proof(
        operation: IdentityLifecycleOperation,
        intent_fingerprint: [u8; 32],
        principal_fingerprint: [u8; 32],
        event_author_pubkey: [u8; 32],
    ) -> VerifiedReplacementProof {
        let expires_at = Utc::now() + Duration::hours(1);
        VerifiedReplacementProof::from_verifier_sealed_receipt(
            operation.community_id,
            operation.operation_id,
            intent_fingerprint,
            principal_fingerprint,
            event_author_pubkey,
            [91; 32],
            expires_at,
            expires_at,
        )
        .expect("valid sealed replacement proof")
    }

    fn principal_resolution(
        operation: IdentityLifecycleOperation,
        intent_fingerprint: [u8; 32],
        principal_fingerprint: [u8; 32],
    ) -> VerifiedPrincipalResolution {
        VerifiedPrincipalResolution::from_verifier_sealed_receipt(
            operation.community_id,
            operation.operation_id,
            intent_fingerprint,
            principal_fingerprint,
            "private-issuer-canary".to_owned(),
            "private-subject-canary".to_owned(),
            IdentityBindingProvenance::AttestedKey,
            1,
            [201; 32],
            [93; 32],
            Utc::now() + Duration::hours(1),
        )
        .expect("valid sealed principal resolution")
    }

    async fn enroll_for_postgres(
        db: &Db,
        community_id: CommunityId,
        principal_fingerprint: [u8; 32],
        event_author_pubkey: [u8; 32],
        subject: &str,
    ) -> IdentityBindingEvidence {
        let mut request = AuthoritativeEnrollmentRequest {
            operation: domain_operation(community_id),
            transition: IdentityLifecycleTransition::Enroll,
            issuer: "https://issuer.example".to_owned(),
            subject: subject.to_owned(),
            principal_fingerprint,
            event_author_pubkey,
            provenance: IdentityBindingProvenance::AttestedKey,
            policy_revision: 1,
            policy_digest: [201; 32],
            enrollment_evidence_digest: [202; 32],
            evidence_expires_at: Utc::now() + chrono::Duration::minutes(5),
            expires_at: None,
            actor: actor_for_postgres(db, community_id).await,
        };
        request.operation.request_fingerprint =
            authoritative_enrollment_request_fingerprint(&request);
        match db
            .execute_authoritative_enrollment(&request)
            .await
            .expect("enroll identity")
        {
            IdentityLifecycleObservation::Applied {
                binding: Some(binding),
                ..
            } => binding,
            observation => panic!("unexpected enrollment observation: {observation:?}"),
        }
    }

    async fn install_lifecycle_test_domain(db: &Db, community_id: CommunityId, max_events: i64) {
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(community_id.as_uuid())
            .bind(format!(
                "s3-fenced-{}.example",
                community_id.as_uuid().simple()
            ))
            .execute(&db.pool)
            .await
            .expect("insert fenced test community");
        sqlx::query(
            "INSERT INTO identity_enrollment_policies \
             (community_id,policy_revision,enrollment_mode,policy_digest,effective_at) \
             VALUES ($1,1,1,$2,clock_timestamp()-INTERVAL '1 second')",
        )
        .bind(community_id.as_uuid())
        .bind([201_u8; 32].as_slice())
        .execute(&db.pool)
        .await
        .expect("insert fenced test enrollment policy");
        sqlx::query(
            "INSERT INTO authorization_event_capacity \
             (community_id,max_events_per_domain,max_bytes_per_domain,max_envelope_bytes) \
             VALUES ($1,$2,1048576,16384)",
        )
        .bind(community_id.as_uuid())
        .bind(max_events)
        .execute(&db.pool)
        .await
        .expect("install fenced test audit capacity");
        sqlx::query(
            "INSERT INTO authorization_invalidation_domains (community_id,current_generation) \
             VALUES ($1,0)",
        )
        .bind(community_id.as_uuid())
        .execute(&db.pool)
        .await
        .expect("activate fenced test invalidation");
    }

    async fn create_disposable_lifecycle_database(prefix: &str) -> (Db, sqlx::PgPool, String) {
        use sqlx::postgres::PgPoolOptions;

        let admin_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_owned());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .expect("connect lifecycle test administrator");
        let name = format!("{prefix}_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("create lifecycle test database");
        let split = admin_url.rfind('/').expect("database URL path");
        let database_url = format!("{}/{}", &admin_url[..split], name);
        let db = Db::new(&DbConfig {
            database_url,
            min_connections: 0,
            max_connections: 4,
            ..DbConfig::default()
        })
        .await
        .expect("connect lifecycle test database");
        db.migrate().await.expect("migrate lifecycle test database");
        (db, admin, name)
    }

    async fn close_disposable_lifecycle_database(
        db: &Db,
        admin: sqlx::PgPool,
        _preserved_name: String,
    ) {
        db.pool.close().await;
        admin.close().await;
    }

    async fn prepare_policy_admission_loss_for_postgres(
        db: &Db,
        community_id: CommunityId,
        principal_fingerprint: [u8; 32],
        event_author_pubkey: [u8; 32],
        subject: &str,
    ) -> (PreparedAdmissionLoss, IdentityBindingEvidence, [u8; 32]) {
        let binding = enroll_for_postgres(
            db,
            community_id,
            principal_fingerprint,
            event_author_pubkey,
            subject,
        )
        .await;
        let (creation_operation, creation_fingerprint): (Uuid, Vec<u8>) = sqlx::query_as(
            "SELECT creation_operation_id,creation_request_fingerprint \
             FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(community_id.as_uuid())
        .bind(binding.binding_id)
        .fetch_one(&db.pool)
        .await
        .expect("load fenced admission binding receipt");
        let authority_object: [u8; 32] = Sha256::digest(binding.binding_id.as_bytes()).into();
        let authority_fence: [u8; 32] = Sha256::digest(authority_object).into();
        sqlx::query(
            "INSERT INTO authorization_authority_epochs \
             (community_id,object_kind,object_key,authority_epoch,fence,operation_id,request_fingerprint) \
             VALUES ($1,2,$2,1,$3,$4,$5)",
        )
        .bind(community_id.as_uuid())
        .bind(authority_object.as_slice())
        .bind(authority_fence.as_slice())
        .bind(creation_operation)
        .bind(&creation_fingerprint)
        .execute(&db.pool)
        .await
        .expect("seed fenced admission authority epoch");
        sqlx::query(
            "INSERT INTO protected_object_authority \
             (community_id,object_kind,object_key,capability,actor_pubkey,binding_id, \
              binding_version,policy_revision,invalidation_generation,authority_epoch,fence, \
              issued_at,expires_at,operation_id,request_fingerprint) \
             VALUES ($1,2,$2,1,$3,$4,$5,1,0,1,$6,clock_timestamp()-INTERVAL '1 second', \
                     clock_timestamp()+INTERVAL '1 hour',$7,$8)",
        )
        .bind(community_id.as_uuid())
        .bind(authority_object.as_slice())
        .bind(event_author_pubkey.as_slice())
        .bind(binding.binding_id)
        .bind(i64_from_u64(binding.binding_version).expect("binding version"))
        .bind(authority_fence.as_slice())
        .bind(creation_operation)
        .bind(&creation_fingerprint)
        .execute(&db.pool)
        .await
        .expect("seed fenced protected authority");
        let operation = AdmissionLossOperationIdentity::new(
            community_id,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .expect("valid fenced admission-loss operation identity");
        let target = ExactAdmissionLossTarget::from_authoritative_binding(
            binding.binding_id,
            binding.binding_version,
            1,
            principal_fingerprint,
            event_author_pubkey,
        )
        .expect("valid authoritative fenced admission-loss target");
        (
            prepare_admission_loss(
                operation,
                target,
                TrustedAdmissionLossCause::LocalPolicy { revision: 1 },
                actor_for_postgres(db, community_id).await,
            )
            .expect("prepare fenced admission loss"),
            binding,
            authority_object,
        )
    }

    #[test]
    fn enrollment_request_debug_redacts_private_coordinates() {
        let mut request = AuthoritativeEnrollmentRequest {
            operation: operation(),
            transition: IdentityLifecycleTransition::Enroll,
            issuer: "private-issuer-canary".to_owned(),
            subject: "private-subject-canary".to_owned(),
            principal_fingerprint: [3; 32],
            event_author_pubkey: [4; 32],
            provenance: IdentityBindingProvenance::AttestedKey,
            policy_revision: 1,
            policy_digest: [5; 32],
            enrollment_evidence_digest: [6; 32],
            evidence_expires_at: Utc::now() + chrono::Duration::minutes(5),
            expires_at: None,
            actor: actor(),
        };
        request.operation.request_fingerprint =
            authoritative_enrollment_request_fingerprint(&request);
        let debug = format!("{request:?}");
        assert!(!debug.contains("private-issuer-canary"));
        assert!(!debug.contains("private-subject-canary"));
        assert!(!debug.contains(&hex::encode([4; 32])));
        assert!(validate_enrollment_request(&request).is_ok());
    }

    #[test]
    fn transition_and_event_codes_remain_closed() {
        assert_eq!(IdentityLifecycleTransition::Enroll as i16, 1);
        assert_eq!(IdentityLifecycleTransition::AdmissionLoss as i16, 9);
        assert_eq!(
            event_kind_for_transition(IdentityLifecycleTransition::AdmissionLoss),
            AuthorizationEventKind::AdmissionLost
        );
        assert_eq!(IdentityLifecycleDenial::StaleExpectedState as i16, 8);
    }

    #[test]
    fn local_lifecycle_actor_cannot_select_operator_denial_provenance() {
        assert_eq!(
            actor().denial_event_kind(),
            AuthorizationEventKind::ProtectedDenied
        );
    }

    #[tokio::test]
    async fn verifier_sealed_operator_grant_is_the_only_operator_actor_origin() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let operation_id = Uuid::new_v4();
        let operator = verified_operator_actor(
            domain,
            operation_id,
            OperatorLifecycleAction::Retire,
            ExactActiveBindingTarget {
                binding_id: Uuid::new_v4(),
                binding_version: 1,
                expected_lifecycle_revision: 1,
                principal_fingerprint: [19; 32],
                event_author_pubkey: [20; 32],
            },
            None,
        )
        .await;
        assert_eq!(
            operator.denial_event_kind(),
            AuthorizationEventKind::OperatorDenied
        );
        assert!(operator.canonical(domain).is_ok());
        assert!(operator
            .canonical(CommunityId::from_uuid(Uuid::new_v4()))
            .is_err());
        assert_eq!(
            format!("{operator:?}"),
            "AuthenticatedLifecycleActor([REDACTED])"
        );
    }

    #[test]
    fn admission_loss_manifest_requires_exact_complete_component_equality() {
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let selector_a = Uuid::new_v4();
        let selector_b = Uuid::new_v4();
        let relationship_id = Uuid::new_v4();
        let mut lifecycle = vec![
            AuthorizationOperationVersionDelta::new(
                AuthorizationVersionComponentKind::LifecycleSelector,
                authorization_version_lifecycle_selector_component_key(community_id, selector_a),
                0,
                1,
            )
            .expect("first selector"),
            AuthorizationOperationVersionDelta::new(
                AuthorizationVersionComponentKind::LifecycleSelector,
                authorization_version_lifecycle_selector_component_key(community_id, selector_b),
                0,
                1,
            )
            .expect("second selector"),
        ];
        lifecycle.sort_by_key(|component| (component.component_kind(), component.component_key()));
        let invalidation = AuthorizationOperationVersionDelta::new(
            AuthorizationVersionComponentKind::InvalidationGeneration,
            authorization_version_invalidation_generation_component_key(community_id),
            7,
            8,
        )
        .expect("invalidation generation");
        let authority = AuthorizationOperationVersionDelta::new(
            AuthorizationVersionComponentKind::AuthorityEpoch,
            authorization_version_authority_epoch_component_key(
                community_id,
                AuthorizationProtectedObjectKind::Channel,
                [41; 32],
            ),
            3,
            4,
        )
        .expect("authority epoch");
        let relationship = AuthorizationOperationVersionDelta::new(
            AuthorizationVersionComponentKind::DelegatedRelationship,
            authorization_version_delegated_relationship_component_key(
                community_id,
                relationship_id,
            ),
            0,
            5,
        )
        .expect("delegated relationship");
        let mut exact = lifecycle.clone();
        exact.extend([
            invalidation.clone(),
            authority.clone(),
            relationship.clone(),
        ]);
        exact.sort_by_key(|component| (component.component_kind(), component.component_key()));
        assert!(validate_admission_loss_manifest_shape(
            community_id,
            TrustedAdmissionLossCause::DelegationAuthority {
                relationship_id,
                revision: 5,
            },
            1,
            &lifecycle,
            &exact,
        )
        .is_ok());
        let zero_authority: Vec<_> = exact
            .iter()
            .filter(|component| {
                component.component_kind() != AuthorizationVersionComponentKind::AuthorityEpoch
            })
            .cloned()
            .collect();
        assert!(validate_admission_loss_manifest_shape(
            community_id,
            TrustedAdmissionLossCause::DelegationAuthority {
                relationship_id,
                revision: 5,
            },
            0,
            &lifecycle,
            &zero_authority,
        )
        .is_ok());
        assert!(matches!(
            validate_admission_loss_manifest_shape(
                community_id,
                TrustedAdmissionLossCause::DelegationAuthority {
                    relationship_id,
                    revision: 5,
                },
                1,
                &lifecycle,
                &zero_authority,
            ),
            Err(IdentityLifecycleFailure::CorruptStoredResult)
        ));
        assert!(validate_exact_version_components(&exact, &exact).is_ok());

        let corruptions = [
            exact
                .iter()
                .filter(|component| {
                    component.component_kind() != AuthorizationVersionComponentKind::AuthorityEpoch
                })
                .cloned()
                .collect::<Vec<_>>(),
            {
                let mut value = exact.clone();
                value.retain(|component| component != &authority);
                value.push(
                    AuthorizationOperationVersionDelta::new(
                        AuthorizationVersionComponentKind::AuthorityEpoch,
                        authorization_version_authority_epoch_component_key(
                            community_id,
                            AuthorizationProtectedObjectKind::Channel,
                            [42; 32],
                        ),
                        3,
                        4,
                    )
                    .expect("wrong authority key"),
                );
                value.sort_by_key(|component| {
                    (component.component_kind(), component.component_key())
                });
                value
            },
            {
                let mut value = exact.clone();
                value.retain(|component| component != &authority);
                value.push(
                    AuthorizationOperationVersionDelta::new(
                        AuthorizationVersionComponentKind::AuthorityEpoch,
                        authority.component_key(),
                        2,
                        4,
                    )
                    .expect("wrong authority versions"),
                );
                value.sort_by_key(|component| {
                    (component.component_kind(), component.component_key())
                });
                value
            },
            {
                let mut value = exact.clone();
                value.push(
                    AuthorizationOperationVersionDelta::new(
                        AuthorizationVersionComponentKind::AuthorityEpoch,
                        authorization_version_authority_epoch_component_key(
                            community_id,
                            AuthorizationProtectedObjectKind::Repository,
                            [43; 32],
                        ),
                        1,
                        2,
                    )
                    .expect("extra authority"),
                );
                value.sort_by_key(|component| {
                    (component.component_kind(), component.component_key())
                });
                value
            },
            {
                let mut value = exact.clone();
                value.retain(|component| component != &invalidation);
                value
            },
            {
                let mut value = exact.clone();
                value.retain(|component| component != &invalidation);
                value.push(
                    AuthorizationOperationVersionDelta::new(
                        AuthorizationVersionComponentKind::InvalidationGeneration,
                        [44; 32],
                        7,
                        8,
                    )
                    .expect("wrong invalidation key"),
                );
                value.sort_by_key(|component| {
                    (component.component_kind(), component.component_key())
                });
                value
            },
            {
                let mut value = exact.clone();
                value.push(
                    AuthorizationOperationVersionDelta::new(
                        AuthorizationVersionComponentKind::InvalidationGeneration,
                        [45; 32],
                        1,
                        2,
                    )
                    .expect("extra invalidation"),
                );
                value.sort_by_key(|component| {
                    (component.component_kind(), component.component_key())
                });
                value
            },
            exact
                .iter()
                .filter(|component| component != &&relationship)
                .cloned()
                .collect::<Vec<_>>(),
            {
                let mut value = exact.clone();
                value.retain(|component| component != &relationship);
                value.push(
                    AuthorizationOperationVersionDelta::new(
                        AuthorizationVersionComponentKind::DelegatedRelationship,
                        authorization_version_delegated_relationship_component_key(
                            community_id,
                            Uuid::new_v4(),
                        ),
                        0,
                        5,
                    )
                    .expect("wrong relationship key"),
                );
                value.sort_by_key(|component| {
                    (component.component_kind(), component.component_key())
                });
                value
            },
            {
                let mut value = exact.clone();
                value.push(
                    AuthorizationOperationVersionDelta::new(
                        AuthorizationVersionComponentKind::DelegatedRelationship,
                        authorization_version_delegated_relationship_component_key(
                            community_id,
                            Uuid::new_v4(),
                        ),
                        0,
                        1,
                    )
                    .expect("extra relationship"),
                );
                value.sort_by_key(|component| {
                    (component.component_kind(), component.component_key())
                });
                value
            },
            {
                let mut value = exact.clone();
                value.retain(|component| component != &lifecycle[0]);
                value
            },
            {
                let mut value = exact.clone();
                value.retain(|component| component != &lifecycle[0]);
                value.push(
                    AuthorizationOperationVersionDelta::new(
                        AuthorizationVersionComponentKind::LifecycleSelector,
                        authorization_version_lifecycle_selector_component_key(
                            community_id,
                            Uuid::new_v4(),
                        ),
                        0,
                        1,
                    )
                    .expect("wrong selector key"),
                );
                value.sort_by_key(|component| {
                    (component.component_kind(), component.component_key())
                });
                value
            },
            {
                let mut value = exact.clone();
                value.push(
                    AuthorizationOperationVersionDelta::new(
                        AuthorizationVersionComponentKind::LifecycleSelector,
                        authorization_version_lifecycle_selector_component_key(
                            community_id,
                            Uuid::new_v4(),
                        ),
                        0,
                        1,
                    )
                    .expect("extra selector"),
                );
                value.sort_by_key(|component| {
                    (component.component_kind(), component.component_key())
                });
                value
            },
        ];
        for corrupted in corruptions {
            assert!(matches!(
                validate_exact_version_components(&corrupted, &exact),
                Err(IdentityLifecycleFailure::CorruptStoredResult)
            ));
        }
    }

    #[test]
    fn retiring_binding_manifest_rejects_wrong_extra_and_missing_components() {
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let selector = AuthorizationOperationVersionDelta::new(
            AuthorizationVersionComponentKind::LifecycleSelector,
            authorization_version_lifecycle_selector_component_key(community_id, Uuid::new_v4()),
            0,
            1,
        )
        .expect("selector");
        let lifecycle = vec![selector.clone()];
        let invalidation = AuthorizationOperationVersionDelta::new(
            AuthorizationVersionComponentKind::InvalidationGeneration,
            authorization_version_invalidation_generation_component_key(community_id),
            4,
            5,
        )
        .expect("invalidation");
        let authority = AuthorizationOperationVersionDelta::new(
            AuthorizationVersionComponentKind::AuthorityEpoch,
            authorization_version_authority_epoch_component_key(
                community_id,
                AuthorizationProtectedObjectKind::Repository,
                [41; 32],
            ),
            8,
            9,
        )
        .expect("authority");
        let mut exact = vec![selector, invalidation.clone(), authority];
        exact.sort_by_key(|component| (component.component_kind(), component.component_key()));
        assert!(validate_retiring_binding_manifest_shape(community_id, &lifecycle, &exact).is_ok());

        let missing: Vec<_> = exact
            .iter()
            .filter(|component| {
                component.component_kind()
                    != AuthorizationVersionComponentKind::InvalidationGeneration
            })
            .cloned()
            .collect();
        assert!(
            validate_retiring_binding_manifest_shape(community_id, &lifecycle, &missing).is_err()
        );

        let mut wrong = exact.clone();
        wrong.retain(|component| {
            component.component_kind() != AuthorizationVersionComponentKind::InvalidationGeneration
        });
        wrong.push(
            AuthorizationOperationVersionDelta::new(
                AuthorizationVersionComponentKind::InvalidationGeneration,
                authorization_version_invalidation_generation_component_key(
                    CommunityId::from_uuid(Uuid::new_v4()),
                ),
                4,
                5,
            )
            .expect("wrong-domain invalidation"),
        );
        wrong.sort_by_key(|component| (component.component_kind(), component.component_key()));
        assert!(
            validate_retiring_binding_manifest_shape(community_id, &lifecycle, &wrong).is_err()
        );

        let mut extra = exact;
        extra.push(
            AuthorizationOperationVersionDelta::new(
                AuthorizationVersionComponentKind::Policy,
                [91; 32],
                1,
                2,
            )
            .expect("extra component"),
        );
        extra.sort_by_key(|component| (component.component_kind(), component.component_key()));
        assert!(
            validate_retiring_binding_manifest_shape(community_id, &lifecycle, &extra).is_err()
        );

        let zero_authority: Vec<_> = exact_without_authority(community_id, lifecycle[0].clone());
        assert!(validate_retiring_binding_manifest_shape(
            community_id,
            &lifecycle,
            &zero_authority,
        )
        .is_ok());
    }

    fn exact_without_authority(
        community_id: CommunityId,
        selector: AuthorizationOperationVersionDelta,
    ) -> Vec<AuthorizationOperationVersionDelta> {
        let mut components = vec![
            selector,
            AuthorizationOperationVersionDelta::new(
                AuthorizationVersionComponentKind::InvalidationGeneration,
                authorization_version_invalidation_generation_component_key(community_id),
                4,
                5,
            )
            .expect("invalidation"),
        ];
        components.sort_by_key(|component| (component.component_kind(), component.component_key()));
        components
    }

    #[test]
    fn admission_loss_requires_exact_active_revision_and_cause_revision() {
        let mut request = ExactAdmissionLossRequest {
            operation: operation(),
            target: ExactAdmissionLossTarget {
                binding_id: Uuid::new_v4(),
                binding_version: 1,
                expected_lifecycle_revision: 2,
                principal_fingerprint: [7; 32],
                event_author_pubkey: [8; 32],
            },
            cause: TrustedAdmissionLossCause::LocalPolicy { revision: 0 },
            actor: actor(),
        };
        request.operation.request_fingerprint = exact_admission_loss_request_fingerprint(&request);
        assert!(matches!(
            validate_admission_loss_request(&request),
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));
    }

    #[test]
    fn selector_digest_is_domain_and_scope_separated() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let p = selector_fingerprint(b"retired-pair", domain, &[&[1; 32], &[2; 32]]);
        let q = selector_fingerprint(b"pending-replacement", domain, &[&[1; 32], &[2; 32]]);
        assert_ne!(p, q);
        assert_eq!(
            p,
            selector_fingerprint(b"retired-pair", domain, &[&[1; 32], &[2; 32]])
        );
    }

    #[test]
    fn destructive_requests_bind_exact_target_and_expected_presence() {
        let target = ExactActiveBindingTarget {
            binding_id: Uuid::new_v4(),
            binding_version: 9,
            expected_lifecycle_revision: 1,
            principal_fingerprint: [9; 32],
            event_author_pubkey: [10; 32],
        };
        let mut retire = RetireIdentityPairRequest {
            operation: operation(),
            target,
            actor: actor(),
        };
        retire.operation.request_fingerprint = retire_identity_pair_request_fingerprint(&retire);
        assert!(validate_retire_request(&retire).is_ok());
        retire.target.binding_version += 1;
        assert!(matches!(
            validate_retire_request(&retire),
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));

        let mut disable = DisableIdentityPrincipalRequest {
            operation: operation(),
            principal_fingerprint: target.principal_fingerprint,
            expected_active_binding: None,
            actor: actor(),
        };
        disable.operation.request_fingerprint =
            disable_identity_principal_request_fingerprint(&disable);
        assert!(validate_disable_request(&disable).is_ok());
        disable.expected_active_binding = Some(target);
        assert!(matches!(
            validate_disable_request(&disable),
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));

        let mut revoke = RevokeIdentityKeyRequest {
            operation: operation(),
            event_author_pubkey: target.event_author_pubkey,
            expected_active_binding: Some(target),
            actor: actor(),
        };
        revoke.operation.request_fingerprint = revoke_identity_key_request_fingerprint(&revoke);
        assert!(validate_revoke_request(&revoke).is_ok());
        revoke.event_author_pubkey = [11; 32];
        assert!(matches!(
            validate_revoke_request(&revoke),
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));
    }

    #[test]
    fn operation_and_admission_debug_redact_all_authority_coordinates() {
        let operation = operation();
        let relationship_id = Uuid::new_v4();
        let request = ExactAdmissionLossRequest {
            operation,
            target: ExactAdmissionLossTarget {
                binding_id: Uuid::new_v4(),
                binding_version: 41,
                expected_lifecycle_revision: 1,
                principal_fingerprint: [12; 32],
                event_author_pubkey: [13; 32],
            },
            cause: TrustedAdmissionLossCause::DelegationAuthority {
                relationship_id,
                revision: 17,
            },
            actor: actor(),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains(&operation.operation_id.to_string()));
        assert!(!debug.contains(&operation.correlation_id.to_string()));
        assert!(!debug.contains(&relationship_id.to_string()));
        assert!(!debug.contains(&hex::encode([12; 32])));
        assert!(!debug.contains(&hex::encode([13; 32])));
    }

    #[test]
    fn prepared_admission_loss_is_canonical_sealed_and_redacted() {
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let operation_id = Uuid::new_v4();
        let binding_id = Uuid::new_v4();
        let operation = AdmissionLossOperationIdentity::new(
            community_id,
            operation_id,
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .expect("valid authoritative operation identity");
        let target = ExactAdmissionLossTarget::from_authoritative_binding(
            binding_id, 41, 1, [14; 32], [15; 32],
        )
        .expect("valid authoritative target");
        let prepared = prepare_admission_loss(
            operation,
            target,
            TrustedAdmissionLossCause::LocalPolicy { revision: 7 },
            AuthenticatedLifecycleActor::from_sealed_event_actor(
                [2; 32],
                AuthorizationEventActor::test_direct(community_id),
            )
            .expect("seal authoritative lifecycle actor"),
        )
        .expect("prepare authoritative admission loss");
        assert_eq!(prepared.authorization_domain(), community_id);
        assert_eq!(prepared.operation_id(), operation_id);
        assert_ne!(prepared.request_fingerprint(), [0; 32]);
        let debug = format!("{prepared:?}");
        assert!(!debug.contains(&operation_id.to_string()));
        assert!(!debug.contains(&binding_id.to_string()));
        assert!(!debug.contains(&hex::encode(prepared.request_fingerprint())));
        assert!(!debug.contains(&hex::encode([14; 32])));

        let mut request = prepared.request.clone();
        request.operation.request_fingerprint[0] ^= 1;
        assert!(matches!(
            PreparedAdmissionLoss::seal(request),
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));
        assert!(AdmissionLossOperationIdentity::new(
            community_id,
            Uuid::nil(),
            Uuid::new_v4(),
            Uuid::new_v4()
        )
        .is_err());
        assert!(ExactAdmissionLossTarget::from_authoritative_binding(
            binding_id, 41, 1, [0; 32], [15; 32]
        )
        .is_err());
    }

    #[test]
    fn prepared_admission_loss_failures_classify_restore_terminalization() {
        assert!(matches!(
            map_prepared_admission_loss_failure(IdentityLifecycleFailure::InvalidRequest),
            PreparedAdmissionLossWriteFailure::Rejected(
                PreparedAdmissionLossRejection::InvalidRequest
            )
        ));
        assert!(matches!(
            map_prepared_admission_loss_failure(IdentityLifecycleFailure::IntentConflict),
            PreparedAdmissionLossWriteFailure::Rejected(
                PreparedAdmissionLossRejection::IntentConflict
            )
        ));
        assert!(matches!(
            map_prepared_admission_loss_failure(IdentityLifecycleFailure::AuditUnavailable),
            PreparedAdmissionLossWriteFailure::AuditUnavailable
        ));
        assert!(matches!(
            map_prepared_admission_loss_failure(IdentityLifecycleFailure::CorruptStoredResult),
            PreparedAdmissionLossWriteFailure::CorruptStoredResult
        ));
        assert!(matches!(
            map_prepared_admission_loss_failure(IdentityLifecycleFailure::Storage(
                DbError::InvalidData("deterministic storage failure".to_owned())
            )),
            PreparedAdmissionLossWriteFailure::Database(DbError::InvalidData(_))
        ));
    }

    #[test]
    fn replay_history_requires_exact_transition_digest_and_state_tuple() {
        let operation = operation();
        let old = (Uuid::new_v4(), 23_i64);
        let mut history = StoredLifecycleHistory {
            transition_kind: IdentityLifecycleTransition::Retire as i16,
            outcome_code: APPLIED_OUTCOME,
            old_binding_id: Some(old.0),
            old_binding_version: Some(old.1),
            old_prior_lifecycle_revision: Some(1),
            old_prior_state: Some(1),
            old_resulting_lifecycle_revision: Some(2),
            old_resulting_state: Some(2),
            successor_binding_id: None,
            successor_binding_version: None,
            successor_lifecycle_revision: None,
            successor_state: None,
            request_fingerprint: operation.request_fingerprint.to_vec(),
            transition_digest: transition_digest(
                &operation,
                IdentityLifecycleTransition::Retire,
                Some(old),
                None,
            )
            .to_vec(),
        };
        assert!(validate_replay_history(
            &operation,
            IdentityLifecycleTransition::Retire,
            APPLIED_OUTCOME,
            &history,
        )
        .is_ok());

        history.transition_digest[0] ^= 1;
        assert!(matches!(
            validate_replay_history(
                &operation,
                IdentityLifecycleTransition::Retire,
                APPLIED_OUTCOME,
                &history,
            ),
            Err(IdentityLifecycleFailure::CorruptStoredResult)
        ));
    }

    #[test]
    fn enrollment_noop_replay_digest_reproduces_exact_original_binding() {
        let mut request = AuthoritativeEnrollmentRequest {
            operation: operation(),
            transition: IdentityLifecycleTransition::Enroll,
            issuer: "issuer".to_owned(),
            subject: "subject".to_owned(),
            principal_fingerprint: [14; 32],
            event_author_pubkey: [15; 32],
            provenance: IdentityBindingProvenance::AttestedKey,
            policy_revision: 3,
            policy_digest: [16; 32],
            enrollment_evidence_digest: [17; 32],
            evidence_expires_at: Utc::now() + chrono::Duration::minutes(5),
            expires_at: None,
            actor: actor(),
        };
        request.operation.request_fingerprint =
            authoritative_enrollment_request_fingerprint(&request);
        let binding = IdentityBindingEvidence {
            binding_id: Uuid::new_v4(),
            binding_version: 29,
            lifecycle_revision: 1,
        };
        let digest = replay_result_digest(
            LifecycleReplayRequest::Enrollment(&request),
            NO_OP_OUTCOME,
            None,
            Some(binding),
            None,
            [0; 32],
            None,
        )
        .expect("valid replay digest");
        assert_eq!(
            digest,
            lifecycle_digest(
                b"buzz:identity-lifecycle-result:v1",
                &[
                    request.operation.community_id.as_uuid().as_bytes(),
                    request.operation.operation_id.as_bytes(),
                    &[IdentityLifecycleTransition::Enroll as u8],
                    b"no-op",
                    binding.binding_id.as_bytes(),
                    &binding.binding_version.to_be_bytes(),
                ],
            )
        );
    }

    #[test]
    fn rotate_request_requires_exact_operation_bound_replacement_proof() {
        let operation = operation();
        let target = ExactActiveBindingTarget {
            binding_id: Uuid::new_v4(),
            binding_version: 17,
            expected_lifecycle_revision: 1,
            principal_fingerprint: [31; 32],
            event_author_pubkey: [32; 32],
        };
        let mut request = RotateIdentityBindingRequest {
            operation,
            target,
            replacement: replacement_proof(operation, [1; 32], [31; 32], [33; 32]),
            actor: actor(),
        };
        let intent = rotate_identity_intent_fingerprint(&request);
        request.replacement.intent_fingerprint = intent;
        request.operation.request_fingerprint =
            rotate_identity_binding_request_fingerprint(&request);
        assert!(validate_rotate_request(&request).is_ok());

        request.replacement.operation_id = Uuid::new_v4();
        assert!(matches!(
            validate_rotate_request(&request),
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));
        request.replacement.operation_id = operation.operation_id;
        request.replacement.event_author_pubkey = target.event_author_pubkey;
        assert!(matches!(
            validate_rotate_request(&request),
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));
    }

    #[test]
    fn sealed_proof_fingerprints_bind_every_private_coordinate() {
        type ReplacementMutation = Box<dyn Fn(&mut VerifiedReplacementProof)>;
        type ResolutionMutation = Box<dyn Fn(&mut VerifiedPrincipalResolution)>;

        let operation = operation();
        let replacement = replacement_proof(operation, [21; 32], [22; 32], [23; 32]);
        let replacement_fingerprint = replacement.proof_fingerprint();
        let replacement_mutations: Vec<ReplacementMutation> = vec![
            Box::new(|proof| proof.community_id = CommunityId::from_uuid(Uuid::new_v4())),
            Box::new(|proof| proof.operation_id = Uuid::new_v4()),
            Box::new(|proof| proof.intent_fingerprint = [24; 32]),
            Box::new(|proof| proof.principal_fingerprint = [25; 32]),
            Box::new(|proof| proof.event_author_pubkey = [26; 32]),
            Box::new(|proof| proof.proof_digest = [27; 32]),
            Box::new(|proof| proof.expires_at += Duration::seconds(1)),
            Box::new(|proof| proof.authorization_expires_at -= Duration::seconds(1)),
        ];
        for mutate in replacement_mutations {
            let mut changed = replacement.clone();
            mutate(&mut changed);
            assert_ne!(changed.proof_fingerprint(), replacement_fingerprint);
        }

        let resolution = principal_resolution(operation, [31; 32], [32; 32]);
        let resolution_fingerprint = resolution.proof_fingerprint();
        let resolution_mutations: Vec<ResolutionMutation> = vec![
            Box::new(|proof| proof.community_id = CommunityId::from_uuid(Uuid::new_v4())),
            Box::new(|proof| proof.operation_id = Uuid::new_v4()),
            Box::new(|proof| proof.intent_fingerprint = [33; 32]),
            Box::new(|proof| proof.principal_fingerprint = [34; 32]),
            Box::new(|proof| proof.issuer.push_str("-changed")),
            Box::new(|proof| proof.subject.push_str("-changed")),
            Box::new(|proof| proof.provenance = IdentityBindingProvenance::RiskLabelledTofu),
            Box::new(|proof| proof.policy_revision += 1),
            Box::new(|proof| proof.policy_digest = [35; 32]),
            Box::new(|proof| proof.proof_digest = [36; 32]),
            Box::new(|proof| proof.expires_at += Duration::seconds(1)),
        ];
        for mutate in resolution_mutations {
            let mut changed = resolution.clone();
            mutate(&mut changed);
            assert_ne!(changed.proof_fingerprint(), resolution_fingerprint);
        }
    }

    #[test]
    fn enable_exact_pending_lineages_have_distinct_sealed_intents() {
        let operation = operation();
        let principal = [41; 32];
        let mut first = EnableIdentityPrincipalRequest {
            operation,
            principal_fingerprint: principal,
            disabled_fact_generation: 3,
            pending: ExpectedPendingReplacement {
                target: ExactRetiredBindingTarget {
                    binding_id: Uuid::new_v4(),
                    binding_version: 17,
                    expected_lifecycle_revision: 2,
                    principal_fingerprint: principal,
                    event_author_pubkey: [43; 32],
                },
                fact_generation: 4,
            },
            replacement: replacement_proof(operation, [1; 32], principal, [42; 32]),
            principal_resolution: Some(principal_resolution(operation, [1; 32], principal)),
            actor: actor(),
        };
        let first_intent = enable_identity_intent_fingerprint(&first);
        first.replacement.intent_fingerprint = first_intent;
        first
            .principal_resolution
            .as_mut()
            .expect("principal resolution")
            .intent_fingerprint = first_intent;
        first.operation.request_fingerprint = enable_identity_principal_request_fingerprint(&first);
        assert!(validate_enable_request(&first).is_ok());

        let mut second = first.clone();
        second.pending = ExpectedPendingReplacement {
            target: ExactRetiredBindingTarget {
                binding_id: Uuid::new_v4(),
                binding_version: 19,
                expected_lifecycle_revision: 2,
                principal_fingerprint: principal,
                event_author_pubkey: [43; 32],
            },
            fact_generation: 5,
        };
        let second_intent = enable_identity_intent_fingerprint(&second);
        assert_ne!(first_intent, second_intent);
        second.replacement.intent_fingerprint = second_intent;
        second
            .principal_resolution
            .as_mut()
            .expect("principal resolution")
            .intent_fingerprint = second_intent;
        second.operation.request_fingerprint =
            enable_identity_principal_request_fingerprint(&second);
        assert!(validate_enable_request(&second).is_ok());

        second.disabled_fact_generation += 1;
        assert!(matches!(
            validate_enable_request(&second),
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));
        let debug = format!(
            "{:?} {:?} {:?}",
            second, second.replacement, second.principal_resolution
        );
        assert!(!debug.contains("private-issuer-canary"));
        assert!(!debug.contains("private-subject-canary"));
        assert!(!debug.contains(&hex::encode([42; 32])));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_operator_first_execution_uses_database_exclusive_expiry() {
        let url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_owned());
        let pool = sqlx::PgPool::connect(&url).await.expect("connect Postgres");
        let mut transaction = pool.begin().await.expect("begin eligibility transaction");
        assert!(validate_operator_first_execution_eligibility_tx(
            &mut transaction,
            Some(&OperatorFirstExecutionEligibility {
                issued_at: Utc::now() - Duration::seconds(5),
                expires_at: Utc::now() + Duration::seconds(5),
            }),
        )
        .await
        .is_ok());
        assert!(matches!(
            validate_operator_first_execution_eligibility_tx(
                &mut transaction,
                Some(&OperatorFirstExecutionEligibility {
                    issued_at: Utc::now() - Duration::seconds(10),
                    expires_at: Utc::now() - Duration::seconds(1),
                }),
            )
            .await,
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));
        assert!(matches!(
            validate_operator_first_execution_eligibility_tx(
                &mut transaction,
                Some(&OperatorFirstExecutionEligibility {
                    issued_at: Utc::now() + Duration::seconds(1),
                    expires_at: Utc::now() + Duration::seconds(10),
                }),
            )
            .await,
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));
        transaction
            .rollback()
            .await
            .expect("rollback eligibility test");
        pool.close().await;
    }

    #[test]
    fn recover_history_preserves_retired_old_generation_and_births_successor() {
        let operation = operation();
        let old = (Uuid::new_v4(), 51_i64);
        let successor = (Uuid::new_v4(), 52_i64);
        let mut history = StoredLifecycleHistory {
            transition_kind: IdentityLifecycleTransition::Recover as i16,
            outcome_code: APPLIED_OUTCOME,
            old_binding_id: Some(old.0),
            old_binding_version: Some(old.1),
            old_prior_lifecycle_revision: Some(2),
            old_prior_state: Some(2),
            old_resulting_lifecycle_revision: Some(2),
            old_resulting_state: Some(2),
            successor_binding_id: Some(successor.0),
            successor_binding_version: Some(successor.1),
            successor_lifecycle_revision: Some(1),
            successor_state: Some(1),
            request_fingerprint: operation.request_fingerprint.to_vec(),
            transition_digest: transition_digest(
                &operation,
                IdentityLifecycleTransition::Recover,
                Some(old),
                Some(successor),
            )
            .to_vec(),
        };
        assert!(validate_replay_history(
            &operation,
            IdentityLifecycleTransition::Recover,
            APPLIED_OUTCOME,
            &history,
        )
        .is_ok());
        history.old_prior_lifecycle_revision = Some(1);
        assert!(matches!(
            validate_replay_history(
                &operation,
                IdentityLifecycleTransition::Recover,
                APPLIED_OUTCOME,
                &history,
            ),
            Err(IdentityLifecycleFailure::CorruptStoredResult)
        ));
    }

    #[tokio::test]
    #[ignore = "requires a dedicated disposable Postgres database"]
    async fn postgres_prepared_admission_loss_is_fenced_replay_safe_and_atomic() {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .expect("BUZZ_TEST_DATABASE_URL must name a disposable database");
        let config = DbConfig {
            database_url,
            min_connections: 0,
            max_connections: 8,
            ..DbConfig::default()
        };
        let db = Db::new(&config).await.expect("connect disposable database");
        db.migrate().await.expect("migrate disposable database");

        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let admission_loss_test_fixture::PreparedAdmissionLossPgFixture {
            prepared,
            binding_id,
        } = admission_loss_test_fixture::provision(&db, community_id).await;
        let authority_object: [u8; 32] = Sha256::digest(binding_id.as_bytes()).into();
        let mut wrong_fingerprint = prepared.request_fingerprint();
        wrong_fingerprint[0] ^= 1;
        let mut wrong_fence = AuthorizationOperationFence::acquire_for_operation_restore(
            &db.pool,
            prepared.authorization_domain(),
            prepared.operation_id(),
            wrong_fingerprint,
            std::time::Duration::from_secs(2),
        )
        .await
        .expect("acquire mismatched operation fence")
        .expect("mismatched operation fence is available");
        assert!(matches!(
            db.execute_prepared_admission_loss_fenced(&mut wrong_fence, &prepared)
                .await,
            Err(PreparedAdmissionLossWriteFailure::Database(_))
        ));
        wrong_fence
            .release(std::time::Duration::from_secs(2))
            .await
            .expect("release mismatched operation fence");
        let pre_fence_receipts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM authorization_operation_receipts \
             WHERE community_id=$1 AND operation_id=$2",
        )
        .bind(community_id.as_uuid())
        .bind(prepared.operation_id())
        .fetch_one(&db.pool)
        .await
        .expect("verify mismatched fence wrote nothing");
        assert_eq!(pre_fence_receipts, 0);
        let mut fence = AuthorizationOperationFence::acquire_for_operation_restore(
            &db.pool,
            prepared.authorization_domain(),
            prepared.operation_id(),
            prepared.request_fingerprint(),
            std::time::Duration::from_secs(2),
        )
        .await
        .expect("acquire exact operation fence")
        .expect("operation fence is available");
        assert_eq!(
            db.execute_prepared_admission_loss_fenced(&mut fence, &prepared)
                .await
                .expect("apply fenced admission loss"),
            PreparedAdmissionLossObservation::Applied {
                invalidation_generation: 1,
            }
        );
        assert_eq!(
            db.execute_prepared_admission_loss_fenced(&mut fence, &prepared)
                .await
                .expect("replay fenced admission loss"),
            PreparedAdmissionLossObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                invalidation_generation: Some(1),
            }
        );
        fence
            .release(std::time::Duration::from_secs(2))
            .await
            .expect("release exact operation fence");
        let (binding_state, lifecycle_revision, receipts, histories, events, manifests): (
            i16,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = sqlx::query_as(
            "SELECT binding_state,lifecycle_revision, \
               (SELECT count(*) FROM authorization_operation_receipts \
                 WHERE community_id=$1 AND operation_id=$3), \
               (SELECT count(*) FROM identity_lifecycle_history \
                 WHERE community_id=$1 AND operation_id=$3), \
               (SELECT count(*) FROM authorization_events \
                 WHERE community_id=$1 AND operation_id=$3), \
               (SELECT count(*) FROM authorization_operation_version_delta_manifests \
                 WHERE community_id=$1 AND operation_id=$3) \
             FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(community_id.as_uuid())
        .bind(binding_id)
        .bind(prepared.operation_id())
        .fetch_one(&db.pool)
        .await
        .expect("load exact fenced operation evidence");
        assert_eq!(
            (
                binding_state,
                lifecycle_revision,
                receipts,
                histories,
                events,
                manifests,
            ),
            (2, 2, 1, 1, 1, 1)
        );
        let (authority_epoch, protected_epoch): (i64, i64) = sqlx::query_as(
            "SELECT epoch.authority_epoch,protected.authority_epoch \
             FROM authorization_authority_epochs epoch \
             JOIN protected_object_authority protected \
               ON protected.community_id=epoch.community_id \
              AND protected.object_kind=epoch.object_kind \
              AND protected.object_key=epoch.object_key \
             WHERE epoch.community_id=$1 AND epoch.object_kind=2 AND epoch.object_key=$2",
        )
        .bind(community_id.as_uuid())
        .bind(authority_object.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("load exact fenced authority advance");
        assert_eq!((authority_epoch, protected_epoch), (2, 2));

        let (_, denial_binding, _) = prepare_policy_admission_loss_for_postgres(
            &db,
            community_id,
            [223; 32],
            [224; 32],
            "fenced-denial",
        )
        .await;
        let denied = prepare_admission_loss(
            AdmissionLossOperationIdentity::new(
                community_id,
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
            )
            .expect("valid denial operation identity"),
            ExactAdmissionLossTarget::from_authoritative_binding(
                denial_binding.binding_id,
                denial_binding.binding_version + 1,
                1,
                [223; 32],
                [224; 32],
            )
            .expect("valid stale denial target"),
            TrustedAdmissionLossCause::LocalPolicy { revision: 1 },
            actor_for_postgres(&db, community_id).await,
        )
        .expect("prepare stale admission-loss target");
        let mut denial_fence = AuthorizationOperationFence::acquire_for_operation_restore(
            &db.pool,
            denied.authorization_domain(),
            denied.operation_id(),
            denied.request_fingerprint(),
            std::time::Duration::from_secs(2),
        )
        .await
        .expect("acquire denial operation fence")
        .expect("denial operation fence is available");
        assert_eq!(
            db.execute_prepared_admission_loss_fenced(&mut denial_fence, &denied)
                .await
                .expect("commit fenced denial"),
            PreparedAdmissionLossObservation::Denied {
                reason: IdentityLifecycleDenial::StaleExpectedState,
            }
        );
        assert_eq!(
            db.execute_prepared_admission_loss_fenced(&mut denial_fence, &denied)
                .await
                .expect("replay fenced denial"),
            PreparedAdmissionLossObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Denied(
                    IdentityLifecycleDenial::StaleExpectedState,
                ),
                invalidation_generation: None,
            }
        );
        denial_fence
            .release(std::time::Duration::from_secs(2))
            .await
            .expect("release denial operation fence");

        let rollback_domain = CommunityId::from_uuid(Uuid::new_v4());
        install_lifecycle_test_domain(&db, rollback_domain, 1).await;
        let (rollback_prepared, rollback_binding, rollback_object) =
            prepare_policy_admission_loss_for_postgres(
                &db,
                rollback_domain,
                [225; 32],
                [226; 32],
                "fenced-rollback",
            )
            .await;
        let mut rollback_fence = AuthorizationOperationFence::acquire_for_operation_restore(
            &db.pool,
            rollback_prepared.authorization_domain(),
            rollback_prepared.operation_id(),
            rollback_prepared.request_fingerprint(),
            std::time::Duration::from_secs(2),
        )
        .await
        .expect("acquire rollback operation fence")
        .expect("rollback operation fence is available");
        assert!(matches!(
            db.execute_prepared_admission_loss_fenced(&mut rollback_fence, &rollback_prepared,)
                .await,
            Err(PreparedAdmissionLossWriteFailure::AuditUnavailable)
        ));
        rollback_fence
            .release(std::time::Duration::from_secs(2))
            .await
            .expect("release rollback operation fence");
        let (
            rollback_state,
            rollback_revision,
            rollback_epoch,
            rollback_protected_epoch,
            rollback_generation,
            rollback_receipts,
            rollback_histories,
            rollback_events,
            rollback_manifests,
        ): (i16, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT binding.binding_state,binding.lifecycle_revision, \
                    epoch.authority_epoch,protected.authority_epoch,domain.current_generation, \
               (SELECT count(*) FROM authorization_operation_receipts \
                 WHERE community_id=$1 AND operation_id=$4), \
               (SELECT count(*) FROM identity_lifecycle_history \
                 WHERE community_id=$1 AND operation_id=$4), \
               (SELECT count(*) FROM authorization_events \
                 WHERE community_id=$1 AND operation_id=$4), \
               (SELECT count(*) FROM authorization_operation_version_delta_manifests \
                 WHERE community_id=$1 AND operation_id=$4) \
             FROM identity_bindings binding \
             JOIN authorization_authority_epochs epoch \
               ON epoch.community_id=binding.community_id AND epoch.object_kind=2 \
              AND epoch.object_key=$3 \
             JOIN protected_object_authority protected \
               ON protected.community_id=epoch.community_id \
              AND protected.object_kind=epoch.object_kind \
              AND protected.object_key=epoch.object_key \
             JOIN authorization_invalidation_domains domain \
               ON domain.community_id=binding.community_id \
             WHERE binding.community_id=$1 AND binding.binding_id=$2",
        )
        .bind(rollback_domain.as_uuid())
        .bind(rollback_binding.binding_id)
        .bind(rollback_object.as_slice())
        .bind(rollback_prepared.operation_id())
        .fetch_one(&db.pool)
        .await
        .expect("verify audit failure rolled back all canonical writes");
        assert_eq!(
            (
                rollback_state,
                rollback_revision,
                rollback_epoch,
                rollback_protected_epoch,
                rollback_generation,
                rollback_receipts,
                rollback_histories,
                rollback_events,
                rollback_manifests,
            ),
            (1, 1, 1, 1, 0, 0, 0, 0, 0)
        );

        let storage_domain = CommunityId::from_uuid(Uuid::new_v4());
        install_lifecycle_test_domain(&db, storage_domain, 100).await;
        let (storage_prepared, storage_binding, storage_object) =
            prepare_policy_admission_loss_for_postgres(
                &db,
                storage_domain,
                [227; 32],
                [228; 32],
                "fenced-storage-rollback",
            )
            .await;
        let trigger_suffix = Uuid::new_v4().simple().to_string();
        let function_name = format!("s3_fail_lifecycle_update_{trigger_suffix}");
        let trigger_name = format!("s3_fail_lifecycle_update_trigger_{trigger_suffix}");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN \
               IF NEW.binding_id = '{}'::uuid THEN \
                 RAISE EXCEPTION 'forced deterministic lifecycle storage failure'; \
               END IF; \
               RETURN NEW; \
             END $$",
            storage_binding.binding_id
        )))
        .execute(&db.pool)
        .await
        .expect("install deterministic storage failure function");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE TRIGGER {trigger_name} BEFORE UPDATE ON identity_bindings \
             FOR EACH ROW EXECUTE FUNCTION {function_name}()"
        )))
        .execute(&db.pool)
        .await
        .expect("install deterministic storage failure trigger");
        let mut storage_fence = AuthorizationOperationFence::acquire_for_operation_restore(
            &db.pool,
            storage_prepared.authorization_domain(),
            storage_prepared.operation_id(),
            storage_prepared.request_fingerprint(),
            std::time::Duration::from_secs(2),
        )
        .await
        .expect("acquire storage-failure operation fence")
        .expect("storage-failure operation fence is available");
        assert!(matches!(
            db.execute_prepared_admission_loss_fenced(&mut storage_fence, &storage_prepared)
                .await,
            Err(PreparedAdmissionLossWriteFailure::Database(_))
        ));
        storage_fence
            .release(std::time::Duration::from_secs(2))
            .await
            .expect("release storage-failure operation fence");
        let (
            storage_state,
            storage_revision,
            storage_epoch,
            storage_protected_epoch,
            storage_generation,
            storage_receipts,
            storage_histories,
            storage_events,
            storage_manifests,
        ): (i16, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT binding.binding_state,binding.lifecycle_revision, \
                    epoch.authority_epoch,protected.authority_epoch,domain.current_generation, \
               (SELECT count(*) FROM authorization_operation_receipts \
                 WHERE community_id=$1 AND operation_id=$4), \
               (SELECT count(*) FROM identity_lifecycle_history \
                 WHERE community_id=$1 AND operation_id=$4), \
               (SELECT count(*) FROM authorization_events \
                 WHERE community_id=$1 AND operation_id=$4), \
               (SELECT count(*) FROM authorization_operation_version_delta_manifests \
                 WHERE community_id=$1 AND operation_id=$4) \
             FROM identity_bindings binding \
             JOIN authorization_authority_epochs epoch \
               ON epoch.community_id=binding.community_id AND epoch.object_kind=2 \
              AND epoch.object_key=$3 \
             JOIN protected_object_authority protected \
               ON protected.community_id=epoch.community_id \
              AND protected.object_kind=epoch.object_kind \
              AND protected.object_key=epoch.object_key \
             JOIN authorization_invalidation_domains domain \
               ON domain.community_id=binding.community_id \
             WHERE binding.community_id=$1 AND binding.binding_id=$2",
        )
        .bind(storage_domain.as_uuid())
        .bind(storage_binding.binding_id)
        .bind(storage_object.as_slice())
        .bind(storage_prepared.operation_id())
        .fetch_one(&db.pool)
        .await
        .expect("verify deterministic storage failure rolled back all writes");
        assert_eq!(
            (
                storage_state,
                storage_revision,
                storage_epoch,
                storage_protected_epoch,
                storage_generation,
                storage_receipts,
                storage_histories,
                storage_events,
                storage_manifests,
            ),
            (1, 1, 1, 1, 0, 0, 0, 0, 0)
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_admission_loss_replay_survives_later_protected_head() {
        use sqlx::postgres::PgPoolOptions;

        let admin_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_owned());
        let admin = sqlx::PgPool::connect(&admin_url)
            .await
            .expect("connect admin database");
        let name = format!("s5_admission_replay_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("create admission replay database");
        let split = admin_url.rfind('/').expect("database URL path");
        let url = format!("{}/{}", &admin_url[..split], name);
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .expect("connect admission replay database");
        crate::migration::run_migrations(&pool)
            .await
            .expect("migrate admission replay database");
        let db = Db::from_pool(pool.clone());
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        let admission_loss_test_fixture::PreparedAdmissionLossPgFixture {
            prepared,
            binding_id,
        } = admission_loss_test_fixture::provision(&db, community_id).await;
        let authority_object: [u8; 32] = Sha256::digest(binding_id.as_bytes()).into();
        let mut fence = AuthorizationOperationFence::acquire_for_operation_restore(
            &db.pool,
            prepared.authorization_domain(),
            prepared.operation_id(),
            prepared.request_fingerprint(),
            std::time::Duration::from_secs(2),
        )
        .await
        .expect("acquire admission-loss fence")
        .expect("admission-loss fence is available");
        assert_eq!(
            db.execute_prepared_admission_loss_fenced(&mut fence, &prepared)
                .await
                .expect("apply nonzero admission loss"),
            PreparedAdmissionLossObservation::Applied {
                invalidation_generation: 1,
            }
        );
        assert_eq!(
            db.execute_prepared_admission_loss_fenced(&mut fence, &prepared)
                .await
                .expect("immediate admission-loss replay"),
            PreparedAdmissionLossObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                invalidation_generation: Some(1),
            }
        );
        let original_manifest = db
            .authorization_operation_version_delta(
                community_id,
                prepared.operation_id(),
                prepared.request_fingerprint(),
            )
            .await
            .expect("load immutable admission-loss manifest");
        assert_eq!(
            original_manifest
                .components()
                .iter()
                .filter(|component| {
                    component.component_kind() == AuthorizationVersionComponentKind::AuthorityEpoch
                })
                .count(),
            1
        );
        fence
            .release(std::time::Duration::from_secs(2))
            .await
            .expect("release admission-loss fence");

        let later_head = advance_protected_publication_head_for_postgres(
            &db,
            community_id,
            AuthorizationProtectedObjectKind::Channel,
            authority_object,
        )
        .await;
        let (current_head, current_epoch): (Uuid, i64) = sqlx::query_as(
            "SELECT operation_id,authority_epoch FROM protected_object_authority \
             WHERE community_id=$1 AND object_kind=2 AND object_key=$2",
        )
        .bind(community_id.as_uuid())
        .bind(authority_object.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("load later protected head");
        assert_eq!((current_head, current_epoch), (later_head, 3));

        let mut replay_fence = AuthorizationOperationFence::acquire_for_operation_restore(
            &db.pool,
            prepared.authorization_domain(),
            prepared.operation_id(),
            prepared.request_fingerprint(),
            std::time::Duration::from_secs(2),
        )
        .await
        .expect("reacquire admission-loss replay fence")
        .expect("admission-loss replay fence is available");
        assert_eq!(
            db.execute_prepared_admission_loss_fenced(&mut replay_fence, &prepared)
                .await
                .expect("replay admission loss after later protected head"),
            PreparedAdmissionLossObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                invalidation_generation: Some(1),
            }
        );
        replay_fence
            .release(std::time::Duration::from_secs(2))
            .await
            .expect("release admission-loss replay fence");
        let replay_manifest = db
            .authorization_operation_version_delta(
                community_id,
                prepared.operation_id(),
                prepared.request_fingerprint(),
            )
            .await
            .expect("reload immutable admission-loss manifest");
        assert_eq!(replay_manifest, original_manifest);
        let (receipts, histories, events, manifests): (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM authorization_operation_receipts \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM identity_lifecycle_history \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM authorization_events \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM authorization_operation_version_delta_manifests \
                 WHERE community_id=$1 AND operation_id=$2)",
        )
        .bind(community_id.as_uuid())
        .bind(prepared.operation_id())
        .fetch_one(&db.pool)
        .await
        .expect("load original admission-loss evidence cardinality");
        assert_eq!((receipts, histories, events, manifests), (1, 1, 1, 1));

        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("drop admission replay database");
        admin.close().await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_operator_retirement_refences_exact_authority_and_rolls_back_atomically() {
        use sqlx::postgres::PgPoolOptions;

        let admin_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_owned());
        let admin = sqlx::PgPool::connect(&admin_url)
            .await
            .expect("connect admin database");
        let name = format!("s5_operator_authority_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("create operator authority database");
        let split = admin_url.rfind('/').expect("database URL path");
        let url = format!("{}/{}", &admin_url[..split], name);
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .expect("connect operator authority database");
        crate::migration::run_migrations(&pool)
            .await
            .expect("migrate operator authority database");
        let db = Db::from_pool(pool.clone());

        async fn seed_binding_authority(
            db: &Db,
            domain: CommunityId,
            binding: IdentityBindingEvidence,
            event_author: [u8; 32],
            ordinal: u64,
        ) -> [u8; 32] {
            let (creation_operation, creation_fingerprint): (Uuid, Vec<u8>) = sqlx::query_as(
                "SELECT creation_operation_id,creation_request_fingerprint \
                 FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
            )
            .bind(domain.as_uuid())
            .bind(binding.binding_id)
            .fetch_one(&db.pool)
            .await
            .expect("load binding creation attribution");
            let object_key = lifecycle_digest(
                b"buzz:test:operator-authority-object:v1",
                &[binding.binding_id.as_bytes(), &ordinal.to_be_bytes()],
            );
            let fence: [u8; 32] = Sha256::digest(object_key).into();
            sqlx::query(
                "INSERT INTO authorization_authority_epochs \
                 (community_id,object_kind,object_key,authority_epoch,fence,operation_id,request_fingerprint) \
                 VALUES ($1,3,$2,1,$3,$4,$5)",
            )
            .bind(domain.as_uuid())
            .bind(object_key.as_slice())
            .bind(fence.as_slice())
            .bind(creation_operation)
            .bind(&creation_fingerprint)
            .execute(&db.pool)
            .await
            .expect("seed operator authority epoch");
            sqlx::query(
                "INSERT INTO protected_object_authority \
                 (community_id,object_kind,object_key,capability,actor_pubkey,binding_id, \
                  binding_version,policy_revision,invalidation_generation,authority_epoch,fence, \
                  issued_at,expires_at,operation_id,request_fingerprint) \
                 VALUES ($1,3,$2,3,$3,$4,$5,1,0,1,$6,clock_timestamp()-INTERVAL '1 second', \
                         clock_timestamp()+INTERVAL '1 hour',$7,$8)",
            )
            .bind(domain.as_uuid())
            .bind(object_key.as_slice())
            .bind(event_author.as_slice())
            .bind(binding.binding_id)
            .bind(i64_from_u64(binding.binding_version).expect("binding version"))
            .bind(fence.as_slice())
            .bind(creation_operation)
            .bind(&creation_fingerprint)
            .execute(&db.pool)
            .await
            .expect("seed protected operator authority");
            object_key
        }

        let domain = CommunityId::from_uuid(Uuid::new_v4());
        install_lifecycle_test_domain(&db, domain, 100).await;
        let principal = [141; 32];
        let event_author = [142; 32];
        let binding =
            enroll_for_postgres(&db, domain, principal, event_author, "operator-retire").await;
        let object_key = seed_binding_authority(&db, domain, binding, event_author, 1).await;
        let second_object_key = seed_binding_authority(&db, domain, binding, event_author, 2).await;
        let mut operation = domain_operation(domain);
        let target = ExactActiveBindingTarget {
            binding_id: binding.binding_id,
            binding_version: binding.binding_version,
            expected_lifecycle_revision: 1,
            principal_fingerprint: principal,
            event_author_pubkey: event_author,
        };
        let actor = verified_operator_actor(
            domain,
            operation.operation_id,
            OperatorLifecycleAction::Retire,
            target,
            None,
        )
        .await;
        let mut request = RetireIdentityPairRequest {
            operation,
            target,
            actor,
        };
        request.operation.request_fingerprint = retire_identity_pair_request_fingerprint(&request);
        operation = request.operation;
        assert!(matches!(
            db.retire_identity_pair(&request)
                .await
                .expect("retire binding"),
            IdentityLifecycleObservation::Applied { binding: None, .. }
        ));
        assert!(matches!(
            db.retire_identity_pair(&request)
                .await
                .expect("replay retirement"),
            IdentityLifecycleObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                binding: None,
                ..
            }
        ));
        let mut fresh_delivery = request.clone();
        fresh_delivery.operation.correlation_id = Uuid::new_v4();
        fresh_delivery.operation.attempt_id = Uuid::new_v4();
        assert!(matches!(
            db.retire_identity_pair(&fresh_delivery)
                .await
                .expect("replay retirement with fresh delivery ids"),
            IdentityLifecycleObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                binding: None,
                ..
            }
        ));

        let mut missing_event = db.pool.begin().await.expect("begin missing-event probe");
        sqlx::query("ALTER TABLE authorization_events DISABLE TRIGGER USER")
            .execute(&mut *missing_event)
            .await
            .expect("disable immutable event triggers");
        sqlx::query("DELETE FROM authorization_events WHERE community_id=$1 AND operation_id=$2")
            .bind(domain.as_uuid())
            .bind(operation.operation_id)
            .execute(&mut *missing_event)
            .await
            .expect("remove lifecycle event");
        assert!(matches!(
            replay_observation_tx(
                &mut missing_event,
                LifecycleReplayRequest::Retire(&fresh_delivery),
            )
            .await,
            Err(IdentityLifecycleFailure::CorruptStoredResult)
        ));
        missing_event
            .rollback()
            .await
            .expect("rollback missing-event probe");

        let mut mismatched_event = db.pool.begin().await.expect("begin event mismatch probe");
        sqlx::query("ALTER TABLE authorization_events DISABLE TRIGGER USER")
            .execute(&mut *mismatched_event)
            .await
            .expect("disable immutable event triggers");
        sqlx::query(
            "UPDATE authorization_events SET request_fingerprint=$3 \
             WHERE community_id=$1 AND operation_id=$2",
        )
        .bind(domain.as_uuid())
        .bind(operation.operation_id)
        .bind([211_u8; 32].as_slice())
        .execute(&mut *mismatched_event)
        .await
        .expect("corrupt lifecycle event request fingerprint");
        assert!(matches!(
            replay_observation_tx(
                &mut mismatched_event,
                LifecycleReplayRequest::Retire(&fresh_delivery),
            )
            .await,
            Err(IdentityLifecycleFailure::CorruptStoredResult)
                | Err(IdentityLifecycleFailure::Storage(DbError::InvalidData(_)))
        ));
        mismatched_event
            .rollback()
            .await
            .expect("rollback event mismatch probe");

        let mut duplicate_event = db.pool.begin().await.expect("begin duplicate-event probe");
        sqlx::query("ALTER TABLE authorization_events DISABLE TRIGGER USER")
            .execute(&mut *duplicate_event)
            .await
            .expect("disable immutable event triggers");
        sqlx::query(
            "INSERT INTO authorization_events \
             (community_id,event_id,event_kind,outcome_code,reason_code,actor_kind,actor_fingerprint, \
              subject_fingerprint,operation_id,request_fingerprint,correlation_id,attempt_id, \
              occurred_at,canonical_envelope,envelope_digest) \
             SELECT community_id,$3,event_kind,outcome_code,reason_code,actor_kind,actor_fingerprint, \
                    subject_fingerprint,operation_id,request_fingerprint,$4,$5,occurred_at, \
                    canonical_envelope,envelope_digest \
             FROM authorization_events WHERE community_id=$1 AND operation_id=$2",
        )
        .bind(domain.as_uuid())
        .bind(operation.operation_id)
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .execute(&mut *duplicate_event)
        .await
        .expect("duplicate lifecycle event identity");
        assert!(matches!(
            replay_observation_tx(
                &mut duplicate_event,
                LifecycleReplayRequest::Retire(&fresh_delivery),
            )
            .await,
            Err(IdentityLifecycleFailure::CorruptStoredResult)
        ));
        duplicate_event
            .rollback()
            .await
            .expect("rollback duplicate-event probe");
        let manifest = db
            .authorization_operation_version_delta(
                domain,
                operation.operation_id,
                operation.request_fingerprint,
            )
            .await
            .expect("load operator retirement manifest");
        assert_eq!(
            manifest
                .components()
                .iter()
                .filter(|component| component.component_kind()
                    == AuthorizationVersionComponentKind::AuthorityEpoch)
                .count(),
            2
        );
        assert_eq!(
            manifest
                .components()
                .iter()
                .filter(|component| component.component_kind()
                    == AuthorizationVersionComponentKind::InvalidationGeneration)
                .count(),
            1
        );
        let first_authority_key = authorization_version_authority_epoch_component_key(
            domain,
            AuthorizationProtectedObjectKind::Repository,
            object_key,
        );
        let mut missing_manifest = db.pool.begin().await.expect("begin missing-manifest probe");
        sqlx::query("ALTER TABLE authorization_operation_version_deltas DISABLE TRIGGER USER")
            .execute(&mut *missing_manifest)
            .await
            .expect("disable immutable manifest triggers");
        sqlx::query(
            "DELETE FROM authorization_operation_version_deltas \
             WHERE community_id=$1 AND operation_id=$2 AND component_kind=4 AND component_key=$3",
        )
        .bind(domain.as_uuid())
        .bind(operation.operation_id)
        .bind(first_authority_key.as_slice())
        .execute(&mut *missing_manifest)
        .await
        .expect("remove one authority component");
        let missing_result = replay_observation_tx(
            &mut missing_manifest,
            LifecycleReplayRequest::Retire(&request),
        )
        .await;
        assert!(
            matches!(
                missing_result,
                Err(IdentityLifecycleFailure::CorruptStoredResult)
                    | Err(IdentityLifecycleFailure::Storage(DbError::InvalidData(_)))
            ),
            "unexpected missing-manifest result: {missing_result:?}"
        );
        missing_manifest
            .rollback()
            .await
            .expect("rollback missing-manifest probe");

        let mut wrong_manifest = db.pool.begin().await.expect("begin wrong-manifest probe");
        sqlx::query("ALTER TABLE authorization_operation_version_deltas DISABLE TRIGGER USER")
            .execute(&mut *wrong_manifest)
            .await
            .expect("disable immutable manifest triggers");
        sqlx::query(
            "UPDATE authorization_operation_version_deltas SET component_key=$4 \
             WHERE community_id=$1 AND operation_id=$2 AND component_kind=4 AND component_key=$3",
        )
        .bind(domain.as_uuid())
        .bind(operation.operation_id)
        .bind(first_authority_key.as_slice())
        .bind([201_u8; 32].as_slice())
        .execute(&mut *wrong_manifest)
        .await
        .expect("replace one authority coordinate");
        let wrong_result = replay_observation_tx(
            &mut wrong_manifest,
            LifecycleReplayRequest::Retire(&request),
        )
        .await;
        assert!(
            matches!(
                wrong_result,
                Err(IdentityLifecycleFailure::CorruptStoredResult)
                    | Err(IdentityLifecycleFailure::Storage(DbError::InvalidData(_)))
            ),
            "unexpected wrong-manifest result: {wrong_result:?}"
        );
        wrong_manifest
            .rollback()
            .await
            .expect("rollback wrong-manifest probe");

        let mut extra_manifest = db.pool.begin().await.expect("begin extra-manifest probe");
        sqlx::query("ALTER TABLE authorization_operation_version_deltas DISABLE TRIGGER USER")
            .execute(&mut *extra_manifest)
            .await
            .expect("disable immutable manifest triggers");
        sqlx::query(
            "INSERT INTO authorization_operation_version_deltas \
             (community_id,operation_id,component_kind,component_key,before_version, \
              after_version,component_digest) VALUES ($1,$2,4,$3,1,2,$4)",
        )
        .bind(domain.as_uuid())
        .bind(operation.operation_id)
        .bind([202_u8; 32].as_slice())
        .bind([203_u8; 32].as_slice())
        .execute(&mut *extra_manifest)
        .await
        .expect("insert extra authority component");
        let extra_result = replay_observation_tx(
            &mut extra_manifest,
            LifecycleReplayRequest::Retire(&request),
        )
        .await;
        assert!(
            matches!(
                extra_result,
                Err(IdentityLifecycleFailure::CorruptStoredResult)
                    | Err(IdentityLifecycleFailure::Storage(DbError::InvalidData(_)))
            ),
            "unexpected extra-manifest result: {extra_result:?}"
        );
        extra_manifest
            .rollback()
            .await
            .expect("rollback extra-manifest probe");

        let authority_states: Vec<(Vec<u8>, i64, i64, i64)> = sqlx::query_as(
            "SELECT epoch.object_key,epoch.authority_epoch,protected.authority_epoch,domain.current_generation \
             FROM authorization_authority_epochs epoch \
             JOIN protected_object_authority protected USING (community_id,object_kind,object_key) \
             JOIN authorization_invalidation_domains domain USING (community_id) \
             WHERE epoch.community_id=$1 AND epoch.object_kind=3 \
               AND epoch.object_key IN ($2,$3) ORDER BY epoch.object_key",
        )
        .bind(domain.as_uuid())
        .bind(object_key.as_slice())
        .bind(second_object_key.as_slice())
        .fetch_all(&db.pool)
        .await
        .expect("load retired authority state");
        assert_eq!(authority_states.len(), 2);
        assert!(authority_states
            .iter()
            .all(|(_, epoch, protected_epoch, generation)| (
                *epoch,
                *protected_epoch,
                *generation
            ) == (2, 2, 1)));

        let rollback_domain = CommunityId::from_uuid(Uuid::new_v4());
        install_lifecycle_test_domain(&db, rollback_domain, 1).await;
        let rollback_principal = [151; 32];
        let rollback_key = [152; 32];
        let rollback_binding = enroll_for_postgres(
            &db,
            rollback_domain,
            rollback_principal,
            rollback_key,
            "operator-rollback",
        )
        .await;
        let rollback_object =
            seed_binding_authority(&db, rollback_domain, rollback_binding, rollback_key, 1).await;
        let rollback_operation = domain_operation(rollback_domain);
        let rollback_target = ExactActiveBindingTarget {
            binding_id: rollback_binding.binding_id,
            binding_version: rollback_binding.binding_version,
            expected_lifecycle_revision: 1,
            principal_fingerprint: rollback_principal,
            event_author_pubkey: rollback_key,
        };
        let rollback_actor = verified_operator_actor(
            rollback_domain,
            rollback_operation.operation_id,
            OperatorLifecycleAction::Retire,
            rollback_target,
            None,
        )
        .await;
        let mut rollback = RetireIdentityPairRequest {
            operation: rollback_operation,
            target: rollback_target,
            actor: rollback_actor,
        };
        rollback.operation.request_fingerprint =
            retire_identity_pair_request_fingerprint(&rollback);
        assert!(matches!(
            db.retire_identity_pair(&rollback).await,
            Err(IdentityLifecycleFailure::AuditUnavailable)
        ));
        let rollback_state: (i16, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT binding.binding_state,epoch.authority_epoch,domain.current_generation, \
               (SELECT count(*) FROM authorization_operation_receipts WHERE community_id=$1 AND operation_id=$4), \
               (SELECT count(*) FROM identity_lifecycle_history WHERE community_id=$1 AND operation_id=$4), \
               (SELECT count(*) FROM authorization_operation_version_delta_manifests WHERE community_id=$1 AND operation_id=$4) \
             FROM identity_bindings binding \
             JOIN authorization_authority_epochs epoch ON epoch.community_id=binding.community_id \
               AND epoch.object_kind=3 AND epoch.object_key=$3 \
             JOIN authorization_invalidation_domains domain ON domain.community_id=binding.community_id \
             WHERE binding.community_id=$1 AND binding.binding_id=$2",
        )
        .bind(rollback_domain.as_uuid())
        .bind(rollback_binding.binding_id)
        .bind(rollback_object.as_slice())
        .bind(rollback.operation.operation_id)
        .fetch_one(&db.pool)
        .await
        .expect("verify operator retirement rollback");
        assert_eq!(rollback_state, (1, 1, 0, 0, 0, 0));

        let zero_domain = CommunityId::from_uuid(Uuid::new_v4());
        install_lifecycle_test_domain(&db, zero_domain, 100).await;
        let zero_principal = [161; 32];
        let zero_key = [162; 32];
        let zero_binding =
            enroll_for_postgres(&db, zero_domain, zero_principal, zero_key, "operator-zero").await;
        let zero_target = ExactActiveBindingTarget {
            binding_id: zero_binding.binding_id,
            binding_version: zero_binding.binding_version,
            expected_lifecycle_revision: 1,
            principal_fingerprint: zero_principal,
            event_author_pubkey: zero_key,
        };
        let zero_operation = domain_operation(zero_domain);
        let zero_actor = verified_operator_actor(
            zero_domain,
            zero_operation.operation_id,
            OperatorLifecycleAction::Retire,
            zero_target,
            None,
        )
        .await;
        let mut zero_request = RetireIdentityPairRequest {
            operation: zero_operation,
            target: zero_target,
            actor: zero_actor,
        };
        zero_request.operation.request_fingerprint =
            retire_identity_pair_request_fingerprint(&zero_request);
        assert!(matches!(
            db.retire_identity_pair(&zero_request)
                .await
                .expect("retire binding without protected objects"),
            IdentityLifecycleObservation::Applied { binding: None, .. }
        ));
        let zero_manifest = db
            .authorization_operation_version_delta(
                zero_domain,
                zero_request.operation.operation_id,
                zero_request.operation.request_fingerprint,
            )
            .await
            .expect("load zero-object operator manifest");
        assert_eq!(
            zero_manifest
                .components()
                .iter()
                .filter(|component| component.component_kind()
                    == AuthorizationVersionComponentKind::AuthorityEpoch)
                .count(),
            0
        );
        assert_eq!(
            zero_manifest
                .components()
                .iter()
                .filter(|component| component.component_kind()
                    == AuthorizationVersionComponentKind::InvalidationGeneration)
                .count(),
            1
        );

        let substitution_domain = CommunityId::from_uuid(Uuid::new_v4());
        install_lifecycle_test_domain(&db, substitution_domain, 100).await;
        let authority_principal = [171; 32];
        let authority_key = [172; 32];
        let authority_binding = enroll_for_postgres(
            &db,
            substitution_domain,
            authority_principal,
            authority_key,
            "operator-authority-a",
        )
        .await;
        let target_principal = [173; 32];
        let target_key = [174; 32];
        let target_binding = enroll_for_postgres(
            &db,
            substitution_domain,
            target_principal,
            target_key,
            "operator-target-b",
        )
        .await;
        let authority_target = ExactActiveBindingTarget {
            binding_id: authority_binding.binding_id,
            binding_version: authority_binding.binding_version,
            expected_lifecycle_revision: 1,
            principal_fingerprint: authority_principal,
            event_author_pubkey: authority_key,
        };
        let substituted_target = ExactActiveBindingTarget {
            binding_id: target_binding.binding_id,
            binding_version: target_binding.binding_version,
            expected_lifecycle_revision: 1,
            principal_fingerprint: target_principal,
            event_author_pubkey: target_key,
        };

        let retire_operation = domain_operation(substitution_domain);
        let retire_actor = verified_operator_actor(
            substitution_domain,
            retire_operation.operation_id,
            OperatorLifecycleAction::Retire,
            authority_target,
            None,
        )
        .await;
        let mut substituted_retire = RetireIdentityPairRequest {
            operation: retire_operation,
            target: substituted_target,
            actor: retire_actor,
        };
        substituted_retire.operation.request_fingerprint =
            retire_identity_pair_request_fingerprint(&substituted_retire);
        assert!(matches!(
            db.retire_identity_pair(&substituted_retire).await,
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));

        let disable_operation = domain_operation(substitution_domain);
        let disable_actor = verified_operator_actor(
            substitution_domain,
            disable_operation.operation_id,
            OperatorLifecycleAction::Disable,
            authority_target,
            None,
        )
        .await;
        let mut substituted_disable = DisableIdentityPrincipalRequest {
            operation: disable_operation,
            principal_fingerprint: target_principal,
            expected_active_binding: Some(substituted_target),
            actor: disable_actor,
        };
        substituted_disable.operation.request_fingerprint =
            disable_identity_principal_request_fingerprint(&substituted_disable);
        assert!(matches!(
            db.disable_identity_principal(&substituted_disable).await,
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));

        let revoke_operation = domain_operation(substitution_domain);
        let revoke_actor = verified_operator_actor(
            substitution_domain,
            revoke_operation.operation_id,
            OperatorLifecycleAction::Revoke,
            authority_target,
            None,
        )
        .await;
        let mut substituted_revoke = RevokeIdentityKeyRequest {
            operation: revoke_operation,
            event_author_pubkey: target_key,
            expected_active_binding: Some(substituted_target),
            actor: revoke_actor,
        };
        substituted_revoke.operation.request_fingerprint =
            revoke_identity_key_request_fingerprint(&substituted_revoke);
        assert!(matches!(
            db.revoke_identity_key(&substituted_revoke).await,
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));

        let rotate_operation = domain_operation(substitution_domain);
        let replacement_keys = Keys::generate();
        let replacement_expires_at = Utc::now() + Duration::seconds(30);
        let rotate_actor = verified_operator_actor(
            substitution_domain,
            rotate_operation.operation_id,
            OperatorLifecycleAction::Rotate,
            authority_target,
            Some((&replacement_keys, replacement_expires_at)),
        )
        .await;
        let mut substituted_rotate = RotateIdentityBindingRequest {
            operation: rotate_operation,
            target: substituted_target,
            replacement: replacement_proof(
                rotate_operation,
                [175; 32],
                target_principal,
                replacement_keys.public_key().to_bytes(),
            ),
            actor: rotate_actor,
        };
        substituted_rotate.replacement.expires_at = replacement_expires_at;
        substituted_rotate.replacement.intent_fingerprint =
            rotate_identity_intent_fingerprint(&substituted_rotate);
        substituted_rotate.operation.request_fingerprint =
            rotate_identity_binding_request_fingerprint(&substituted_rotate);
        assert!(matches!(
            db.rotate_identity_binding(&substituted_rotate).await,
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));

        let substitution_state: (i16, i64, i64) = sqlx::query_as(
            "SELECT binding_state, \
               (SELECT current_generation FROM authorization_invalidation_domains WHERE community_id=$1), \
               (SELECT count(*) FROM authorization_operation_receipts WHERE community_id=$1 \
                  AND operation_id IN ($3,$4,$5,$6)) \
             FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(substitution_domain.as_uuid())
        .bind(target_binding.binding_id)
        .bind(substituted_retire.operation.operation_id)
        .bind(substituted_disable.operation.operation_id)
        .bind(substituted_revoke.operation.operation_id)
        .bind(substituted_rotate.operation.operation_id)
        .fetch_one(&db.pool)
        .await
        .expect("verify target substitution left no mutation");
        assert_eq!(substitution_state, (1, 0, 0));

        let partial_domain = CommunityId::from_uuid(Uuid::new_v4());
        install_lifecycle_test_domain(&db, partial_domain, 100).await;
        let partial_principal = [181; 32];
        let partial_key = [182; 32];
        let partial_binding = enroll_for_postgres(
            &db,
            partial_domain,
            partial_principal,
            partial_key,
            "operator-partial",
        )
        .await;
        let partial_target = ExactActiveBindingTarget {
            binding_id: partial_binding.binding_id,
            binding_version: partial_binding.binding_version,
            expected_lifecycle_revision: 1,
            principal_fingerprint: partial_principal,
            event_author_pubkey: partial_key,
        };
        let partial_operation = domain_operation(partial_domain);
        let partial_actor = verified_operator_actor(
            partial_domain,
            partial_operation.operation_id,
            OperatorLifecycleAction::Retire,
            partial_target,
            None,
        )
        .await;
        let mut partial_request = RetireIdentityPairRequest {
            operation: partial_operation,
            target: partial_target,
            actor: partial_actor,
        };
        partial_request.operation.request_fingerprint =
            retire_identity_pair_request_fingerprint(&partial_request);
        let (partial_creation, partial_fingerprint): (Uuid, Vec<u8>) = sqlx::query_as(
            "SELECT creation_operation_id,creation_request_fingerprint FROM identity_bindings \
             WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(partial_domain.as_uuid())
        .bind(partial_binding.binding_id)
        .fetch_one(&db.pool)
        .await
        .expect("load partial authority attribution");
        let partial_object = [183_u8; 32];
        let partial_fence = [184_u8; 32];
        let mut partial_tx = db.pool.begin().await.expect("begin partial authority tx");
        sqlx::query(
            "INSERT INTO protected_object_authority \
             (community_id,object_kind,object_key,capability,actor_pubkey,binding_id, \
              binding_version,policy_revision,invalidation_generation,authority_epoch,fence, \
              issued_at,expires_at,operation_id,request_fingerprint) \
             VALUES ($1,3,$2,3,$3,$4,$5,1,0,1,$6,clock_timestamp()-INTERVAL '1 second', \
                     clock_timestamp()+INTERVAL '1 hour',$7,$8)",
        )
        .bind(partial_domain.as_uuid())
        .bind(partial_object.as_slice())
        .bind(partial_key.as_slice())
        .bind(partial_binding.binding_id)
        .bind(i64_from_u64(partial_binding.binding_version).expect("partial binding version"))
        .bind(partial_fence.as_slice())
        .bind(partial_creation)
        .bind(&partial_fingerprint)
        .execute(&mut *partial_tx)
        .await
        .expect("stage deferred partial protected authority");
        assert!(matches!(
            execute_retire_tx(&mut partial_tx, &partial_request, None).await,
            Err(IdentityLifecycleFailure::Storage(DbError::InvalidData(_)))
        ));
        partial_tx
            .rollback()
            .await
            .expect("rollback partial authority transaction");
        let partial_state: (i16, i64, i64) = sqlx::query_as(
            "SELECT binding_state, \
               (SELECT current_generation FROM authorization_invalidation_domains WHERE community_id=$1), \
               (SELECT count(*) FROM authorization_operation_receipts WHERE community_id=$1 \
                  AND operation_id=$3) \
             FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(partial_domain.as_uuid())
        .bind(partial_binding.binding_id)
        .bind(partial_request.operation.operation_id)
        .fetch_one(&db.pool)
        .await
        .expect("verify partial authority rollback");
        assert_eq!(partial_state, (1, 0, 0));

        let overcap_domain = CommunityId::from_uuid(Uuid::new_v4());
        install_lifecycle_test_domain(&db, overcap_domain, 100).await;
        let overcap_principal = [191; 32];
        let overcap_key = [192; 32];
        let overcap_binding = enroll_for_postgres(
            &db,
            overcap_domain,
            overcap_principal,
            overcap_key,
            "operator-overcap",
        )
        .await;
        let (overcap_creation, overcap_fingerprint): (Uuid, Vec<u8>) = sqlx::query_as(
            "SELECT creation_operation_id,creation_request_fingerprint FROM identity_bindings \
             WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(overcap_domain.as_uuid())
        .bind(overcap_binding.binding_id)
        .fetch_one(&db.pool)
        .await
        .expect("load over-cap authority attribution");
        sqlx::query(
            "INSERT INTO authorization_authority_epochs \
             (community_id,object_kind,object_key,authority_epoch,fence,operation_id,request_fingerprint) \
             SELECT $1,3,decode(lpad(to_hex(value),64,'0'),'hex'),1, \
                    decode(lpad(to_hex(value + 2048),64,'0'),'hex'),$2,$3 \
             FROM generate_series(1,1025) value",
        )
        .bind(overcap_domain.as_uuid())
        .bind(overcap_creation)
        .bind(&overcap_fingerprint)
        .execute(&db.pool)
        .await
        .expect("seed over-cap authority epochs");
        sqlx::query(
            "INSERT INTO protected_object_authority \
             (community_id,object_kind,object_key,capability,actor_pubkey,binding_id, \
              binding_version,policy_revision,invalidation_generation,authority_epoch,fence, \
              issued_at,expires_at,operation_id,request_fingerprint) \
             SELECT $1,3,decode(lpad(to_hex(value),64,'0'),'hex'),3,$2,$3,$4,1,0,1, \
                    decode(lpad(to_hex(value + 2048),64,'0'),'hex'), \
                    clock_timestamp()-INTERVAL '1 second',clock_timestamp()+INTERVAL '1 hour',$5,$6 \
             FROM generate_series(1,1025) value",
        )
        .bind(overcap_domain.as_uuid())
        .bind(overcap_key.as_slice())
        .bind(overcap_binding.binding_id)
        .bind(i64_from_u64(overcap_binding.binding_version).expect("over-cap binding version"))
        .bind(overcap_creation)
        .bind(&overcap_fingerprint)
        .execute(&db.pool)
        .await
        .expect("seed over-cap protected authorities");
        let overcap_target = ExactActiveBindingTarget {
            binding_id: overcap_binding.binding_id,
            binding_version: overcap_binding.binding_version,
            expected_lifecycle_revision: 1,
            principal_fingerprint: overcap_principal,
            event_author_pubkey: overcap_key,
        };
        let overcap_operation = domain_operation(overcap_domain);
        let overcap_actor = verified_operator_actor(
            overcap_domain,
            overcap_operation.operation_id,
            OperatorLifecycleAction::Retire,
            overcap_target,
            None,
        )
        .await;
        let mut overcap_request = RetireIdentityPairRequest {
            operation: overcap_operation,
            target: overcap_target,
            actor: overcap_actor,
        };
        overcap_request.operation.request_fingerprint =
            retire_identity_pair_request_fingerprint(&overcap_request);
        assert!(matches!(
            db.retire_identity_pair(&overcap_request).await,
            Err(IdentityLifecycleFailure::Storage(DbError::InvalidData(_)))
        ));
        let overcap_state: (i16, i64, i64, i64) = sqlx::query_as(
            "SELECT binding_state, \
               (SELECT max(authority_epoch) FROM authorization_authority_epochs WHERE community_id=$1), \
               (SELECT current_generation FROM authorization_invalidation_domains WHERE community_id=$1), \
               (SELECT count(*) FROM authorization_operation_receipts WHERE community_id=$1 \
                  AND operation_id=$3) \
             FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(overcap_domain.as_uuid())
        .bind(overcap_binding.binding_id)
        .bind(overcap_request.operation.operation_id)
        .fetch_one(&db.pool)
        .await
        .expect("verify over-cap retirement rollback");
        assert_eq!(overcap_state, (1, 1, 0, 0));

        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("drop operator authority database");
        admin.close().await;
    }

    #[tokio::test]
    #[ignore = "requires a dedicated disposable Postgres database"]
    async fn postgres_preauth_capacity_is_independent_from_canonical_lifecycle() {
        use crate::{
            authorization_resolver::ProviderFreeEnrollmentRuntime,
            operator_lifecycle::{OperatorAuthenticationDenialReason, OperatorPreauthDenialWrite},
        };

        let (db, admin, database_name) =
            create_disposable_lifecycle_database("s5_preauth_capacity").await;
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        install_lifecycle_test_domain(&db, domain, 3).await;
        db.install_authorization_event_capacity(
            domain,
            AuthorizationEventCapacityPolicy::new(3, 1 << 20, 16 << 10)
                .expect("bounded test capacity"),
        )
        .await
        .expect("install independent pre-auth capacity");
        let runtime = ProviderFreeEnrollmentRuntime::new(db.clone());
        for body in [b"malformed-1".as_slice(), b"malformed-2", b"malformed-3"] {
            assert_eq!(
                runtime
                    .prepare_operator_provision_authentication_attempt(domain, body)
                    .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                    .await
                    .expect("persist bounded pre-auth denial"),
                OperatorPreauthDenialWrite::Inserted
            );
        }
        assert_eq!(
            runtime
                .prepare_operator_provision_authentication_attempt(domain, b"malformed-4")
                .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                .await
                .expect("classify independent saturation"),
            OperatorPreauthDenialWrite::CapacityExhausted
        );

        let binding =
            enroll_for_postgres(&db, domain, [221; 32], [222; 32], "after-saturation").await;
        assert_ne!(binding.binding_id, Uuid::nil());
        let counters: (i64, i64, i64, i16) = sqlx::query_as(
            "SELECT preauth.retained_event_count,canonical.retained_event_count, \
                    (SELECT count(*) FROM authorization_operation_receipts WHERE community_id=$1), \
                    canonical.health_state \
             FROM authorization_operator_preauth_denial_capacity preauth \
             JOIN authorization_event_capacity canonical USING (community_id) \
             WHERE preauth.community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&db.pool)
        .await
        .expect("load independent capacity state");
        assert_eq!(counters, (3, 1, 1, 1));
        close_disposable_lifecycle_database(&db, admin, database_name).await;
    }

    #[tokio::test]
    #[ignore = "requires a dedicated disposable Postgres database"]
    async fn postgres_successor_transitions_consume_exact_facts_and_replay_once() {
        let (db, admin, database_name) =
            create_disposable_lifecycle_database("s5_successor_expiry").await;

        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(community_id.as_uuid())
            .bind(format!("s3-{}.example", community_id.as_uuid().simple()))
            .execute(&db.pool)
            .await
            .expect("insert test community");
        sqlx::query(
            "INSERT INTO identity_enrollment_policies \
             (community_id,policy_revision,enrollment_mode,policy_digest,effective_at,expires_at) \
             VALUES ($1,1,1,$2,clock_timestamp()-INTERVAL '1 second', \
                     clock_timestamp()+INTERVAL '30 minutes')",
        )
        .bind(community_id.as_uuid())
        .bind([201_u8; 32].as_slice())
        .execute(&db.pool)
        .await
        .expect("insert enrollment policy");
        let policy_expires_at: DateTime<Utc> = sqlx::query_scalar(
            "SELECT expires_at FROM identity_enrollment_policies \
             WHERE community_id=$1 AND policy_revision=1",
        )
        .bind(community_id.as_uuid())
        .fetch_one(&db.pool)
        .await
        .expect("load finite enrollment policy expiry");
        sqlx::query(
            "INSERT INTO authorization_event_capacity \
             (community_id,max_events_per_domain,max_bytes_per_domain,max_envelope_bytes) \
             VALUES ($1,1000,1048576,16384)",
        )
        .bind(community_id.as_uuid())
        .execute(&db.pool)
        .await
        .expect("install audit capacity");
        sqlx::query(
            "INSERT INTO authorization_invalidation_domains (community_id,current_generation) \
             VALUES ($1,0)",
        )
        .bind(community_id.as_uuid())
        .execute(&db.pool)
        .await
        .expect("activate authorization invalidation");
        let canonical_actor = actor_for_postgres(&db, community_id).await;

        let principal = [61; 32];
        let old_key = [62; 32];
        let rotated_key = [63; 32];
        let enabled_key = [64; 32];
        let original =
            enroll_for_postgres(&db, community_id, principal, old_key, "rotate-enable").await;
        let target = ExactActiveBindingTarget {
            binding_id: original.binding_id,
            binding_version: original.binding_version,
            expected_lifecycle_revision: 1,
            principal_fingerprint: principal,
            event_author_pubkey: old_key,
        };
        let mut rotate = RotateIdentityBindingRequest {
            operation: domain_operation(community_id),
            target,
            replacement: replacement_proof(
                domain_operation(community_id),
                [1; 32],
                principal,
                rotated_key,
            ),
            actor: canonical_actor.clone(),
        };
        rotate.replacement.community_id = community_id;
        rotate.replacement.operation_id = rotate.operation.operation_id;
        rotate.replacement.intent_fingerprint = rotate_identity_intent_fingerprint(&rotate);
        rotate.operation.request_fingerprint = rotate_identity_binding_request_fingerprint(&rotate);
        let rotated = match db
            .rotate_identity_binding(&rotate)
            .await
            .expect("rotate binding")
        {
            IdentityLifecycleObservation::Applied {
                binding: Some(binding),
                ..
            } => binding,
            observation => panic!("unexpected rotate observation: {observation:?}"),
        };
        let rotated_expires_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT expires_at FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(community_id.as_uuid())
        .bind(rotated.binding_id)
        .fetch_one(&db.pool)
        .await
        .expect("load rotated successor expiry");
        assert_eq!(rotated_expires_at, Some(policy_expires_at));
        let mut rotate_retry = rotate.clone();
        rotate_retry.operation.correlation_id = Uuid::new_v4();
        rotate_retry.operation.attempt_id = Uuid::new_v4();
        assert!(matches!(
            db.rotate_identity_binding(&rotate_retry)
                .await
                .expect("replay rotate with fresh delivery ids"),
            IdentityLifecycleObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                binding: Some(binding),
                ..
            } if binding == rotated
        ));
        let mut changed_rotate_proof = rotate.clone();
        changed_rotate_proof.replacement.proof_digest = [94; 32];
        changed_rotate_proof.operation.request_fingerprint =
            rotate_identity_binding_request_fingerprint(&changed_rotate_proof);
        assert!(matches!(
            db.rotate_identity_binding(&changed_rotate_proof).await,
            Err(IdentityLifecycleFailure::IntentConflict)
        ));

        let rotated_target = ExactActiveBindingTarget {
            binding_id: rotated.binding_id,
            binding_version: rotated.binding_version,
            expected_lifecycle_revision: 1,
            principal_fingerprint: principal,
            event_author_pubkey: rotated_key,
        };
        let mut disable = DisableIdentityPrincipalRequest {
            operation: domain_operation(community_id),
            principal_fingerprint: principal,
            expected_active_binding: Some(rotated_target),
            actor: canonical_actor.clone(),
        };
        disable.operation.request_fingerprint =
            disable_identity_principal_request_fingerprint(&disable);
        assert!(matches!(
            db.disable_identity_principal(&disable)
                .await
                .expect("disable rotated principal"),
            IdentityLifecycleObservation::Applied { binding: None, .. }
        ));
        let disabled_generation: i64 = sqlx::query_scalar(
            "SELECT fact_generation FROM identity_lifecycle_selectors selector \
             LEFT JOIN identity_lifecycle_selector_consumptions consumption \
               ON consumption.community_id=selector.community_id \
              AND consumption.selector_id=selector.selector_id \
             WHERE selector.community_id=$1 AND selector.selector_kind=2 \
               AND selector.principal_fingerprint=$2 AND consumption.selector_id IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("open disabled fact");
        let pending_generation: i64 = sqlx::query_scalar(
            "SELECT fact_generation FROM identity_lifecycle_selectors selector \
             LEFT JOIN identity_lifecycle_selector_consumptions consumption \
               ON consumption.community_id=selector.community_id \
              AND consumption.selector_id=selector.selector_id \
             WHERE selector.community_id=$1 AND selector.selector_kind=4 \
               AND selector.principal_fingerprint=$2 AND consumption.selector_id IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("open pending fact");
        let mut enable = EnableIdentityPrincipalRequest {
            operation: domain_operation(community_id),
            principal_fingerprint: principal,
            disabled_fact_generation: u64_from_i64(disabled_generation).expect("generation"),
            pending: ExpectedPendingReplacement {
                target: ExactRetiredBindingTarget {
                    binding_id: rotated.binding_id,
                    binding_version: rotated.binding_version,
                    expected_lifecycle_revision: 2,
                    principal_fingerprint: principal,
                    event_author_pubkey: rotated_key,
                },
                fact_generation: u64_from_i64(pending_generation).expect("generation"),
            },
            replacement: replacement_proof(
                domain_operation(community_id),
                [1; 32],
                principal,
                enabled_key,
            ),
            principal_resolution: Some(principal_resolution(
                domain_operation(community_id),
                [1; 32],
                principal,
            )),
            actor: canonical_actor.clone(),
        };
        enable.replacement.community_id = community_id;
        enable.replacement.operation_id = enable.operation.operation_id;
        let enable_resolution = enable
            .principal_resolution
            .as_mut()
            .expect("principal resolution");
        enable_resolution.community_id = community_id;
        enable_resolution.operation_id = enable.operation.operation_id;
        enable_resolution.issuer = "https://issuer.example".to_owned();
        enable_resolution.subject = "rotate-enable".to_owned();
        let enable_intent = enable_identity_intent_fingerprint(&enable);
        enable.replacement.intent_fingerprint = enable_intent;
        enable
            .principal_resolution
            .as_mut()
            .expect("principal resolution")
            .intent_fingerprint = enable_intent;
        enable.operation.request_fingerprint =
            enable_identity_principal_request_fingerprint(&enable);
        assert_eq!(
            enable.replacement.intent_fingerprint,
            enable_identity_intent_fingerprint(&enable),
            "replacement proof intent must remain exact"
        );
        assert_eq!(
            enable
                .principal_resolution
                .as_ref()
                .expect("principal resolution")
                .intent_fingerprint,
            enable_identity_intent_fingerprint(&enable),
            "principal proof intent must remain exact"
        );
        assert_eq!(
            enable.operation.request_fingerprint,
            enable_identity_principal_request_fingerprint(&enable),
            "request fingerprint must remain exact"
        );
        validate_enable_request(&enable).expect("valid sealed enable request");
        let enabled = match db
            .enable_identity_principal(&enable)
            .await
            .expect("enable principal with pending lineage")
        {
            IdentityLifecycleObservation::Applied {
                binding: Some(binding),
                ..
            } => binding,
            observation => panic!("unexpected enable observation: {observation:?}"),
        };
        let enabled_expires_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT expires_at FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(community_id.as_uuid())
        .bind(enabled.binding_id)
        .fetch_one(&db.pool)
        .await
        .expect("load enabled successor expiry");
        assert_eq!(enabled_expires_at, Some(policy_expires_at));
        assert!(matches!(
            db.enable_identity_principal(&enable)
                .await
                .expect("replay enable"),
            IdentityLifecycleObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                binding: Some(binding),
                ..
            } if binding == enabled
        ));
        let mut changed_enable_proof = enable.clone();
        changed_enable_proof
            .principal_resolution
            .as_mut()
            .expect("principal resolution")
            .proof_digest = [95; 32];
        changed_enable_proof.operation.request_fingerprint =
            enable_identity_principal_request_fingerprint(&changed_enable_proof);
        assert!(matches!(
            db.enable_identity_principal(&changed_enable_proof).await,
            Err(IdentityLifecycleFailure::IntentConflict)
        ));

        let (receipt_count, history_count, event_count, consumption_count): (i64, i64, i64, i64) =
            sqlx::query_as(
                "SELECT \
                   (SELECT count(*) FROM authorization_operation_receipts \
                     WHERE community_id=$1 AND operation_id=$2), \
                   (SELECT count(*) FROM identity_lifecycle_history \
                     WHERE community_id=$1 AND operation_id=$2), \
                   (SELECT count(*) FROM authorization_events \
                     WHERE community_id=$1 AND operation_id=$2), \
                   (SELECT count(*) FROM identity_lifecycle_selector_consumptions \
                     WHERE community_id=$1 AND operation_id=$2)",
            )
            .bind(community_id.as_uuid())
            .bind(enable.operation.operation_id)
            .fetch_one(&db.pool)
            .await
            .expect("count exact enable artifacts");
        assert_eq!(
            (receipt_count, history_count, event_count, consumption_count),
            (1, 1, 1, 2)
        );

        let concurrent_principal = [65; 32];
        let concurrent_old_key = [66; 32];
        let concurrent_old = enroll_for_postgres(
            &db,
            community_id,
            concurrent_principal,
            concurrent_old_key,
            "concurrent-enable",
        )
        .await;
        let concurrent_target = ExactActiveBindingTarget {
            binding_id: concurrent_old.binding_id,
            binding_version: concurrent_old.binding_version,
            expected_lifecycle_revision: 1,
            principal_fingerprint: concurrent_principal,
            event_author_pubkey: concurrent_old_key,
        };
        let mut concurrent_disable = DisableIdentityPrincipalRequest {
            operation: domain_operation(community_id),
            principal_fingerprint: concurrent_principal,
            expected_active_binding: Some(concurrent_target),
            actor: canonical_actor.clone(),
        };
        concurrent_disable.operation.request_fingerprint =
            disable_identity_principal_request_fingerprint(&concurrent_disable);
        db.disable_identity_principal(&concurrent_disable)
            .await
            .expect("disable concurrent-enable fixture");
        let (concurrent_disabled, concurrent_pending): (i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT fact_generation FROM identity_lifecycle_selectors selector \
                 LEFT JOIN identity_lifecycle_selector_consumptions consumption \
                   ON consumption.community_id=selector.community_id \
                  AND consumption.selector_id=selector.selector_id \
                 WHERE selector.community_id=$1 AND selector.selector_kind=2 \
                   AND selector.principal_fingerprint=$2 AND consumption.selector_id IS NULL), \
               (SELECT fact_generation FROM identity_lifecycle_selectors selector \
                 LEFT JOIN identity_lifecycle_selector_consumptions consumption \
                   ON consumption.community_id=selector.community_id \
                  AND consumption.selector_id=selector.selector_id \
                 WHERE selector.community_id=$1 AND selector.selector_kind=4 \
                   AND selector.principal_fingerprint=$2 AND consumption.selector_id IS NULL)",
        )
        .bind(community_id.as_uuid())
        .bind(concurrent_principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("load concurrent-enable facts");
        let concurrent_pending = ExpectedPendingReplacement {
            target: ExactRetiredBindingTarget {
                binding_id: concurrent_old.binding_id,
                binding_version: concurrent_old.binding_version,
                expected_lifecycle_revision: 2,
                principal_fingerprint: concurrent_principal,
                event_author_pubkey: concurrent_old_key,
            },
            fact_generation: u64_from_i64(concurrent_pending).expect("pending generation"),
        };
        let build_concurrent_enable = |new_key: [u8; 32]| {
            let operation = domain_operation(community_id);
            let mut request = EnableIdentityPrincipalRequest {
                operation,
                principal_fingerprint: concurrent_principal,
                disabled_fact_generation: u64_from_i64(concurrent_disabled)
                    .expect("disabled generation"),
                pending: concurrent_pending,
                replacement: replacement_proof(operation, [1; 32], concurrent_principal, new_key),
                principal_resolution: Some(principal_resolution(
                    operation,
                    [1; 32],
                    concurrent_principal,
                )),
                actor: canonical_actor.clone(),
            };
            request.replacement.community_id = community_id;
            request.replacement.operation_id = operation.operation_id;
            let resolution = request
                .principal_resolution
                .as_mut()
                .expect("principal resolution");
            resolution.community_id = community_id;
            resolution.operation_id = operation.operation_id;
            resolution.issuer = "https://issuer.example".to_owned();
            resolution.subject = "concurrent-enable".to_owned();
            let intent = enable_identity_intent_fingerprint(&request);
            request.replacement.intent_fingerprint = intent;
            request
                .principal_resolution
                .as_mut()
                .expect("principal resolution")
                .intent_fingerprint = intent;
            request.operation.request_fingerprint =
                enable_identity_principal_request_fingerprint(&request);
            request
        };
        let concurrent_a = build_concurrent_enable([67; 32]);
        let concurrent_b = build_concurrent_enable([68; 32]);
        let (result_a, result_b) = tokio::join!(
            db.enable_identity_principal(&concurrent_a),
            db.enable_identity_principal(&concurrent_b),
        );
        let applied = [result_a.as_ref(), result_b.as_ref()]
            .into_iter()
            .filter(|result| matches!(result, Ok(IdentityLifecycleObservation::Applied { .. })))
            .count();
        let denied = [result_a.as_ref(), result_b.as_ref()]
            .into_iter()
            .filter(|result| matches!(result, Ok(IdentityLifecycleObservation::Denied { .. })))
            .count();
        assert_eq!((applied, denied), (1, 1));
        let concurrent_state: (i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM identity_bindings WHERE community_id=$1 \
                 AND principal_fingerprint=$2 AND binding_state=1), \
               (SELECT count(*) FROM identity_lifecycle_selector_consumptions consumption \
                 JOIN identity_lifecycle_selectors selector \
                   ON selector.community_id=consumption.community_id \
                  AND selector.selector_id=consumption.selector_id \
                 WHERE selector.community_id=$1 AND selector.selector_kind=4 \
                   AND selector.principal_fingerprint=$2)",
        )
        .bind(community_id.as_uuid())
        .bind(concurrent_principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("load concurrent-enable result");
        assert_eq!(concurrent_state, (1, 1));

        let absent_principal = [71; 32];
        let mut inactive_disable = DisableIdentityPrincipalRequest {
            operation: domain_operation(community_id),
            principal_fingerprint: absent_principal,
            expected_active_binding: None,
            actor: canonical_actor.clone(),
        };
        inactive_disable.operation.request_fingerprint =
            disable_identity_principal_request_fingerprint(&inactive_disable);
        db.disable_identity_principal(&inactive_disable)
            .await
            .expect("disable inactive principal");
        let absent_pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM identity_lifecycle_selectors selector \
             LEFT JOIN identity_lifecycle_selector_consumptions consumption \
               ON consumption.community_id=selector.community_id \
              AND consumption.selector_id=selector.selector_id \
             WHERE selector.community_id=$1 AND selector.selector_kind=4 \
               AND selector.principal_fingerprint=$2 AND consumption.selector_id IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(absent_principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("count absent pending fact");
        assert_eq!(absent_pending, 0, "Enable cannot synthesize a missing Q");

        let recover_principal = [81; 32];
        let recover_old_key = [82; 32];
        let recover_new_key = [83; 32];
        let recover_old = enroll_for_postgres(
            &db,
            community_id,
            recover_principal,
            recover_old_key,
            "recover",
        )
        .await;
        let recover_target = ExactActiveBindingTarget {
            binding_id: recover_old.binding_id,
            binding_version: recover_old.binding_version,
            expected_lifecycle_revision: 1,
            principal_fingerprint: recover_principal,
            event_author_pubkey: recover_old_key,
        };
        let mut retire = RetireIdentityPairRequest {
            operation: domain_operation(community_id),
            target: recover_target,
            actor: canonical_actor.clone(),
        };
        retire.operation.request_fingerprint = retire_identity_pair_request_fingerprint(&retire);
        db.retire_identity_pair(&retire)
            .await
            .expect("retire binding before recovery");
        let recover_generation: i64 = sqlx::query_scalar(
            "SELECT fact_generation FROM identity_lifecycle_selectors selector \
             LEFT JOIN identity_lifecycle_selector_consumptions consumption \
               ON consumption.community_id=selector.community_id \
              AND consumption.selector_id=selector.selector_id \
             WHERE selector.community_id=$1 AND selector.selector_kind=4 \
               AND selector.principal_fingerprint=$2 AND consumption.selector_id IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(recover_principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("open recovery pending fact");
        let mut recover = RecoverIdentityBindingRequest {
            operation: domain_operation(community_id),
            pending: ExpectedPendingReplacement {
                target: ExactRetiredBindingTarget {
                    binding_id: recover_old.binding_id,
                    binding_version: recover_old.binding_version,
                    expected_lifecycle_revision: 2,
                    principal_fingerprint: recover_principal,
                    event_author_pubkey: recover_old_key,
                },
                fact_generation: u64_from_i64(recover_generation).expect("generation"),
            },
            replacement: replacement_proof(
                domain_operation(community_id),
                [1; 32],
                recover_principal,
                recover_new_key,
            ),
            actor: canonical_actor.clone(),
        };
        recover.replacement.community_id = community_id;
        recover.replacement.operation_id = recover.operation.operation_id;
        recover.replacement.intent_fingerprint = recover_identity_intent_fingerprint(&recover);
        recover.operation.request_fingerprint =
            recover_identity_binding_request_fingerprint(&recover);
        let recovered = match db
            .recover_identity_binding(&recover)
            .await
            .expect("recover exact pending lineage")
        {
            IdentityLifecycleObservation::Applied {
                binding: Some(binding),
                ..
            } => binding,
            observation => panic!("unexpected recover observation: {observation:?}"),
        };
        let recovered_expires_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT expires_at FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(community_id.as_uuid())
        .bind(recovered.binding_id)
        .fetch_one(&db.pool)
        .await
        .expect("load recovered successor expiry");
        assert_eq!(recovered_expires_at, Some(policy_expires_at));
        assert!(matches!(
            db.recover_identity_binding(&recover)
                .await
                .expect("replay recover"),
            IdentityLifecycleObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                binding: Some(binding),
                ..
            } if binding == recovered
        ));
        let (recover_consumptions, revoked_old_key): (i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM identity_lifecycle_selector_consumptions \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM identity_lifecycle_selectors \
                 WHERE community_id=$1 AND selector_kind=3 AND event_author_pubkey=$3)",
        )
        .bind(community_id.as_uuid())
        .bind(recover.operation.operation_id)
        .bind(recover_old_key.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("count exact recover artifacts");
        assert_eq!(recover_consumptions, 1);
        assert_eq!(
            revoked_old_key, 0,
            "retire/recover must not revoke the old key"
        );

        let admission_principal = [107; 32];
        let admission_key = [108; 32];
        let admission_binding = enroll_for_postgres(
            &db,
            community_id,
            admission_principal,
            admission_key,
            "admission-loss",
        )
        .await;
        let (creation_operation, creation_fingerprint): (Uuid, Vec<u8>) = sqlx::query_as(
            "SELECT creation_operation_id,creation_request_fingerprint \
             FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(community_id.as_uuid())
        .bind(admission_binding.binding_id)
        .fetch_one(&db.pool)
        .await
        .expect("load admission binding creation receipt");
        let authority_object = [109_u8; 32];
        let authority_fence = [110_u8; 32];
        sqlx::query(
            "INSERT INTO authorization_authority_epochs \
             (community_id,object_kind,object_key,authority_epoch,fence,operation_id,request_fingerprint) \
             VALUES ($1,2,$2,1,$3,$4,$5)",
        )
        .bind(community_id.as_uuid())
        .bind(authority_object.as_slice())
        .bind(authority_fence.as_slice())
        .bind(creation_operation)
        .bind(&creation_fingerprint)
        .execute(&db.pool)
        .await
        .expect("seed admission authority epoch");
        sqlx::query(
            "INSERT INTO protected_object_authority \
             (community_id,object_kind,object_key,capability,actor_pubkey,binding_id, \
              binding_version,policy_revision,invalidation_generation,authority_epoch,fence, \
              issued_at,expires_at,operation_id,request_fingerprint) \
             VALUES ($1,2,$2,1,$3,$4,$5,1,0,1,$6,clock_timestamp()-INTERVAL '1 second', \
                     clock_timestamp()+INTERVAL '1 hour',$7,$8)",
        )
        .bind(community_id.as_uuid())
        .bind(authority_object.as_slice())
        .bind(admission_key.as_slice())
        .bind(admission_binding.binding_id)
        .bind(i64_from_u64(admission_binding.binding_version).expect("binding version"))
        .bind(authority_fence.as_slice())
        .bind(creation_operation)
        .bind(&creation_fingerprint)
        .execute(&db.pool)
        .await
        .expect("seed protected admission authority");
        let admission_actor = {
            let mut transaction = db.pool.begin().await.expect("begin admission actor");
            let actor = resolve_local_admission_loss_actor_tx(
                &mut transaction,
                community_id,
                LocalAdmissionLossCause::Binding {
                    binding_id: admission_binding.binding_id,
                    binding_version: admission_binding.binding_version,
                },
            )
            .await
            .expect("resolve binding admission actor");
            transaction.commit().await.expect("commit admission actor");
            AuthenticatedLifecycleActor::from_sealed_event_actor([111; 32], actor)
                .expect("seal admission actor")
        };
        let mut admission_loss = ExactAdmissionLossRequest {
            operation: domain_operation(community_id),
            target: ExactAdmissionLossTarget {
                binding_id: admission_binding.binding_id,
                binding_version: admission_binding.binding_version,
                expected_lifecycle_revision: 1,
                principal_fingerprint: admission_principal,
                event_author_pubkey: admission_key,
            },
            cause: TrustedAdmissionLossCause::LocalBinding,
            actor: admission_actor,
        };
        admission_loss.operation.request_fingerprint =
            exact_admission_loss_request_fingerprint(&admission_loss);
        assert!(matches!(
            db.apply_exact_admission_loss(&admission_loss)
                .await
                .expect("apply exact admission loss"),
            IdentityLifecycleObservation::Applied {
                transition: IdentityLifecycleTransition::AdmissionLoss,
                binding: None
            }
        ));
        assert!(matches!(
            db.apply_exact_admission_loss(&admission_loss)
                .await
                .expect("replay exact admission loss"),
            IdentityLifecycleObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                binding: None,
                ..
            }
        ));
        let admission_manifest = db
            .authorization_operation_version_delta(
                community_id,
                admission_loss.operation.operation_id,
                admission_loss.operation.request_fingerprint,
            )
            .await
            .expect("load complete admission-loss manifest");
        assert_eq!(admission_manifest.components().len(), 4);
        assert_eq!(
            admission_manifest
                .components()
                .iter()
                .filter(|component| {
                    component.component_kind()
                        == AuthorizationVersionComponentKind::LifecycleSelector
                        && component.before_version() == 0
                        && component.after_version() == 1
                })
                .count(),
            2
        );
        assert_eq!(
            admission_manifest
                .components()
                .iter()
                .filter(|component| {
                    component.component_kind()
                        == AuthorizationVersionComponentKind::InvalidationGeneration
                        && component.before_version() == 0
                        && component.after_version() == 1
                })
                .count(),
            1
        );
        assert_eq!(
            admission_manifest
                .components()
                .iter()
                .filter(|component| {
                    component.component_kind() == AuthorizationVersionComponentKind::AuthorityEpoch
                        && component.before_version() == 1
                        && component.after_version() == 2
                })
                .count(),
            1
        );
        let (admission_binding_state, epoch, protected_epoch): (i16, i64, i64) = sqlx::query_as(
            "SELECT binding.binding_state,epoch.authority_epoch,protected.authority_epoch \
                 FROM identity_bindings binding \
                 JOIN authorization_authority_epochs epoch \
                   ON epoch.community_id=binding.community_id AND epoch.object_kind=2 \
                  AND epoch.object_key=$3 \
                 JOIN protected_object_authority protected \
                   ON protected.community_id=epoch.community_id \
                  AND protected.object_kind=epoch.object_kind \
                  AND protected.object_key=epoch.object_key \
                 WHERE binding.community_id=$1 AND binding.binding_id=$2",
        )
        .bind(community_id.as_uuid())
        .bind(admission_binding.binding_id)
        .bind(authority_object.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("load coupled admission-loss state");
        assert_eq!((admission_binding_state, epoch, protected_epoch), (2, 2, 2));

        let delegated_principal = [112; 32];
        let delegated_actor_key = [113; 32];
        let delegated_owner_key = [114_u8; 32];
        let delegated_relationship_id = Uuid::new_v4();
        let delegated_relationship_revision = 5_u64;
        let delegated_object = [115_u8; 32];
        let delegated_fence = [116_u8; 32];
        let delegated_conditions = [118_u8; 32];
        let delegated_binding = enroll_for_postgres(
            &db,
            community_id,
            delegated_principal,
            delegated_actor_key,
            "delegated-admission-loss",
        )
        .await;
        let (delegated_creation_operation, delegated_creation_fingerprint): (Uuid, Vec<u8>) =
            sqlx::query_as(
                "SELECT creation_operation_id,creation_request_fingerprint \
                 FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
            )
            .bind(community_id.as_uuid())
            .bind(delegated_binding.binding_id)
            .fetch_one(&db.pool)
            .await
            .expect("load delegated binding creation receipt");
        sqlx::query(
            "INSERT INTO authorization_authority_epochs \
             (community_id,object_kind,object_key,authority_epoch,fence,operation_id,request_fingerprint) \
             VALUES ($1,3,$2,1,$3,$4,$5)",
        )
        .bind(community_id.as_uuid())
        .bind(delegated_object.as_slice())
        .bind(delegated_fence.as_slice())
        .bind(delegated_creation_operation)
        .bind(&delegated_creation_fingerprint)
        .execute(&db.pool)
        .await
        .expect("seed delegated authority epoch");
        sqlx::query(
            "INSERT INTO protected_object_authority \
             (community_id,object_kind,object_key,capability,actor_pubkey,owner_pubkey, \
              binding_id,binding_version,delegated_relationship_id, \
              delegated_relationship_revision,delegation_conditions_fingerprint, \
              policy_revision,invalidation_generation, \
              authority_epoch,fence,issued_at,expires_at,operation_id,request_fingerprint) \
             VALUES ($1,3,$2,1,$3,$4,$5,$6,$7,$8,$9,1,1,1,$10, \
                     clock_timestamp()-INTERVAL '1 second', \
                     clock_timestamp()+INTERVAL '1 hour',$11,$12)",
        )
        .bind(community_id.as_uuid())
        .bind(delegated_object.as_slice())
        .bind(delegated_actor_key.as_slice())
        .bind(delegated_owner_key.as_slice())
        .bind(delegated_binding.binding_id)
        .bind(i64_from_u64(delegated_binding.binding_version).expect("binding version"))
        .bind(delegated_relationship_id)
        .bind(i64_from_u64(delegated_relationship_revision).expect("relationship revision"))
        .bind(delegated_conditions.as_slice())
        .bind(delegated_fence.as_slice())
        .bind(delegated_creation_operation)
        .bind(&delegated_creation_fingerprint)
        .execute(&db.pool)
        .await
        .expect("seed protected delegated authority");
        let delegated_actor = {
            let mut transaction = db.pool.begin().await.expect("begin delegated actor");
            let actor = resolve_local_admission_loss_actor_tx(
                &mut transaction,
                community_id,
                LocalAdmissionLossCause::DelegatedRelationship {
                    relationship_id: delegated_relationship_id,
                    relationship_revision: delegated_relationship_revision,
                },
            )
            .await
            .expect("resolve delegated admission actor");
            transaction.commit().await.expect("commit delegated actor");
            AuthenticatedLifecycleActor::from_sealed_event_actor([117; 32], actor)
                .expect("seal delegated admission actor")
        };
        let mut delegated_loss = ExactAdmissionLossRequest {
            operation: domain_operation(community_id),
            target: ExactAdmissionLossTarget {
                binding_id: delegated_binding.binding_id,
                binding_version: delegated_binding.binding_version,
                expected_lifecycle_revision: 1,
                principal_fingerprint: delegated_principal,
                event_author_pubkey: delegated_actor_key,
            },
            cause: TrustedAdmissionLossCause::DelegationAuthority {
                relationship_id: delegated_relationship_id,
                revision: delegated_relationship_revision,
            },
            actor: delegated_actor,
        };
        delegated_loss.operation.request_fingerprint =
            exact_admission_loss_request_fingerprint(&delegated_loss);
        assert!(matches!(
            db.apply_exact_admission_loss(&delegated_loss)
                .await
                .expect("apply delegated admission loss"),
            IdentityLifecycleObservation::Applied {
                transition: IdentityLifecycleTransition::AdmissionLoss,
                binding: None
            }
        ));
        assert!(matches!(
            db.apply_exact_admission_loss(&delegated_loss)
                .await
                .expect("replay delegated admission loss"),
            IdentityLifecycleObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                binding: None,
                ..
            }
        ));
        let delegated_manifest = db
            .authorization_operation_version_delta(
                community_id,
                delegated_loss.operation.operation_id,
                delegated_loss.operation.request_fingerprint,
            )
            .await
            .expect("load delegated admission-loss manifest");
        assert_eq!(delegated_manifest.components().len(), 5);
        assert!(delegated_manifest.components().iter().any(|component| {
            component.component_kind() == AuthorizationVersionComponentKind::InvalidationGeneration
                && component.before_version() == 1
                && component.after_version() == 2
        }));
        assert!(delegated_manifest.components().iter().any(|component| {
            component.component_kind() == AuthorizationVersionComponentKind::DelegatedRelationship
                && component.component_key()
                    == authorization_version_delegated_relationship_component_key(
                        community_id,
                        delegated_relationship_id,
                    )
                && component.before_version() == 0
                && component.after_version() == delegated_relationship_revision
        }));
        assert!(delegated_manifest.components().iter().any(|component| {
            component.component_kind() == AuthorizationVersionComponentKind::AuthorityEpoch
                && component.before_version() == 1
                && component.after_version() == 2
        }));

        let race_principal = [84; 32];
        let race_old_key = [85; 32];
        let race_old =
            enroll_for_postgres(&db, community_id, race_principal, race_old_key, "race").await;
        let mut race_retire = RetireIdentityPairRequest {
            operation: domain_operation(community_id),
            target: ExactActiveBindingTarget {
                binding_id: race_old.binding_id,
                binding_version: race_old.binding_version,
                expected_lifecycle_revision: 1,
                principal_fingerprint: race_principal,
                event_author_pubkey: race_old_key,
            },
            actor: canonical_actor.clone(),
        };
        race_retire.operation.request_fingerprint =
            retire_identity_pair_request_fingerprint(&race_retire);
        db.retire_identity_pair(&race_retire)
            .await
            .expect("retire race target");
        let race_generation: i64 = sqlx::query_scalar(
            "SELECT fact_generation FROM identity_lifecycle_selectors selector \
             LEFT JOIN identity_lifecycle_selector_consumptions consumption \
               ON consumption.community_id=selector.community_id \
              AND consumption.selector_id=selector.selector_id \
             WHERE selector.community_id=$1 AND selector.selector_kind=4 \
               AND selector.principal_fingerprint=$2 AND consumption.selector_id IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(race_principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("open raced pending fact");
        let make_raced_recover = |new_key: [u8; 32]| {
            let mut request = RecoverIdentityBindingRequest {
                operation: domain_operation(community_id),
                pending: ExpectedPendingReplacement {
                    target: ExactRetiredBindingTarget {
                        binding_id: race_old.binding_id,
                        binding_version: race_old.binding_version,
                        expected_lifecycle_revision: 2,
                        principal_fingerprint: race_principal,
                        event_author_pubkey: race_old_key,
                    },
                    fact_generation: u64_from_i64(race_generation).expect("generation"),
                },
                replacement: replacement_proof(
                    domain_operation(community_id),
                    [1; 32],
                    race_principal,
                    new_key,
                ),
                actor: canonical_actor.clone(),
            };
            request.replacement.community_id = community_id;
            request.replacement.operation_id = request.operation.operation_id;
            request.replacement.intent_fingerprint = recover_identity_intent_fingerprint(&request);
            request.operation.request_fingerprint =
                recover_identity_binding_request_fingerprint(&request);
            request
        };
        let race_a = make_raced_recover([86; 32]);
        let race_b = make_raced_recover([87; 32]);
        let (race_a, race_b) = tokio::join!(
            db.recover_identity_binding(&race_a),
            db.recover_identity_binding(&race_b)
        );
        let race_a = race_a.expect("first raced recovery completes");
        let race_b = race_b.expect("second raced recovery completes");
        let applied_count = [race_a, race_b]
            .into_iter()
            .filter(|observation| {
                matches!(
                    observation,
                    IdentityLifecycleObservation::Applied {
                        transition: IdentityLifecycleTransition::Recover,
                        binding: Some(_)
                    }
                )
            })
            .count();
        let denied_count = [race_a, race_b]
            .into_iter()
            .filter(|observation| {
                matches!(
                    observation,
                    IdentityLifecycleObservation::Denied {
                        transition: IdentityLifecycleTransition::Recover,
                        reason: IdentityLifecycleDenial::StaleExpectedState
                    }
                )
            })
            .count();
        assert_eq!((applied_count, denied_count), (1, 1));
        let (race_consumptions, race_active): (i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM identity_lifecycle_selector_consumptions consumption \
                 JOIN identity_lifecycle_selectors selector \
                   ON selector.community_id=consumption.community_id \
                  AND selector.selector_id=consumption.selector_id \
                 WHERE selector.community_id=$1 AND selector.selector_kind=4 \
                   AND selector.principal_fingerprint=$2), \
               (SELECT count(*) FROM identity_bindings \
                 WHERE community_id=$1 AND principal_fingerprint=$2 AND binding_state=1)",
        )
        .bind(community_id.as_uuid())
        .bind(race_principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("count raced recovery state");
        assert_eq!((race_consumptions, race_active), (1, 1));

        let revoked_principal = [101; 32];
        let revoked_key = [102; 32];
        let revoked_binding = enroll_for_postgres(
            &db,
            community_id,
            revoked_principal,
            revoked_key,
            "active-revoke",
        )
        .await;
        let mut active_revoke = RevokeIdentityKeyRequest {
            operation: domain_operation(community_id),
            event_author_pubkey: revoked_key,
            expected_active_binding: Some(ExactActiveBindingTarget {
                binding_id: revoked_binding.binding_id,
                binding_version: revoked_binding.binding_version,
                expected_lifecycle_revision: 1,
                principal_fingerprint: revoked_principal,
                event_author_pubkey: revoked_key,
            }),
            actor: canonical_actor.clone(),
        };
        active_revoke.operation.request_fingerprint =
            revoke_identity_key_request_fingerprint(&active_revoke);
        assert!(matches!(
            db.revoke_identity_key(&active_revoke)
                .await
                .expect("revoke active key"),
            IdentityLifecycleObservation::Applied {
                transition: IdentityLifecycleTransition::Revoke,
                binding: None
            }
        ));
        assert!(matches!(
            db.revoke_identity_key(&active_revoke)
                .await
                .expect("replay active revoke"),
            IdentityLifecycleObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                binding: None,
                ..
            }
        ));
        let (
            active_revoke_receipts,
            active_revoke_history,
            active_revoke_events,
            active_revoke_retired,
            active_revoke_p,
            active_revoke_y,
            active_revoke_q,
        ): (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM authorization_operation_receipts \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM identity_lifecycle_history \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM authorization_events \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM identity_bindings \
                 WHERE community_id=$1 AND binding_id=$3 AND binding_state=2 \
                   AND lifecycle_revision=2), \
               (SELECT count(*) FROM identity_lifecycle_selectors \
                 WHERE community_id=$1 AND selector_kind=1 \
                   AND principal_fingerprint=$5 AND event_author_pubkey=$4), \
               (SELECT count(*) FROM identity_lifecycle_selectors \
                 WHERE community_id=$1 AND selector_kind=3 AND event_author_pubkey=$4), \
               (SELECT count(*) FROM identity_lifecycle_selectors selector \
                 LEFT JOIN identity_lifecycle_selector_consumptions consumption \
                   ON consumption.community_id=selector.community_id \
                  AND consumption.selector_id=selector.selector_id \
                 WHERE selector.community_id=$1 AND selector.selector_kind=4 \
                   AND selector.principal_fingerprint=$5 \
                   AND consumption.selector_id IS NULL)",
        )
        .bind(community_id.as_uuid())
        .bind(active_revoke.operation.operation_id)
        .bind(revoked_binding.binding_id)
        .bind(revoked_key.as_slice())
        .bind(revoked_principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("count exact active-revoke artifacts");
        assert_eq!(
            (
                active_revoke_receipts,
                active_revoke_history,
                active_revoke_events,
                active_revoke_retired,
                active_revoke_p,
                active_revoke_y,
                active_revoke_q,
            ),
            (1, 1, 1, 1, 1, 1, 1)
        );

        let mut revoked_key_reenrollment = AuthoritativeEnrollmentRequest {
            operation: domain_operation(community_id),
            transition: IdentityLifecycleTransition::Enroll,
            issuer: "https://issuer.example".to_owned(),
            subject: "revoked-key-reenrollment".to_owned(),
            principal_fingerprint: [103; 32],
            event_author_pubkey: revoked_key,
            provenance: IdentityBindingProvenance::AttestedKey,
            policy_revision: 1,
            policy_digest: [201; 32],
            enrollment_evidence_digest: [202; 32],
            evidence_expires_at: Utc::now() + chrono::Duration::minutes(5),
            expires_at: None,
            actor: canonical_actor.clone(),
        };
        revoked_key_reenrollment.operation.request_fingerprint =
            authoritative_enrollment_request_fingerprint(&revoked_key_reenrollment);
        assert!(matches!(
            db.execute_authoritative_enrollment(&revoked_key_reenrollment)
                .await
                .expect("deny revoked-key reenrollment"),
            IdentityLifecycleObservation::Denied {
                transition: IdentityLifecycleTransition::Enroll,
                reason: IdentityLifecycleDenial::EventAuthorUnavailable
            }
        ));

        let inactive_revoked_key = [104; 32];
        let mut inactive_revoke = RevokeIdentityKeyRequest {
            operation: domain_operation(community_id),
            event_author_pubkey: inactive_revoked_key,
            expected_active_binding: None,
            actor: canonical_actor.clone(),
        };
        inactive_revoke.operation.request_fingerprint =
            revoke_identity_key_request_fingerprint(&inactive_revoke);
        assert!(matches!(
            db.revoke_identity_key(&inactive_revoke)
                .await
                .expect("revoke inactive key"),
            IdentityLifecycleObservation::Applied {
                transition: IdentityLifecycleTransition::Revoke,
                binding: None
            }
        ));
        assert!(matches!(
            db.revoke_identity_key(&inactive_revoke)
                .await
                .expect("replay inactive revoke"),
            IdentityLifecycleObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                binding: None,
                ..
            }
        ));
        let (
            inactive_revoke_receipts,
            inactive_revoke_history,
            inactive_revoke_events,
            inactive_revoke_y,
            inactive_revoke_other_selectors,
        ): (i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM authorization_operation_receipts \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM identity_lifecycle_history \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM authorization_events \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM identity_lifecycle_selectors \
                 WHERE community_id=$1 AND selector_kind=3 AND event_author_pubkey=$3), \
               (SELECT count(*) FROM identity_lifecycle_selectors \
                 WHERE community_id=$1 AND selector_kind<>3 AND event_author_pubkey=$3)",
        )
        .bind(community_id.as_uuid())
        .bind(inactive_revoke.operation.operation_id)
        .bind(inactive_revoked_key.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("count exact inactive-revoke artifacts");
        assert_eq!(
            (
                inactive_revoke_receipts,
                inactive_revoke_history,
                inactive_revoke_events,
                inactive_revoke_y,
                inactive_revoke_other_selectors,
            ),
            (1, 1, 1, 1, 0)
        );

        let inactive_disable_principal = [105; 32];
        let inactive_disable_key = [106; 32];
        let inactive_disable_binding = enroll_for_postgres(
            &db,
            community_id,
            inactive_disable_principal,
            inactive_disable_key,
            "inactive-disable-with-q",
        )
        .await;
        let mut retire_before_inactive_disable = RetireIdentityPairRequest {
            operation: domain_operation(community_id),
            target: ExactActiveBindingTarget {
                binding_id: inactive_disable_binding.binding_id,
                binding_version: inactive_disable_binding.binding_version,
                expected_lifecycle_revision: 1,
                principal_fingerprint: inactive_disable_principal,
                event_author_pubkey: inactive_disable_key,
            },
            actor: canonical_actor.clone(),
        };
        retire_before_inactive_disable.operation.request_fingerprint =
            retire_identity_pair_request_fingerprint(&retire_before_inactive_disable);
        db.retire_identity_pair(&retire_before_inactive_disable)
            .await
            .expect("retire before inactive disable");
        let mut disable_with_existing_q = DisableIdentityPrincipalRequest {
            operation: domain_operation(community_id),
            principal_fingerprint: inactive_disable_principal,
            expected_active_binding: None,
            actor: canonical_actor.clone(),
        };
        disable_with_existing_q.operation.request_fingerprint =
            disable_identity_principal_request_fingerprint(&disable_with_existing_q);
        assert!(matches!(
            db.disable_identity_principal(&disable_with_existing_q)
                .await
                .expect("disable inactive principal with existing pending lineage"),
            IdentityLifecycleObservation::Applied {
                transition: IdentityLifecycleTransition::Disable,
                binding: None
            }
        ));
        assert!(matches!(
            db.disable_identity_principal(&disable_with_existing_q)
                .await
                .expect("replay inactive disable with pending lineage"),
            IdentityLifecycleObservation::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                binding: None,
                ..
            }
        ));
        let (
            inactive_disable_receipts,
            inactive_disable_history,
            inactive_disable_events,
            inactive_disable_x,
            inactive_disable_q,
        ): (i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM authorization_operation_receipts \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM identity_lifecycle_history \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM authorization_events \
                 WHERE community_id=$1 AND operation_id=$2), \
               (SELECT count(*) FROM identity_lifecycle_selectors selector \
                 LEFT JOIN identity_lifecycle_selector_consumptions consumption \
                   ON consumption.community_id=selector.community_id \
                  AND consumption.selector_id=selector.selector_id \
                 WHERE selector.community_id=$1 AND selector.selector_kind=2 \
                   AND selector.principal_fingerprint=$3 \
                   AND consumption.selector_id IS NULL), \
               (SELECT count(*) FROM identity_lifecycle_selectors selector \
                 LEFT JOIN identity_lifecycle_selector_consumptions consumption \
                   ON consumption.community_id=selector.community_id \
                  AND consumption.selector_id=selector.selector_id \
                 WHERE selector.community_id=$1 AND selector.selector_kind=4 \
                   AND selector.principal_fingerprint=$3 \
                   AND consumption.selector_id IS NULL)",
        )
        .bind(community_id.as_uuid())
        .bind(disable_with_existing_q.operation.operation_id)
        .bind(inactive_disable_principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("count inactive-disable artifacts and open facts");
        assert_eq!(
            (
                inactive_disable_receipts,
                inactive_disable_history,
                inactive_disable_events,
                inactive_disable_x,
                inactive_disable_q,
            ),
            (1, 1, 1, 1, 1)
        );

        let expired_principal = [88; 32];
        let expired_key = [90; 32];
        let expired_binding = enroll_for_postgres(
            &db,
            community_id,
            expired_principal,
            expired_key,
            "expired-enable",
        )
        .await;
        let mut expired_disable = DisableIdentityPrincipalRequest {
            operation: domain_operation(community_id),
            principal_fingerprint: expired_principal,
            expected_active_binding: Some(ExactActiveBindingTarget {
                binding_id: expired_binding.binding_id,
                binding_version: expired_binding.binding_version,
                expected_lifecycle_revision: 1,
                principal_fingerprint: expired_principal,
                event_author_pubkey: expired_key,
            }),
            actor: canonical_actor.clone(),
        };
        expired_disable.operation.request_fingerprint =
            disable_identity_principal_request_fingerprint(&expired_disable);
        db.disable_identity_principal(&expired_disable)
            .await
            .expect("disable principal for expiry test");
        let expired_generation: i64 = sqlx::query_scalar(
            "SELECT fact_generation FROM identity_lifecycle_selectors selector \
             LEFT JOIN identity_lifecycle_selector_consumptions consumption \
               ON consumption.community_id=selector.community_id \
              AND consumption.selector_id=selector.selector_id \
             WHERE selector.community_id=$1 AND selector.selector_kind=2 \
               AND selector.principal_fingerprint=$2 AND consumption.selector_id IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(expired_principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("open expiry-test disabled fact");
        let expired_pending_generation: i64 = sqlx::query_scalar(
            "SELECT fact_generation FROM identity_lifecycle_selectors selector \
             LEFT JOIN identity_lifecycle_selector_consumptions consumption \
               ON consumption.community_id=selector.community_id \
              AND consumption.selector_id=selector.selector_id \
             WHERE selector.community_id=$1 AND selector.selector_kind=4 \
               AND selector.principal_fingerprint=$2 AND consumption.selector_id IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(expired_principal.as_slice())
        .fetch_one(&db.pool)
        .await
        .expect("open expiry-test pending fact");
        let mut expired_enable = EnableIdentityPrincipalRequest {
            operation: domain_operation(community_id),
            principal_fingerprint: expired_principal,
            disabled_fact_generation: u64_from_i64(expired_generation).expect("generation"),
            pending: ExpectedPendingReplacement {
                target: ExactRetiredBindingTarget {
                    binding_id: expired_binding.binding_id,
                    binding_version: expired_binding.binding_version,
                    expected_lifecycle_revision: 2,
                    principal_fingerprint: expired_principal,
                    event_author_pubkey: expired_key,
                },
                fact_generation: u64_from_i64(expired_pending_generation).expect("generation"),
            },
            replacement: replacement_proof(
                domain_operation(community_id),
                [1; 32],
                expired_principal,
                [89; 32],
            ),
            principal_resolution: Some(principal_resolution(
                domain_operation(community_id),
                [1; 32],
                expired_principal,
            )),
            actor: canonical_actor.clone(),
        };
        expired_enable.replacement.community_id = community_id;
        expired_enable.replacement.operation_id = expired_enable.operation.operation_id;
        expired_enable.replacement.expires_at = Utc::now() - Duration::seconds(1);
        expired_enable.replacement.authorization_expires_at = expired_enable.replacement.expires_at;
        expired_enable
            .principal_resolution
            .as_mut()
            .expect("principal resolution")
            .community_id = community_id;
        expired_enable
            .principal_resolution
            .as_mut()
            .expect("principal resolution")
            .operation_id = expired_enable.operation.operation_id;
        let expired_intent = enable_identity_intent_fingerprint(&expired_enable);
        expired_enable.replacement.intent_fingerprint = expired_intent;
        expired_enable
            .principal_resolution
            .as_mut()
            .expect("principal resolution")
            .intent_fingerprint = expired_intent;
        expired_enable.operation.request_fingerprint =
            enable_identity_principal_request_fingerprint(&expired_enable);
        assert!(matches!(
            db.enable_identity_principal(&expired_enable).await,
            Err(IdentityLifecycleFailure::InvalidRequest)
        ));
        let (expired_consumptions, expired_receipts): (i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM identity_lifecycle_selector_consumptions consumption \
                 JOIN identity_lifecycle_selectors selector \
                   ON selector.community_id=consumption.community_id \
                  AND selector.selector_id=consumption.selector_id \
                 WHERE selector.community_id=$1 AND selector.selector_kind=2 \
                   AND selector.principal_fingerprint=$2), \
               (SELECT count(*) FROM authorization_operation_receipts \
                 WHERE community_id=$1 AND operation_id=$3)",
        )
        .bind(community_id.as_uuid())
        .bind(expired_principal.as_slice())
        .bind(expired_enable.operation.operation_id)
        .fetch_one(&db.pool)
        .await
        .expect("verify expired proof leaves no durable evidence");
        assert_eq!((expired_consumptions, expired_receipts), (0, 0));
        close_disposable_lifecycle_database(&db, admin, database_name).await;
    }
}
