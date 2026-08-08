//! Closed deployment-operator lifecycle intent contract.
//!
//! This module contains no actor minting, database writer, restore fence,
//! lifecycle mutation, or caller-supplied fingerprint constructor. The relay
//! may parse bounded request coordinates into an opaque intent; only the
//! origin-sealed verifier grant and canonical database transition added by the
//! operation-specific restore boundary may authorize it.
//!
//! Raw intent fields and the internal transition plan are not public:
//!
//! ```compile_fail
//! use buzz_db::operator_lifecycle::OperatorLifecycleIntent;
//! let _ = OperatorLifecycleIntent {};
//! ```
//!
//! Exact binding coordinates are constructor-validated and remain opaque:
//!
//! ```compile_fail
//! use buzz_db::operator_lifecycle::ExactActiveOperatorTarget;
//! let _ = ExactActiveOperatorTarget {};
//! ```

use std::fmt;

use buzz_auth::OperatorLifecycleAction;
use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    authorization_events::{
        canonical_event_envelope, AuthorizationEventActor, AuthorizationEventKind,
        AuthorizationEventOutcome, AuthorizationReasonCode, NewAuthorizationEvent,
    },
    Db, DbError,
};

const MAX_OPERATOR_PROVISION_BODY_BYTES: usize = 64 * 1024;

/// Closed failures shared by request parsing and the later canonical executor.
#[derive(Debug, thiserror::Error)]
pub enum OperatorLifecycleError {
    /// The bounded request coordinates were invalid.
    #[error("invalid operator lifecycle request")]
    InvalidRequest,
    /// The operation id is already bound to different canonical semantics.
    #[error("operator lifecycle operation intent conflict")]
    IntentConflict,
    /// Required authorization audit evidence could not be committed.
    #[error("operator lifecycle audit unavailable")]
    AuditUnavailable,
    /// Stored immutable canonical evidence was inconsistent.
    #[error("operator lifecycle stored result is corrupt")]
    CorruptStoredResult,
    /// Ordinary database failure; the canonical transaction did not commit.
    #[error("operator lifecycle storage unavailable")]
    Storage(#[source] DbError),
}

impl From<DbError> for OperatorLifecycleError {
    fn from(value: DbError) -> Self {
        Self::Storage(value)
    }
}

/// Redaction-safe operation identity parsed from the exact request body.
#[derive(Clone, Copy)]
pub struct OperatorLifecycleOperation {
    community_id: CommunityId,
    operation_id: Uuid,
    correlation_id: Uuid,
    attempt_id: Uuid,
}

impl OperatorLifecycleOperation {
    /// Validate the server-resolved domain and bounded operation identifiers.
    pub fn new(
        community_id: CommunityId,
        operation_id: Uuid,
        correlation_id: Uuid,
        attempt_id: Uuid,
    ) -> Result<Self, OperatorLifecycleError> {
        if community_id.as_uuid().is_nil()
            || operation_id.is_nil()
            || correlation_id.is_nil()
            || attempt_id.is_nil()
        {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Ok(Self {
            community_id,
            operation_id,
            correlation_id,
            attempt_id,
        })
    }

    /// Server-resolved authorization domain.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.community_id
    }

    /// Stable operation identity used by canonical idempotency.
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    /// Redaction-safe correlation identity.
    pub const fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }

    /// Unique delivery-attempt identity.
    pub const fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
}

impl fmt::Debug for OperatorLifecycleOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorLifecycleOperation([REDACTED])")
    }
}

/// Exact immutable active binding generation named by a request.
#[derive(Clone, Copy)]
pub struct ExactActiveOperatorTarget {
    binding_id: Uuid,
    binding_version: u64,
    expected_lifecycle_revision: u64,
    principal_fingerprint: [u8; 32],
    event_author_pubkey: [u8; 32],
}

// The crate-local accessors are consumed by the immediately dependent S5
// restore child; keep this standalone dependency cut warning-clean.
#[allow(dead_code)]
impl ExactActiveOperatorTarget {
    /// Validate an exact active generation (whose lifecycle revision is one).
    pub fn new(
        binding_id: Uuid,
        binding_version: u64,
        expected_lifecycle_revision: u64,
        principal_fingerprint: [u8; 32],
        event_author_pubkey: [u8; 32],
    ) -> Result<Self, OperatorLifecycleError> {
        if binding_id.is_nil()
            || binding_version == 0
            || expected_lifecycle_revision != 1
            || principal_fingerprint == [0; 32]
            || event_author_pubkey == [0; 32]
        {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Ok(Self {
            binding_id,
            binding_version,
            expected_lifecycle_revision,
            principal_fingerprint,
            event_author_pubkey,
        })
    }

    pub(crate) const fn binding_id(&self) -> Uuid {
        self.binding_id
    }

    pub(crate) const fn binding_version(&self) -> u64 {
        self.binding_version
    }

    pub(crate) const fn expected_lifecycle_revision(&self) -> u64 {
        self.expected_lifecycle_revision
    }

    pub(crate) const fn principal_fingerprint(&self) -> [u8; 32] {
        self.principal_fingerprint
    }

    pub(crate) const fn event_author_pubkey(&self) -> [u8; 32] {
        self.event_author_pubkey
    }
}

impl fmt::Debug for ExactActiveOperatorTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactActiveOperatorTarget([REDACTED])")
    }
}

/// Exact immutable retired binding generation named by recovery.
#[derive(Clone, Copy)]
pub struct ExactRetiredOperatorTarget {
    binding_id: Uuid,
    binding_version: u64,
    expected_lifecycle_revision: u64,
    principal_fingerprint: [u8; 32],
    event_author_pubkey: [u8; 32],
}

#[allow(dead_code)]
impl ExactRetiredOperatorTarget {
    /// Validate an exact retired generation (whose lifecycle revision is two).
    pub fn new(
        binding_id: Uuid,
        binding_version: u64,
        expected_lifecycle_revision: u64,
        principal_fingerprint: [u8; 32],
        event_author_pubkey: [u8; 32],
    ) -> Result<Self, OperatorLifecycleError> {
        if binding_id.is_nil()
            || binding_version == 0
            || expected_lifecycle_revision != 2
            || principal_fingerprint == [0; 32]
            || event_author_pubkey == [0; 32]
        {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Ok(Self {
            binding_id,
            binding_version,
            expected_lifecycle_revision,
            principal_fingerprint,
            event_author_pubkey,
        })
    }

    pub(crate) const fn binding_id(&self) -> Uuid {
        self.binding_id
    }

    pub(crate) const fn binding_version(&self) -> u64 {
        self.binding_version
    }

    pub(crate) const fn expected_lifecycle_revision(&self) -> u64 {
        self.expected_lifecycle_revision
    }

    pub(crate) const fn principal_fingerprint(&self) -> [u8; 32] {
        self.principal_fingerprint
    }

    pub(crate) const fn event_author_pubkey(&self) -> [u8; 32] {
        self.event_author_pubkey
    }
}

impl fmt::Debug for ExactRetiredOperatorTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactRetiredOperatorTarget([REDACTED])")
    }
}

/// Exact immutable open pending-replacement fact named by recovery.
#[derive(Clone, Copy)]
pub struct ExpectedOperatorPendingReplacement {
    target: ExactRetiredOperatorTarget,
    fact_generation: u64,
}

#[allow(dead_code)]
impl ExpectedOperatorPendingReplacement {
    /// Bind a retired generation to its exact open pending-fact generation.
    pub fn new(
        target: ExactRetiredOperatorTarget,
        fact_generation: u64,
    ) -> Result<Self, OperatorLifecycleError> {
        if fact_generation == 0 {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Ok(Self {
            target,
            fact_generation,
        })
    }

    pub(crate) const fn target(&self) -> ExactRetiredOperatorTarget {
        self.target
    }

    pub(crate) const fn fact_generation(&self) -> u64 {
        self.fact_generation
    }
}

impl fmt::Debug for ExpectedOperatorPendingReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedOperatorPendingReplacement([REDACTED])")
    }
}

/// Requested successor key and exclusive expiry bound by replacement proof.
#[derive(Clone, Copy)]
pub struct RequestedOperatorReplacement {
    event_author_pubkey: [u8; 32],
    expires_at: DateTime<Utc>,
}

#[allow(dead_code)]
impl RequestedOperatorReplacement {
    /// Validate bounded successor coordinates without asserting proof validity.
    pub fn new(
        event_author_pubkey: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<Self, OperatorLifecycleError> {
        if event_author_pubkey == [0; 32] || expires_at.timestamp_micros() <= 0 {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Ok(Self {
            event_author_pubkey,
            expires_at,
        })
    }

    pub(crate) const fn event_author_pubkey(&self) -> [u8; 32] {
        self.event_author_pubkey
    }

    pub(crate) const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl fmt::Debug for RequestedOperatorReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestedOperatorReplacement([REDACTED])")
    }
}

#[derive(Clone)]
pub(crate) enum OperatorLifecyclePlan {
    Retire {
        target: ExactActiveOperatorTarget,
    },
    Disable {
        principal_fingerprint: [u8; 32],
        expected_active_binding: Option<ExactActiveOperatorTarget>,
    },
    Revoke {
        event_author_pubkey: [u8; 32],
        expected_active_binding: Option<ExactActiveOperatorTarget>,
    },
    Rotate {
        target: ExactActiveOperatorTarget,
        replacement: RequestedOperatorReplacement,
    },
    Recover {
        pending: ExpectedOperatorPendingReplacement,
        replacement: RequestedOperatorReplacement,
    },
    Enable {
        principal_fingerprint: [u8; 32],
        disabled_fact_generation: u64,
        pending: ExpectedOperatorPendingReplacement,
        replacement: RequestedOperatorReplacement,
    },
}

/// Opaque bounded six-action intent accepted by the verified operator seam.
///
/// Constructors validate request shape only. They confer no authority: the
/// later operation-specific restore boundary must exact-match this digest and
/// every coordinate to an origin-sealed verifier grant and locked DB state.
#[derive(Clone)]
pub struct OperatorLifecycleIntent {
    operation: OperatorLifecycleOperation,
    expected_revision: u64,
    action: OperatorLifecycleAction,
    intent_digest: [u8; 32],
    plan: OperatorLifecyclePlan,
}

#[allow(dead_code)]
impl OperatorLifecycleIntent {
    /// Prepare exact active-pair retirement.
    pub fn retire(
        operation: OperatorLifecycleOperation,
        expected_revision: u64,
        target: ExactActiveOperatorTarget,
    ) -> Result<Self, OperatorLifecycleError> {
        if expected_revision != target.expected_lifecycle_revision {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Self::seal(
            operation,
            expected_revision,
            OperatorLifecycleAction::Retire,
            OperatorLifecyclePlan::Retire { target },
        )
    }

    /// Prepare exact principal disablement, with an optional active target.
    pub fn disable(
        operation: OperatorLifecycleOperation,
        expected_revision: u64,
        principal_fingerprint: [u8; 32],
        expected_active_binding: Option<ExactActiveOperatorTarget>,
    ) -> Result<Self, OperatorLifecycleError> {
        if principal_fingerprint == [0; 32]
            || expected_active_binding.is_some_and(|target| {
                target.principal_fingerprint != principal_fingerprint
                    || target.expected_lifecycle_revision != expected_revision
            })
        {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Self::seal(
            operation,
            expected_revision,
            OperatorLifecycleAction::Disable,
            OperatorLifecyclePlan::Disable {
                principal_fingerprint,
                expected_active_binding,
            },
        )
    }

    /// Prepare permanent event-author key revocation.
    pub fn revoke(
        operation: OperatorLifecycleOperation,
        expected_revision: u64,
        event_author_pubkey: [u8; 32],
        expected_active_binding: Option<ExactActiveOperatorTarget>,
    ) -> Result<Self, OperatorLifecycleError> {
        if event_author_pubkey == [0; 32]
            || expected_active_binding.is_some_and(|target| {
                target.event_author_pubkey != event_author_pubkey
                    || target.expected_lifecycle_revision != expected_revision
            })
        {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Self::seal(
            operation,
            expected_revision,
            OperatorLifecycleAction::Revoke,
            OperatorLifecyclePlan::Revoke {
                event_author_pubkey,
                expected_active_binding,
            },
        )
    }

    /// Prepare exact active-binding rotation.
    pub fn rotate(
        operation: OperatorLifecycleOperation,
        expected_revision: u64,
        target: ExactActiveOperatorTarget,
        replacement: RequestedOperatorReplacement,
    ) -> Result<Self, OperatorLifecycleError> {
        if expected_revision != target.expected_lifecycle_revision
            || target.event_author_pubkey == replacement.event_author_pubkey
        {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Self::seal(
            operation,
            expected_revision,
            OperatorLifecycleAction::Rotate,
            OperatorLifecyclePlan::Rotate {
                target,
                replacement,
            },
        )
    }

    /// Prepare exact pending-lineage recovery.
    pub fn recover(
        operation: OperatorLifecycleOperation,
        expected_revision: u64,
        pending: ExpectedOperatorPendingReplacement,
        replacement: RequestedOperatorReplacement,
    ) -> Result<Self, OperatorLifecycleError> {
        if expected_revision != pending.fact_generation
            || pending.target.event_author_pubkey == replacement.event_author_pubkey
        {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Self::seal(
            operation,
            expected_revision,
            OperatorLifecycleAction::Recover,
            OperatorLifecyclePlan::Recover {
                pending,
                replacement,
            },
        )
    }

    /// Prepare exact disabled-principal enablement from one immutable retired
    /// binding generation and its exact open pending-replacement fact.
    pub fn enable(
        operation: OperatorLifecycleOperation,
        expected_revision: u64,
        principal_fingerprint: [u8; 32],
        disabled_fact_generation: u64,
        pending: ExpectedOperatorPendingReplacement,
        replacement: RequestedOperatorReplacement,
    ) -> Result<Self, OperatorLifecycleError> {
        if principal_fingerprint == [0; 32]
            || disabled_fact_generation != expected_revision
            || pending.target.principal_fingerprint != principal_fingerprint
        {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Self::seal(
            operation,
            expected_revision,
            OperatorLifecycleAction::Enable,
            OperatorLifecyclePlan::Enable {
                principal_fingerprint,
                disabled_fact_generation,
                pending,
                replacement,
            },
        )
    }

    fn seal(
        operation: OperatorLifecycleOperation,
        expected_revision: u64,
        action: OperatorLifecycleAction,
        plan: OperatorLifecyclePlan,
    ) -> Result<Self, OperatorLifecycleError> {
        if expected_revision == 0 {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        let intent_digest = operator_intent_digest(operation, expected_revision, action, &plan);
        Ok(Self {
            operation,
            expected_revision,
            action,
            intent_digest,
            plan,
        })
    }

    /// Server-resolved authorization domain.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.operation.community_id
    }

    /// Stable operation identity.
    pub const fn operation_id(&self) -> Uuid {
        self.operation.operation_id
    }

    /// Redaction-safe correlation identity.
    pub const fn correlation_id(&self) -> Uuid {
        self.operation.correlation_id
    }

    /// Unique delivery-attempt identity.
    pub const fn attempt_id(&self) -> Uuid {
        self.operation.attempt_id
    }

    /// Closed action from `buzz-auth`.
    pub const fn action(&self) -> OperatorLifecycleAction {
        self.action
    }

    /// Exact expected lifecycle revision or selector generation.
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    /// Canonical semantic digest that every operator proof must bind.
    pub const fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }

    /// Borrow the closed request plan for crate-local canonical preparation.
    /// The plan and every coordinate accessor remain unavailable outside
    /// `buzz-db` and confer no actor, grant, fence, or mutation authority.
    pub(crate) const fn plan(&self) -> &OperatorLifecyclePlan {
        &self.plan
    }

    /// Requested successor key for replacement actions.
    pub const fn replacement_event_author_pubkey(&self) -> Option<[u8; 32]> {
        match &self.plan {
            OperatorLifecyclePlan::Rotate { replacement, .. }
            | OperatorLifecyclePlan::Recover { replacement, .. }
            | OperatorLifecyclePlan::Enable { replacement, .. } => {
                Some(replacement.event_author_pubkey)
            }
            OperatorLifecyclePlan::Retire { .. }
            | OperatorLifecyclePlan::Disable { .. }
            | OperatorLifecyclePlan::Revoke { .. } => None,
        }
    }

    /// Exclusive requested successor-proof expiry for replacement actions.
    pub const fn replacement_expires_at(&self) -> Option<DateTime<Utc>> {
        match &self.plan {
            OperatorLifecyclePlan::Rotate { replacement, .. }
            | OperatorLifecyclePlan::Recover { replacement, .. }
            | OperatorLifecyclePlan::Enable { replacement, .. } => Some(replacement.expires_at),
            OperatorLifecyclePlan::Retire { .. }
            | OperatorLifecyclePlan::Disable { .. }
            | OperatorLifecyclePlan::Revoke { .. } => None,
        }
    }

    /// Recompute the sole canonical intent digest from one exact binding row
    /// while the canonical lifecycle transaction holds its locks.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn matches_locked_retiring_binding(
        &self,
        action: OperatorLifecycleAction,
        binding_id: Uuid,
        binding_version: u64,
        principal_fingerprint: [u8; 32],
        event_author_pubkey: [u8; 32],
        lifecycle_revision: u64,
        replacement: Option<([u8; 32], DateTime<Utc>)>,
    ) -> bool {
        let target = ExactActiveOperatorTarget {
            binding_id,
            binding_version,
            expected_lifecycle_revision: lifecycle_revision,
            principal_fingerprint,
            event_author_pubkey,
        };
        let plan = match (action, replacement) {
            (OperatorLifecycleAction::Retire, None) => OperatorLifecyclePlan::Retire { target },
            (OperatorLifecycleAction::Disable, None) => OperatorLifecyclePlan::Disable {
                principal_fingerprint,
                expected_active_binding: Some(target),
            },
            (OperatorLifecycleAction::Revoke, None) => OperatorLifecyclePlan::Revoke {
                event_author_pubkey,
                expected_active_binding: Some(target),
            },
            (OperatorLifecycleAction::Rotate, Some((event_author_pubkey, expires_at))) => {
                OperatorLifecyclePlan::Rotate {
                    target,
                    replacement: RequestedOperatorReplacement {
                        event_author_pubkey,
                        expires_at,
                    },
                }
            }
            _ => return false,
        };
        self.action == action
            && self.expected_revision == lifecycle_revision
            && self.intent_digest
                == operator_intent_digest(self.operation, lifecycle_revision, action, &plan)
    }
}

impl fmt::Debug for OperatorLifecycleIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorLifecycleIntent")
            .field("action", &self.action)
            .field("coordinates", &"[REDACTED]")
            .finish()
    }
}

/// Closed credential-free authentication failures. They never authorize an
/// operation or occupy its canonical result receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub enum OperatorAuthenticationDenialReason {
    /// The Authorization header was absent.
    MissingCredential = 1,
    /// The credential envelope was malformed or ambiguous.
    InvalidCredential = 2,
    /// The configured verifier rejected a well-formed credential.
    Unauthenticated = 3,
}

/// Durable outcome of one credential-free operator denial attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatorPreauthDenialWrite {
    /// The immutable redacted denial event was inserted.
    Inserted,
    /// The exact denial attempt was already present.
    ExactReplay,
    /// The independent pre-authentication budget is full. Canonical audit
    /// health and capacity are unaffected.
    CapacityExhausted,
}

/// A durable pre-authentication denial write failed after preparation.
#[derive(Debug, thiserror::Error)]
pub enum OperatorPreauthDenialPersistenceError {
    /// PostgreSQL or the dedicated audit dependency was unavailable.
    #[error("operator pre-authentication denial audit unavailable")]
    Unavailable,
    /// Persisted immutable evidence did not match the sealed attempt.
    #[error("operator pre-authentication denial evidence is corrupt")]
    CorruptStoredResult,
}

#[derive(Clone)]
pub(crate) struct PreparedOperatorAuthenticationDenial {
    community_id: CommunityId,
    operation_id: Uuid,
    correlation_id: Uuid,
    attempt_id: Uuid,
    semantic_fingerprint: [u8; 32],
    expected_revision: u64,
    action: i16,
}

impl PreparedOperatorAuthenticationDenial {
    pub(crate) fn from_lifecycle_intent(
        intent: &OperatorLifecycleIntent,
    ) -> Result<Self, OperatorLifecycleError> {
        let prepared = Self {
            community_id: intent.authorization_domain(),
            operation_id: intent.operation_id(),
            correlation_id: intent.correlation_id(),
            attempt_id: intent.attempt_id(),
            semantic_fingerprint: intent.intent_digest(),
            expected_revision: intent.expected_revision(),
            action: intent.action() as i16,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    fn validate(&self) -> Result<(), OperatorLifecycleError> {
        if self.community_id.as_uuid().is_nil()
            || self.operation_id.is_nil()
            || self.correlation_id.is_nil()
            || self.attempt_id.is_nil()
            || self.semantic_fingerprint == [0; 32]
            || self.expected_revision == 0
            || !(1..=8).contains(&self.action)
        {
            return Err(OperatorLifecycleError::InvalidRequest);
        }
        Ok(())
    }
}

impl fmt::Debug for PreparedOperatorAuthenticationDenial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedOperatorAuthenticationDenial([REDACTED])")
    }
}

/// Opaque redaction-safe Provision authentication attempt. It contains no
/// issuer, subject, selected key, credential, or raw request body.
///
/// ```compile_fail
/// use buzz_db::operator_lifecycle::OperatorProvisionAuthenticationAttempt;
/// let _ = OperatorProvisionAuthenticationAttempt {};
/// ```
pub struct OperatorProvisionAuthenticationAttempt {
    db: Db,
    prepared: PreparedOperatorAuthenticationDenial,
}

impl OperatorProvisionAuthenticationAttempt {
    pub(crate) fn from_bounded_body(
        db: Db,
        authorization_domain: CommunityId,
        request_body: &[u8],
    ) -> Self {
        let semantic_fingerprint = operator_digest(
            b"buzz:operator-provision-authentication-attempt:v1",
            &[authorization_domain.as_uuid().as_bytes(), request_body],
        );
        let canonical = serde_json::from_slice::<ProvisionDenialWireCoordinates>(request_body)
            .ok()
            .filter(|wire| {
                wire.authorization_domain == *authorization_domain.as_uuid()
                    && !wire.operation_id.is_nil()
                    && wire.policy_revision > 0
                    && valid_private_coordinate(&wire.issuer)
                    && valid_private_coordinate(&wire.subject)
                    && valid_hex_32(&wire.policy_digest)
                    && valid_hex_32(&wire.selected_event_author_pubkey)
            });
        let prepared = PreparedOperatorAuthenticationDenial {
            community_id: authorization_domain,
            operation_id: canonical.as_ref().map_or_else(
                || denial_uuid(b"operation", semantic_fingerprint),
                |wire| wire.operation_id,
            ),
            correlation_id: denial_uuid(b"correlation", semantic_fingerprint),
            attempt_id: denial_uuid(b"attempt", semantic_fingerprint),
            semantic_fingerprint,
            expected_revision: canonical.as_ref().map_or(1, |wire| wire.policy_revision),
            action: 2,
        };
        debug_assert!(request_body.len() <= MAX_OPERATOR_PROVISION_BODY_BYTES);
        debug_assert!(!authorization_domain.as_uuid().is_nil());
        debug_assert!(prepared.validate().is_ok());
        Self { db, prepared }
    }

    /// Persist one origin-classified credential denial in the independent
    /// bounded pre-authentication ledger. The attempt is consumed so no
    /// caller can relabel one sealed body as multiple denial attempts.
    pub async fn persist_denial(
        self,
        reason: OperatorAuthenticationDenialReason,
    ) -> Result<OperatorPreauthDenialWrite, OperatorPreauthDenialPersistenceError> {
        self.db
            .record_operator_authentication_denial(&self.prepared, reason)
            .await
    }
}

impl fmt::Debug for OperatorProvisionAuthenticationAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorProvisionAuthenticationAttempt([REDACTED])")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionDenialWireCoordinates {
    authorization_domain: Uuid,
    operation_id: Uuid,
    policy_revision: u64,
    policy_digest: String,
    issuer: String,
    subject: String,
    selected_event_author_pubkey: String,
}

fn valid_private_coordinate(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024
}

fn valid_hex_32(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.as_bytes() != b"0000000000000000000000000000000000000000000000000000000000000000"
}

fn denial_uuid(label: &[u8], fingerprint: [u8; 32]) -> Uuid {
    let digest = operator_digest(
        b"buzz:operator-authentication-denial-uuid:v1",
        &[label, &fingerprint],
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

impl Db {
    /// Durably append one credential-free denial without creating or
    /// occupying a canonical lifecycle receipt.
    pub(crate) async fn record_operator_authentication_denial(
        &self,
        prepared: &PreparedOperatorAuthenticationDenial,
        reason: OperatorAuthenticationDenialReason,
    ) -> Result<OperatorPreauthDenialWrite, OperatorPreauthDenialPersistenceError> {
        prepared
            .validate()
            .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
        let reason_code = match reason {
            OperatorAuthenticationDenialReason::MissingCredential => {
                AuthorizationReasonCode::Missing
            }
            OperatorAuthenticationDenialReason::InvalidCredential => {
                AuthorizationReasonCode::Invalid
            }
            OperatorAuthenticationDenialReason::Unauthenticated => {
                AuthorizationReasonCode::Unauthenticated
            }
        };
        let event_id = denial_uuid(
            b"event",
            operator_digest(
                b"buzz:operator-authentication-denial-event:v1",
                &[
                    prepared.community_id.as_uuid().as_bytes(),
                    prepared.operation_id.as_bytes(),
                    prepared.correlation_id.as_bytes(),
                    &prepared.semantic_fingerprint,
                    &(reason as i16).to_be_bytes(),
                ],
            ),
        );
        let event = NewAuthorizationEvent::new(
            prepared.community_id,
            event_id,
            AuthorizationEventKind::OperatorDenied,
            AuthorizationEventOutcome::Denied,
            reason_code,
            AuthorizationEventActor::unresolved_authentication_denial(),
            None,
            prepared.operation_id,
            None,
            prepared.correlation_id,
            prepared.attempt_id,
        )
        .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
        let lock_key = i64::from_be_bytes(
            prepared.semantic_fingerprint[..8]
                .try_into()
                .expect("fixed fingerprint prefix"),
        );
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *transaction)
            .await
            .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
        let existing = sqlx::query(
            "SELECT event_id,attempt_id,expected_revision,action,reason_code,occurred_at, \
                    accepted_at,retain_until, \
                    canonical_envelope,envelope_digest \
             FROM authorization_operator_preauth_denial_events \
             WHERE community_id=$1 AND operation_id=$2 AND correlation_id=$3 \
               AND semantic_fingerprint=$4 AND denial_reason=$5",
        )
        .bind(prepared.community_id.as_uuid())
        .bind(prepared.operation_id)
        .bind(prepared.correlation_id)
        .bind(prepared.semantic_fingerprint.as_slice())
        .bind(reason as i16)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
        if let Some(row) = existing {
            let occurred_at: DateTime<Utc> = row
                .try_get("occurred_at")
                .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
            let stored_envelope: Vec<u8> = row
                .try_get("canonical_envelope")
                .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
            let stored_digest: Vec<u8> = row
                .try_get("envelope_digest")
                .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
            let accepted_at: DateTime<Utc> = row
                .try_get("accepted_at")
                .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
            let retain_until: DateTime<Utc> = row
                .try_get("retain_until")
                .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
            let calculated: [u8; 32] = Sha256::digest(&stored_envelope).into();
            let exact = row.try_get::<Uuid, _>("event_id").ok() == Some(event_id)
                && row.try_get::<Uuid, _>("attempt_id").ok() == Some(prepared.attempt_id)
                && row.try_get::<i64, _>("expected_revision").ok()
                    == i64::try_from(prepared.expected_revision).ok()
                && row.try_get::<i16, _>("action").ok() == Some(prepared.action)
                && row.try_get::<i16, _>("reason_code").ok() == Some(reason_code as i16)
                && retain_until > accepted_at
                && stored_envelope == canonical_event_envelope(&event, occurred_at)
                && stored_digest.as_slice() == calculated;
            if !exact {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
                return Err(OperatorPreauthDenialPersistenceError::CorruptStoredResult);
            }
            transaction
                .commit()
                .await
                .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
            return Ok(OperatorPreauthDenialWrite::ExactReplay);
        }

        let occurred_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
        let envelope = canonical_event_envelope(&event, occurred_at);
        let envelope_digest: [u8; 32] = Sha256::digest(&envelope).into();
        let insert = sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_events \
             (community_id,event_id,operation_id,correlation_id,attempt_id,semantic_fingerprint, \
              denial_reason,expected_revision,action,reason_code,occurred_at,canonical_envelope, \
              envelope_digest) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(prepared.community_id.as_uuid())
        .bind(event_id)
        .bind(prepared.operation_id)
        .bind(prepared.correlation_id)
        .bind(prepared.attempt_id)
        .bind(prepared.semantic_fingerprint.as_slice())
        .bind(reason as i16)
        .bind(
            i64::try_from(prepared.expected_revision)
                .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?,
        )
        .bind(prepared.action)
        .bind(reason_code as i16)
        .bind(occurred_at)
        .bind(&envelope)
        .bind(envelope_digest.as_slice())
        .execute(&mut *transaction)
        .await;
        match insert {
            Ok(result) if result.rows_affected() == 1 => {
                transaction
                    .commit()
                    .await
                    .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
                Ok(OperatorPreauthDenialWrite::Inserted)
            }
            Ok(result) if result.rows_affected() == 0 => {
                let saturation = sqlx::query(
                    "SELECT saturation_generation,last_signaled_generation, \
                            last_signal_xid = pg_current_xact_id() AS signal_claimed, \
                            retained_event_count, \
                            retained_envelope_bytes,max_events_per_domain,max_bytes_per_domain, \
                            max_envelope_bytes \
                     FROM authorization_operator_preauth_denial_capacity \
                     WHERE community_id=$1",
                )
                .bind(prepared.community_id.as_uuid())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?
                .ok_or(OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
                let saturation_generation: i64 = saturation
                    .try_get("saturation_generation")
                    .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
                let last_signaled_generation: i64 = saturation
                    .try_get("last_signaled_generation")
                    .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
                let signal_claimed: bool = saturation
                    .try_get("signal_claimed")
                    .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
                let retained_event_count: i64 = saturation
                    .try_get("retained_event_count")
                    .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
                let retained_envelope_bytes: i64 = saturation
                    .try_get("retained_envelope_bytes")
                    .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
                let max_events_per_domain: i64 = saturation
                    .try_get("max_events_per_domain")
                    .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
                let max_bytes_per_domain: i64 = saturation
                    .try_get("max_bytes_per_domain")
                    .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
                let max_envelope_bytes: i32 = saturation
                    .try_get("max_envelope_bytes")
                    .map_err(|_| OperatorPreauthDenialPersistenceError::CorruptStoredResult)?;
                if saturation_generation <= 0
                    || last_signaled_generation <= 0
                    || last_signaled_generation > saturation_generation
                    || retained_event_count < 0
                    || retained_envelope_bytes < 0
                    || max_events_per_domain <= 0
                    || max_bytes_per_domain <= 0
                    || max_envelope_bytes <= 0
                    || retained_event_count > max_events_per_domain
                    || retained_envelope_bytes > max_bytes_per_domain
                    || (signal_claimed && last_signaled_generation != saturation_generation)
                {
                    transaction
                        .rollback()
                        .await
                        .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
                    return Err(OperatorPreauthDenialPersistenceError::CorruptStoredResult);
                }
                transaction
                    .commit()
                    .await
                    .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
                if signal_claimed {
                    tracing::warn!(
                        authorization_domain = %prepared.community_id.as_uuid(),
                        saturation_generation,
                        retained_event_count,
                        retained_envelope_bytes,
                        max_events_per_domain,
                        max_bytes_per_domain,
                        max_envelope_bytes,
                        "operator pre-authentication denial audit capacity exhausted"
                    );
                    metrics::counter!("buzz_operator_preauth_capacity_exhausted_total")
                        .increment(1);
                }
                Ok(OperatorPreauthDenialWrite::CapacityExhausted)
            }
            Ok(_) => {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
                Err(OperatorPreauthDenialPersistenceError::CorruptStoredResult)
            }
            Err(_) => {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| OperatorPreauthDenialPersistenceError::Unavailable)?;
                Err(OperatorPreauthDenialPersistenceError::Unavailable)
            }
        }
    }
}

fn operator_intent_digest(
    operation: OperatorLifecycleOperation,
    expected_revision: u64,
    action: OperatorLifecycleAction,
    plan: &OperatorLifecyclePlan,
) -> [u8; 32] {
    let plan_digest = match plan {
        OperatorLifecyclePlan::Retire { target } => operator_digest(
            b"buzz:operator-retire-intent:v1",
            &[&active_target_digest(*target)],
        ),
        OperatorLifecyclePlan::Disable {
            principal_fingerprint,
            expected_active_binding,
        } => operator_digest(
            b"buzz:operator-disable-intent:v1",
            &[
                principal_fingerprint,
                &expected_active_binding
                    .map(active_target_digest)
                    .unwrap_or([0; 32]),
            ],
        ),
        OperatorLifecyclePlan::Revoke {
            event_author_pubkey,
            expected_active_binding,
        } => operator_digest(
            b"buzz:operator-revoke-intent:v1",
            &[
                event_author_pubkey,
                &expected_active_binding
                    .map(active_target_digest)
                    .unwrap_or([0; 32]),
            ],
        ),
        OperatorLifecyclePlan::Rotate {
            target,
            replacement,
        } => operator_digest(
            b"buzz:operator-rotate-intent:v1",
            &[
                &active_target_digest(*target),
                &replacement_digest(replacement),
            ],
        ),
        OperatorLifecyclePlan::Recover {
            pending,
            replacement,
        } => operator_digest(
            b"buzz:operator-recover-intent:v1",
            &[&pending_digest(*pending), &replacement_digest(replacement)],
        ),
        OperatorLifecyclePlan::Enable {
            principal_fingerprint,
            disabled_fact_generation,
            pending,
            replacement,
        } => operator_digest(
            b"buzz:operator-enable-intent:v1",
            &[
                principal_fingerprint,
                &disabled_fact_generation.to_be_bytes(),
                &pending_digest(*pending),
                &replacement_digest(replacement),
            ],
        ),
    };
    operator_digest(
        b"buzz:operator-lifecycle-intent:v1",
        &[
            operation.community_id.as_uuid().as_bytes(),
            operation.operation_id.as_bytes(),
            &(action as i16).to_be_bytes(),
            &expected_revision.to_be_bytes(),
            &plan_digest,
        ],
    )
}

fn active_target_digest(target: ExactActiveOperatorTarget) -> [u8; 32] {
    operator_digest(
        b"buzz:operator-active-target:v1",
        &[
            target.binding_id.as_bytes(),
            &target.binding_version.to_be_bytes(),
            &target.expected_lifecycle_revision.to_be_bytes(),
            &target.principal_fingerprint,
            &target.event_author_pubkey,
        ],
    )
}

fn retired_target_digest(target: ExactRetiredOperatorTarget) -> [u8; 32] {
    operator_digest(
        b"buzz:operator-retired-target:v1",
        &[
            target.binding_id.as_bytes(),
            &target.binding_version.to_be_bytes(),
            &target.expected_lifecycle_revision.to_be_bytes(),
            &target.principal_fingerprint,
            &target.event_author_pubkey,
        ],
    )
}

fn pending_digest(pending: ExpectedOperatorPendingReplacement) -> [u8; 32] {
    operator_digest(
        b"buzz:operator-pending-replacement:v1",
        &[
            &retired_target_digest(pending.target),
            &pending.fact_generation.to_be_bytes(),
        ],
    )
}

fn replacement_digest(replacement: &RequestedOperatorReplacement) -> [u8; 32] {
    operator_digest(
        b"buzz:operator-replacement:v1",
        &[
            &replacement.event_author_pubkey,
            &replacement.expires_at.timestamp_micros().to_be_bytes(),
        ],
    )
}

fn operator_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn operation(domain: CommunityId, operation_id: Uuid) -> OperatorLifecycleOperation {
        OperatorLifecycleOperation::new(domain, operation_id, Uuid::new_v4(), Uuid::new_v4())
            .expect("operation")
    }

    fn active() -> ExactActiveOperatorTarget {
        ExactActiveOperatorTarget::new(Uuid::new_v4(), 7, 1, [11; 32], [12; 32])
            .expect("active target")
    }

    fn retired() -> ExactRetiredOperatorTarget {
        ExactRetiredOperatorTarget::new(Uuid::new_v4(), 7, 2, [11; 32], [12; 32])
            .expect("retired target")
    }

    fn replacement() -> RequestedOperatorReplacement {
        RequestedOperatorReplacement::new([13; 32], Utc::now() + Duration::minutes(5))
            .expect("replacement")
    }

    #[test]
    fn all_six_actions_are_typed_and_redacted() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let active = active();
        let pending = ExpectedOperatorPendingReplacement::new(retired(), 3).expect("pending");
        let intents = [
            OperatorLifecycleIntent::retire(operation(domain, Uuid::new_v4()), 1, active),
            OperatorLifecycleIntent::disable(
                operation(domain, Uuid::new_v4()),
                1,
                [11; 32],
                Some(active),
            ),
            OperatorLifecycleIntent::revoke(
                operation(domain, Uuid::new_v4()),
                1,
                [12; 32],
                Some(active),
            ),
            OperatorLifecycleIntent::rotate(
                operation(domain, Uuid::new_v4()),
                1,
                active,
                replacement(),
            ),
            OperatorLifecycleIntent::recover(
                operation(domain, Uuid::new_v4()),
                3,
                pending,
                replacement(),
            ),
            OperatorLifecycleIntent::enable(
                operation(domain, Uuid::new_v4()),
                4,
                [11; 32],
                4,
                pending,
                replacement(),
            ),
        ];
        for intent in intents {
            let intent = intent.expect("typed intent");
            assert_ne!(intent.intent_digest(), [0; 32]);
            let debug = format!("{intent:?}");
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains(&intent.operation_id().to_string()));
        }
    }

    #[test]
    fn semantic_digest_ignores_delivery_ids_but_binds_operation_and_target() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let operation_id = Uuid::new_v4();
        let target = active();
        let first = OperatorLifecycleIntent::retire(operation(domain, operation_id), 1, target)
            .expect("first");
        let retry = OperatorLifecycleIntent::retire(operation(domain, operation_id), 1, target)
            .expect("retry");
        assert_eq!(first.intent_digest(), retry.intent_digest());

        let changed = OperatorLifecycleIntent::retire(operation(domain, operation_id), 1, active())
            .expect("changed");
        assert_ne!(first.intent_digest(), changed.intent_digest());
    }

    #[test]
    fn invalid_coordinates_fail_before_fingerprinting() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        assert!(OperatorLifecycleOperation::new(
            domain,
            Uuid::nil(),
            Uuid::new_v4(),
            Uuid::new_v4()
        )
        .is_err());
        assert!(ExactActiveOperatorTarget::new(Uuid::new_v4(), 1, 2, [1; 32], [2; 32]).is_err());
        assert!(ExactRetiredOperatorTarget::new(Uuid::new_v4(), 1, 1, [1; 32], [2; 32]).is_err());
        assert!(RequestedOperatorReplacement::new([0; 32], Utc::now()).is_err());
    }

    #[test]
    fn enable_requires_and_binds_exact_pending_lineage() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let pending = ExpectedOperatorPendingReplacement::new(retired(), 7).expect("pending");
        let intent = OperatorLifecycleIntent::enable(
            operation(domain, Uuid::new_v4()),
            4,
            [11; 32],
            4,
            pending,
            replacement(),
        )
        .expect("exact pending intent");
        assert_eq!(intent.action(), OperatorLifecycleAction::Enable);
        assert_ne!(intent.intent_digest(), [0; 32]);

        let changed = OperatorLifecycleIntent::enable(
            operation(domain, intent.operation_id()),
            4,
            [11; 32],
            4,
            ExpectedOperatorPendingReplacement::new(retired(), 8).expect("changed pending"),
            replacement(),
        )
        .expect("changed pending intent");
        assert_ne!(intent.intent_digest(), changed.intent_digest());
    }

    #[tokio::test]
    async fn provision_authentication_attempt_is_exact_and_redacted() {
        use sqlx::postgres::PgPoolOptions;

        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let db = Db::from_pool(
            PgPoolOptions::new()
                .connect_lazy("postgres://buzz:buzz_dev@localhost:5432/buzz")
                .expect("lazy test pool"),
        );
        let body = serde_json::to_vec(&serde_json::json!({
            "authorization_domain": domain.as_uuid(),
            "operation_id": Uuid::new_v4(),
            "policy_revision": 7,
            "policy_digest": hex::encode([21_u8; 32]),
            "issuer": "https://private-issuer.example",
            "subject": "private-subject-canary",
            "selected_event_author_pubkey": hex::encode([22_u8; 32]),
        }))
        .expect("serialize provision attempt");
        let attempt =
            OperatorProvisionAuthenticationAttempt::from_bounded_body(db.clone(), domain, &body);
        let replay =
            OperatorProvisionAuthenticationAttempt::from_bounded_body(db.clone(), domain, &body);
        assert_eq!(
            attempt.prepared.semantic_fingerprint,
            replay.prepared.semantic_fingerprint
        );
        let debug = format!("{attempt:?}");
        assert!(!debug.contains("private-issuer"));
        assert!(!debug.contains("private-subject"));

        let mut changed: serde_json::Value =
            serde_json::from_slice(&body).expect("parse provision attempt");
        changed["selected_event_author_pubkey"] = serde_json::Value::String(hex::encode([23; 32]));
        let changed = serde_json::to_vec(&changed).expect("serialize changed attempt");
        assert_ne!(
            attempt.prepared.semantic_fingerprint,
            OperatorProvisionAuthenticationAttempt::from_bounded_body(db.clone(), domain, &changed)
                .prepared
                .semantic_fingerprint
        );
        let other_domain = OperatorProvisionAuthenticationAttempt::from_bounded_body(
            db,
            CommunityId::from_uuid(Uuid::new_v4()),
            &body,
        );
        assert_ne!(
            attempt.prepared.semantic_fingerprint,
            other_domain.prepared.semantic_fingerprint
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_authentication_denials_dedupe_without_receipt_occupancy() {
        use crate::authorization_resolver::ProviderFreeEnrollmentRuntime;
        use buzz_auth::AuthorizationEventCapacityPolicy;
        use sqlx::postgres::PgPoolOptions;

        let admin_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_owned());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .expect("connect admin");
        let name = format!("s5_operator_denial_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("create scratch database");
        let split = admin_url.rfind('/').expect("database URL path");
        let url = format!("{}/{}", &admin_url[..split], name);
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect scratch database");
        crate::migration::run_migrations(&pool)
            .await
            .expect("migrate scratch database");
        let db = Db::from_pool(pool.clone());
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(domain.as_uuid())
            .bind(format!(
                "operator-denial-{}.example",
                domain.as_uuid().simple()
            ))
            .execute(&pool)
            .await
            .expect("insert denial community");
        db.install_authorization_event_capacity(
            domain,
            AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10).expect("valid capacity"),
        )
        .await
        .expect("atomically install canonical and pre-auth capacities");
        let runtime = ProviderFreeEnrollmentRuntime::new(db);
        let lifecycle =
            OperatorLifecycleIntent::revoke(operation(domain, Uuid::new_v4()), 1, [31; 32], None)
                .expect("lifecycle denial intent");
        assert_eq!(
            runtime
                .record_operator_authentication_denial(
                    &lifecycle,
                    OperatorAuthenticationDenialReason::MissingCredential,
                )
                .await
                .expect("record lifecycle denial"),
            OperatorPreauthDenialWrite::Inserted
        );
        assert_eq!(
            runtime
                .record_operator_authentication_denial(
                    &lifecycle,
                    OperatorAuthenticationDenialReason::MissingCredential,
                )
                .await
                .expect("replay lifecycle denial"),
            OperatorPreauthDenialWrite::ExactReplay
        );

        let provision_body = serde_json::to_vec(&serde_json::json!({
            "authorization_domain": domain.as_uuid(),
            "operation_id": Uuid::new_v4(),
            "policy_revision": 3,
            "policy_digest": hex::encode([32_u8; 32]),
            "issuer": "https://private-issuer.example",
            "subject": "private-subject-canary",
            "selected_event_author_pubkey": hex::encode([33_u8; 32]),
        }))
        .expect("serialize provision denial");
        let provision =
            runtime.prepare_operator_provision_authentication_attempt(domain, &provision_body);
        assert_eq!(
            provision
                .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                .await
                .expect("record provision denial"),
            OperatorPreauthDenialWrite::Inserted
        );
        let malformed_body = b"{\"authorization_domain\":";
        assert_eq!(
            runtime
                .prepare_operator_provision_authentication_attempt(domain, malformed_body)
                .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                .await
                .expect("record malformed bounded provision denial"),
            OperatorPreauthDenialWrite::Inserted
        );
        assert_eq!(
            runtime
                .prepare_operator_provision_authentication_attempt(domain, malformed_body)
                .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                .await
                .expect("replay malformed bounded provision denial"),
            OperatorPreauthDenialWrite::ExactReplay
        );

        let (attempts, events, receipts): (i64, i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM authorization_operator_preauth_denial_events \
                 WHERE community_id=$1), \
               (SELECT count(*) FROM authorization_events WHERE community_id=$1), \
               (SELECT count(*) FROM authorization_operation_receipts WHERE community_id=$1)",
        )
        .bind(domain.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("load denial cardinality");
        assert_eq!((attempts, events, receipts), (3, 0, 0));

        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("drop scratch database");
        admin.close().await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_preauth_retention_reclaims_boundedly_and_rate_limits_signals() {
        use crate::authorization_resolver::ProviderFreeEnrollmentRuntime;
        use buzz_auth::AuthorizationEventCapacityPolicy;
        use sqlx::postgres::PgPoolOptions;

        let admin_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_owned());
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .expect("connect admin");
        let name = format!("s5_preauth_retention_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("create scratch database");
        let split = admin_url.rfind('/').expect("database URL path");
        let url = format!("{}/{}", &admin_url[..split], name);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect scratch database");
        crate::migration::run_migrations(&pool)
            .await
            .expect("migrate scratch database");
        let trigger_security: (bool, bool, bool, bool) = sqlx::query_as(
            "SELECT prosecdef, \
                    proconfig @> ARRAY['search_path=pg_catalog, public']::text[], \
                    pronargs=0, \
                    NOT EXISTS ( \
                        SELECT 1 \
                        FROM aclexplode(COALESCE(proacl,acldefault('f',proowner))) privilege \
                        WHERE privilege.grantee=0 AND privilege.privilege_type='EXECUTE' \
                    ) \
             FROM pg_proc \
             WHERE proname='authorization_operator_preauth_denial_capacity_before_insert_v1'",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect retention trigger security");
        assert_eq!(trigger_security, (true, true, true, true));

        let db = Db::from_pool(pool.clone());
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(domain.as_uuid())
            .bind(format!("retention-{}.example", domain.as_uuid().simple()))
            .execute(&pool)
            .await
            .expect("insert retention community");
        db.install_authorization_event_capacity(
            domain,
            AuthorizationEventCapacityPolicy::new(300, 1 << 20, 1).expect("test capacity"),
        )
        .await
        .expect("install capacity");

        // Seed 257 expired terminal rows through a privileged test fixture.
        // Production callers have no trigger-disable or counter-reset surface.
        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_events \
                 DISABLE TRIGGER authorization_operator_preauth_denial_capacity_insert; \
             ALTER TABLE authorization_operator_preauth_denial_capacity \
                 DISABLE TRIGGER authorization_operator_preauth_denial_capacity_monotonic",
        )
        .execute(&pool)
        .await
        .expect("open retention fixture");
        sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_events \
             (community_id,event_id,operation_id,correlation_id,attempt_id,semantic_fingerprint, \
              denial_reason,expected_revision,action,reason_code,occurred_at,accepted_at, \
              canonical_envelope,envelope_digest,retain_until) \
             SELECT $1, \
                    ('00000000-0000-4000-8000-' || lpad(to_hex(value),12,'0'))::uuid, \
                    ('10000000-0000-4000-8000-' || lpad(to_hex(value),12,'0'))::uuid, \
                    ('20000000-0000-4000-8000-' || lpad(to_hex(value),12,'0'))::uuid, \
                    ('30000000-0000-4000-8000-' || lpad(to_hex(value),12,'0'))::uuid, \
                    decode(md5('semantic-a' || value::text) || \
                           md5('semantic-b' || value::text),'hex'), \
                    1,1,2,1,clock_timestamp() - interval '25 hours', \
                    clock_timestamp() - interval '25 hours',decode('01','hex'), \
                    decode(md5('digest-a' || value::text) || \
                           md5('digest-b' || value::text),'hex'), \
                    clock_timestamp() - interval '1 second' \
             FROM generate_series(1,257) value",
        )
        .bind(domain.as_uuid())
        .execute(&pool)
        .await
        .expect("seed expired terminal rows");
        sqlx::query(
            "UPDATE authorization_operator_preauth_denial_capacity \
             SET retained_event_count=257,retained_envelope_bytes=257 WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .execute(&pool)
        .await
        .expect("set exact fixture counters");
        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_capacity \
                 ENABLE TRIGGER authorization_operator_preauth_denial_capacity_monotonic; \
             ALTER TABLE authorization_operator_preauth_denial_events \
                 ENABLE TRIGGER authorization_operator_preauth_denial_capacity_insert",
        )
        .execute(&pool)
        .await
        .expect("seal retention fixture");

        let direct_delete = sqlx::query(
            "DELETE FROM authorization_operator_preauth_denial_events \
             WHERE community_id=$1 AND event_id= \
                   '00000000-0000-4000-8000-000000000001'::uuid",
        )
        .bind(domain.as_uuid())
        .execute(&pool)
        .await;
        assert!(
            direct_delete.is_err(),
            "expired rows remain directly immutable"
        );

        for (transition, forged_update) in [
            (
                "reclaim",
                "UPDATE authorization_operator_preauth_denial_capacity \
                 SET updated_at=updated_at WHERE community_id=$1",
            ),
            (
                "saturate",
                "UPDATE authorization_operator_preauth_denial_capacity \
                 SET updated_at=updated_at WHERE community_id=$1",
            ),
            (
                "insert",
                "UPDATE authorization_operator_preauth_denial_capacity \
                 SET retained_event_count=retained_event_count+1, \
                     retained_envelope_bytes=retained_envelope_bytes+1 \
                 WHERE community_id=$1",
            ),
        ] {
            let mut transaction = pool.begin().await.expect("begin transition forgery");
            let setting = format!(
                "SET LOCAL buzz.operator_preauth_capacity_transition = \
                 '{transition}:{}'",
                domain.as_uuid()
            );
            sqlx::query(sqlx::AssertSqlSafe(setting))
                .execute(&mut *transaction)
                .await
                .expect("set forged local transition");
            let error = sqlx::query(forged_update)
                .bind(domain.as_uuid())
                .execute(&mut *transaction)
                .await
                .expect_err("direct transition forgery must fail");
            assert!(
                error.to_string().contains("nested trigger ownership"),
                "unexpected {transition} transition forgery result: {error}"
            );
            transaction
                .rollback()
                .await
                .expect("roll back transition forgery");
        }

        let runtime = ProviderFreeEnrollmentRuntime::new(db.clone());
        let first = runtime.prepare_operator_provision_authentication_attempt(domain, b"first");
        assert_eq!(
            first
                .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                .await
                .expect("first bounded reclaim"),
            OperatorPreauthDenialWrite::CapacityExhausted
        );
        let first_state: (i64, i64, i64, i64, String) = sqlx::query_as(
            "SELECT retained_event_count,retained_envelope_bytes,saturation_generation, \
                    last_signaled_generation,last_signal_xid::text \
             FROM authorization_operator_preauth_denial_capacity WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("first saturation state");
        assert_eq!(
            (first_state.0, first_state.1, first_state.2, first_state.3),
            (1, 1, 1, 1)
        );

        assert_eq!(
            runtime
                .prepare_operator_provision_authentication_attempt(domain, b"first")
                .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                .await
                .expect("same saturated attempt replay"),
            OperatorPreauthDenialWrite::CapacityExhausted
        );
        let replayed_signal: (i64, i64, String) = sqlx::query_as(
            "SELECT saturation_generation,last_signaled_generation,last_signal_xid::text \
             FROM authorization_operator_preauth_denial_capacity WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("same-attempt saturation state");
        assert_eq!((replayed_signal.0, replayed_signal.1), (1, 1));
        assert_eq!(
            replayed_signal.2, first_state.4,
            "same saturated attempt cannot claim a second signal"
        );

        assert_eq!(
            runtime
                .prepare_operator_provision_authentication_attempt(domain, b"second")
                .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                .await
                .expect("second bounded reclaim"),
            OperatorPreauthDenialWrite::CapacityExhausted
        );
        let second_state: (i64, i64, i64, i64, String) = sqlx::query_as(
            "SELECT retained_event_count,retained_envelope_bytes,saturation_generation, \
                    last_signaled_generation,last_signal_xid::text \
             FROM authorization_operator_preauth_denial_capacity WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("second saturation state");
        assert_eq!(
            (
                second_state.0,
                second_state.1,
                second_state.2,
                second_state.3
            ),
            (0, 0, 1, 1)
        );
        assert_eq!(second_state.4, first_state.4, "one claim per generation");

        // A successful retained write closes generation one. The immediately
        // following saturation opens generation two but cannot claim before
        // the database-owned 60-second deadline.
        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_capacity \
                 DISABLE TRIGGER authorization_operator_preauth_denial_capacity_monotonic",
        )
        .execute(&pool)
        .await
        .expect("open capacity fixture");
        sqlx::query(
            "UPDATE authorization_operator_preauth_denial_capacity \
             SET max_envelope_bytes=16384 WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .execute(&pool)
        .await
        .expect("open capacity for recovery");
        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_capacity \
                 ENABLE TRIGGER authorization_operator_preauth_denial_capacity_monotonic",
        )
        .execute(&pool)
        .await
        .expect("seal recovery capacity");
        assert_eq!(
            runtime
                .prepare_operator_provision_authentication_attempt(domain, b"recovery")
                .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                .await
                .expect("recover saturation episode"),
            OperatorPreauthDenialWrite::Inserted
        );
        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_capacity \
                 DISABLE TRIGGER authorization_operator_preauth_denial_capacity_monotonic",
        )
        .execute(&pool)
        .await
        .expect("open saturation fixture");
        sqlx::query(
            "UPDATE authorization_operator_preauth_denial_capacity \
             SET max_envelope_bytes=1 WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .execute(&pool)
        .await
        .expect("restore saturation bound");
        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_capacity \
                 ENABLE TRIGGER authorization_operator_preauth_denial_capacity_monotonic",
        )
        .execute(&pool)
        .await
        .expect("seal saturation fixture");
        assert_eq!(
            runtime
                .prepare_operator_provision_authentication_attempt(domain, b"generation-two")
                .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                .await
                .expect("open generation two"),
            OperatorPreauthDenialWrite::CapacityExhausted
        );
        let unopened_claim: (i64, i64, String) = sqlx::query_as(
            "SELECT saturation_generation,last_signaled_generation,last_signal_xid::text \
             FROM authorization_operator_preauth_denial_capacity WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("unclaimed generation two");
        assert_eq!((unopened_claim.0, unopened_claim.1), (2, 1));
        assert_eq!(unopened_claim.2, first_state.4);

        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_capacity \
                 DISABLE TRIGGER authorization_operator_preauth_denial_capacity_monotonic",
        )
        .execute(&pool)
        .await
        .expect("open signal fixture");
        sqlx::query(
            "WITH authoritative AS (SELECT clock_timestamp() AS now) \
             UPDATE authorization_operator_preauth_denial_capacity \
             SET last_signal_at=authoritative.now - interval '61 seconds', \
                 next_signal_at=authoritative.now - interval '1 second' \
             FROM authoritative WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .execute(&pool)
        .await
        .expect("advance authoritative signal fixture");
        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_capacity \
                 ENABLE TRIGGER authorization_operator_preauth_denial_capacity_monotonic",
        )
        .execute(&pool)
        .await
        .expect("seal signal fixture");
        let deadline: DateTime<Utc> = sqlx::query_scalar(
            "SELECT next_signal_at FROM authorization_operator_preauth_denial_capacity \
             WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("signal deadline");
        let first_concurrent =
            runtime.prepare_operator_provision_authentication_attempt(domain, b"concurrent-one");
        let second_concurrent =
            runtime.prepare_operator_provision_authentication_attempt(domain, b"concurrent-two");
        let (first_result, second_result) = tokio::join!(
            first_concurrent.persist_denial(OperatorAuthenticationDenialReason::InvalidCredential),
            second_concurrent.persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
        );
        assert_eq!(
            first_result.expect("first concurrent saturation"),
            OperatorPreauthDenialWrite::CapacityExhausted
        );
        assert_eq!(
            second_result.expect("second concurrent saturation"),
            OperatorPreauthDenialWrite::CapacityExhausted
        );
        let claimed: (i64, i64, DateTime<Utc>) = sqlx::query_as(
            "SELECT saturation_generation,last_signaled_generation,last_signal_at \
             FROM authorization_operator_preauth_denial_capacity WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("claimed generation two");
        assert_eq!((claimed.0, claimed.1), (2, 2));
        assert!(
            claimed.2 >= deadline,
            "cross-generation signal observes DB deadline"
        );

        let boundary_domain = CommunityId::from_uuid(Uuid::new_v4());
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(boundary_domain.as_uuid())
            .bind(format!(
                "retention-boundary-{}.example",
                boundary_domain.as_uuid().simple()
            ))
            .execute(&pool)
            .await
            .expect("insert boundary community");
        db.install_authorization_event_capacity(
            boundary_domain,
            AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10)
                .expect("boundary capacity"),
        )
        .await
        .expect("install boundary capacity");
        let boundary_runtime = ProviderFreeEnrollmentRuntime::new(db);
        let future_body = b"retention-future";
        let equal_body = b"retention-equal";
        let past_body = b"retention-past";
        let future_fingerprint = boundary_runtime
            .prepare_operator_provision_authentication_attempt(boundary_domain, future_body)
            .prepared
            .semantic_fingerprint;
        let equal_fingerprint = boundary_runtime
            .prepare_operator_provision_authentication_attempt(boundary_domain, equal_body)
            .prepared
            .semantic_fingerprint;
        let past_fingerprint = boundary_runtime
            .prepare_operator_provision_authentication_attempt(boundary_domain, past_body)
            .prepared
            .semantic_fingerprint;
        for body in [
            future_body.as_slice(),
            equal_body.as_slice(),
            past_body.as_slice(),
        ] {
            assert_eq!(
                boundary_runtime
                    .prepare_operator_provision_authentication_attempt(boundary_domain, body)
                    .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                    .await
                    .expect("insert boundary denial"),
                OperatorPreauthDenialWrite::Inserted
            );
        }
        assert_eq!(
            boundary_runtime
                .prepare_operator_provision_authentication_attempt(boundary_domain, future_body)
                .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                .await
                .expect("retained exact replay"),
            OperatorPreauthDenialWrite::ExactReplay
        );
        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_events \
                 DISABLE TRIGGER authorization_operator_preauth_denial_events_immutable",
        )
        .execute(&pool)
        .await
        .expect("open boundary fixture");
        sqlx::query(
            "WITH authoritative AS (SELECT clock_timestamp() AS now) \
             UPDATE authorization_operator_preauth_denial_events events \
             SET accepted_at = CASE \
                    WHEN semantic_fingerprint=$2 THEN accepted_at \
                    ELSE authoritative.now - interval '25 hours' \
                 END, \
                 retain_until = CASE \
                    WHEN semantic_fingerprint=$2 THEN authoritative.now + interval '1 hour' \
                    WHEN semantic_fingerprint=$3 THEN authoritative.now \
                    WHEN semantic_fingerprint=$4 THEN authoritative.now - interval '1 second' \
                 END \
             FROM authoritative \
             WHERE community_id=$1 \
               AND semantic_fingerprint IN ($2,$3,$4)",
        )
        .bind(boundary_domain.as_uuid())
        .bind(future_fingerprint.as_slice())
        .bind(equal_fingerprint.as_slice())
        .bind(past_fingerprint.as_slice())
        .execute(&pool)
        .await
        .expect("set authoritative boundary fixture");
        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_events \
                 ENABLE TRIGGER authorization_operator_preauth_denial_events_immutable",
        )
        .execute(&pool)
        .await
        .expect("seal boundary fixture");
        assert_eq!(
            boundary_runtime
                .prepare_operator_provision_authentication_attempt(
                    boundary_domain,
                    b"retention-trigger",
                )
                .persist_denial(OperatorAuthenticationDenialReason::InvalidCredential)
                .await
                .expect("trigger boundary reclamation"),
            OperatorPreauthDenialWrite::Inserted
        );
        let boundary_rows: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT count(*), \
                    count(*) FILTER (WHERE semantic_fingerprint=$2), \
                    count(*) FILTER (WHERE semantic_fingerprint=$3), \
                    count(*) FILTER (WHERE semantic_fingerprint=$4) \
             FROM authorization_operator_preauth_denial_events WHERE community_id=$1",
        )
        .bind(boundary_domain.as_uuid())
        .bind(future_fingerprint.as_slice())
        .bind(equal_fingerprint.as_slice())
        .bind(past_fingerprint.as_slice())
        .fetch_one(&pool)
        .await
        .expect("read retention boundaries");
        assert_eq!(boundary_rows, (2, 1, 0, 0));

        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("drop scratch database");
        admin.close().await;
    }
}
