//! Immutable provider-free authorization events and capacity controls.
//!
//! V1 deliberately has no claim, export, acknowledgement, retry, pruning, or
//! compaction workflow. Inserts consume an explicitly configured immutable
//! per-domain budget; exhaustion aborts the surrounding authorization
//! transaction and is latched unhealthy by the caller.

use std::fmt;

use buzz_auth::{AuthContext, AuthorizationEventCapacityPolicy};
use buzz_core::{CanonicalCurrentBindingEvidence, CommunityId};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::{Db, DbError, Result};

const MAX_EVENT_PAGE: u16 = 1_000;

#[derive(Serialize)]
struct CanonicalAuthorizationEnvelope<'a> {
    schema_version: i16,
    event_id: Uuid,
    event_kind: i16,
    outcome_code: i16,
    reason_code: i16,
    actor_kind: i16,
    actor_fingerprint: Option<&'a str>,
    subject_fingerprint: Option<&'a str>,
    operation_id: Uuid,
    request_fingerprint: Option<&'a str>,
    correlation_id: Uuid,
    attempt_id: Uuid,
    occurred_at_micros: i64,
}

/// Closed operation kinds stored in the single canonical receipt table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
#[allow(dead_code)] // Closed codes are consumed incrementally by S3/S5 children.
pub(crate) enum AuthorizationOperationKind {
    /// Direct enrollment.
    Enroll = 1,
    /// Separate provisioning.
    Provision = 2,
    /// Retire an exact binding generation.
    Retire = 3,
    /// Disable a principal.
    Disable = 4,
    /// Revoke authority.
    Revoke = 5,
    /// Rotate to a successor binding.
    Rotate = 6,
    /// Recover a retired principal.
    Recover = 7,
    /// Enable a disabled principal.
    Enable = 8,
    /// Local admission loss.
    AdmissionLoss = 9,
    /// Authenticated operator action.
    Operator = 10,
    /// Protected mutation.
    ProtectedMutation = 11,
    /// Invalidation advance.
    Invalidation = 12,
    /// Client-status revision.
    StatusRevision = 13,
}

/// Persisted result classification for one operation receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
#[allow(dead_code)] // Closed codes are consumed incrementally by S3/S5 children.
pub(crate) enum AuthorizationOperationOutcome {
    /// State changed successfully.
    Applied = 1,
    /// Closed denial with durable evidence.
    Denied = 2,
    /// Successful semantic no-op.
    NoOp = 3,
}

/// Canonical operation receipt supplied by a transaction owner.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthorizationOperationReceipt {
    pub(crate) community_id: CommunityId,
    pub(crate) operation_id: Uuid,
    pub(crate) request_fingerprint: [u8; 32],
    pub(crate) operation_kind: AuthorizationOperationKind,
    pub(crate) actor_fingerprint: [u8; 32],
    pub(crate) outcome: AuthorizationOperationOutcome,
    pub(crate) result_digest: [u8; 32],
}

impl AuthorizationOperationReceipt {
    /// Validate one receipt without persisting it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        community_id: CommunityId,
        operation_id: Uuid,
        request_fingerprint: [u8; 32],
        operation_kind: AuthorizationOperationKind,
        actor: AuthorizationEventActor,
        outcome: AuthorizationOperationOutcome,
        result_digest: [u8; 32],
    ) -> Result<Self> {
        if community_id.as_uuid().is_nil()
            || operation_id.is_nil()
            || request_fingerprint == [0; 32]
            || !actor.is_bound_to(community_id)
            || result_digest == [0; 32]
        {
            return Err(DbError::InvalidData(
                "authorization operation receipt is invalid".to_owned(),
            ));
        }
        let actor_fingerprint = actor.fingerprint().ok_or_else(|| {
            DbError::InvalidData("authorization operation actor is unauthenticated".to_owned())
        })?;
        Ok(Self {
            community_id,
            operation_id,
            request_fingerprint,
            operation_kind,
            actor_fingerprint,
            outcome,
            result_digest,
        })
    }
}

impl fmt::Debug for AuthorizationOperationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationOperationReceipt")
            .field("community_id", &"[REDACTED]")
            .field("operation_id", &"[REDACTED]")
            .field("request_fingerprint", &"[REDACTED]")
            .field("operation_kind", &self.operation_kind)
            .field("actor_fingerprint", &"[REDACTED]")
            .field("outcome", &self.outcome)
            .field("result_digest", &"[REDACTED]")
            .finish()
    }
}

/// Whether a receipt insert created state or replayed an identical receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationReceiptWrite {
    /// New receipt inserted.
    Inserted,
    /// Byte-for-byte semantic replay.
    ExactReplay,
}

/// Canonical authorization event kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub enum AuthorizationEventKind {
    /// Binding enrolled.
    Enrolled = 1,
    /// Authority revoked.
    Revoked = 2,
    /// Binding rotated.
    Rotated = 3,
    /// Principal recovered.
    Recovered = 4,
    /// Principal enabled.
    PrincipalEnabled = 5,
    /// Binding retired.
    Retired = 6,
    /// Principal disabled.
    PrincipalDisabled = 7,
    /// Local authority admission lost.
    AdmissionLost = 8,
    /// Operator action denied.
    OperatorDenied = 9,
    /// Protected operation allowed.
    ProtectedAllowed = 10,
    /// Protected operation denied.
    ProtectedDenied = 11,
    /// Current-binding status published.
    StatusPublished = 12,
    /// Current-binding status withdrawn.
    StatusWithdrawn = 13,
    /// Invalidation generation advanced.
    InvalidationAdvanced = 14,
}

impl AuthorizationEventKind {
    fn from_database(value: i16) -> Result<Self> {
        match value {
            1 => Ok(Self::Enrolled),
            2 => Ok(Self::Revoked),
            3 => Ok(Self::Rotated),
            4 => Ok(Self::Recovered),
            5 => Ok(Self::PrincipalEnabled),
            6 => Ok(Self::Retired),
            7 => Ok(Self::PrincipalDisabled),
            8 => Ok(Self::AdmissionLost),
            9 => Ok(Self::OperatorDenied),
            10 => Ok(Self::ProtectedAllowed),
            11 => Ok(Self::ProtectedDenied),
            12 => Ok(Self::StatusPublished),
            13 => Ok(Self::StatusWithdrawn),
            14 => Ok(Self::InvalidationAdvanced),
            _ => Err(DbError::InvalidData(
                "authorization event kind is invalid".to_owned(),
            )),
        }
    }
}

/// Stable canonical event outcome code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
#[allow(dead_code)] // Closed codes are consumed incrementally by S3/S5 children.
pub(crate) enum AuthorizationEventOutcome {
    /// Allowed or applied.
    Allowed = 1,
    /// Denied closed.
    Denied = 2,
    /// No-op.
    NoOp = 3,
    /// Failed closed because durable evidence was unavailable.
    AuditUnavailable = 4,
    /// Withdrawn.
    Withdrawn = 5,
}

/// Stable redaction-safe event reason code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
#[allow(dead_code)] // Closed codes are consumed incrementally by S3/S5 children.
pub(crate) enum AuthorizationReasonCode {
    /// Successful current policy.
    Current = 1,
    /// Missing credential or evidence.
    Missing = 2,
    /// Invalid credential or evidence.
    Invalid = 3,
    /// Unauthenticated attempt.
    Unauthenticated = 4,
    /// Stale authority.
    StaleAuthority = 5,
    /// Cross-domain evidence.
    CrossDomain = 6,
    /// Binding mismatch.
    BindingMismatch = 7,
    /// Delegation mismatch.
    DelegationMismatch = 8,
    /// Policy denial.
    PolicyDenied = 9,
    /// Invalidation fence changed.
    Invalidated = 10,
    /// Capacity exhausted.
    CapacityExhausted = 11,
    /// Storage unavailable.
    StorageUnavailable = 12,
    /// Proof expired.
    Expired = 13,
    /// Exact replay.
    Replay = 14,
    /// Intent conflict.
    IntentConflict = 15,
    /// Explicit withdrawal.
    Withdrawn = 16,
}

/// Pseudonymous actor classification derived only from sealed or
/// authoritatively rechecked evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
#[allow(dead_code)] // Operator construction is added only with a sealed S3 grant.
pub(crate) enum AuthorizationActorKind {
    /// Authenticated direct actor.
    Direct = 1,
    /// Authenticated delegate.
    Delegate = 2,
    /// Authenticated operator.
    Operator = 3,
    /// Credential-free unresolved attempt.
    Unresolved = 4,
}

/// Exact local authority coordinate whose loss was rechecked in PostgreSQL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Consumed by the review-pending S3 lifecycle child.
pub(crate) enum LocalAdmissionLossCause {
    /// Exact active binding generation.
    Binding {
        /// Stable binding identifier.
        binding_id: Uuid,
        /// Immutable binding generation.
        binding_version: u64,
    },
    /// Exact active local policy revision.
    Policy {
        /// Positive policy revision.
        policy_revision: u64,
    },
    /// Exact delegated relationship revision already installed in local
    /// protected authority.
    DelegatedRelationship {
        /// Stable relationship identifier.
        relationship_id: Uuid,
        /// Positive relationship revision.
        relationship_revision: u64,
    },
}

/// Database-rechecked loss coordinate retained inside an opaque actor proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Constructed only by the authoritative resolver above.
pub(crate) enum AuthorizationAuthorityLossTarget {
    /// Every protected object owned by one exact binding generation.
    Binding(Uuid, u64),
    /// Every protected object admitted by one exact policy revision.
    Policy(u64),
    /// Every protected object admitted by one exact delegated relationship.
    DelegatedRelationship(Uuid, u64),
}

/// Opaque authenticated event actor.
///
/// Callers cannot choose an actor kind or fingerprint. Direct/delegated route
/// actors are derived from a sealed [`AuthContext`]; local admission-loss
/// actors are minted only after an authoritative PostgreSQL recheck.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthorizationEventActor {
    community_id: Option<CommunityId>,
    kind: AuthorizationActorKind,
    fingerprint: Option<[u8; 32]>,
    authority_loss_target: Option<AuthorizationAuthorityLossTarget>,
}

impl AuthorizationEventActor {
    /// Derive direct/delegated attribution from the complete sealed route.
    #[allow(dead_code)] // Consumed by the S5 protected-route child.
    pub(crate) fn from_auth_context(context: &AuthContext) -> Result<Self> {
        let lease = context.lease();
        let (request_fingerprint, _, _) = lease.request_binding();
        if lease.authorization_domain() != context.authorization_domain()
            || lease.actor_pubkey() != context.actor_pubkey()
            || lease.owner_pubkey() != context.owner_pubkey()
            || lease.binding() != context.binding()
            || lease.capability() != context.capability()
            || request_fingerprint != context.request_fingerprint()
        {
            return Err(DbError::InvalidData(
                "authorization actor route coordinates do not match".to_owned(),
            ));
        }
        actor_from_route_coordinates(
            context.authorization_domain(),
            context.actor_pubkey().to_bytes(),
            context.owner_pubkey().map(|value| value.to_bytes()),
            context.binding(),
            lease.delegated_relationship(),
        )
    }

    /// Credential-free actor used only by the dedicated pre-authentication
    /// denial lane, which cannot own a canonical operation receipt.
    #[allow(dead_code)] // Consumed by the S3 pre-authentication child.
    pub(crate) const fn unresolved_authentication_denial() -> Self {
        Self {
            community_id: None,
            kind: AuthorizationActorKind::Unresolved,
            fingerprint: None,
            authority_loss_target: None,
        }
    }

    const fn kind(&self) -> AuthorizationActorKind {
        self.kind
    }

    const fn fingerprint(&self) -> Option<[u8; 32]> {
        self.fingerprint
    }

    pub(crate) fn is_bound_to(&self, community_id: CommunityId) -> bool {
        matches!(self.community_id, Some(bound) if bound == community_id)
    }

    /// Whether this actor may own a canonical operation receipt.
    pub(crate) const fn is_authenticated(&self) -> bool {
        self.fingerprint.is_some() && !matches!(self.kind, AuthorizationActorKind::Unresolved)
    }

    /// Exact database-rechecked coordinate available to the coupled authority
    /// refence seam.
    pub(crate) const fn authority_loss_target(&self) -> Option<AuthorizationAuthorityLossTarget> {
        self.authority_loss_target
    }

    #[cfg(test)]
    pub(crate) fn test_direct(community_id: CommunityId) -> Self {
        local_actor(
            AuthorizationActorKind::Direct,
            community_id,
            &[b"test"],
            None,
        )
    }
}

impl fmt::Debug for AuthorizationEventActor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationEventActor([REDACTED])")
    }
}

/// Recheck a local admission-loss cause and mint its non-forgeable event actor.
#[allow(dead_code)] // Consumed by the review-pending S3 lifecycle child.
pub(crate) async fn resolve_local_admission_loss_actor_tx(
    transaction: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    cause: LocalAdmissionLossCause,
) -> Result<AuthorizationEventActor> {
    if community_id.as_uuid().is_nil() {
        return Err(DbError::InvalidData(
            "authorization admission-loss actor domain is invalid".to_owned(),
        ));
    }
    match cause {
        LocalAdmissionLossCause::Binding {
            binding_id,
            binding_version,
        } => {
            if binding_id.is_nil() || binding_version == 0 || binding_version > i64::MAX as u64 {
                return Err(DbError::InvalidData(
                    "authorization admission-loss binding actor is invalid".to_owned(),
                ));
            }
            let actor: Vec<u8> = sqlx::query_scalar(
                "SELECT event_author_pubkey FROM identity_bindings \
                 WHERE community_id=$1 AND binding_id=$2 AND binding_version=$3 \
                   AND binding_state=1 AND (expires_at IS NULL OR expires_at > clock_timestamp())",
            )
            .bind(community_id.as_uuid())
            .bind(binding_id)
            .bind(i64::try_from(binding_version).map_err(|_| {
                DbError::InvalidData("authorization binding version is out of range".to_owned())
            })?)
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or_else(|| DbError::NotFound("active authorization binding".to_owned()))?;
            let actor = bytes32(actor, "local binding actor")?;
            Ok(local_actor(
                AuthorizationActorKind::Direct,
                community_id,
                &[
                    binding_id.as_bytes(),
                    &binding_version.to_be_bytes(),
                    &actor,
                ],
                Some(AuthorizationAuthorityLossTarget::Binding(
                    binding_id,
                    binding_version,
                )),
            ))
        }
        LocalAdmissionLossCause::Policy { policy_revision } => {
            if policy_revision == 0 || policy_revision > i64::MAX as u64 {
                return Err(DbError::InvalidData(
                    "authorization admission-loss policy actor is invalid".to_owned(),
                ));
            }
            let policy_digest: Vec<u8> = sqlx::query_scalar(
                "SELECT policy_digest FROM identity_enrollment_policies \
                 WHERE community_id=$1 AND policy_revision=$2 \
                   AND effective_at <= clock_timestamp() \
                   AND (expires_at IS NULL OR expires_at > clock_timestamp())",
            )
            .bind(community_id.as_uuid())
            .bind(i64::try_from(policy_revision).map_err(|_| {
                DbError::InvalidData("authorization policy revision is out of range".to_owned())
            })?)
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or_else(|| DbError::NotFound("active authorization policy".to_owned()))?;
            let policy_digest = bytes32(policy_digest, "local policy digest")?;
            Ok(local_actor(
                AuthorizationActorKind::Direct,
                community_id,
                &[&policy_revision.to_be_bytes(), &policy_digest],
                Some(AuthorizationAuthorityLossTarget::Policy(policy_revision)),
            ))
        }
        LocalAdmissionLossCause::DelegatedRelationship {
            relationship_id,
            relationship_revision,
        } => {
            if relationship_id.is_nil()
                || relationship_revision == 0
                || relationship_revision > i64::MAX as u64
            {
                return Err(DbError::InvalidData(
                    "authorization admission-loss delegation actor is invalid".to_owned(),
                ));
            }
            let rows = sqlx::query(
                "SELECT DISTINCT p.actor_pubkey,p.owner_pubkey,p.binding_id,p.binding_version \
                 FROM protected_object_authority p \
                 JOIN identity_bindings b ON b.community_id=p.community_id \
                   AND b.binding_id=p.binding_id AND b.binding_version=p.binding_version \
                 WHERE p.community_id=$1 AND p.delegated_relationship_id=$2 \
                   AND p.delegated_relationship_revision=$3 AND p.expires_at > clock_timestamp() \
                   AND b.binding_state=1 AND (b.expires_at IS NULL OR b.expires_at > clock_timestamp()) \
                 ORDER BY p.actor_pubkey,p.owner_pubkey,p.binding_id,p.binding_version LIMIT 2",
            )
            .bind(community_id.as_uuid())
            .bind(relationship_id)
            .bind(i64::try_from(relationship_revision).map_err(|_| {
                DbError::InvalidData(
                    "authorization relationship revision is out of range".to_owned(),
                )
            })?)
            .fetch_all(&mut **transaction)
            .await?;
            if rows.len() != 1 {
                return Err(DbError::InvalidData(
                    "authorization delegated authority is missing or ambiguous".to_owned(),
                ));
            }
            let row = &rows[0];
            let actor = bytes32(row.try_get("actor_pubkey")?, "delegated actor")?;
            let owner = bytes32(
                row.try_get::<Option<Vec<u8>>, _>("owner_pubkey")?
                    .ok_or_else(|| {
                        DbError::InvalidData("authorization delegated owner is missing".to_owned())
                    })?,
                "delegated owner",
            )?;
            let binding_id: Uuid = row.try_get("binding_id")?;
            let binding_version = u64::try_from(row.try_get::<i64, _>("binding_version")?)
                .map_err(|_| {
                    DbError::InvalidData(
                        "authorization delegated binding version is invalid".to_owned(),
                    )
                })?;
            Ok(local_actor(
                AuthorizationActorKind::Delegate,
                community_id,
                &[
                    relationship_id.as_bytes(),
                    &relationship_revision.to_be_bytes(),
                    &actor,
                    &owner,
                    binding_id.as_bytes(),
                    &binding_version.to_be_bytes(),
                ],
                Some(AuthorizationAuthorityLossTarget::DelegatedRelationship(
                    relationship_id,
                    relationship_revision,
                )),
            ))
        }
    }
}

fn actor_from_route_coordinates(
    community_id: CommunityId,
    actor: [u8; 32],
    owner: Option<[u8; 32]>,
    binding: (Uuid, u64),
    relationship: Option<(Uuid, u64)>,
) -> Result<AuthorizationEventActor> {
    let kind = match (owner, relationship) {
        (None, None) => AuthorizationActorKind::Direct,
        (Some(_), Some(_)) => AuthorizationActorKind::Delegate,
        _ => {
            return Err(DbError::InvalidData(
                "authorization actor route is partially delegated".to_owned(),
            ));
        }
    };
    let mut digest = Sha256::new();
    framed(&mut digest, b"buzz:authorization-event-actor:route:v1");
    framed(&mut digest, community_id.as_uuid().as_bytes());
    framed(&mut digest, &(kind as i16).to_be_bytes());
    framed(&mut digest, &actor);
    append_hash_optional(&mut digest, owner.as_ref().map(<[u8; 32]>::as_slice));
    framed(&mut digest, binding.0.as_bytes());
    framed(&mut digest, &binding.1.to_be_bytes());
    match relationship {
        Some((id, revision)) => {
            framed(&mut digest, id.as_bytes());
            framed(&mut digest, &revision.to_be_bytes());
        }
        None => framed(&mut digest, &[]),
    }
    Ok(AuthorizationEventActor {
        community_id: Some(community_id),
        kind,
        fingerprint: Some(digest.finalize().into()),
        authority_loss_target: None,
    })
}

fn local_actor(
    kind: AuthorizationActorKind,
    community_id: CommunityId,
    parts: &[&[u8]],
    authority_loss_target: Option<AuthorizationAuthorityLossTarget>,
) -> AuthorizationEventActor {
    let mut digest = Sha256::new();
    framed(
        &mut digest,
        b"buzz:authorization-event-actor:local-authority:v1",
    );
    framed(&mut digest, community_id.as_uuid().as_bytes());
    framed(&mut digest, &(kind as i16).to_be_bytes());
    for part in parts {
        framed(&mut digest, part);
    }
    AuthorizationEventActor {
        community_id: Some(community_id),
        kind,
        fingerprint: Some(digest.finalize().into()),
        authority_loss_target,
    }
}

/// Mint status-publication attribution only after the complete evidence tuple
/// has been rechecked inside the allocation transaction.
pub(crate) async fn resolve_current_binding_event_actor_tx(
    transaction: &mut Transaction<'_, Postgres>,
    evidence: &CanonicalCurrentBindingEvidence,
) -> Result<AuthorizationEventActor> {
    let mut object_key_digest = Sha256::new();
    object_key_digest.update(b"buzz:client-binding-status-authority:v1");
    object_key_digest.update((16_u64).to_be_bytes());
    object_key_digest.update(evidence.authorization_domain().as_uuid().as_bytes());
    object_key_digest.update((32_u64).to_be_bytes());
    object_key_digest.update(evidence.event_author_pubkey().to_bytes());
    let object_key: [u8; 32] = object_key_digest.finalize().into();
    sqlx::query(
        "SELECT 1 FROM identity_bindings b \
         JOIN identity_enrollment_policies p \
           ON p.community_id=b.community_id AND p.policy_revision=b.policy_revision \
         JOIN authorization_invalidation_domains d ON d.community_id=b.community_id \
         JOIN authorization_authority_epochs a \
           ON a.community_id=b.community_id AND a.object_kind=7 AND a.object_key=$10 \
         WHERE b.community_id=$1 AND b.binding_id=$2 AND b.binding_version=$3 \
           AND b.event_author_pubkey=$4 AND b.policy_revision=$5 \
           AND d.current_generation=$6 AND a.authority_epoch=$7 AND a.fence=$8 \
           AND b.binding_state=1 AND $9 > clock_timestamp() \
           AND $11 <= clock_timestamp() \
           AND (b.expires_at IS NULL OR b.expires_at > clock_timestamp()) \
           AND p.effective_at <= clock_timestamp() \
           AND (p.expires_at IS NULL OR p.expires_at > clock_timestamp()) \
         FOR SHARE OF b,p,d,a",
    )
    .bind(evidence.authorization_domain().as_uuid())
    .bind(evidence.binding_id())
    .bind(i64::try_from(evidence.binding_version()).map_err(|_| {
        DbError::InvalidData("authorization binding version is out of range".to_owned())
    })?)
    .bind(evidence.event_author_pubkey().to_bytes().as_slice())
    .bind(i64::try_from(evidence.policy_revision()).map_err(|_| {
        DbError::InvalidData("authorization policy revision is out of range".to_owned())
    })?)
    .bind(
        i64::try_from(evidence.invalidation_generation()).map_err(|_| {
            DbError::InvalidData("authorization invalidation generation is out of range".to_owned())
        })?,
    )
    .bind(i64::try_from(evidence.authority_epoch()).map_err(|_| {
        DbError::InvalidData("authorization authority epoch is out of range".to_owned())
    })?)
    .bind(evidence.fence().as_bytes().as_slice())
    .bind(evidence.fresh_until())
    .bind(object_key.as_slice())
    .bind(evidence.observed_at())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| DbError::NotFound("current binding event actor".to_owned()))?;
    current_binding_event_actor(evidence)
}

pub(crate) fn current_binding_event_actor(
    evidence: &CanonicalCurrentBindingEvidence,
) -> Result<AuthorizationEventActor> {
    Ok(local_actor(
        AuthorizationActorKind::Direct,
        evidence.authorization_domain(),
        &[
            evidence.binding_id().as_bytes(),
            &evidence.binding_version().to_be_bytes(),
            &evidence.event_author_pubkey().to_bytes(),
        ],
        None,
    ))
}

/// Mint withdrawal attribution only from the exact current durable status
/// receipt that is about to be superseded.
pub(crate) async fn resolve_status_withdrawal_event_actor_tx(
    transaction: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    event_author_pubkey: [u8; 32],
    supersedes_revision: u64,
) -> Result<AuthorizationEventActor> {
    let current = sqlx::query(
        "SELECT revision,disposition FROM client_status_revisions \
         WHERE community_id=$1 AND event_author_pubkey=$2 \
         ORDER BY revision DESC LIMIT 1 FOR UPDATE",
    )
    .bind(community_id.as_uuid())
    .bind(event_author_pubkey.as_slice())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(current) = current else {
        return Err(DbError::NotFound(
            "current status withdrawal actor".to_owned(),
        ));
    };
    if current.try_get::<i16, _>("disposition")? != 1
        || u64::try_from(current.try_get::<i64, _>("revision")?).map_err(|_| {
            DbError::InvalidData("authorization status revision is invalid".to_owned())
        })? != supersedes_revision
    {
        return Err(DbError::InvalidData(
            "current status withdrawal actor changed".to_owned(),
        ));
    }
    status_withdrawal_event_actor(community_id, event_author_pubkey, supersedes_revision)
}

pub(crate) fn status_withdrawal_event_actor(
    community_id: CommunityId,
    event_author_pubkey: [u8; 32],
    supersedes_revision: u64,
) -> Result<AuthorizationEventActor> {
    if community_id.as_uuid().is_nil() || supersedes_revision == 0 {
        return Err(DbError::InvalidData(
            "authorization status withdrawal actor is invalid".to_owned(),
        ));
    }
    Ok(local_actor(
        AuthorizationActorKind::Direct,
        community_id,
        &[&event_author_pubkey, &supersedes_revision.to_be_bytes()],
        None,
    ))
}

fn append_hash_optional(digest: &mut Sha256, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            framed(digest, &[1]);
            framed(digest, value);
        }
        None => framed(digest, &[0]),
    }
}

/// Validated immutable authorization event ready for insertion.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NewAuthorizationEvent {
    pub(crate) community_id: CommunityId,
    pub(crate) event_id: Uuid,
    pub(crate) event_kind: AuthorizationEventKind,
    pub(crate) outcome: AuthorizationEventOutcome,
    pub(crate) reason: AuthorizationReasonCode,
    pub(crate) actor_kind: AuthorizationActorKind,
    pub(crate) actor_fingerprint: [u8; 32],
    pub(crate) subject_fingerprint: [u8; 32],
    pub(crate) operation_id: Uuid,
    pub(crate) request_fingerprint: [u8; 32],
    pub(crate) correlation_id: Uuid,
    pub(crate) attempt_id: Uuid,
    pub(crate) occurred_at: DateTime<Utc>,
}

impl NewAuthorizationEvent {
    /// Validate a redaction-safe canonical event envelope.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        community_id: CommunityId,
        event_id: Uuid,
        event_kind: AuthorizationEventKind,
        outcome: AuthorizationEventOutcome,
        reason: AuthorizationReasonCode,
        actor: AuthorizationEventActor,
        subject_fingerprint: Option<[u8; 32]>,
        operation_id: Uuid,
        request_fingerprint: Option<[u8; 32]>,
        correlation_id: Uuid,
        attempt_id: Uuid,
    ) -> Result<Self> {
        let actor_kind = actor.kind();
        let unresolved = actor_kind == AuthorizationActorKind::Unresolved;
        let actor_fingerprint = actor.fingerprint();
        if community_id.as_uuid().is_nil()
            || event_id.is_nil()
            || operation_id.is_nil()
            || correlation_id.is_nil()
            || attempt_id.is_nil()
            || (!unresolved && !actor.is_bound_to(community_id))
            || !valid_event_semantics(event_kind, outcome, reason, unresolved)
            || (unresolved
                && (actor_fingerprint.is_some()
                    || subject_fingerprint.is_some()
                    || request_fingerprint.is_some()))
            || (!unresolved
                && (request_fingerprint.is_none()
                    || request_fingerprint == Some([0; 32])
                    || actor_fingerprint.is_none()))
        {
            return Err(DbError::InvalidData(
                "authorization event envelope is invalid".to_owned(),
            ));
        }
        Ok(Self {
            community_id,
            event_id,
            event_kind,
            outcome,
            reason,
            actor_kind,
            actor_fingerprint: actor_fingerprint.unwrap_or([0; 32]),
            subject_fingerprint: subject_fingerprint.unwrap_or([0; 32]),
            operation_id,
            request_fingerprint: request_fingerprint.unwrap_or([0; 32]),
            correlation_id,
            attempt_id,
            // The recorder replaces this private constructor sentinel with one
            // PostgreSQL clock sample. Accepted #4772 lifecycle literals keep
            // their already-DB-derived timestamp byte-for-byte.
            occurred_at: DateTime::<Utc>::MIN_UTC,
        })
    }
}

fn valid_event_semantics(
    event_kind: AuthorizationEventKind,
    outcome: AuthorizationEventOutcome,
    reason: AuthorizationReasonCode,
    unresolved: bool,
) -> bool {
    use AuthorizationEventKind as Kind;
    use AuthorizationEventOutcome as Outcome;
    use AuthorizationReasonCode as Reason;

    if unresolved {
        return event_kind == Kind::OperatorDenied
            && outcome == Outcome::Denied
            && matches!(
                reason,
                Reason::Missing | Reason::Invalid | Reason::Unauthenticated
            );
    }
    match event_kind {
        Kind::Enrolled
        | Kind::Revoked
        | Kind::Rotated
        | Kind::Recovered
        | Kind::PrincipalEnabled
        | Kind::Retired
        | Kind::PrincipalDisabled => {
            matches!(outcome, Outcome::Allowed | Outcome::NoOp)
                && matches!(reason, Reason::Current | Reason::Replay)
        }
        Kind::AdmissionLost => {
            matches!(outcome, Outcome::Allowed | Outcome::NoOp)
                && matches!(reason, Reason::Invalidated | Reason::Replay)
        }
        Kind::OperatorDenied | Kind::ProtectedDenied => {
            matches!(outcome, Outcome::Denied | Outcome::AuditUnavailable)
                && !matches!(reason, Reason::Current | Reason::Replay | Reason::Withdrawn)
        }
        Kind::ProtectedAllowed => outcome == Outcome::Allowed && reason == Reason::Current,
        Kind::StatusPublished => outcome == Outcome::Allowed && reason == Reason::Current,
        Kind::StatusWithdrawn => outcome == Outcome::Withdrawn && reason == Reason::Withdrawn,
        Kind::InvalidationAdvanced => outcome == Outcome::Allowed && reason == Reason::Invalidated,
    }
}

impl fmt::Debug for NewAuthorizationEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewAuthorizationEvent")
            .field("event_kind", &self.event_kind)
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("actor_kind", &self.actor_kind)
            .field("event_id", &"[REDACTED]")
            .field("operation_id", &"[REDACTED]")
            .finish()
    }
}

/// One immutable event returned from a bounded domain page.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationEventRecord {
    /// Stable event identity.
    pub event_id: Uuid,
    /// Canonical event class.
    pub event_kind: AuthorizationEventKind,
    /// Stable event outcome.
    pub outcome_code: i16,
    /// Stable reason code.
    pub reason_code: i16,
    /// Authoritative acceptance time.
    pub accepted_at: DateTime<Utc>,
    /// Canonical redaction-safe envelope.
    pub canonical_envelope: Vec<u8>,
    /// Digest of the exact envelope.
    pub envelope_digest: [u8; 32],
}

impl fmt::Debug for AuthorizationEventRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationEventRecord")
            .field("event_id", &"[REDACTED]")
            .field("event_kind", &self.event_kind)
            .field("outcome_code", &self.outcome_code)
            .field("reason_code", &self.reason_code)
            .field("accepted_at", &"[REDACTED]")
            .field("canonical_envelope", &"[REDACTED]")
            .field("envelope_digest", &"[REDACTED]")
            .finish()
    }
}

/// Stable keyset cursor for descending event pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationEventPageCursor {
    /// Acceptance time of the final row on the prior page.
    pub accepted_at: DateTime<Utc>,
    /// Stable event ID breaking timestamp ties.
    pub event_id: Uuid,
}

/// One bounded page and its continuation cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationEventPage {
    /// Events ordered newest-first.
    pub events: Vec<AuthorizationEventRecord>,
    /// Cursor for the next older page.
    pub next: Option<AuthorizationEventPageCursor>,
}

/// Durable immutable-capacity health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationEventCapacityHealth {
    /// Whether new events may be accepted.
    pub healthy: bool,
    /// Retained event count.
    pub retained_event_count: u64,
    /// Retained canonical envelope bytes.
    pub retained_envelope_bytes: u64,
    /// Sticky failure code, when unhealthy.
    pub failure_code: Option<AuthorizationAuditFailureCode>,
}

/// Sticky authorization-audit failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i16)]
pub enum AuthorizationAuditFailureCode {
    /// Configured immutable capacity was exhausted.
    CapacityExhausted = 1,
    /// PostgreSQL audit persistence was unavailable.
    StorageUnavailable = 2,
    /// Canonical envelope contract failed.
    InvalidEnvelope = 3,
}

impl AuthorizationAuditFailureCode {
    fn from_database(value: i16) -> Result<Self> {
        match value {
            1 => Ok(Self::CapacityExhausted),
            2 => Ok(Self::StorageUnavailable),
            3 => Ok(Self::InvalidEnvelope),
            _ => Err(DbError::InvalidData(
                "authorization audit failure code is invalid".to_owned(),
            )),
        }
    }
}

/// Typed classification of an event insert failure.
#[derive(Debug, Error)]
pub(crate) enum AuthorizationEventWriteError {
    /// Immutable audit capacity is absent, unhealthy, or exhausted.
    #[error("authorization event capacity is unavailable")]
    CapacityUnavailable,
    /// PostgreSQL or contract failure outside capacity enforcement.
    #[error(transparent)]
    Database(#[from] DbError),
}

impl From<AuthorizationEventWriteError> for DbError {
    fn from(error: AuthorizationEventWriteError) -> Self {
        match error {
            AuthorizationEventWriteError::CapacityUnavailable => {
                DbError::InvalidData("authorization event capacity is unavailable".to_owned())
            }
            AuthorizationEventWriteError::Database(error) => error,
        }
    }
}

/// Insert or exact-replay the single canonical operation receipt.
pub(crate) async fn record_authorization_operation_receipt_tx(
    transaction: &mut Transaction<'_, Postgres>,
    receipt: &AuthorizationOperationReceipt,
) -> Result<AuthorizationReceiptWrite> {
    validate_receipt(receipt)?;
    if let Some(row) = sqlx::query(
        "SELECT request_fingerprint, operation_kind, actor_fingerprint, outcome_code, result_digest \
         FROM authorization_operation_receipts WHERE community_id=$1 AND operation_id=$2",
    )
    .bind(receipt.community_id.as_uuid())
    .bind(receipt.operation_id)
    .fetch_optional(&mut **transaction)
    .await?
    {
        let exact = bytes32(row.try_get("request_fingerprint")?, "request fingerprint")?
            == receipt.request_fingerprint
            && row.try_get::<i16, _>("operation_kind")? == receipt.operation_kind as i16
            && bytes32(row.try_get("actor_fingerprint")?, "actor fingerprint")?
                == receipt.actor_fingerprint
            && row.try_get::<i16, _>("outcome_code")? == receipt.outcome as i16
            && bytes32(row.try_get("result_digest")?, "result digest")?
                == receipt.result_digest;
        if exact {
            return Ok(AuthorizationReceiptWrite::ExactReplay);
        }
        return Err(DbError::InvalidData(
            "authorization operation intent conflicts with prior receipt".to_owned(),
        ));
    }

    sqlx::query(
        "INSERT INTO authorization_operation_receipts \
         (community_id, operation_id, request_fingerprint, operation_kind, actor_fingerprint, \
          outcome_code, result_digest) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(receipt.community_id.as_uuid())
    .bind(receipt.operation_id)
    .bind(receipt.request_fingerprint.as_slice())
    .bind(receipt.operation_kind as i16)
    .bind(receipt.actor_fingerprint.as_slice())
    .bind(receipt.outcome as i16)
    .bind(receipt.result_digest.as_slice())
    .execute(&mut **transaction)
    .await?;
    Ok(AuthorizationReceiptWrite::Inserted)
}

/// Insert or exact-replay one canonical event in a caller-owned transaction.
pub(crate) async fn record_authorization_event_tx(
    transaction: &mut Transaction<'_, Postgres>,
    event: &NewAuthorizationEvent,
) -> std::result::Result<AuthorizationReceiptWrite, AuthorizationEventWriteError> {
    validate_event(event).map_err(AuthorizationEventWriteError::Database)?;
    if let Some(row) = sqlx::query(
        "SELECT event_id, outcome_code, reason_code, actor_kind, actor_fingerprint, \
                subject_fingerprint, request_fingerprint, correlation_id, occurred_at, \
                canonical_envelope, envelope_digest \
         FROM authorization_events \
         WHERE community_id=$1 AND operation_id=$2 AND event_kind=$3 AND attempt_id=$4",
    )
    .bind(event.community_id.as_uuid())
    .bind(event.operation_id)
    .bind(event.event_kind as i16)
    .bind(event.attempt_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| AuthorizationEventWriteError::Database(error.into()))?
    {
        let occurred_at: DateTime<Utc> = row.try_get("occurred_at").map_err(DbError::from)?;
        let canonical_envelope: Vec<u8> =
            row.try_get("canonical_envelope").map_err(DbError::from)?;
        let envelope_digest = bytes32(
            row.try_get("envelope_digest").map_err(DbError::from)?,
            "event envelope digest",
        )?;
        let expected_envelope = canonical_event_envelope(event, occurred_at);
        let calculated_envelope_digest: [u8; 32] = Sha256::digest(&canonical_envelope).into();
        let exact = row.try_get::<Uuid, _>("event_id").map_err(DbError::from)? == event.event_id
            && row
                .try_get::<i16, _>("outcome_code")
                .map_err(DbError::from)?
                == event.outcome as i16
            && row
                .try_get::<i16, _>("reason_code")
                .map_err(DbError::from)?
                == event.reason as i16
            && row.try_get::<i16, _>("actor_kind").map_err(DbError::from)?
                == event.actor_kind as i16
            && optional_bytes32(
                row.try_get("actor_fingerprint").map_err(DbError::from)?,
                "actor fingerprint",
            )? == (event.actor_fingerprint != [0; 32]).then_some(event.actor_fingerprint)
            && optional_bytes32(
                row.try_get("subject_fingerprint").map_err(DbError::from)?,
                "subject fingerprint",
            )? == (event.subject_fingerprint != [0; 32]).then_some(event.subject_fingerprint)
            && optional_bytes32(
                row.try_get("request_fingerprint").map_err(DbError::from)?,
                "request fingerprint",
            )? == (event.request_fingerprint != [0; 32]).then_some(event.request_fingerprint)
            && row
                .try_get::<Uuid, _>("correlation_id")
                .map_err(DbError::from)?
                == event.correlation_id
            && canonical_envelope == expected_envelope
            && envelope_digest == calculated_envelope_digest;
        if exact {
            return Ok(AuthorizationReceiptWrite::ExactReplay);
        }
        return Err(AuthorizationEventWriteError::Database(
            DbError::InvalidData(
                "authorization event attempt conflicts with prior evidence".to_owned(),
            ),
        ));
    }

    let occurred_at = if event.occurred_at == DateTime::<Utc>::MIN_UTC {
        sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| AuthorizationEventWriteError::Database(error.into()))?
    } else {
        event.occurred_at
    };
    let canonical_envelope = canonical_event_envelope(event, occurred_at);
    let envelope_digest: [u8; 32] = Sha256::digest(&canonical_envelope).into();
    let result = sqlx::query(
        "INSERT INTO authorization_events \
         (community_id,event_id,event_kind,outcome_code,reason_code,actor_kind,actor_fingerprint, \
          subject_fingerprint,operation_id,request_fingerprint,correlation_id,attempt_id, \
          occurred_at,canonical_envelope,envelope_digest) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(event.community_id.as_uuid())
    .bind(event.event_id)
    .bind(event.event_kind as i16)
    .bind(event.outcome as i16)
    .bind(event.reason as i16)
    .bind(event.actor_kind as i16)
    .bind((event.actor_fingerprint != [0; 32]).then_some(event.actor_fingerprint.to_vec()))
    .bind((event.subject_fingerprint != [0; 32]).then_some(event.subject_fingerprint.to_vec()))
    .bind(event.operation_id)
    .bind((event.request_fingerprint != [0; 32]).then_some(event.request_fingerprint.to_vec()))
    .bind(event.correlation_id)
    .bind(event.attempt_id)
    .bind(occurred_at)
    .bind(&canonical_envelope)
    .bind(envelope_digest.as_slice())
    .execute(&mut **transaction)
    .await;
    match result {
        Ok(_) => Ok(AuthorizationReceiptWrite::Inserted),
        Err(error) if is_capacity_constraint(&error) => {
            Err(AuthorizationEventWriteError::CapacityUnavailable)
        }
        Err(error) => Err(AuthorizationEventWriteError::Database(error.into())),
    }
}

fn validate_receipt(receipt: &AuthorizationOperationReceipt) -> Result<()> {
    if receipt.community_id.as_uuid().is_nil()
        || receipt.operation_id.is_nil()
        || receipt.request_fingerprint == [0; 32]
        || receipt.actor_fingerprint == [0; 32]
        || receipt.result_digest == [0; 32]
    {
        return Err(DbError::InvalidData(
            "authorization operation receipt is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_event(event: &NewAuthorizationEvent) -> Result<()> {
    let unresolved = event.actor_kind == AuthorizationActorKind::Unresolved;
    if event.community_id.as_uuid().is_nil()
        || event.event_id.is_nil()
        || event.operation_id.is_nil()
        || event.correlation_id.is_nil()
        || event.attempt_id.is_nil()
        || !valid_event_semantics(event.event_kind, event.outcome, event.reason, unresolved)
        || (unresolved
            && (event.actor_fingerprint != [0; 32]
                || event.subject_fingerprint != [0; 32]
                || event.request_fingerprint != [0; 32]))
        || (!unresolved
            && (event.actor_fingerprint == [0; 32] || event.request_fingerprint == [0; 32]))
    {
        return Err(DbError::InvalidData(
            "authorization event is invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Install or exactly replay one immutable event-capacity policy.
///
/// Migration-bootstrap counters are adopted only through the migration-owned
/// integrity function; this API never fabricates retained counts.
pub async fn install_authorization_event_capacity(
    db: &Db,
    community_id: CommunityId,
    policy: AuthorizationEventCapacityPolicy,
) -> Result<()> {
    let mut transaction = db.pool.begin().await?;
    install_authorization_event_capacity_tx(&mut transaction, community_id, policy).await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn install_authorization_event_capacity_tx(
    transaction: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    policy: AuthorizationEventCapacityPolicy,
) -> Result<()> {
    if community_id.as_uuid().is_nil() {
        return Err(DbError::InvalidData(
            "authorization event capacity domain must not be nil".to_owned(),
        ));
    }
    sqlx::query("SELECT authorization_event_capacity_install_v1($1,$2,$3,$4)")
        .bind(community_id.as_uuid())
        .bind(i64::try_from(policy.max_events_per_domain()).map_err(|_| {
            DbError::InvalidData("authorization event count exceeds PostgreSQL range".to_owned())
        })?)
        .bind(i64::try_from(policy.max_bytes_per_domain()).map_err(|_| {
            DbError::InvalidData("authorization event bytes exceed PostgreSQL range".to_owned())
        })?)
        .bind(i32::try_from(policy.max_envelope_bytes()).map_err(|_| {
            DbError::InvalidData("authorization event envelope exceeds PostgreSQL range".to_owned())
        })?)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub(crate) async fn event_capacity_is_configured_tx(
    transaction: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
) -> Result<bool> {
    let configured: Option<bool> = sqlx::query_scalar(
        "SELECT TRUE FROM authorization_event_capacity \
         WHERE community_id=$1 AND configuration_state=2 AND health_state=1",
    )
    .bind(community_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    Ok(configured.unwrap_or(false))
}

impl Db {
    /// Install the immutable capacity policy for one enabled domain.
    ///
    /// Exact replay is accepted; changed limits require offline migration.
    pub async fn install_authorization_event_capacity(
        &self,
        community_id: CommunityId,
        policy: AuthorizationEventCapacityPolicy,
    ) -> Result<()> {
        crate::authorization_events::install_authorization_event_capacity(
            self,
            community_id,
            policy,
        )
        .await
    }

    /// Permanently latch one domain's audit capacity unhealthy.
    pub async fn latch_authorization_event_failure(
        &self,
        community_id: CommunityId,
        failure: AuthorizationAuditFailureCode,
    ) -> Result<()> {
        let result = sqlx::query(
            "UPDATE authorization_event_capacity \
             SET health_state=2, failure_code=$2, failure_observed_at=clock_timestamp(), \
                 updated_at=transaction_timestamp() \
             WHERE community_id=$1 AND health_state=1",
        )
        .bind(community_id.as_uuid())
        .bind(failure as i16)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            let health = self
                .authorization_event_capacity_health(community_id)
                .await?;
            if health.healthy {
                return Err(DbError::InvalidData(
                    "authorization audit health cannot be latched".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Read immutable-capacity health for readiness and operator controls.
    pub async fn authorization_event_capacity_health(
        &self,
        community_id: CommunityId,
    ) -> Result<AuthorizationEventCapacityHealth> {
        let row = sqlx::query(
            "SELECT retained_event_count,retained_envelope_bytes,health_state,failure_code \
             FROM authorization_event_capacity WHERE community_id=$1",
        )
        .bind(community_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| DbError::NotFound("authorization event capacity policy".to_owned()))?;
        let health_state: i16 = row.try_get("health_state")?;
        let failure_code: Option<i16> = row.try_get("failure_code")?;
        Ok(AuthorizationEventCapacityHealth {
            healthy: health_state == 1,
            retained_event_count: nonnegative(row.try_get("retained_event_count")?)?,
            retained_envelope_bytes: nonnegative(row.try_get("retained_envelope_bytes")?)?,
            failure_code: failure_code
                .map(AuthorizationAuditFailureCode::from_database)
                .transpose()?,
        })
    }

    /// Read one bounded, domain-scoped immutable event page.
    pub async fn authorization_event_page(
        &self,
        community_id: CommunityId,
        cursor: Option<AuthorizationEventPageCursor>,
        limit: u16,
    ) -> Result<AuthorizationEventPage> {
        if community_id.as_uuid().is_nil() || limit == 0 || limit > MAX_EVENT_PAGE {
            return Err(DbError::InvalidData(
                "authorization event page bounds are invalid".to_owned(),
            ));
        }
        let rows = sqlx::query(
            "SELECT event_id,event_kind,outcome_code,reason_code,accepted_at, \
                    canonical_envelope,envelope_digest \
             FROM authorization_events \
             WHERE community_id=$1 \
               AND ($2::timestamptz IS NULL OR (accepted_at,event_id) < ($2,$3)) \
             ORDER BY accepted_at DESC,event_id DESC LIMIT $4",
        )
        .bind(community_id.as_uuid())
        .bind(cursor.map(|value| value.accepted_at))
        .bind(cursor.map(|value| value.event_id))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(AuthorizationEventRecord {
                event_id: row.try_get("event_id")?,
                event_kind: AuthorizationEventKind::from_database(row.try_get("event_kind")?)?,
                outcome_code: row.try_get("outcome_code")?,
                reason_code: row.try_get("reason_code")?,
                accepted_at: row.try_get("accepted_at")?,
                canonical_envelope: row.try_get("canonical_envelope")?,
                envelope_digest: bytes32(row.try_get("envelope_digest")?, "envelope digest")?,
            });
        }
        let next = events.last().map(|event| AuthorizationEventPageCursor {
            accepted_at: event.accepted_at,
            event_id: event.event_id,
        });
        Ok(AuthorizationEventPage { events, next })
    }
}

fn is_capacity_constraint(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database| {
        matches!(
            database.constraint(),
            Some(
                "authorization_event_capacity_policy_required"
                    | "authorization_event_capacity_health"
                    | "authorization_event_capacity_exhausted"
                    | "authorization_events_envelope_size"
            )
        )
    })
}

fn canonical_event_envelope(event: &NewAuthorizationEvent, occurred_at: DateTime<Utc>) -> Vec<u8> {
    let actor = (event.actor_fingerprint != [0; 32]).then(|| hex::encode(event.actor_fingerprint));
    let subject =
        (event.subject_fingerprint != [0; 32]).then(|| hex::encode(event.subject_fingerprint));
    let request =
        (event.request_fingerprint != [0; 32]).then(|| hex::encode(event.request_fingerprint));
    serde_json::to_vec(&CanonicalAuthorizationEnvelope {
        schema_version: 1,
        event_id: event.event_id,
        event_kind: event.event_kind as i16,
        outcome_code: event.outcome as i16,
        reason_code: event.reason as i16,
        actor_kind: event.actor_kind as i16,
        actor_fingerprint: actor.as_deref(),
        subject_fingerprint: subject.as_deref(),
        operation_id: event.operation_id,
        request_fingerprint: request.as_deref(),
        correlation_id: event.correlation_id,
        attempt_id: event.attempt_id,
        occurred_at_micros: occurred_at.timestamp_micros(),
    })
    .expect("canonical authorization envelope contains only infallible primitives")
}

fn framed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn bytes32(value: Vec<u8>, name: &str) -> Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| DbError::InvalidData(format!("authorization {name} is malformed")))
}

fn optional_bytes32(value: Option<Vec<u8>>, name: &str) -> Result<Option<[u8; 32]>> {
    value.map(|value| bytes32(value, name)).transpose()
}

fn nonnegative(value: i64) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| DbError::InvalidData("authorization capacity is negative".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> CommunityId {
        CommunityId::from_uuid(Uuid::from_u128(1))
    }

    fn direct_actor() -> AuthorizationEventActor {
        actor_from_route_coordinates(domain(), [3; 32], None, (Uuid::from_u128(4), 5), None)
            .expect("valid sealed-route shape")
    }

    #[test]
    fn unresolved_events_cannot_carry_identity_or_receipt_evidence() {
        let common = || {
            NewAuthorizationEvent::new(
                domain(),
                Uuid::from_u128(2),
                AuthorizationEventKind::OperatorDenied,
                AuthorizationEventOutcome::Denied,
                AuthorizationReasonCode::Unauthenticated,
                AuthorizationEventActor::unresolved_authentication_denial(),
                None,
                Uuid::from_u128(3),
                None,
                Uuid::from_u128(4),
                Uuid::from_u128(5),
            )
        };
        let event = common().expect("valid unresolved event");
        assert_eq!(event.actor_kind, AuthorizationActorKind::Unresolved);
        assert_eq!(event.actor_fingerprint, [0; 32]);
        assert_eq!(event.subject_fingerprint, [0; 32]);
        assert!(!AuthorizationEventActor::unresolved_authentication_denial().is_authenticated());
    }

    #[test]
    fn event_and_receipt_debug_are_redacted() {
        let receipt = AuthorizationOperationReceipt::new(
            domain(),
            Uuid::from_u128(2),
            [3; 32],
            AuthorizationOperationKind::ProtectedMutation,
            direct_actor(),
            AuthorizationOperationOutcome::Applied,
            [5; 32],
        )
        .expect("valid receipt");
        let debug = format!("{receipt:?}");
        assert!(!debug.contains(&hex::encode([3; 32])));
        assert!(!debug.contains(&hex::encode([4; 32])));
        assert!(!debug.contains(&hex::encode([5; 32])));
    }

    #[test]
    fn page_limits_are_bounded() {
        assert_eq!(MAX_EVENT_PAGE, 1_000);
        assert_eq!(AuthorizationAuditFailureCode::CapacityExhausted as i16, 1);
    }

    #[test]
    fn canonical_event_encoder_is_stable_and_binds_typed_fields() {
        let event = NewAuthorizationEvent::new(
            domain(),
            Uuid::from_u128(2),
            AuthorizationEventKind::ProtectedAllowed,
            AuthorizationEventOutcome::Allowed,
            AuthorizationReasonCode::Current,
            direct_actor(),
            Some([4; 32]),
            Uuid::from_u128(5),
            Some([6; 32]),
            Uuid::from_u128(7),
            Uuid::from_u128(8),
        )
        .expect("valid event");
        let occurred_at = DateTime::from_timestamp(9, 10).expect("valid timestamp");
        let first = canonical_event_envelope(&event, occurred_at);
        let second = canonical_event_envelope(&event, occurred_at);
        assert_eq!(first, second);
        assert!(first.len() <= 16_384);

        let changed = NewAuthorizationEvent::new(
            domain(),
            Uuid::from_u128(2),
            AuthorizationEventKind::ProtectedDenied,
            AuthorizationEventOutcome::Denied,
            AuthorizationReasonCode::PolicyDenied,
            direct_actor(),
            Some([4; 32]),
            Uuid::from_u128(5),
            Some([6; 32]),
            Uuid::from_u128(7),
            Uuid::from_u128(8),
        )
        .expect("valid changed event");
        assert_ne!(first, canonical_event_envelope(&changed, occurred_at));
    }

    #[test]
    fn actor_route_shape_is_closed_and_debug_is_redacted() {
        assert!(actor_from_route_coordinates(
            domain(),
            [1; 32],
            Some([2; 32]),
            (Uuid::from_u128(3), 4),
            None,
        )
        .is_err());
        let actor = direct_actor();
        assert_eq!(actor.kind(), AuthorizationActorKind::Direct);
        assert!(!format!("{actor:?}").contains(&hex::encode([3; 32])));
    }

    #[test]
    fn authenticated_actor_cannot_cross_domains() {
        let actor = direct_actor();
        let other = CommunityId::from_uuid(Uuid::from_u128(99));
        assert!(!actor.is_bound_to(other));
        assert!(AuthorizationOperationReceipt::new(
            other,
            Uuid::from_u128(20),
            [21; 32],
            AuthorizationOperationKind::ProtectedMutation,
            actor.clone(),
            AuthorizationOperationOutcome::Applied,
            [22; 32],
        )
        .is_err());
        assert!(NewAuthorizationEvent::new(
            other,
            Uuid::from_u128(23),
            AuthorizationEventKind::ProtectedAllowed,
            AuthorizationEventOutcome::Allowed,
            AuthorizationReasonCode::Current,
            actor,
            None,
            Uuid::from_u128(20),
            Some([21; 32]),
            Uuid::from_u128(24),
            Uuid::from_u128(25),
        )
        .is_err());
    }

    #[test]
    fn canonical_event_semantics_reject_contradictions() {
        let base = |kind, outcome, reason| {
            NewAuthorizationEvent::new(
                domain(),
                Uuid::from_u128(30),
                kind,
                outcome,
                reason,
                direct_actor(),
                None,
                Uuid::from_u128(31),
                Some([32; 32]),
                Uuid::from_u128(33),
                Uuid::from_u128(34),
            )
        };
        assert!(base(
            AuthorizationEventKind::StatusPublished,
            AuthorizationEventOutcome::Denied,
            AuthorizationReasonCode::Withdrawn,
        )
        .is_err());
        assert!(base(
            AuthorizationEventKind::InvalidationAdvanced,
            AuthorizationEventOutcome::Allowed,
            AuthorizationReasonCode::Current,
        )
        .is_err());
        assert!(base(
            AuthorizationEventKind::ProtectedAllowed,
            AuthorizationEventOutcome::Allowed,
            AuthorizationReasonCode::Current,
        )
        .is_ok());
    }

    #[test]
    fn recorder_validation_rejects_invalid_direct_literals() {
        let receipt = AuthorizationOperationReceipt {
            community_id: domain(),
            operation_id: Uuid::from_u128(40),
            request_fingerprint: [41; 32],
            operation_kind: AuthorizationOperationKind::Enroll,
            actor_fingerprint: [42; 32],
            outcome: AuthorizationOperationOutcome::Applied,
            result_digest: [43; 32],
        };
        assert!(validate_receipt(&receipt).is_ok());
        let mut invalid_receipt = receipt.clone();
        invalid_receipt.actor_fingerprint = [0; 32];
        assert!(validate_receipt(&invalid_receipt).is_err());

        let occurred_at = DateTime::from_timestamp(44, 45).expect("valid timestamp");
        let event = NewAuthorizationEvent {
            community_id: domain(),
            event_id: Uuid::from_u128(46),
            event_kind: AuthorizationEventKind::Enrolled,
            outcome: AuthorizationEventOutcome::Allowed,
            reason: AuthorizationReasonCode::Current,
            actor_kind: AuthorizationActorKind::Direct,
            actor_fingerprint: [47; 32],
            subject_fingerprint: [48; 32],
            operation_id: Uuid::from_u128(40),
            request_fingerprint: [41; 32],
            correlation_id: Uuid::from_u128(49),
            attempt_id: Uuid::from_u128(50),
            occurred_at,
        };
        assert!(validate_event(&event).is_ok());

        let mut contradictory = event.clone();
        contradictory.outcome = AuthorizationEventOutcome::Denied;
        assert!(validate_event(&contradictory).is_err());

        let mut forged_unresolved = event;
        forged_unresolved.event_kind = AuthorizationEventKind::OperatorDenied;
        forged_unresolved.outcome = AuthorizationEventOutcome::Denied;
        forged_unresolved.reason = AuthorizationReasonCode::Unauthenticated;
        forged_unresolved.actor_kind = AuthorizationActorKind::Unresolved;
        assert!(validate_event(&forged_unresolved).is_err());
    }

    #[test]
    fn accepted_lifecycle_literal_envelope_and_replay_are_byte_identical() {
        let occurred_at = DateTime::from_timestamp(9, 10).expect("valid timestamp");
        let event = NewAuthorizationEvent {
            community_id: domain(),
            event_id: Uuid::from_u128(2),
            event_kind: AuthorizationEventKind::Enrolled,
            outcome: AuthorizationEventOutcome::Allowed,
            reason: AuthorizationReasonCode::Current,
            actor_kind: AuthorizationActorKind::Direct,
            actor_fingerprint: [3; 32],
            subject_fingerprint: [4; 32],
            operation_id: Uuid::from_u128(5),
            request_fingerprint: [6; 32],
            correlation_id: Uuid::from_u128(7),
            attempt_id: Uuid::from_u128(8),
            occurred_at,
        };
        assert!(validate_event(&event).is_ok());

        let expected = format!(
            concat!(
                "{{\"schema_version\":1,\"event_id\":\"{}\",\"event_kind\":1,",
                "\"outcome_code\":1,\"reason_code\":1,\"actor_kind\":1,",
                "\"actor_fingerprint\":\"{}\",\"subject_fingerprint\":\"{}\",",
                "\"operation_id\":\"{}\",\"request_fingerprint\":\"{}\",",
                "\"correlation_id\":\"{}\",\"attempt_id\":\"{}\",",
                "\"occurred_at_micros\":9000000}}"
            ),
            event.event_id,
            "03".repeat(32),
            "04".repeat(32),
            event.operation_id,
            "06".repeat(32),
            event.correlation_id,
            event.attempt_id,
        );
        let first = canonical_event_envelope(&event, occurred_at);
        assert_eq!(first, expected.as_bytes());
        assert_eq!(first, canonical_event_envelope(&event, occurred_at));
    }
}
