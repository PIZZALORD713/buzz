//! Epoch-free PostgreSQL revision allocation for kind-24244 binding status.
//!
//! Allocation starts from privacy-safe current-binding evidence and locks the
//! complete authoritative tuple through commit. Withdrawal supersedes the
//! exact latest current receipt. Both paths share the canonical operation
//! receipt, immutable event, and exact operation-delta manifest.

use std::fmt;

use buzz_core::{CanonicalCurrentBindingEvidence, CommunityId};
use chrono::{DateTime, Duration, Utc};
use nostr::PublicKey;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    authorization_events::{
        current_binding_event_actor, record_authorization_event_tx,
        record_authorization_operation_receipt_tx, resolve_current_binding_event_actor_tx,
        resolve_status_withdrawal_event_actor_tx, status_withdrawal_event_actor,
        AuthorizationAuditFailureCode, AuthorizationEventActor, AuthorizationEventKind,
        AuthorizationEventOutcome, AuthorizationEventWriteError, AuthorizationOperationKind,
        AuthorizationOperationOutcome, AuthorizationOperationReceipt, AuthorizationReasonCode,
        AuthorizationReceiptWrite, NewAuthorizationEvent,
    },
    authorization_resolver::client_status_authority_object_key,
    authorization_version::{
        authorization_version_client_status_component_key, load_manifest_connection,
        record_authorization_operation_version_delta_tx, AuthorizationOperationFence,
        AuthorizationOperationVersionDelta, AuthorizationVersionComponentKind,
    },
    Db, DbError,
};

const STATUS_AUTHORITY_OBJECT_KIND: i16 = 7;

/// Server-generated identity shared by one status operation and its audit.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientStatusOperationIdentity {
    operation_id: Uuid,
    request_fingerprint: [u8; 32],
    correlation_id: Uuid,
    attempt_id: Uuid,
    event_id: Uuid,
}

impl ClientStatusOperationIdentity {
    /// Validate one server-generated status operation identity.
    pub fn new(
        operation_id: Uuid,
        request_fingerprint: [u8; 32],
        correlation_id: Uuid,
        attempt_id: Uuid,
        event_id: Uuid,
    ) -> crate::Result<Self> {
        if operation_id.is_nil()
            || request_fingerprint == [0; 32]
            || correlation_id.is_nil()
            || attempt_id.is_nil()
            || event_id.is_nil()
        {
            return Err(DbError::InvalidData(
                "client status operation identity is invalid".to_owned(),
            ));
        }
        Ok(Self {
            operation_id,
            request_fingerprint,
            correlation_id,
            attempt_id,
            event_id,
        })
    }

    /// Exact idempotency operation ID.
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }
}

/// Exact operation coordinate exposed only by a sealed status request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClientStatusRestoreIdentity {
    authorization_domain: CommunityId,
    operation_id: Uuid,
    request_fingerprint: [u8; 32],
}

impl ClientStatusRestoreIdentity {
    /// Server-resolved authorization domain.
    pub const fn authorization_domain(self) -> CommunityId {
        self.authorization_domain
    }

    /// Server-generated operation ID.
    pub const fn operation_id(self) -> Uuid {
        self.operation_id
    }

    /// Canonical request fingerprint.
    pub const fn request_fingerprint(self) -> [u8; 32] {
        self.request_fingerprint
    }
}

impl fmt::Debug for ClientStatusRestoreIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientStatusRestoreIdentity([REDACTED])")
    }
}

impl fmt::Debug for ClientStatusOperationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientStatusOperationIdentity([REDACTED])")
    }
}

/// Current-status revision allocation input.
#[derive(Clone)]
pub struct ClientStatusAllocationRequest {
    evidence: CanonicalCurrentBindingEvidence,
    operation: ClientStatusOperationIdentity,
}

impl ClientStatusAllocationRequest {
    /// Bind exact current evidence to one server-generated operation.
    pub fn new(
        evidence: CanonicalCurrentBindingEvidence,
        operation: ClientStatusOperationIdentity,
    ) -> Self {
        Self {
            evidence,
            operation,
        }
    }

    /// Exact restore identity sealed by this allocation request.
    pub const fn restore_identity(&self) -> ClientStatusRestoreIdentity {
        ClientStatusRestoreIdentity {
            authorization_domain: self.evidence.authorization_domain(),
            operation_id: self.operation.operation_id,
            request_fingerprint: self.operation.request_fingerprint,
        }
    }
}

impl fmt::Debug for ClientStatusAllocationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientStatusAllocationRequest([REDACTED])")
    }
}

/// Exact-current status withdrawal input.
#[derive(Clone)]
pub struct ClientStatusWithdrawalRequest {
    community_id: CommunityId,
    event_author_pubkey: PublicKey,
    supersedes_revision: u64,
    operation: ClientStatusOperationIdentity,
}

impl ClientStatusWithdrawalRequest {
    /// Bind a withdrawal to the exact current published revision.
    pub fn new(
        community_id: CommunityId,
        event_author_pubkey: PublicKey,
        supersedes_revision: u64,
        operation: ClientStatusOperationIdentity,
    ) -> crate::Result<Self> {
        if community_id.as_uuid().is_nil()
            || supersedes_revision == 0
            || supersedes_revision > i64::MAX as u64
        {
            return Err(DbError::InvalidData(
                "client status withdrawal is invalid".to_owned(),
            ));
        }
        Ok(Self {
            community_id,
            event_author_pubkey,
            supersedes_revision,
            operation,
        })
    }

    /// Exact restore identity sealed by this withdrawal request.
    pub const fn restore_identity(&self) -> ClientStatusRestoreIdentity {
        ClientStatusRestoreIdentity {
            authorization_domain: self.community_id,
            operation_id: self.operation.operation_id,
            request_fingerprint: self.operation.request_fingerprint,
        }
    }
}

impl fmt::Debug for ClientStatusWithdrawalRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientStatusWithdrawalRequest([REDACTED])")
    }
}

/// One durable revision allocated by PostgreSQL.
#[derive(Clone, PartialEq, Eq)]
pub struct AllocatedClientStatusRevision {
    /// Server-resolved domain.
    pub community_id: CommunityId,
    /// Exact status author.
    pub event_author_pubkey: PublicKey,
    /// Strictly monotonic per-author revision.
    pub revision: u64,
    /// Current revision superseded by a withdrawal, if any.
    pub supersedes_revision: Option<u64>,
    /// Digest of the complete immutable status receipt.
    pub receipt_digest: [u8; 32],
    /// Authoritative issue time used by the signed kind-24244 event.
    pub issued_at: DateTime<Utc>,
    /// Exclusive presentation expiry used by the signed kind-24244 event.
    pub fresh_until: DateTime<Utc>,
    /// Whether this is an exact operation replay.
    pub replay: bool,
}

impl fmt::Debug for AllocatedClientStatusRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AllocatedClientStatusRevision")
            .field("community_id", &"[REDACTED]")
            .field("event_author_pubkey", &"[REDACTED]")
            .field("revision", &"[REDACTED]")
            .field("supersedes_revision", &"[REDACTED]")
            .field("receipt_digest", &"[REDACTED]")
            .field("issued_at", &"[REDACTED]")
            .field("fresh_until", &"[REDACTED]")
            .field("replay", &self.replay)
            .finish()
    }
}

/// Fail-closed status revision failures.
#[derive(Debug, Error)]
pub enum ClientStatusRevisionError {
    /// The complete evidence tuple changed or expired.
    #[error("current binding status evidence is stale")]
    StaleEvidence,
    /// The requested superseded revision is not the exact current receipt.
    #[error("current binding status revision conflicts")]
    RevisionConflict,
    /// Canonical evidence could not be durably recorded.
    #[error("client status audit is unavailable")]
    AuditUnavailable,
    /// PostgreSQL or immutable-contract failure.
    #[error(transparent)]
    Database(#[from] DbError),
}

impl Db {
    /// Allocate on the exact physical session fenced before external Pending.
    pub(crate) async fn allocate_client_status_revision_fenced(
        &self,
        fence: &mut AuthorizationOperationFence,
        request: ClientStatusAllocationRequest,
    ) -> Result<AllocatedClientStatusRevision, ClientStatusRevisionError> {
        let identity = request.restore_identity();
        let connection = fence.connection_for(
            identity.authorization_domain(),
            identity.operation_id(),
            identity.request_fingerprint(),
        )?;
        let transaction = Transaction::begin(&mut *connection, None)
            .await
            .map_err(DbError::from)?;
        self.allocate_client_status_revision_tx(transaction, request)
            .await
    }

    /// Allocate one current kind-24244 revision after atomically revalidating
    /// every field of the supplied privacy-safe evidence tuple.
    #[cfg(test)]
    pub async fn allocate_client_status_revision(
        &self,
        request: ClientStatusAllocationRequest,
    ) -> Result<AllocatedClientStatusRevision, ClientStatusRevisionError> {
        let transaction = self.pool.begin().await.map_err(DbError::from)?;
        self.allocate_client_status_revision_tx(transaction, request)
            .await
    }

    async fn allocate_client_status_revision_tx(
        &self,
        mut transaction: Transaction<'_, Postgres>,
        request: ClientStatusAllocationRequest,
    ) -> Result<AllocatedClientStatusRevision, ClientStatusRevisionError> {
        let evidence = &request.evidence;
        let community_id = evidence.authorization_domain();
        let author = evidence.event_author_pubkey();
        lock_status_coordinate(&mut transaction, community_id, author).await?;

        if let Some(replay) = replay_status_operation(
            &mut transaction,
            community_id,
            author,
            &request.operation,
            Some(evidence),
            None,
        )
        .await?
        {
            transaction.rollback().await.map_err(DbError::from)?;
            return Ok(replay);
        }

        if !recheck_status_evidence_tx(&mut transaction, evidence).await? {
            transaction.rollback().await.map_err(DbError::from)?;
            return Err(ClientStatusRevisionError::StaleEvidence);
        }

        let before = latest_status_revision_tx(&mut transaction, community_id, author).await?;
        let revision = before
            .checked_add(1)
            .ok_or_else(|| DbError::InvalidData("client status revision exhausted".to_owned()))?;
        let receipt_digest = current_receipt_digest(evidence, revision, &request.operation);
        let actor = resolve_current_binding_event_actor_tx(&mut transaction, evidence).await?;

        let receipt = AuthorizationOperationReceipt::new(
            community_id,
            request.operation.operation_id,
            request.operation.request_fingerprint,
            AuthorizationOperationKind::StatusRevision,
            actor.clone(),
            AuthorizationOperationOutcome::Applied,
            receipt_digest,
        )?;
        require_inserted_receipt(&mut transaction, &receipt).await?;

        sqlx::query(
            "INSERT INTO client_status_revisions \
             (community_id,event_author_pubkey,revision,disposition,binding_id,binding_version, \
              policy_revision,invalidation_generation,authority_epoch,fence,observed_at,fresh_until, \
              supersedes_revision,receipt_digest,operation_id,request_fingerprint) \
             VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,NULL,$12,$13,$14)",
        )
        .bind(community_id.as_uuid())
        .bind(author.to_bytes().as_slice())
        .bind(to_database_version(revision)?)
        .bind(evidence.binding_id())
        .bind(to_database_version(evidence.binding_version())?)
        .bind(to_database_version(evidence.policy_revision())?)
        .bind(to_database_version(evidence.invalidation_generation())?)
        .bind(to_database_version(evidence.authority_epoch())?)
        .bind(evidence.fence().as_bytes().as_slice())
        .bind(evidence.observed_at())
        .bind(evidence.fresh_until())
        .bind(receipt_digest.as_slice())
        .bind(request.operation.operation_id)
        .bind(request.operation.request_fingerprint.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(DbError::from)?;

        record_status_manifest(
            &mut transaction,
            community_id,
            author,
            before,
            revision,
            &request.operation,
        )
        .await?;
        let event = status_event(
            &request.operation,
            community_id,
            AuthorizationEventKind::StatusPublished,
            AuthorizationEventOutcome::Allowed,
            AuthorizationReasonCode::Current,
            actor,
        )?;
        if let Err(error) = record_authorization_event_tx(&mut transaction, &event).await {
            return status_audit_failed(self, transaction, community_id, error).await;
        }

        if let Err(error) = transaction.commit().await {
            tracing::error!(error = %error, "client status allocation commit failed closed");
            latch_status_storage_failure(self, community_id).await;
            return Err(ClientStatusRevisionError::AuditUnavailable);
        }
        Ok(AllocatedClientStatusRevision {
            community_id,
            event_author_pubkey: author,
            revision,
            supersedes_revision: None,
            receipt_digest,
            issued_at: evidence.observed_at(),
            fresh_until: evidence.fresh_until(),
            replay: false,
        })
    }

    /// Withdraw on the exact physical session fenced before external Pending.
    pub(crate) async fn withdraw_client_status_revision_fenced(
        &self,
        fence: &mut AuthorizationOperationFence,
        request: ClientStatusWithdrawalRequest,
    ) -> Result<AllocatedClientStatusRevision, ClientStatusRevisionError> {
        let identity = request.restore_identity();
        let connection = fence.connection_for(
            identity.authorization_domain(),
            identity.operation_id(),
            identity.request_fingerprint(),
        )?;
        let transaction = Transaction::begin(&mut *connection, None)
            .await
            .map_err(DbError::from)?;
        self.withdraw_client_status_revision_tx(transaction, request)
            .await
    }

    /// Allocate a withdrawal that supersedes the exact latest current status
    /// receipt. A stale or already-withdrawn coordinate fails closed.
    #[cfg(test)]
    pub async fn withdraw_client_status_revision(
        &self,
        request: ClientStatusWithdrawalRequest,
    ) -> Result<AllocatedClientStatusRevision, ClientStatusRevisionError> {
        let transaction = self.pool.begin().await.map_err(DbError::from)?;
        self.withdraw_client_status_revision_tx(transaction, request)
            .await
    }

    async fn withdraw_client_status_revision_tx(
        &self,
        mut transaction: Transaction<'_, Postgres>,
        request: ClientStatusWithdrawalRequest,
    ) -> Result<AllocatedClientStatusRevision, ClientStatusRevisionError> {
        lock_status_coordinate(
            &mut transaction,
            request.community_id,
            request.event_author_pubkey,
        )
        .await?;

        if let Some(replay) = replay_status_operation(
            &mut transaction,
            request.community_id,
            request.event_author_pubkey,
            &request.operation,
            None,
            Some(request.supersedes_revision),
        )
        .await?
        {
            transaction.rollback().await.map_err(DbError::from)?;
            return Ok(replay);
        }

        let current = sqlx::query(
            "SELECT revision,disposition FROM client_status_revisions \
             WHERE community_id=$1 AND event_author_pubkey=$2 \
             ORDER BY revision DESC LIMIT 1 FOR UPDATE",
        )
        .bind(request.community_id.as_uuid())
        .bind(request.event_author_pubkey.to_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(DbError::from)?;
        let Some(current) = current else {
            transaction.rollback().await.map_err(DbError::from)?;
            return Err(ClientStatusRevisionError::RevisionConflict);
        };
        let before = database_version(current.try_get("revision").map_err(DbError::from)?)?;
        let disposition: i16 = current.try_get("disposition").map_err(DbError::from)?;
        if disposition != 1 || before != request.supersedes_revision {
            transaction.rollback().await.map_err(DbError::from)?;
            return Err(ClientStatusRevisionError::RevisionConflict);
        }
        let revision = before
            .checked_add(1)
            .ok_or_else(|| DbError::InvalidData("client status revision exhausted".to_owned()))?;
        let receipt_digest = withdrawal_receipt_digest(
            request.community_id,
            request.event_author_pubkey,
            revision,
            before,
            &request.operation,
        );
        let issued_at: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(DbError::from)?;
        let fresh_until = issued_at
            .checked_add_signed(Duration::seconds(300))
            .ok_or_else(|| {
                DbError::InvalidData("client status withdrawal time is out of range".to_owned())
            })?;
        let actor = resolve_status_withdrawal_event_actor_tx(
            &mut transaction,
            request.community_id,
            request.event_author_pubkey.to_bytes(),
            before,
        )
        .await?;
        let receipt = AuthorizationOperationReceipt::new(
            request.community_id,
            request.operation.operation_id,
            request.operation.request_fingerprint,
            AuthorizationOperationKind::StatusRevision,
            actor.clone(),
            AuthorizationOperationOutcome::Applied,
            receipt_digest,
        )?;
        require_inserted_receipt(&mut transaction, &receipt).await?;

        sqlx::query(
            "INSERT INTO client_status_revisions \
             (community_id,event_author_pubkey,revision,disposition,binding_id,binding_version, \
              policy_revision,invalidation_generation,authority_epoch,fence,observed_at,fresh_until, \
              supersedes_revision,receipt_digest,operation_id,request_fingerprint) \
             VALUES ($1,$2,$3,2,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,$4,$5,$6,$7)",
        )
        .bind(request.community_id.as_uuid())
        .bind(request.event_author_pubkey.to_bytes().as_slice())
        .bind(to_database_version(revision)?)
        .bind(to_database_version(before)?)
        .bind(receipt_digest.as_slice())
        .bind(request.operation.operation_id)
        .bind(request.operation.request_fingerprint.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(DbError::from)?;

        record_status_manifest(
            &mut transaction,
            request.community_id,
            request.event_author_pubkey,
            before,
            revision,
            &request.operation,
        )
        .await?;
        let event = status_event(
            &request.operation,
            request.community_id,
            AuthorizationEventKind::StatusWithdrawn,
            AuthorizationEventOutcome::Withdrawn,
            AuthorizationReasonCode::Withdrawn,
            actor,
        )?;
        if let Err(error) = record_authorization_event_tx(&mut transaction, &event).await {
            return status_audit_failed(self, transaction, request.community_id, error).await;
        }

        if let Err(error) = transaction.commit().await {
            tracing::error!(error = %error, "client status withdrawal commit failed closed");
            latch_status_storage_failure(self, request.community_id).await;
            return Err(ClientStatusRevisionError::AuditUnavailable);
        }
        Ok(AllocatedClientStatusRevision {
            community_id: request.community_id,
            event_author_pubkey: request.event_author_pubkey,
            revision,
            supersedes_revision: Some(before),
            receipt_digest,
            issued_at,
            fresh_until,
            replay: false,
        })
    }
}

async fn lock_status_coordinate(
    transaction: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    author: PublicKey,
) -> crate::Result<()> {
    let mut digest = Sha256::new();
    framed(&mut digest, b"buzz:client-status-allocation-lock:v1");
    framed(&mut digest, community_id.as_uuid().as_bytes());
    framed(&mut digest, &author.to_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let lock = i64::from_be_bytes(bytes[..8].try_into().map_err(|_| {
        DbError::InvalidData("client status lock coordinate is malformed".to_owned())
    })?);
    sqlx::query("SELECT pg_advisory_xact_lock($1::bigint)")
        .bind(lock)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn recheck_status_evidence_tx(
    transaction: &mut Transaction<'_, Postgres>,
    evidence: &CanonicalCurrentBindingEvidence,
) -> crate::Result<bool> {
    let object_key = client_status_authority_object_key(
        evidence.authorization_domain(),
        evidence.event_author_pubkey(),
    );
    let row = sqlx::query(
        "WITH authoritative_time AS MATERIALIZED (SELECT clock_timestamp() AS now) \
         SELECT 1 \
         FROM identity_bindings b \
         JOIN identity_enrollment_policies p \
           ON p.community_id=b.community_id AND p.policy_revision=b.policy_revision \
         JOIN authorization_invalidation_domains d ON d.community_id=b.community_id \
         JOIN authorization_authority_epochs a \
           ON a.community_id=b.community_id AND a.object_kind=$10 AND a.object_key=$11 \
         CROSS JOIN authoritative_time t \
         WHERE b.community_id=$1 AND b.event_author_pubkey=$2 AND b.binding_id=$3 \
           AND b.binding_version=$4 AND b.policy_revision=$5 AND d.current_generation=$6 \
           AND a.authority_epoch=$7 AND a.fence=$8 AND b.binding_state=1 \
           AND $9 > t.now AND $12 <= t.now \
           AND (b.expires_at IS NULL OR b.expires_at > t.now) \
           AND p.effective_at <= t.now \
           AND (p.expires_at IS NULL OR p.expires_at > t.now) \
         FOR SHARE OF b,p,d,a",
    )
    .bind(evidence.authorization_domain().as_uuid())
    .bind(evidence.event_author_pubkey().to_bytes().as_slice())
    .bind(evidence.binding_id())
    .bind(to_database_version(evidence.binding_version())?)
    .bind(to_database_version(evidence.policy_revision())?)
    .bind(to_database_version(evidence.invalidation_generation())?)
    .bind(to_database_version(evidence.authority_epoch())?)
    .bind(evidence.fence().as_bytes().as_slice())
    .bind(evidence.fresh_until())
    .bind(STATUS_AUTHORITY_OBJECT_KIND)
    .bind(object_key.as_slice())
    .bind(evidence.observed_at())
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.is_some())
}

async fn latest_status_revision_tx(
    transaction: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    author: PublicKey,
) -> crate::Result<u64> {
    let value: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(revision) FROM client_status_revisions \
         WHERE community_id=$1 AND event_author_pubkey=$2",
    )
    .bind(community_id.as_uuid())
    .bind(author.to_bytes().as_slice())
    .fetch_one(&mut **transaction)
    .await?;
    value
        .map(database_version)
        .transpose()
        .map(|value| value.unwrap_or(0))
}

async fn require_inserted_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    receipt: &AuthorizationOperationReceipt,
) -> crate::Result<()> {
    match record_authorization_operation_receipt_tx(transaction, receipt).await? {
        AuthorizationReceiptWrite::Inserted => Ok(()),
        AuthorizationReceiptWrite::ExactReplay => Err(DbError::InvalidData(
            "client status receipt raced with another writer".to_owned(),
        )),
    }
}

async fn record_status_manifest(
    transaction: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    author: PublicKey,
    before: u64,
    after: u64,
    operation: &ClientStatusOperationIdentity,
) -> crate::Result<()> {
    record_authorization_operation_version_delta_tx(
        transaction,
        community_id,
        operation.operation_id,
        operation.request_fingerprint,
        vec![AuthorizationOperationVersionDelta::new(
            AuthorizationVersionComponentKind::ClientStatusRevision,
            authorization_version_client_status_component_key(community_id, author.to_bytes()),
            before,
            after,
        )?],
    )
    .await?;
    Ok(())
}

async fn replay_status_operation(
    transaction: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    author: PublicKey,
    operation: &ClientStatusOperationIdentity,
    evidence: Option<&CanonicalCurrentBindingEvidence>,
    supersedes_revision: Option<u64>,
) -> Result<Option<AllocatedClientStatusRevision>, ClientStatusRevisionError> {
    let receipt = sqlx::query(
        "SELECT request_fingerprint,operation_kind,outcome_code,result_digest \
         FROM authorization_operation_receipts WHERE community_id=$1 AND operation_id=$2",
    )
    .bind(community_id.as_uuid())
    .bind(operation.operation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    let receipt_request_fingerprint = bytes32(
        receipt
            .try_get("request_fingerprint")
            .map_err(DbError::from)?,
        "request fingerprint",
    )?;
    let receipt_operation_kind: i16 = receipt.try_get("operation_kind").map_err(DbError::from)?;
    let receipt_outcome: i16 = receipt.try_get("outcome_code").map_err(DbError::from)?;
    if receipt_request_fingerprint != operation.request_fingerprint
        || receipt_operation_kind != AuthorizationOperationKind::StatusRevision as i16
        || receipt_outcome != AuthorizationOperationOutcome::Applied as i16
    {
        return Err(ClientStatusRevisionError::RevisionConflict);
    }
    let row = sqlx::query(
        "SELECT event_author_pubkey,revision,disposition,binding_id,binding_version,policy_revision, \
                invalidation_generation,authority_epoch,fence,observed_at,fresh_until, \
                supersedes_revision,receipt_digest,request_fingerprint,recorded_at \
         FROM client_status_revisions WHERE community_id=$1 AND operation_id=$2",
    )
    .bind(community_id.as_uuid())
    .bind(operation.operation_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(DbError::from)?
    .ok_or_else(|| DbError::InvalidData("client status replay is incomplete".to_owned()))?;

    let revision = database_version(row.try_get("revision").map_err(DbError::from)?)?;
    let stored_supersedes = row
        .try_get::<Option<i64>, _>("supersedes_revision")
        .map_err(DbError::from)?
        .map(database_version)
        .transpose()?;
    let receipt_digest = bytes32(
        row.try_get("receipt_digest").map_err(DbError::from)?,
        "status receipt digest",
    )?;
    let exact_receipt = bytes32(
        receipt.try_get("result_digest").map_err(DbError::from)?,
        "result digest",
    )? == receipt_digest
        && bytes32(
            row.try_get("request_fingerprint").map_err(DbError::from)?,
            "status request fingerprint",
        )? == operation.request_fingerprint
        && bytes32(
            row.try_get("event_author_pubkey").map_err(DbError::from)?,
            "status author",
        )? == author.to_bytes()
        && stored_supersedes == supersedes_revision;
    if !exact_receipt || !replay_row_matches_evidence(&row, evidence)? {
        return Err(ClientStatusRevisionError::RevisionConflict);
    }

    let actor = match evidence {
        Some(evidence) => current_binding_event_actor(evidence)?,
        None => status_withdrawal_event_actor(
            community_id,
            author.to_bytes(),
            supersedes_revision.ok_or(ClientStatusRevisionError::RevisionConflict)?,
        )?,
    };
    let expected_receipt_digest = match evidence {
        Some(evidence) => current_receipt_digest(evidence, revision, operation),
        None => withdrawal_receipt_digest(
            community_id,
            author,
            revision,
            supersedes_revision.ok_or(ClientStatusRevisionError::RevisionConflict)?,
            operation,
        ),
    };
    if receipt_digest != expected_receipt_digest {
        return Err(ClientStatusRevisionError::RevisionConflict);
    }
    let expected_receipt = AuthorizationOperationReceipt::new(
        community_id,
        operation.operation_id,
        operation.request_fingerprint,
        AuthorizationOperationKind::StatusRevision,
        actor.clone(),
        AuthorizationOperationOutcome::Applied,
        receipt_digest,
    )?;
    if record_authorization_operation_receipt_tx(transaction, &expected_receipt).await?
        != AuthorizationReceiptWrite::ExactReplay
    {
        return Err(ClientStatusRevisionError::RevisionConflict);
    }

    let manifest = load_manifest_connection(transaction, community_id, operation.operation_id)
        .await?
        .ok_or_else(|| DbError::InvalidData("client status replay lacks attribution".to_owned()))?;
    let expected_before = revision.checked_sub(1).ok_or_else(|| {
        DbError::InvalidData("client status replay revision is invalid".to_owned())
    })?;
    let exact_delta = manifest.request_fingerprint() == operation.request_fingerprint
        && manifest.components().len() == 1
        && manifest.components()[0].component_kind()
            == AuthorizationVersionComponentKind::ClientStatusRevision
        && manifest.components()[0].component_key()
            == authorization_version_client_status_component_key(community_id, author.to_bytes())
        && manifest.components()[0].before_version() == expected_before
        && manifest.components()[0].after_version() == revision;
    if !exact_delta {
        return Err(ClientStatusRevisionError::RevisionConflict);
    }
    let (kind, outcome, reason) = if evidence.is_some() {
        (
            AuthorizationEventKind::StatusPublished,
            AuthorizationEventOutcome::Allowed,
            AuthorizationReasonCode::Current,
        )
    } else {
        (
            AuthorizationEventKind::StatusWithdrawn,
            AuthorizationEventOutcome::Withdrawn,
            AuthorizationReasonCode::Withdrawn,
        )
    };
    let event_attempts = sqlx::query_scalar::<_, Uuid>(
        "SELECT attempt_id FROM authorization_events \
         WHERE community_id=$1 AND operation_id=$2 AND event_kind=$3 LIMIT 2",
    )
    .bind(community_id.as_uuid())
    .bind(operation.operation_id)
    .bind(kind as i16)
    .fetch_all(&mut **transaction)
    .await
    .map_err(DbError::from)?;
    if event_attempts.as_slice() != [operation.attempt_id] {
        return Err(ClientStatusRevisionError::RevisionConflict);
    }
    let expected_event = status_event(operation, community_id, kind, outcome, reason, actor)?;
    match record_authorization_event_tx(transaction, &expected_event).await {
        Ok(AuthorizationReceiptWrite::ExactReplay) => {}
        Ok(AuthorizationReceiptWrite::Inserted)
        | Err(AuthorizationEventWriteError::CapacityUnavailable)
        | Err(AuthorizationEventWriteError::Database(DbError::InvalidData(_))) => {
            return Err(ClientStatusRevisionError::RevisionConflict);
        }
        Err(AuthorizationEventWriteError::Database(error)) => {
            return Err(ClientStatusRevisionError::Database(error));
        }
    }
    let (issued_at, fresh_until) = if let Some(evidence) = evidence {
        (evidence.observed_at(), evidence.fresh_until())
    } else {
        let issued_at: DateTime<Utc> = row.try_get("recorded_at").map_err(DbError::from)?;
        let fresh_until = issued_at
            .checked_add_signed(Duration::seconds(300))
            .ok_or_else(|| {
                DbError::InvalidData("client status replay time is out of range".to_owned())
            })?;
        (issued_at, fresh_until)
    };
    Ok(Some(AllocatedClientStatusRevision {
        community_id,
        event_author_pubkey: author,
        revision,
        supersedes_revision: stored_supersedes,
        receipt_digest,
        issued_at,
        fresh_until,
        replay: true,
    }))
}

fn replay_row_matches_evidence(
    row: &sqlx::postgres::PgRow,
    evidence: Option<&CanonicalCurrentBindingEvidence>,
) -> crate::Result<bool> {
    let disposition: i16 = row.try_get("disposition")?;
    let Some(evidence) = evidence else {
        return Ok(disposition == 2
            && row.try_get::<Option<Uuid>, _>("binding_id")?.is_none()
            && row.try_get::<Option<i64>, _>("binding_version")?.is_none());
    };
    Ok(disposition == 1
        && row.try_get::<Option<Uuid>, _>("binding_id")? == Some(evidence.binding_id())
        && optional_database_version(row.try_get("binding_version")?)?
            == Some(evidence.binding_version())
        && optional_database_version(row.try_get("policy_revision")?)?
            == Some(evidence.policy_revision())
        && optional_database_version(row.try_get("invalidation_generation")?)?
            == Some(evidence.invalidation_generation())
        && optional_database_version(row.try_get("authority_epoch")?)?
            == Some(evidence.authority_epoch())
        && optional_bytes32(row.try_get("fence")?, "status fence")?
            == Some(*evidence.fence().as_bytes())
        && row.try_get::<Option<DateTime<Utc>>, _>("observed_at")? == Some(evidence.observed_at())
        && row.try_get::<Option<DateTime<Utc>>, _>("fresh_until")? == Some(evidence.fresh_until()))
}

fn status_event(
    operation: &ClientStatusOperationIdentity,
    community_id: CommunityId,
    kind: AuthorizationEventKind,
    outcome: AuthorizationEventOutcome,
    reason: AuthorizationReasonCode,
    actor: AuthorizationEventActor,
) -> crate::Result<NewAuthorizationEvent> {
    NewAuthorizationEvent::new(
        community_id,
        operation.event_id,
        kind,
        outcome,
        reason,
        actor,
        None,
        operation.operation_id,
        Some(operation.request_fingerprint),
        operation.correlation_id,
        operation.attempt_id,
    )
}

async fn status_audit_failed(
    db: &Db,
    transaction: Transaction<'_, Postgres>,
    community_id: CommunityId,
    error: AuthorizationEventWriteError,
) -> Result<AllocatedClientStatusRevision, ClientStatusRevisionError> {
    transaction.rollback().await.map_err(DbError::from)?;
    let failure = match error {
        AuthorizationEventWriteError::CapacityUnavailable => {
            AuthorizationAuditFailureCode::CapacityExhausted
        }
        AuthorizationEventWriteError::Database(_) => {
            AuthorizationAuditFailureCode::StorageUnavailable
        }
    };
    if let Err(latch_error) = db
        .latch_authorization_event_failure(community_id, failure)
        .await
    {
        tracing::error!(error = %latch_error, "failed to durably latch client status audit health");
    }
    Err(ClientStatusRevisionError::AuditUnavailable)
}

async fn latch_status_storage_failure(db: &Db, community_id: CommunityId) {
    if let Err(latch_error) = db
        .latch_authorization_event_failure(
            community_id,
            AuthorizationAuditFailureCode::StorageUnavailable,
        )
        .await
    {
        tracing::error!(error = %latch_error, "failed to durably latch client status storage health");
    }
}

fn current_receipt_digest(
    evidence: &CanonicalCurrentBindingEvidence,
    revision: u64,
    operation: &ClientStatusOperationIdentity,
) -> [u8; 32] {
    let mut digest = status_receipt_hasher(
        b"current",
        evidence.authorization_domain(),
        evidence.event_author_pubkey(),
        revision,
        operation,
    );
    framed(&mut digest, evidence.binding_id().as_bytes());
    framed(&mut digest, &evidence.binding_version().to_be_bytes());
    framed(&mut digest, &evidence.policy_revision().to_be_bytes());
    framed(
        &mut digest,
        &evidence.invalidation_generation().to_be_bytes(),
    );
    framed(&mut digest, &evidence.authority_epoch().to_be_bytes());
    framed(&mut digest, evidence.fence().as_bytes());
    framed(&mut digest, &timestamp_bytes(evidence.observed_at()));
    framed(&mut digest, &timestamp_bytes(evidence.fresh_until()));
    digest.finalize().into()
}

fn withdrawal_receipt_digest(
    community_id: CommunityId,
    author: PublicKey,
    revision: u64,
    supersedes: u64,
    operation: &ClientStatusOperationIdentity,
) -> [u8; 32] {
    let mut digest = status_receipt_hasher(b"withdrawn", community_id, author, revision, operation);
    framed(&mut digest, &supersedes.to_be_bytes());
    digest.finalize().into()
}

fn status_receipt_hasher(
    disposition: &[u8],
    community_id: CommunityId,
    author: PublicKey,
    revision: u64,
    operation: &ClientStatusOperationIdentity,
) -> Sha256 {
    let mut digest = Sha256::new();
    framed(&mut digest, b"buzz:client-status-receipt:v1");
    framed(&mut digest, disposition);
    framed(&mut digest, community_id.as_uuid().as_bytes());
    framed(&mut digest, &author.to_bytes());
    framed(&mut digest, &revision.to_be_bytes());
    framed(&mut digest, operation.operation_id.as_bytes());
    framed(&mut digest, &operation.request_fingerprint);
    digest
}

fn timestamp_bytes(value: DateTime<Utc>) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&value.timestamp().to_be_bytes());
    bytes[8..].copy_from_slice(&u64::from(value.timestamp_subsec_nanos()).to_be_bytes());
    bytes
}

fn framed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn bytes32(value: Vec<u8>, name: &str) -> crate::Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| DbError::InvalidData(format!("client status {name} is malformed")))
}

fn optional_bytes32(value: Option<Vec<u8>>, name: &str) -> crate::Result<Option<[u8; 32]>> {
    value.map(|value| bytes32(value, name)).transpose()
}

fn to_database_version(value: u64) -> crate::Result<i64> {
    i64::try_from(value)
        .map_err(|_| DbError::InvalidData("client status version exceeds BIGINT".to_owned()))
}

fn database_version(value: i64) -> crate::Result<u64> {
    u64::try_from(value)
        .map_err(|_| DbError::InvalidData("client status version is negative".to_owned()))
}

fn optional_database_version(value: Option<i64>) -> crate::Result<Option<u64>> {
    value.map(database_version).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_auth::AuthorizationEventCapacityPolicy;
    use buzz_core::AuthorizationLeaseFence;
    use chrono::Duration;
    use nostr::Keys;
    use sqlx::PgPool;

    fn evidence() -> CanonicalCurrentBindingEvidence {
        let observed = Utc::now();
        CanonicalCurrentBindingEvidence::new(
            CommunityId::from_uuid(Uuid::from_u128(1)),
            Keys::generate().public_key(),
            Uuid::from_u128(2),
            3,
            4,
            5,
            6,
            AuthorizationLeaseFence::from_bytes([7; 32]).expect("nonzero fence"),
            observed,
            observed + Duration::seconds(30),
        )
        .expect("valid evidence")
    }

    fn operation() -> ClientStatusOperationIdentity {
        ClientStatusOperationIdentity::new(
            Uuid::from_u128(8),
            [9; 32],
            Uuid::from_u128(10),
            Uuid::from_u128(11),
            Uuid::from_u128(12),
        )
        .expect("valid operation")
    }

    fn operation_tag(tag: u128) -> ClientStatusOperationIdentity {
        ClientStatusOperationIdentity::new(
            Uuid::from_u128(tag),
            [(tag & 0xff) as u8; 32],
            Uuid::from_u128(tag + 1),
            Uuid::from_u128(tag + 2),
            Uuid::from_u128(tag + 3),
        )
        .expect("valid tagged operation")
    }

    #[test]
    fn current_and_withdrawal_receipts_are_domain_separated_and_redacted() {
        let evidence = evidence();
        let operation = operation();
        let current = current_receipt_digest(&evidence, 1, &operation);
        let withdrawn = withdrawal_receipt_digest(
            evidence.authorization_domain(),
            evidence.event_author_pubkey(),
            2,
            1,
            &operation,
        );
        assert_ne!(current, withdrawn);
        assert!(!format!("{operation:?}").contains(&operation.operation_id().to_string()));
    }

    #[test]
    fn status_component_is_exact_author_and_domain_scoped() {
        let evidence = evidence();
        let first = authorization_version_client_status_component_key(
            evidence.authorization_domain(),
            evidence.event_author_pubkey().to_bytes(),
        );
        let other = authorization_version_client_status_component_key(
            CommunityId::from_uuid(Uuid::from_u128(99)),
            evidence.event_author_pubkey().to_bytes(),
        );
        assert_ne!(first, other);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_status_allocation_withdrawal_replay_and_failure_are_closed() {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_owned());
        let admin = PgPool::connect(&admin_url).await.expect("connect admin");
        let name = format!("s5_client_status_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("create scratch database");
        let split = admin_url.rfind('/').expect("database URL path");
        let scratch_url = format!("{}/{}", &admin_url[..split], name);
        let pool = PgPool::connect(&scratch_url)
            .await
            .expect("connect scratch database");
        crate::migration::run_migrations(&pool)
            .await
            .expect("migrate scratch database");

        let community_uuid = Uuid::new_v4();
        let community = CommunityId::from_uuid(community_uuid);
        let author = Keys::generate().public_key();
        let binding_id = Uuid::new_v4();
        let fence = AuthorizationLeaseFence::from_bytes([41_u8; 32]).expect("valid fence");
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(community_uuid)
            .bind(format!("status-{}.example", community_uuid.simple()))
            .execute(&pool)
            .await
            .expect("insert community");
        sqlx::query(
            "INSERT INTO identity_enrollment_policies \
             (community_id,policy_revision,enrollment_mode,policy_digest,effective_at) \
             VALUES ($1,1,1,$2,clock_timestamp() - INTERVAL '1 second')",
        )
        .bind(community_uuid)
        .bind(vec![42_u8; 32])
        .execute(&pool)
        .await
        .expect("insert policy");
        let mut binding_seed = pool.acquire().await.expect("seed binding connection");
        sqlx::query("SET session_replication_role=replica")
            .execute(&mut *binding_seed)
            .await
            .expect("disable binding lifecycle foreign-key trigger");
        let binding_version: i64 = sqlx::query_scalar(
            "INSERT INTO identity_bindings \
             (community_id,binding_id,issuer,subject,principal_fingerprint,event_author_pubkey, \
              binding_state,lifecycle_revision,binding_provenance,policy_revision, \
              enrollment_evidence_digest,birth_history_id,creation_operation_id, \
              creation_request_fingerprint) \
             VALUES ($1,$2,'issuer','subject',$3,$4,1,1,1,1,$5,$6,$7,$8) \
             RETURNING binding_version",
        )
        .bind(community_uuid)
        .bind(binding_id)
        .bind(vec![43_u8; 32])
        .bind(author.to_bytes().as_slice())
        .bind(vec![44_u8; 32])
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(vec![45_u8; 32])
        .fetch_one(&mut *binding_seed)
        .await
        .expect("insert active binding");
        sqlx::query("SET session_replication_role=origin")
            .execute(&mut *binding_seed)
            .await
            .expect("restore binding triggers");
        drop(binding_seed);
        sqlx::query(
            "INSERT INTO authorization_invalidation_domains (community_id,current_generation) \
             VALUES ($1,0)",
        )
        .bind(community_uuid)
        .execute(&pool)
        .await
        .expect("activate invalidation");
        let object_key = client_status_authority_object_key(community, author);
        let mut seed = pool.acquire().await.expect("seed authority connection");
        sqlx::query("SET session_replication_role=replica")
            .execute(&mut *seed)
            .await
            .expect("disable authority foreign-key trigger");
        sqlx::query(
            "INSERT INTO authorization_authority_epochs \
             (community_id,object_kind,object_key,authority_epoch,fence,operation_id,request_fingerprint) \
             VALUES ($1,7,$2,1,$3,$4,$5)",
        )
        .bind(community_uuid)
        .bind(object_key.as_slice())
        .bind(fence.as_bytes().as_slice())
        .bind(Uuid::new_v4())
        .bind(vec![46_u8; 32])
        .execute(&mut *seed)
        .await
        .expect("insert status authority epoch");
        sqlx::query("SET session_replication_role=origin")
            .execute(&mut *seed)
            .await
            .expect("restore authority triggers");
        drop(seed);

        let db = Db::from_pool(pool.clone());
        db.install_authorization_event_capacity(
            community,
            AuthorizationEventCapacityPolicy::new(2, 1 << 20, 16 << 10).expect("valid capacity"),
        )
        .await
        .expect("install status audit capacity");
        let observed_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&pool)
            .await
            .expect("read database time");
        let evidence = CanonicalCurrentBindingEvidence::new(
            community,
            author,
            binding_id,
            u64::try_from(binding_version).expect("positive binding version"),
            1,
            0,
            1,
            fence,
            observed_at,
            observed_at + Duration::seconds(120),
        )
        .expect("valid current evidence");

        let current_operation = operation_tag(100);
        let current = db
            .allocate_client_status_revision(ClientStatusAllocationRequest::new(
                evidence.clone(),
                current_operation.clone(),
            ))
            .await
            .expect("allocate current revision");
        assert_eq!(current.revision, 1);
        assert!(!current.replay);
        assert!(
            db.allocate_client_status_revision(ClientStatusAllocationRequest::new(
                evidence.clone(),
                current_operation.clone(),
            ))
            .await
            .expect("exactly replay current revision")
            .replay
        );

        for changed in [
            ClientStatusOperationIdentity::new(
                current_operation.operation_id,
                current_operation.request_fingerprint,
                Uuid::new_v4(),
                current_operation.attempt_id,
                current_operation.event_id,
            )
            .expect("changed correlation"),
            ClientStatusOperationIdentity::new(
                current_operation.operation_id,
                current_operation.request_fingerprint,
                current_operation.correlation_id,
                Uuid::new_v4(),
                current_operation.event_id,
            )
            .expect("changed attempt"),
            ClientStatusOperationIdentity::new(
                current_operation.operation_id,
                current_operation.request_fingerprint,
                current_operation.correlation_id,
                current_operation.attempt_id,
                Uuid::new_v4(),
            )
            .expect("changed event"),
        ] {
            let result = db
                .allocate_client_status_revision(ClientStatusAllocationRequest::new(
                    evidence.clone(),
                    changed,
                ))
                .await;
            assert!(
                matches!(&result, Err(ClientStatusRevisionError::RevisionConflict)),
                "changed audit identity must conflict, got {result:?}"
            );
        }

        let withdrawal_operation = operation_tag(200);
        let withdrawn = db
            .withdraw_client_status_revision(
                ClientStatusWithdrawalRequest::new(
                    community,
                    author,
                    current.revision,
                    withdrawal_operation.clone(),
                )
                .expect("valid withdrawal"),
            )
            .await
            .expect("withdraw current revision");
        assert_eq!(withdrawn.revision, 2);
        assert_eq!(withdrawn.supersedes_revision, Some(1));
        assert!(
            db.withdraw_client_status_revision(
                ClientStatusWithdrawalRequest::new(
                    community,
                    author,
                    current.revision,
                    withdrawal_operation.clone(),
                )
                .expect("valid replay withdrawal"),
            )
            .await
            .expect("exactly replay withdrawal")
            .replay
        );

        let mut corrupt = pool.acquire().await.expect("corrupt event connection");
        sqlx::query("SET session_replication_role=replica")
            .execute(&mut *corrupt)
            .await
            .expect("disable event immutability trigger");
        sqlx::query("DELETE FROM authorization_events WHERE community_id=$1 AND operation_id=$2")
            .bind(community_uuid)
            .bind(withdrawal_operation.operation_id)
            .execute(&mut *corrupt)
            .await
            .expect("remove withdrawal event");
        sqlx::query("SET session_replication_role=origin")
            .execute(&mut *corrupt)
            .await
            .expect("restore event triggers");
        drop(corrupt);
        assert!(matches!(
            db.withdraw_client_status_revision(
                ClientStatusWithdrawalRequest::new(
                    community,
                    author,
                    current.revision,
                    withdrawal_operation,
                )
                .expect("valid corrupt replay withdrawal"),
            )
            .await,
            Err(ClientStatusRevisionError::RevisionConflict)
        ));

        let capacity_operation = operation_tag(300);
        assert!(matches!(
            db.allocate_client_status_revision(ClientStatusAllocationRequest::new(
                evidence.clone(),
                capacity_operation.clone(),
            ))
            .await,
            Err(ClientStatusRevisionError::AuditUnavailable)
        ));
        let capacity_receipts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM authorization_operation_receipts \
             WHERE community_id=$1 AND operation_id=$2",
        )
        .bind(community_uuid)
        .bind(capacity_operation.operation_id)
        .fetch_one(&pool)
        .await
        .expect("count rolled-back capacity receipt");
        assert_eq!(capacity_receipts, 0);
        let status_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM client_status_revisions WHERE community_id=$1",
        )
        .bind(community_uuid)
        .fetch_one(&pool)
        .await
        .expect("count committed status rows");
        assert_eq!(status_rows, 2);

        sqlx::query(
            "UPDATE authorization_invalidation_domains \
             SET current_generation=1,updated_at=clock_timestamp() WHERE community_id=$1",
        )
        .bind(community_uuid)
        .execute(&pool)
        .await
        .expect("advance invalidation generation");
        assert!(matches!(
            db.allocate_client_status_revision(ClientStatusAllocationRequest::new(
                evidence,
                operation_tag(400),
            ))
            .await,
            Err(ClientStatusRevisionError::StaleEvidence)
        ));

        pool.close().await;
        let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
        )))
        .execute(&admin)
        .await;
    }
}
