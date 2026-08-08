//! Canonical authorization receipt and event persistence.
//!
//! This module is the only compatibility-child writer for the shared
//! operation receipt and immutable authorization-event roots introduced by
//! migration 0031. Callers retain their transaction through every related
//! lifecycle history, selector, consumption, and binding write.

use buzz_auth::AuthorizationEventCapacityPolicy;
use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{Db, DbError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub(crate) enum AuthorizationOperationKind {
    Enroll = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub(crate) enum AuthorizationOperationOutcome {
    Applied = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub(crate) enum AuthorizationEventKind {
    Enrolled = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub(crate) enum AuthorizationEventOutcome {
    Allowed = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub(crate) enum AuthorizationReasonCode {
    Current = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i16)]
pub(crate) enum AuthorizationActorKind {
    Direct = 1,
}

pub(crate) struct AuthorizationOperationReceipt {
    pub(crate) community_id: CommunityId,
    pub(crate) operation_id: Uuid,
    pub(crate) request_fingerprint: [u8; 32],
    pub(crate) operation_kind: AuthorizationOperationKind,
    pub(crate) actor_fingerprint: [u8; 32],
    pub(crate) outcome: AuthorizationOperationOutcome,
    pub(crate) result_digest: [u8; 32],
}

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

#[derive(Serialize)]
struct CanonicalAuthorizationEnvelope<'a> {
    schema_version: i16,
    event_id: Uuid,
    event_kind: i16,
    outcome_code: i16,
    reason_code: i16,
    actor_kind: i16,
    actor_fingerprint: &'a str,
    subject_fingerprint: &'a str,
    operation_id: Uuid,
    request_fingerprint: &'a str,
    correlation_id: Uuid,
    attempt_id: Uuid,
    occurred_at_micros: i64,
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

pub(crate) async fn record_authorization_operation_receipt_tx(
    transaction: &mut Transaction<'_, Postgres>,
    receipt: &AuthorizationOperationReceipt,
) -> Result<()> {
    validate_receipt(receipt)?;
    sqlx::query(
        "INSERT INTO authorization_operation_receipts \
         (community_id,operation_id,request_fingerprint,operation_kind,actor_fingerprint,\
          outcome_code,result_digest) VALUES ($1,$2,$3,$4,$5,$6,$7)",
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
    Ok(())
}

pub(crate) async fn record_authorization_event_tx(
    transaction: &mut Transaction<'_, Postgres>,
    event: &NewAuthorizationEvent,
) -> Result<()> {
    validate_event(event)?;
    let actor = hex::encode(event.actor_fingerprint);
    let subject = hex::encode(event.subject_fingerprint);
    let request = hex::encode(event.request_fingerprint);
    let envelope = serde_json::to_vec(&CanonicalAuthorizationEnvelope {
        schema_version: 1,
        event_id: event.event_id,
        event_kind: event.event_kind as i16,
        outcome_code: event.outcome as i16,
        reason_code: event.reason as i16,
        actor_kind: event.actor_kind as i16,
        actor_fingerprint: &actor,
        subject_fingerprint: &subject,
        operation_id: event.operation_id,
        request_fingerprint: &request,
        correlation_id: event.correlation_id,
        attempt_id: event.attempt_id,
        occurred_at_micros: event.occurred_at.timestamp_micros(),
    })
    .map_err(|error| DbError::InvalidData(format!("authorization event envelope: {error}")))?;
    let envelope_digest: [u8; 32] = Sha256::digest(&envelope).into();
    sqlx::query(
        "INSERT INTO authorization_events \
         (community_id,event_id,schema_version,event_kind,outcome_code,reason_code,actor_kind,\
          actor_fingerprint,subject_fingerprint,operation_id,request_fingerprint,correlation_id,\
          attempt_id,occurred_at,canonical_envelope,envelope_digest) \
         VALUES ($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(event.community_id.as_uuid())
    .bind(event.event_id)
    .bind(event.event_kind as i16)
    .bind(event.outcome as i16)
    .bind(event.reason as i16)
    .bind(event.actor_kind as i16)
    .bind(event.actor_fingerprint.as_slice())
    .bind(event.subject_fingerprint.as_slice())
    .bind(event.operation_id)
    .bind(event.request_fingerprint.as_slice())
    .bind(event.correlation_id)
    .bind(event.attempt_id)
    .bind(event.occurred_at)
    .bind(envelope)
    .bind(envelope_digest.as_slice())
    .execute(&mut **transaction)
    .await?;
    Ok(())
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
    if event.community_id.as_uuid().is_nil()
        || event.event_id.is_nil()
        || event.operation_id.is_nil()
        || event.correlation_id.is_nil()
        || event.attempt_id.is_nil()
        || event.actor_fingerprint == [0; 32]
        || event.subject_fingerprint == [0; 32]
        || event.request_fingerprint == [0; 32]
    {
        return Err(DbError::InvalidData(
            "authorization event is invalid".to_owned(),
        ));
    }
    Ok(())
}
