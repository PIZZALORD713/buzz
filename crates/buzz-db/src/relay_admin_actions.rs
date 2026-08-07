//! HTTP report-resolution enforcement state machine persistence.
//!
//! Backs the `relay_admin_actions` and `relay_admin_outbox` tables from
//! `migrations/0030_relay_admin_actions.sql`.
//!
//! This module is the only persistence allowed to write to `relay_admin_actions`;
//! report claim, step advancement, and finalization all go through the
//! functions here.
//!
//! Lane ownership: relay admin API (Duncan).

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use crate::error::Result;
use crate::CommunityId;

/// A row in `relay_admin_actions`.
#[derive(Debug, Clone)]
pub struct AdminActionRecord {
    /// Action UUID.
    pub id: Uuid,
    /// Report this action targets.
    pub report_id: Uuid,
    /// Community the report belongs to.
    pub report_community_id: Uuid,
    /// Client-generated idempotency key.
    pub request_id: Uuid,
    /// Principal who claimed the report.
    pub actor_pubkey: Vec<u8>,
    /// Role of the actor (`"operator"` | `"moderator"`).
    pub actor_role: String,
    /// Enforcement action name.
    pub action: String,
    /// Optional reason provided by the actor.
    pub reason: Option<String>,
    /// Timeout expiration for timeout actions.
    pub timeout_until: Option<DateTime<Utc>>,
    /// State machine: `"pending"` | `"enforcing"` | `"succeeded"` | `"failed"` | `"cancelled"`.
    pub state: String,
    /// Durably committed step: `None` = not started, `"mutation_committed"`, `"artifacts_done"`.
    pub step_marker: Option<String>,
    /// Error from the last failure, if any.
    pub error_message: Option<String>,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
    /// Row last-updated time.
    pub updated_at: DateTime<Utc>,
}

/// A row in `relay_admin_outbox`.
#[derive(Debug, Clone)]
pub struct OutboxRecord {
    /// Outbox row UUID.
    pub id: Uuid,
    /// Owning action.
    pub action_id: Uuid,
    /// Delivery task type: `"tombstone"` | `"system_message"` | `"reporter_notice"`.
    pub task_type: String,
    /// Task payload.
    pub payload: serde_json::Value,
    /// Delivery state.
    pub state: String,
    /// Deduplication key.
    pub dedup_key: Option<String>,
    /// Error from the last delivery attempt.
    pub error_message: Option<String>,
}

/// Result of attempting to claim a report for HTTP enforcement.
#[derive(Debug)]
pub enum ClaimResult {
    /// Successfully claimed. Returns the new action record.
    Claimed(AdminActionRecord),
    /// An existing action with the same `request_id` was found — idempotent retry.
    AlreadyClaimed(AdminActionRecord),
    /// The report is not in `open` status. Returns its current status.
    NotOpen(String),
    /// The report was not found globally.
    NotFound,
}

/// Atomically resolve a report without enforcement (decision-only).
///
/// Inserts the decision audit row AND CASes the report status `open → terminal`
/// in a single transaction. If the report is not in `open` status, the whole
/// transaction rolls back — no orphan audit row.
///
/// Returns `true` if the report was successfully closed, `false` if the CAS
/// failed (report not open or wrong community).
#[allow(clippy::too_many_arguments)]
pub async fn resolve_report_decision_atomic(
    pool: &PgPool,
    community_id: CommunityId,
    report_id: Uuid,
    terminal_status: &str,
    audit_action: &str,
    actor_pubkey: &[u8],
    actor_authority: &str,
    target_pubkey: Option<&[u8]>,
    target_event_id: Option<&[u8]>,
    channel_id: Option<Uuid>,
    reason: Option<&str>,
) -> Result<bool> {
    let mut tx = pool.begin().await?;

    // CAS: open → terminal. The update count tells us whether the report was open.
    let updated = sqlx::query(
        r#"
        UPDATE moderation_reports
        SET status = $3, resolved_by = $4, resolved_at = now(), active_action_id = NULL
        WHERE community_id = $1 AND id = $2 AND status = 'open'
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(report_id)
    .bind(terminal_status)
    .bind(actor_pubkey)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    // Insert the decision audit row in the same transaction.
    sqlx::query(
        r#"
        INSERT INTO moderation_actions (
            community_id, actor_pubkey, action, target_pubkey, target_event_id,
            channel_id, public_reason, actor_authority
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(actor_pubkey)
    .bind(audit_action)
    .bind(target_pubkey)
    .bind(target_event_id)
    .bind(channel_id)
    .bind(reason)
    .bind(actor_authority)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(true)
}

/// Claim a report for HTTP enforcement via a single-transaction CAS.
///
/// - If `status = 'open'`: sets `status = 'processing'`, `active_action_id = new_action.id`,
///   inserts the decision audit row, inserts the action record, and inserts outbox commands.
///   Returns `ClaimResult::Claimed`.
///
/// - If `status = 'processing'` and an action with the same `(community_id, report_id, request_id)`
///   already exists: idempotent retry — returns `ClaimResult::AlreadyClaimed` with the
///   existing action record.
///
/// - If `status = 'processing'` with a different `request_id`, or any other status:
///   returns `ClaimResult::NotOpen(status)`.
///
/// Decision audit row is written in the same transaction with the given `actor_authority`.
#[allow(clippy::too_many_arguments)]
pub async fn claim_report(
    pool: &PgPool,
    community_id: CommunityId,
    report_id: Uuid,
    request_id: Uuid,
    actor_pubkey: &[u8],
    actor_role: &str,
    action: &str,
    reason: Option<&str>,
    timeout_until: Option<DateTime<Utc>>,
    audit_action: &str,
    actor_authority: &str,
    target_pubkey: Option<&[u8]>,
    target_event_id: Option<&[u8]>,
    channel_id: Option<Uuid>,
) -> Result<ClaimResult> {
    let mut tx = pool.begin().await?;

    // Lock the report row to serialize concurrent claims on the same report.
    let report_row = sqlx::query(
        r#"
        SELECT id, status, active_action_id
        FROM moderation_reports
        WHERE community_id = $1 AND id = $2
        FOR UPDATE
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(report_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(report_row) = report_row else {
        return Ok(ClaimResult::NotFound);
    };

    let status: String = report_row.try_get("status")?;

    // Idempotent retry: if this exact request_id already claimed, return existing.
    if status == "processing" {
        let existing = sqlx::query(
            r#"
            SELECT id, report_id, report_community_id, request_id, actor_pubkey, actor_role,
                   action, reason, timeout_until, state, step_marker, error_message,
                   created_at, updated_at
            FROM relay_admin_actions
            WHERE report_community_id = $1 AND report_id = $2 AND request_id = $3
            "#,
        )
        .bind(community_id.as_uuid())
        .bind(report_id)
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = existing {
            tx.rollback().await?;
            return Ok(ClaimResult::AlreadyClaimed(row_to_action(row)?));
        }
        // Different request_id against processing report → conflict.
        return Ok(ClaimResult::NotOpen(status));
    }

    if status != "open" {
        return Ok(ClaimResult::NotOpen(status));
    }

    // Insert the action record first to get its ID.
    let action_row = sqlx::query(
        r#"
        INSERT INTO relay_admin_actions (
            report_id, report_community_id, request_id, actor_pubkey, actor_role,
            action, reason, timeout_until, state
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')
        RETURNING id, report_id, report_community_id, request_id, actor_pubkey, actor_role,
                  action, reason, timeout_until, state, step_marker, error_message,
                  created_at, updated_at
        "#,
    )
    .bind(report_id)
    .bind(community_id.as_uuid())
    .bind(request_id)
    .bind(actor_pubkey)
    .bind(actor_role)
    .bind(action)
    .bind(reason)
    .bind(timeout_until)
    .fetch_one(&mut *tx)
    .await?;

    let action_id: Uuid = action_row.try_get("id")?;

    // Insert the decision audit row in the same transaction.
    sqlx::query(
        r#"
        INSERT INTO moderation_actions (
            community_id, actor_pubkey, action, target_pubkey, target_event_id,
            channel_id, public_reason, actor_authority
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(actor_pubkey)
    .bind(audit_action)
    .bind(target_pubkey)
    .bind(target_event_id)
    .bind(channel_id)
    .bind(reason)
    .bind(actor_authority)
    .execute(&mut *tx)
    .await?;

    // CAS: set report to processing with active_action_id.
    let updated = sqlx::query(
        r#"
        UPDATE moderation_reports
        SET status = 'processing', active_action_id = $3
        WHERE community_id = $1 AND id = $2 AND status = 'open'
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(report_id)
    .bind(action_id)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() == 0 {
        // Shouldn't happen since we locked the row above, but be defensive.
        tx.rollback().await?;
        return Ok(ClaimResult::NotOpen("concurrent_update".to_string()));
    }

    // Insert outbox delivery commands in the same claim transaction.
    // This ensures at-least-once delivery even if the process crashes before
    // the request path enqueues them. ON CONFLICT DO NOTHING is safe because
    // the worker re-enqueues on re-drive via the same dedup keys.
    let community_str = community_id.as_uuid().to_string();
    let action_str = action_id.to_string();

    if action == "delete" {
        if let (Some(target_eid), Some(ch)) = (target_event_id, channel_id) {
            let payload = serde_json::json!({
                "community_id": community_str,
                "channel_id": ch.to_string(),
                "actor": hex::encode(actor_pubkey),
                "target_event_id": hex::encode(target_eid),
                "action_id": action_str,
                "reason_code": reason.unwrap_or(""),
            });
            sqlx::query(
                r#"
                INSERT INTO relay_admin_outbox (action_id, task_type, payload, dedup_key)
                VALUES ($1, 'tombstone', $2, $3)
                ON CONFLICT (dedup_key) DO NOTHING
                "#,
            )
            .bind(action_id)
            .bind(payload)
            .bind(format!("tombstone:{action_str}"))
            .execute(&mut *tx)
            .await?;
        }
    }

    if action == "kick" {
        if let (Some(target_pk), Some(ch)) = (target_pubkey, channel_id) {
            let payload = serde_json::json!({
                "community_id": community_str,
                "channel_id": ch.to_string(),
                "actor": hex::encode(actor_pubkey),
                "target": hex::encode(target_pk),
                "action_id": action_str,
            });
            sqlx::query(
                r#"
                INSERT INTO relay_admin_outbox (action_id, task_type, payload, dedup_key)
                VALUES ($1, 'system_message', $2, $3)
                ON CONFLICT (dedup_key) DO NOTHING
                "#,
            )
            .bind(action_id)
            .bind(payload)
            .bind(format!("system_message:{action_str}"))
            .execute(&mut *tx)
            .await?;
        }
    }

    // Always enqueue a reporter notice placeholder (payload will be populated by
    // the worker using the reporter_pubkey from the report row at delivery time).
    let notice_payload = serde_json::json!({
        "action_id": action_str,
        "community_id": community_str,
    });
    sqlx::query(
        r#"
        INSERT INTO relay_admin_outbox (action_id, task_type, payload, dedup_key)
        VALUES ($1, 'reporter_notice', $2, $3)
        ON CONFLICT (dedup_key) DO NOTHING
        "#,
    )
    .bind(action_id)
    .bind(notice_payload)
    .bind(format!("reporter_notice:{action_str}"))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(ClaimResult::Claimed(row_to_action(action_row)?))
}

/// Advance the action to 'enforcing' state. Returns false if the action was
/// not in 'pending' state (e.g. concurrent worker picked it up).
pub async fn begin_enforcing(pool: &PgPool, action_id: Uuid) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE relay_admin_actions
        SET state = 'enforcing', updated_at = now()
        WHERE id = $1 AND state = 'pending'
        "#,
    )
    .bind(action_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Commit the core mutation step and advance the step_marker to
/// 'mutation_committed' in one transaction. This is the idempotency point:
/// a crash after this returns true on re-drive; re-drive skips the mutation
/// and resumes from artifact delivery.
///
/// Returns false if the action was not found or not in the expected state.
pub async fn commit_mutation_step(pool: &PgPool, action_id: Uuid) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE relay_admin_actions
        SET step_marker = 'mutation_committed', updated_at = now()
        WHERE id = $1 AND state = 'enforcing' AND step_marker IS NULL
        "#,
    )
    .bind(action_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Atomically finalize the enforcement: action → succeeded, report → terminal status.
/// Requires that:
/// - The action is in `enforcing` state WITH `step_marker = 'mutation_committed'`.
/// - The report's `active_action_id` matches this action (prevents wrong-action finalization).
///
/// Returns false if either fence fails (ownership lost or wrong step).
pub async fn finalize_success(
    pool: &PgPool,
    action_id: Uuid,
    community_id: CommunityId,
    report_id: Uuid,
    terminal_status: &str,
    actor_pubkey: &[u8],
) -> Result<bool> {
    let mut tx = pool.begin().await?;

    // Require step_marker = 'mutation_committed' to prevent premature finalization.
    let updated_action = sqlx::query(
        r#"
        UPDATE relay_admin_actions
        SET state = 'succeeded', step_marker = 'artifacts_done', updated_at = now()
        WHERE id = $1 AND state = 'enforcing' AND step_marker = 'mutation_committed'
        "#,
    )
    .bind(action_id)
    .execute(&mut *tx)
    .await?;

    if updated_action.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    // Transition report to terminal status. Requires active_action_id = this action,
    // which prevents a stale or wrong action from closing the report.
    let updated_report = sqlx::query(
        r#"
        UPDATE moderation_reports
        SET status = $3, resolved_by = $4, resolved_at = now(),
            active_action_id = NULL
        WHERE community_id = $1 AND id = $2
          AND status = 'processing'
          AND active_action_id = $5
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(report_id)
    .bind(terminal_status)
    .bind(actor_pubkey)
    .bind(action_id)
    .execute(&mut *tx)
    .await?;

    if updated_report.rows_affected() == 0 {
        // The report CAS failed: either the report moved to a different state
        // or active_action_id no longer matches. Roll back the action update too.
        tx.rollback().await?;
        return Ok(false);
    }

    tx.commit().await?;
    Ok(true)
}

/// Record a failure on an action. The report remains 'processing' with active_action_id set.
/// Only legal before 'mutation_committed' step marker (post-mutation failures are
/// delivery states, not enforcement failures — handled separately).
pub async fn record_failure(pool: &PgPool, action_id: Uuid, error: &str) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE relay_admin_actions
        SET state = 'failed', error_message = $2, updated_at = now()
        WHERE id = $1 AND state = 'enforcing' AND step_marker IS NULL
        "#,
    )
    .bind(action_id)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

/// Cancel a failed action (pre-mutation only). Clears the claim so the report
/// returns to 'open'. Returns false if the action was not in 'failed' state
/// or had a step_marker (post-mutation cancel is forbidden).
pub async fn cancel_action(
    pool: &PgPool,
    action_id: Uuid,
    community_id: CommunityId,
    report_id: Uuid,
) -> Result<bool> {
    let mut tx = pool.begin().await?;

    // Only cancel from pre-mutation failed state.
    let updated = sqlx::query(
        r#"
        UPDATE relay_admin_actions
        SET state = 'cancelled', updated_at = now()
        WHERE id = $1 AND state = 'failed' AND step_marker IS NULL
        "#,
    )
    .bind(action_id)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    // Clear the claim on the report → back to open.
    sqlx::query(
        r#"
        UPDATE moderation_reports
        SET status = 'open', active_action_id = NULL
        WHERE community_id = $1 AND id = $2 AND active_action_id = $3
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(report_id)
    .bind(action_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(true)
}

/// Fetch an action record by ID.
pub async fn get_action(pool: &PgPool, action_id: Uuid) -> Result<Option<AdminActionRecord>> {
    let row = sqlx::query(
        r#"
        SELECT id, report_id, report_community_id, request_id, actor_pubkey, actor_role,
               action, reason, timeout_until, state, step_marker, error_message,
               created_at, updated_at
        FROM relay_admin_actions WHERE id = $1
        "#,
    )
    .bind(action_id)
    .fetch_optional(pool)
    .await?;
    row.map(row_to_action).transpose()
}

/// Fetch an action record by report + request_id (idempotency lookup).
pub async fn get_action_by_request(
    pool: &PgPool,
    community_id: CommunityId,
    report_id: Uuid,
    request_id: Uuid,
) -> Result<Option<AdminActionRecord>> {
    let row = sqlx::query(
        r#"
        SELECT id, report_id, report_community_id, request_id, actor_pubkey, actor_role,
               action, reason, timeout_until, state, step_marker, error_message,
               created_at, updated_at
        FROM relay_admin_actions
        WHERE report_community_id = $1 AND report_id = $2 AND request_id = $3
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(report_id)
    .bind(request_id)
    .fetch_optional(pool)
    .await?;
    row.map(row_to_action).transpose()
}

/// Insert an outbox command for artifact/notice delivery.
/// `dedup_key` prevents re-creating an artifact that was already delivered.
/// The INSERT is ON CONFLICT DO NOTHING so re-inserting on re-drive is a no-op.
pub async fn enqueue_outbox(
    pool: &PgPool,
    action_id: Uuid,
    task_type: &str,
    payload: serde_json::Value,
    dedup_key: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO relay_admin_outbox (action_id, task_type, payload, dedup_key)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (dedup_key) DO NOTHING
        "#,
    )
    .bind(action_id)
    .bind(task_type)
    .bind(payload)
    .bind(dedup_key)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark an outbox record as delivered.
pub async fn mark_outbox_delivered(pool: &PgPool, outbox_id: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE relay_admin_outbox SET state = 'delivered', updated_at = now() WHERE id = $1",
    )
    .bind(outbox_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark an outbox record as failed with an error message.
pub async fn fail_outbox_row(pool: &PgPool, outbox_id: Uuid, error: &str) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE relay_admin_outbox
        SET state = 'failed', error_message = $2, held_by = NULL, lease_expires_at = NULL,
            updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(outbox_id)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

/// Claim a batch of pending outbox rows using DB-level leases.
///
/// Atomically sets `held_by` and `lease_expires_at` on up to `batch_size`
/// rows whose lease is expired or unset, returning them for processing.
pub async fn claim_pending_outbox_batch(
    pool: &PgPool,
    worker_id: &str,
    lease_until: DateTime<Utc>,
    batch_size: i64,
) -> Result<Vec<OutboxRecord>> {
    // SELECT FOR UPDATE SKIP LOCKED gives each worker pod an exclusive
    // row-level lock on exactly the rows it claims; rows held by another
    // pod are skipped rather than waited on.
    let rows = sqlx::query(
        r#"
        WITH candidates AS (
            SELECT id FROM relay_admin_outbox
            WHERE state = 'pending'
              AND (lease_expires_at IS NULL OR lease_expires_at < now())
            ORDER BY created_at ASC
            LIMIT $3
            FOR UPDATE SKIP LOCKED
        )
        UPDATE relay_admin_outbox o
        SET held_by = $1, lease_expires_at = $2, updated_at = now()
        FROM candidates
        WHERE o.id = candidates.id
        RETURNING o.id, o.action_id, o.task_type, o.payload, o.state,
                  o.dedup_key, o.error_message
        "#,
    )
    .bind(worker_id)
    .bind(lease_until)
    .bind(batch_size)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(row_to_outbox).collect()
}

/// Fetch pending outbox records for a given action.
pub async fn list_pending_outbox(pool: &PgPool, action_id: Uuid) -> Result<Vec<OutboxRecord>> {
    let rows = sqlx::query(
        r#"
        SELECT id, action_id, task_type, payload, state, dedup_key, error_message
        FROM relay_admin_outbox
        WHERE action_id = $1 AND state = 'pending'
        ORDER BY created_at ASC
        "#,
    )
    .bind(action_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(row_to_outbox).collect()
}

/// New deployment-authority kick primitive: removes a member from a channel
/// without requiring the caller to be an active tenant owner/admin.
/// - `Ok(KickResult::Removed)` — member was active and is now removed.
/// - `Ok(KickResult::AlreadyGone)` — member was already absent before this action.
///   (The enforcement mutation landed; the member was simply not there.)
/// - `Err(_)` — unexpected DB error.
///
/// Never blanket-converts "not found" to success — callers must distinguish
/// `AlreadyGone` (expected idempotency) from `Removed` (new removal).
#[derive(Debug, PartialEq, Eq)]
pub enum KickResult {
    /// Member was present and is now removed.
    Removed,
    /// Member was not present (already removed or never joined).
    AlreadyGone,
}

/// Remove a member using deployment authority (no tenant owner/admin check).
///
/// Returns `KickResult::Removed` if the member was present,
/// `KickResult::AlreadyGone` if already absent.
pub async fn deploy_kick_member(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    target_pubkey: &[u8],
    actor_pubkey: &[u8],
) -> Result<KickResult> {
    // Use a direct UPDATE to avoid the tenant ownership check in channel::remove_member.
    // This is the deployment-authority primitive: no actor role check.
    let result = sqlx::query(
        r#"
        UPDATE channel_members
        SET removed_at = NOW(), removed_by = $1
        WHERE community_id = $2 AND channel_id = $3 AND pubkey = $4 AND removed_at IS NULL
        "#,
    )
    .bind(actor_pubkey)
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(target_pubkey)
    .execute(pool)
    .await?;

    if result.rows_affected() > 0 {
        Ok(KickResult::Removed)
    } else {
        Ok(KickResult::AlreadyGone)
    }
}

/// Update product_feedback status.
pub async fn update_feedback_status(pool: &PgPool, id: Uuid, status: &str) -> Result<bool> {
    let result = sqlx::query("UPDATE product_feedback SET status = $2 WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

fn row_to_action(row: sqlx::postgres::PgRow) -> Result<AdminActionRecord> {
    Ok(AdminActionRecord {
        id: row.try_get("id")?,
        report_id: row.try_get("report_id")?,
        report_community_id: row.try_get("report_community_id")?,
        request_id: row.try_get("request_id")?,
        actor_pubkey: row.try_get("actor_pubkey")?,
        actor_role: row.try_get("actor_role")?,
        action: row.try_get("action")?,
        reason: row.try_get("reason")?,
        timeout_until: row.try_get("timeout_until")?,
        state: row.try_get("state")?,
        step_marker: row.try_get("step_marker")?,
        error_message: row.try_get("error_message")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_outbox(row: sqlx::postgres::PgRow) -> Result<OutboxRecord> {
    Ok(OutboxRecord {
        id: row.try_get("id")?,
        action_id: row.try_get("action_id")?,
        task_type: row.try_get("task_type")?,
        payload: row.try_get("payload")?,
        state: row.try_get("state")?,
        dedup_key: row.try_get("dedup_key")?,
        error_message: row.try_get("error_message")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use sqlx::PgPool;
    use uuid::Uuid;

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";

    async fn setup_pool() -> PgPool {
        let url =
            std::env::var("BUZZ_TEST_DATABASE_URL").unwrap_or_else(|_| TEST_DB_URL.to_string());
        PgPool::connect(&url).await.expect("connect to test DB")
    }

    async fn make_community(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let host = format!("admin-action-test-{}.example", id.simple());
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(id)
            .bind(host)
            .execute(pool)
            .await
            .expect("insert community");
        id
    }

    async fn make_report(pool: &PgPool, community_id: Uuid) -> Uuid {
        let reporter = vec![0u8; 32];
        let target = vec![1u8; 32];
        let row = sqlx::query(
            r#"
            INSERT INTO moderation_reports (
                community_id, report_event_id, reporter_pubkey, target_kind,
                target_pubkey, report_type
            ) VALUES ($1, $2, $3, 'pubkey', $4, 'harassment')
            RETURNING id
            "#,
        )
        .bind(community_id)
        .bind(Uuid::new_v4().as_bytes().as_slice())
        .bind(&reporter)
        .bind(&target)
        .fetch_one(pool)
        .await
        .expect("insert report");
        row.try_get("id").expect("id")
    }

    fn actor() -> Vec<u8> {
        vec![2u8; 32]
    }

    // Helper: perform a full claim call.
    async fn do_claim(
        pool: &PgPool,
        community_id: Uuid,
        report_id: Uuid,
        request_id: Uuid,
    ) -> ClaimResult {
        let actor = actor();
        let target = vec![1u8; 32];
        claim_report(
            pool,
            CommunityId::from_uuid(community_id),
            report_id,
            request_id,
            &actor,
            "operator",
            "ban",
            Some("test reason"),
            None,
            "resolve:ban",
            "config",
            Some(&target),
            None,
            None,
        )
        .await
        .expect("claim_report")
    }

    // ── Racing moderators ─────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn racing_moderators_exactly_one_claim_one_conflict() {
        let pool = setup_pool().await;
        let community_id = make_community(&pool).await;
        let report_id = make_report(&pool, community_id).await;

        // Two concurrent claims with different request_ids.
        let req_a = Uuid::new_v4();
        let req_b = Uuid::new_v4();

        let (result_a, result_b) = tokio::join!(
            do_claim(&pool, community_id, report_id, req_a),
            do_claim(&pool, community_id, report_id, req_b),
        );

        // Exactly one should succeed; the other gets NotOpen.
        let (claimed, conflicted) = match (&result_a, &result_b) {
            (ClaimResult::Claimed(_), ClaimResult::NotOpen(_)) => (result_a, result_b),
            (ClaimResult::NotOpen(_), ClaimResult::Claimed(_)) => (result_b, result_a),
            other => panic!("expected one claim + one conflict, got: {other:?}"),
        };

        let action_id = match claimed {
            ClaimResult::Claimed(ref a) => a.id,
            _ => unreachable!(),
        };
        _ = action_id;
        _ = conflicted;

        // No orphan audit rows: exactly one moderation_actions row for this report.
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM moderation_actions WHERE community_id = $1")
                .bind(community_id)
                .fetch_one(&pool)
                .await
                .expect("count audit rows");
        assert_eq!(count, 1, "expected exactly one audit row");
    }

    // ── Same request_id idempotent retry ──────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn same_request_id_retry_returns_same_action_id() {
        let pool = setup_pool().await;
        let community_id = make_community(&pool).await;
        let report_id = make_report(&pool, community_id).await;

        let request_id = Uuid::new_v4();

        let first = do_claim(&pool, community_id, report_id, request_id).await;
        let first_action = match first {
            ClaimResult::Claimed(a) => a,
            other => panic!("expected Claimed, got {other:?}"),
        };

        // Retry with the same request_id.
        let second = do_claim(&pool, community_id, report_id, request_id).await;
        let second_action = match second {
            ClaimResult::AlreadyClaimed(a) => a,
            other => panic!("expected AlreadyClaimed on retry, got {other:?}"),
        };

        assert_eq!(
            first_action.id, second_action.id,
            "idempotent retry must return the same action id"
        );
    }

    // ── Different request_id against processing report → 409 ─────────────────

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn different_request_id_against_processing_report_returns_conflict() {
        let pool = setup_pool().await;
        let community_id = make_community(&pool).await;
        let report_id = make_report(&pool, community_id).await;

        // First claim succeeds.
        let _first = do_claim(&pool, community_id, report_id, Uuid::new_v4()).await;

        // Second claim with a different request_id must fail.
        let second = do_claim(&pool, community_id, report_id, Uuid::new_v4()).await;
        assert!(
            matches!(second, ClaimResult::NotOpen(_)),
            "expected NotOpen for different request_id against processing report"
        );
    }

    // ── Mutation + step_marker atomicity ──────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn cancel_after_mutation_committed_is_rejected() {
        let pool = setup_pool().await;
        let community_id = make_community(&pool).await;
        let report_id = make_report(&pool, community_id).await;

        let request_id = Uuid::new_v4();
        let claimed = match do_claim(&pool, community_id, report_id, request_id).await {
            ClaimResult::Claimed(a) => a,
            other => panic!("expected Claimed, got {other:?}"),
        };
        let action_id = claimed.id;

        // Advance to enforcing.
        let advanced = begin_enforcing(&pool, action_id)
            .await
            .expect("begin_enforcing");
        assert!(advanced);

        // Commit the mutation step marker.
        let committed = commit_mutation_step(&pool, action_id)
            .await
            .expect("commit_mutation_step");
        assert!(committed);

        // Attempt to cancel — must fail because step_marker is set.
        let cancelled = cancel_action(
            &pool,
            action_id,
            CommunityId::from_uuid(community_id),
            report_id,
        )
        .await
        .expect("cancel_action");
        assert!(
            !cancelled,
            "cancel after mutation_committed must be rejected"
        );
    }

    // ── Crash re-drive: step_marker skips the mutation ────────────────────────

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn crash_redrive_with_mutation_committed_skips_to_finalization() {
        let pool = setup_pool().await;
        let community_id = make_community(&pool).await;
        let report_id = make_report(&pool, community_id).await;

        let request_id = Uuid::new_v4();
        let claimed = match do_claim(&pool, community_id, report_id, request_id).await {
            ClaimResult::Claimed(a) => a,
            other => panic!("expected Claimed, got {other:?}"),
        };
        let action_id = claimed.id;

        // Simulate: process advanced, mutation committed, crash before finalization.
        let _ = begin_enforcing(&pool, action_id)
            .await
            .expect("begin_enforcing");
        let _ = commit_mutation_step(&pool, action_id)
            .await
            .expect("commit_mutation_step");

        // Re-load the record (simulates crash recovery).
        let reloaded = get_action(&pool, action_id)
            .await
            .expect("get_action")
            .expect("action exists");

        // step_marker is set — re-drive should skip mutation and go to finalize.
        assert_eq!(reloaded.step_marker.as_deref(), Some("mutation_committed"));

        // Finalize succeeds (proves the re-drive can transition from the persisted marker).
        let actor = actor();
        let finalized = finalize_success(
            &pool,
            action_id,
            CommunityId::from_uuid(community_id),
            report_id,
            "resolved",
            &actor,
        )
        .await
        .expect("finalize_success");
        assert!(
            finalized,
            "finalize_success must succeed from mutation_committed state"
        );

        // Report must be resolved.
        let row: Option<String> =
            sqlx::query_scalar("SELECT status FROM moderation_reports WHERE id = $1")
                .bind(report_id)
                .fetch_optional(&pool)
                .await
                .expect("fetch report");
        assert_eq!(row.as_deref(), Some("resolved"));
    }

    // ── Decision-only atomicity: no orphan audit row on concurrent close ───────

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn decision_only_concurrent_close_no_orphan_audit() {
        let pool = setup_pool().await;
        let community_id = make_community(&pool).await;
        let report_id = make_report(&pool, community_id).await;
        let actor = actor();
        let target = vec![1u8; 32];
        let cid = CommunityId::from_uuid(community_id);

        // First close succeeds.
        let first = resolve_report_decision_atomic(
            &pool,
            cid,
            report_id,
            "dismissed",
            "dismiss_report",
            &actor,
            "config",
            Some(&target),
            None,
            None,
            None,
        )
        .await
        .expect("first close");
        assert!(first, "first close must succeed");

        // Concurrent close on already-closed report must fail.
        let second = resolve_report_decision_atomic(
            &pool,
            cid,
            report_id,
            "dismissed",
            "dismiss_report",
            &actor,
            "config",
            Some(&target),
            None,
            None,
            None,
        )
        .await
        .expect("second close");
        assert!(!second, "second close on non-open report must fail");

        // Exactly one audit row.
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM moderation_actions WHERE community_id = $1")
                .bind(community_id)
                .fetch_one(&pool)
                .await
                .expect("count audit rows");
        assert_eq!(count, 1, "no orphan audit row on concurrent close");
    }

    // ── Outbox in claim transaction ────────────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn claim_transaction_inserts_outbox_rows() {
        let pool = setup_pool().await;
        let community_id = make_community(&pool).await;
        let report_id = make_report(&pool, community_id).await;

        let request_id = Uuid::new_v4();
        let claimed = match do_claim(&pool, community_id, report_id, request_id).await {
            ClaimResult::Claimed(a) => a,
            other => panic!("expected Claimed, got {other:?}"),
        };
        let action_id = claimed.id;

        // At least a reporter_notice outbox row must exist immediately after claim.
        let rows = list_pending_outbox(&pool, action_id)
            .await
            .expect("list_pending_outbox");

        // ban action always gets a reporter_notice row.
        assert!(
            rows.iter().any(|r| r.task_type == "reporter_notice"),
            "claim must insert reporter_notice outbox row; got: {rows:?}"
        );
    }

    // ── Finalize fences: requires step_marker + active_action_id ─────────────

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn finalize_without_step_marker_is_rejected() {
        let pool = setup_pool().await;
        let community_id = make_community(&pool).await;
        let report_id = make_report(&pool, community_id).await;

        let request_id = Uuid::new_v4();
        let claimed = match do_claim(&pool, community_id, report_id, request_id).await {
            ClaimResult::Claimed(a) => a,
            other => panic!("expected Claimed, got {other:?}"),
        };
        let action_id = claimed.id;

        let _ = begin_enforcing(&pool, action_id)
            .await
            .expect("begin_enforcing");

        // Attempt finalize WITHOUT committing step_marker — must fail.
        let actor = actor();
        let finalized = finalize_success(
            &pool,
            action_id,
            CommunityId::from_uuid(community_id),
            report_id,
            "resolved",
            &actor,
        )
        .await
        .expect("finalize_success call");
        assert!(
            !finalized,
            "finalize_success must be rejected when step_marker is NULL"
        );
    }

    // ── Deploy kick member distinguishes Removed vs AlreadyGone ──────────────

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn deploy_kick_member_removed_vs_already_gone() {
        let pool = setup_pool().await;
        let community_id = make_community(&pool).await;
        let actor = actor();
        let target = vec![3u8; 32];

        // Create a channel and add the target as a member.
        let channel_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO channels (id, community_id, name, channel_type, visibility, created_by)
            VALUES ($1, $2, 'test', 'public_group', 'public', $3)
            "#,
        )
        .bind(channel_id)
        .bind(community_id)
        .bind(&actor)
        .execute(&pool)
        .await
        .expect("create channel");
        sqlx::query(
            "INSERT INTO channel_members (community_id, channel_id, pubkey, role) VALUES ($1, $2, $3, 'member')",
        )
        .bind(community_id)
        .bind(channel_id)
        .bind(&target)
        .execute(&pool)
        .await
        .expect("add member");

        // First kick: member is present → Removed.
        let r1 = deploy_kick_member(
            &pool,
            CommunityId::from_uuid(community_id),
            channel_id,
            &target,
            &actor,
        )
        .await
        .expect("first kick");
        assert_eq!(r1, KickResult::Removed, "first kick must return Removed");

        // Second kick: member is gone → AlreadyGone.
        let r2 = deploy_kick_member(
            &pool,
            CommunityId::from_uuid(community_id),
            channel_id,
            &target,
            &actor,
        )
        .await
        .expect("second kick");
        assert_eq!(
            r2,
            KickResult::AlreadyGone,
            "second kick must return AlreadyGone"
        );
    }
}
