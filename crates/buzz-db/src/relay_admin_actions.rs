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
/// Must be called after mutation_committed step. Returns false if action not in expected state.
pub async fn finalize_success(
    pool: &PgPool,
    action_id: Uuid,
    community_id: CommunityId,
    report_id: Uuid,
    terminal_status: &str,
    actor_pubkey: &[u8],
) -> Result<bool> {
    let mut tx = pool.begin().await?;

    let updated_action = sqlx::query(
        r#"
        UPDATE relay_admin_actions
        SET state = 'succeeded', step_marker = 'artifacts_done', updated_at = now()
        WHERE id = $1 AND state = 'enforcing'
        "#,
    )
    .bind(action_id)
    .execute(&mut *tx)
    .await?;

    if updated_action.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    // Transition report to terminal status.
    sqlx::query(
        r#"
        UPDATE moderation_reports
        SET status = $3, resolved_by = $4, resolved_at = now(),
            active_action_id = NULL
        WHERE community_id = $1 AND id = $2 AND status = 'processing'
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(report_id)
    .bind(terminal_status)
    .bind(actor_pubkey)
    .execute(&mut *tx)
    .await?;

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
