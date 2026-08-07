//! Report-resolution orchestrations for the HTTP admin API (Phase 2).
//!
//! Two transport-independent orchestration functions:
//!
//! - [`resolve_report_decision_only`] — HTTP `dismiss`/`escalate` and 9044
//!   community-moderation. Atomically CASes report to terminal status with
//!   a linked decision audit row in **one transaction**.
//!
//! - [`resolve_report_with_enforcement`] — HTTP `delete`/`kick`/`ban`/`timeout`.
//!   Claims the report (`open → processing`) in one transaction, runs the
//!   durable enforcement mutation, commits the step marker, then enqueues
//!   artifact delivery into `relay_admin_outbox`. Delivery is driven by the
//!   outbox worker ([`crate::handlers::admin_outbox_worker`]) — **never from
//!   this request path**.
//!
//! ## Crash safety
//!
//! A crash after `mutation_committed` is committed re-drives by checking
//! `step_marker` and skipping the already-idempotent mutation. The finalization
//! transaction requires both `step_marker = 'mutation_committed'` and the
//! matching `active_action_id` on the report row.
//!
//! ## Action matrix (frozen per Plan v3/v4 §7)
//!
//! | target_kind | actions |
//! |-------------|---------|
//! | event  | delete, kick, ban, timeout, dismiss, escalate |
//! | pubkey | ban, timeout, dismiss, escalate |
//! | blob   | dismiss, escalate |

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tracing::{info, warn};
use uuid::Uuid;

use buzz_core::tenant::TenantContext;
use buzz_db::admin_moderation::AdminReportDetail;
use buzz_db::relay_admin_actions::{AdminActionRecord, ClaimResult, KickResult};

use crate::state::AppState;

/// Error returned by the resolution orchestrations.
#[derive(Debug)]
pub enum ResolutionError {
    /// The report was not found globally.
    NotFound,
    /// The report is not in `open` status. Includes current status.
    NotOpen(String),
    /// The action is not valid for this report's target kind.
    InvalidAction(String),
    /// Enforcement failed (durable mutation did not commit). Action record is
    /// left in `failed` state.
    EnforcementFailed {
        /// UUID of the action record.
        action_id: Uuid,
        /// Human-readable error from the failed enforcement step.
        error: String,
    },
    /// Internal database or infrastructure error.
    Internal(String),
}

impl From<buzz_db::DbError> for ResolutionError {
    fn from(e: buzz_db::DbError) -> Self {
        ResolutionError::Internal(e.to_string())
    }
}

/// Successful outcome of a decision-only resolution.
#[derive(Debug)]
pub struct DecisionResolved {
    /// The terminal status applied.
    pub status: String,
}

/// Successful outcome of an enforcement resolution.
#[derive(Debug)]
pub struct EnforcementResolved {
    /// The action record for the completed enforcement.
    pub action_id: Uuid,
}

/// Validate the action/target matrix and derive HTTP terminal status.
///
/// Returns `Ok(status)` where status is `"dismissed"`, `"escalated"`, or
/// `"resolved"`. Returns `Err` with a human-readable message if the combination
/// is invalid per the frozen action matrix.
pub fn http_validate_and_derive_status(
    action: &str,
    target_kind: &str,
    channel_id: Option<Uuid>,
    timeout_until: Option<DateTime<Utc>>,
) -> Result<String, String> {
    // Validate action/target matrix.
    let valid = matches!(
        (action, target_kind),
        (
            "delete" | "kick" | "ban" | "timeout" | "dismiss" | "escalate",
            "event"
        ) | ("ban" | "timeout" | "dismiss" | "escalate", "pubkey")
            | ("dismiss" | "escalate", "blob")
    );
    if !valid {
        return Err(format!(
            "action `{action}` is not valid for `{target_kind}` reports"
        ));
    }

    // kick requires channel_id from the report row.
    if action == "kick" && channel_id.is_none() {
        return Err("action `kick` requires the report to have an associated channel".to_string());
    }

    // timeout requires expiration; other actions reject it.
    if action == "timeout" && timeout_until.is_none() {
        return Err("`expiration_secs` is required for `timeout`".to_string());
    }
    if action != "timeout" && timeout_until.is_some() {
        return Err(format!(
            "`expiration_secs` is only valid for `timeout`, got `{action}`"
        ));
    }

    // Derive HTTP terminal status.
    Ok(match action {
        "dismiss" => "dismissed",
        "escalate" => "escalated",
        _ => "resolved",
    }
    .to_string())
}

/// Map enforcement action → decision audit row action string.
pub fn enforcement_audit_action(action: &str) -> &'static str {
    match action {
        "delete" => "resolve:delete",
        "kick" => "resolve:kick",
        "ban" => "resolve:ban",
        "timeout" => "resolve:timeout",
        "dismiss" => "dismiss_report",
        "escalate" => "escalate",
        _ => "resolve:delete",
    }
}

/// Atomically resolve a report without server-side enforcement.
///
/// Used by:
/// - HTTP `dismiss` and `escalate`.
/// - The 9044 community-moderation adapter (caller passes the event's signed
///   `status`; `actor_authority` = `"community"`).
///
/// Performs the CAS `open→terminal` AND the decision audit row insert in one
/// transaction via `db.resolve_report_decision_atomic`. A concurrent close
/// rolls back both — no orphan audit row. Reporter notice is best-effort
/// after commit.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_report_decision_only(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    report_id: Uuid,
    terminal_status: &str,
    audit_action: &str,
    actor_pubkey: &[u8],
    actor_authority: &str,
    target_pubkey: Option<&[u8]>,
    target_event_id: Option<&[u8]>,
    channel_id: Option<Uuid>,
    reason: Option<&str>,
    reporter_pubkey: &[u8],
) -> Result<DecisionResolved, ResolutionError> {
    let community_id = tenant.community();

    // Single-transaction CAS + audit — no orphan row on concurrent close.
    let resolved = state
        .db
        .resolve_report_decision_atomic(
            community_id,
            report_id,
            terminal_status,
            audit_action,
            actor_pubkey,
            actor_authority,
            target_pubkey,
            target_event_id,
            channel_id,
            reason,
        )
        .await
        .map_err(ResolutionError::from)?;

    if !resolved {
        return Err(ResolutionError::NotOpen("concurrent_close".to_string()));
    }

    // Best-effort reporter notice after commit.
    use crate::handlers::moderation_notices::{send_moderation_notice, ModerationNotice};
    let summary = reason
        .map(|r| r.to_string())
        .unwrap_or_else(|| match terminal_status {
            "dismissed" => "Your report was reviewed and dismissed.".to_string(),
            "escalated" => "Your report has been escalated for further review.".to_string(),
            _ => "Your report was reviewed and acted on.".to_string(),
        });
    if let Err(e) = send_moderation_notice(
        tenant,
        state,
        reporter_pubkey,
        ModerationNotice::ReportResolved {
            report_id,
            status: terminal_status.to_string(),
            summary,
        },
    )
    .await
    {
        warn!(error = %e, report_id = %report_id, "reporter notice delivery failed");
    }

    info!(report_id = %report_id, status = %terminal_status, "report resolved (decision-only)");
    Ok(DecisionResolved {
        status: terminal_status.to_string(),
    })
}

/// Resolve a report with server-side enforcement.
///
/// Claims report via CAS (`open → processing`) in one transaction, runs the
/// durable enforcement mutation, commits the step marker, then enqueues
/// outbox delivery commands. Artifact delivery never runs from this path.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_report_with_enforcement(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    report: &AdminReportDetail,
    action: &str,
    reason: Option<&str>,
    timeout_until: Option<DateTime<Utc>>,
    request_id: Uuid,
    actor_pubkey: &[u8],
    actor_role: &str,
    actor_authority: &str,
) -> Result<EnforcementResolved, ResolutionError> {
    let community_id = tenant.community();
    let report_id = report.report.id;
    let channel_id = report.report.channel_id;

    let (target_pubkey_opt, target_event_id_opt) =
        decode_report_target(&report.report.target_kind, &report.report.target)?;

    let audit_action = enforcement_audit_action(action);

    // Claim: one transaction — audit row + action record + report CAS open→processing.
    let action_record = match state
        .db
        .claim_report_for_enforcement(
            community_id,
            report_id,
            request_id,
            actor_pubkey,
            actor_role,
            action,
            reason,
            timeout_until,
            audit_action,
            actor_authority,
            target_pubkey_opt.as_deref(),
            target_event_id_opt.as_deref(),
            channel_id,
        )
        .await
        .map_err(ResolutionError::from)?
    {
        ClaimResult::Claimed(a) | ClaimResult::AlreadyClaimed(a) => a,
        ClaimResult::NotOpen(status) => return Err(ResolutionError::NotOpen(status)),
        ClaimResult::NotFound => return Err(ResolutionError::NotFound),
    };

    drive_enforcement(
        state,
        tenant,
        community_id,
        report_id,
        action,
        reason,
        timeout_until,
        actor_pubkey,
        target_pubkey_opt.as_deref(),
        target_event_id_opt.as_deref(),
        channel_id,
        &report.report.reporter_pubkey,
        &action_record,
    )
    .await
}

/// Context for the enforcement mutation — reduces argument count.
struct EnforcementCtx<'a> {
    community_id: buzz_core::tenant::CommunityId,
    action: &'a str,
    reason: Option<&'a str>,
    timeout_until: Option<DateTime<Utc>>,
    actor_pubkey: &'a [u8],
    target_pubkey: Option<&'a [u8]>,
    target_event_id: Option<&'a [u8]>,
    channel_id: Option<Uuid>,
}

/// Drive the enforcement state machine from the given action record forward to
/// completion, then enqueue outbox delivery tasks.
///
/// Uses a loop rather than recursion to advance through CAS contention without
/// boxing async futures. The loop terminates because each iteration either
/// returns or advances the action to a strictly later state (pending →
/// enforcing → succeeded/failed).
#[allow(clippy::too_many_arguments)]
async fn drive_enforcement(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    community_id: buzz_core::tenant::CommunityId,
    report_id: Uuid,
    action: &str,
    reason: Option<&str>,
    timeout_until: Option<DateTime<Utc>>,
    actor_pubkey: &[u8],
    target_pubkey: Option<&[u8]>,
    target_event_id: Option<&[u8]>,
    channel_id: Option<Uuid>,
    reporter_pubkey_hex: &str,
    initial_record: &AdminActionRecord,
) -> Result<EnforcementResolved, ResolutionError> {
    // Work on an owned copy so we can replace it when reloading.
    let mut rec = initial_record.clone();
    let action_id = rec.id;

    loop {
        // Already finalized — idempotent success.
        if rec.state == "succeeded" {
            return Ok(EnforcementResolved { action_id });
        }

        // Pre-mutation failure — surface error; caller retries with a new request_id.
        if rec.state == "failed" {
            return Err(ResolutionError::EnforcementFailed {
                action_id,
                error: rec.error_message.clone().unwrap_or_default(),
            });
        }

        // Advance to enforcing if still pending. False CAS = another driver won;
        // reload and loop — the reloaded state will be enforcing/succeeded/failed.
        if rec.state == "pending" {
            let advanced = state
                .db
                .begin_enforcing_action(action_id)
                .await
                .map_err(ResolutionError::from)?;
            if !advanced {
                rec = state
                    .db
                    .get_admin_action(action_id)
                    .await
                    .map_err(ResolutionError::from)?
                    .ok_or_else(|| {
                        ResolutionError::Internal("action disappeared after claim".to_string())
                    })?;
                continue;
            }
            // Re-read the updated record so step_marker check below is correct.
            rec = state
                .db
                .get_admin_action(action_id)
                .await
                .map_err(ResolutionError::from)?
                .ok_or_else(|| {
                    ResolutionError::Internal(
                        "action disappeared after begin_enforcing".to_string(),
                    )
                })?;
        }

        // Run mutation only if step marker is not yet committed. After a crash that
        // lands here on re-drive, step_marker is still None so the mutation runs
        // again — all mutations are idempotent (ban/timeout: upsert; kick/delete:
        // no-op if already done, except kick-AlreadyGone which is surfaced distinctly).
        if rec.step_marker.is_none() {
            let ctx = EnforcementCtx {
                community_id,
                action,
                reason,
                timeout_until,
                actor_pubkey,
                target_pubkey,
                target_event_id,
                channel_id,
            };
            match run_enforcement_mutation(state, &ctx).await {
                Ok(()) => {
                    // Commit step marker. A crash before this commit restarts here
                    // and re-runs the idempotent mutation.
                    let committed = state
                        .db
                        .commit_action_mutation_step(action_id)
                        .await
                        .map_err(ResolutionError::from)?;
                    if !committed {
                        // Lost ownership: reload and loop.
                        rec = state
                            .db
                            .get_admin_action(action_id)
                            .await
                            .map_err(ResolutionError::from)?
                            .ok_or_else(|| {
                                ResolutionError::Internal(
                                    "action disappeared after mutation".to_string(),
                                )
                            })?;
                        continue;
                    }
                }
                Err(e) => {
                    let _ = state
                        .db
                        .record_action_failure(action_id, &e.to_string())
                        .await;
                    return Err(ResolutionError::EnforcementFailed {
                        action_id,
                        error: e.to_string(),
                    });
                }
            }
        }

        // Finalize: action → succeeded, report → resolved.
        // Requires step_marker = 'mutation_committed' AND active_action_id = this action.
        let finalized = state
            .db
            .finalize_action_success(action_id, community_id, report_id, "resolved", actor_pubkey)
            .await
            .map_err(ResolutionError::from)?;

        if !finalized {
            rec = state
                .db
                .get_admin_action(action_id)
                .await
                .map_err(ResolutionError::from)?
                .ok_or_else(|| {
                    ResolutionError::Internal("action disappeared during finalization".to_string())
                })?;
            if rec.state == "succeeded" {
                return Ok(EnforcementResolved { action_id });
            }
            return Err(ResolutionError::Internal(format!(
                "finalize_success failed (state={}, step={:?})",
                rec.state, rec.step_marker
            )));
        }

        // Enqueue outbox delivery tasks. Processed by the admin outbox worker.
        // ON CONFLICT DO NOTHING makes this idempotent on re-drive.
        enqueue_delivery_tasks(
            state,
            tenant,
            action_id,
            action,
            reason,
            actor_pubkey,
            target_pubkey,
            target_event_id,
            channel_id,
            reporter_pubkey_hex,
            report_id,
        )
        .await;

        info!(action_id = %action_id, report_id = %report_id, action = %action, "enforcement resolved");
        return Ok(EnforcementResolved { action_id });
    }
}

async fn run_enforcement_mutation(
    state: &Arc<AppState>,
    ctx: &EnforcementCtx<'_>,
) -> anyhow::Result<()> {
    match ctx.action {
        "ban" => {
            let target = ctx
                .target_pubkey
                .ok_or_else(|| anyhow::anyhow!("ban requires target_pubkey"))?;
            state
                .db
                .ban_community_member(ctx.community_id, target, ctx.actor_pubkey, ctx.reason, None)
                .await
                .map_err(|e| anyhow::anyhow!("ban failed: {e}"))?;
        }
        "timeout" => {
            let target = ctx
                .target_pubkey
                .ok_or_else(|| anyhow::anyhow!("timeout requires target_pubkey"))?;
            let until = ctx
                .timeout_until
                .ok_or_else(|| anyhow::anyhow!("timeout requires timeout_until"))?;
            state
                .db
                .timeout_community_member(
                    ctx.community_id,
                    target,
                    ctx.actor_pubkey,
                    until,
                    ctx.reason,
                )
                .await
                .map_err(|e| anyhow::anyhow!("timeout failed: {e}"))?;
        }
        "kick" => {
            let target = ctx
                .target_pubkey
                .ok_or_else(|| anyhow::anyhow!("kick requires target_pubkey"))?;
            let ch = ctx
                .channel_id
                .ok_or_else(|| anyhow::anyhow!("kick requires channel_id"))?;
            // Distinguish provenance: AlreadyGone = target was absent BEFORE this
            // action. That is not successful enforcement — surface it distinctly
            // so the operator knows vs. Removed (new removal this action performed).
            match state
                .db
                .deploy_kick_member(ctx.community_id, ch, target, ctx.actor_pubkey)
                .await
                .map_err(|e| anyhow::anyhow!("kick failed: {e}"))?
            {
                KickResult::Removed => {}
                KickResult::AlreadyGone => {
                    return Err(anyhow::anyhow!(
                        "kick target was already absent before this action"
                    ))
                }
            }
        }
        "delete" => {
            let target = ctx
                .target_event_id
                .ok_or_else(|| anyhow::anyhow!("delete requires target_event_id"))?;
            let meta = state
                .db
                .get_thread_metadata_by_event(ctx.community_id, target)
                .await
                .map_err(|e| anyhow::anyhow!("thread metadata lookup failed: {e}"))?;
            let parent_id = meta.as_ref().and_then(|m| m.parent_event_id.clone());
            let root_id = meta.as_ref().and_then(|m| m.root_event_id.clone());
            // false = already deleted = idempotent success.
            let _ = state
                .db
                .soft_delete_event_and_update_thread(
                    ctx.community_id,
                    target,
                    parent_id.as_deref(),
                    root_id.as_deref(),
                )
                .await
                .map_err(|e| anyhow::anyhow!("soft_delete failed: {e}"))?;
        }
        other => return Err(anyhow::anyhow!("unexpected enforcement action: {other}")),
    }
    Ok(())
}

/// Enqueue outbox delivery tasks. Processed by admin outbox worker, not this path.
/// All tasks use `dedup_key` so re-enqueue on re-drive is idempotent.
#[allow(clippy::too_many_arguments)]
async fn enqueue_delivery_tasks(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    action_id: Uuid,
    action: &str,
    reason: Option<&str>,
    actor_pubkey: &[u8],
    target_pubkey: Option<&[u8]>,
    target_event_id: Option<&[u8]>,
    channel_id: Option<Uuid>,
    reporter_pubkey_hex: &str,
    report_id: Uuid,
) {
    if action == "delete" {
        if let (Some(ch), Some(target_id)) = (channel_id, target_event_id) {
            let payload = serde_json::json!({
                "community_id": tenant.community().to_string(),
                "channel_id": ch.to_string(),
                "actor": hex::encode(actor_pubkey),
                "target_event_id": hex::encode(target_id),
                "action_id": action_id.to_string(),
                "reason_code": reason.unwrap_or(""),
            });
            if let Err(e) = state
                .db
                .enqueue_admin_outbox(
                    action_id,
                    "tombstone",
                    payload,
                    &format!("tombstone:{action_id}"),
                )
                .await
            {
                warn!(error = %e, action_id = %action_id, "tombstone enqueue failed");
            }
        }
    }

    if action == "kick" {
        if let (Some(ch), Some(target)) = (channel_id, target_pubkey) {
            let payload = serde_json::json!({
                "community_id": tenant.community().to_string(),
                "channel_id": ch.to_string(),
                "actor": hex::encode(actor_pubkey),
                "target": hex::encode(target),
                "action_id": action_id.to_string(),
            });
            if let Err(e) = state
                .db
                .enqueue_admin_outbox(
                    action_id,
                    "system_message",
                    payload,
                    &format!("system_message:{action_id}"),
                )
                .await
            {
                warn!(error = %e, action_id = %action_id, "kick system message enqueue failed");
            }
        }
    }

    let summary = reason
        .map(|r| r.to_string())
        .unwrap_or_else(|| "Your report was reviewed and acted on.".to_string());
    let payload = serde_json::json!({
        "reporter_pubkey_hex": reporter_pubkey_hex,
        "report_id": report_id.to_string(),
        "action_id": action_id.to_string(),
        "community_id": tenant.community().to_string(),
        "summary": summary,
    });
    if let Err(e) = state
        .db
        .enqueue_admin_outbox(
            action_id,
            "reporter_notice",
            payload,
            &format!("reporter_notice:{action_id}"),
        )
        .await
    {
        warn!(error = %e, action_id = %action_id, "reporter notice enqueue failed");
    }
}

/// Decode the report target hex into binary.
type TargetPair = (Option<Vec<u8>>, Option<Vec<u8>>);

fn decode_report_target(
    target_kind: &str,
    target_hex: &str,
) -> Result<TargetPair, ResolutionError> {
    match target_kind {
        "event" => {
            let bytes = hex::decode(target_hex)
                .map_err(|_| ResolutionError::Internal("invalid event target hex".to_string()))?;
            Ok((None, Some(bytes)))
        }
        "pubkey" => {
            let bytes = hex::decode(target_hex)
                .map_err(|_| ResolutionError::Internal("invalid pubkey target hex".to_string()))?;
            Ok((Some(bytes), None))
        }
        "blob" => Ok((None, None)),
        other => Err(ResolutionError::Internal(format!(
            "unknown target_kind: {other}"
        ))),
    }
}
