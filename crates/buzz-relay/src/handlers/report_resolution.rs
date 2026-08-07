//! Report-resolution orchestrations for the HTTP admin API (Phase 2).
//!
//! Two transport-independent orchestration functions:
//!
//! - [`resolve_report_decision_only`] — HTTP `dismiss`/`escalate` and 9044
//!   community-moderation. Atomically CASes report to terminal status with
//!   a linked decision audit row in one transaction.
//!
//! - [`resolve_report_with_enforcement`] — HTTP `delete`/`kick`/`ban`/`timeout`.
//!   Claims the report (`open → processing`), runs enforcement, finalizes.
//!
//! ## Adapter-specific status semantics
//!
//! HTTP derives terminal status from action: `dismiss`→`dismissed`,
//! `escalate`→`escalated`, enforcement→`resolved`.
//!
//! 9044 preserves its signed `status` field exactly (caller passes it).
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
use buzz_db::moderation::NewAction;
use buzz_db::relay_admin_actions::{AdminActionRecord, ClaimResult};

use crate::handlers::moderation_notices::{send_moderation_notice, ModerationNotice};
use crate::handlers::side_effects::emit_system_message;
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
    let valid = match (action, target_kind) {
        ("delete" | "kick" | "ban" | "timeout" | "dismiss" | "escalate", "event") => true,
        ("ban" | "timeout" | "dismiss" | "escalate", "pubkey") => true,
        ("dismiss" | "escalate", "blob") => true,
        _ => false,
    };
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
/// Writes the decision audit row + CAS report to `terminal_status` in one
/// transaction. Reporter notice is best-effort.
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

    // Write audit row.
    let action_id = state
        .db
        .insert_moderation_action(
            community_id,
            NewAction {
                actor_pubkey,
                action: audit_action,
                target_pubkey,
                target_event_id,
                channel_id,
                reason_code: None,
                public_reason: reason,
                private_reason: None,
                matched_principal: None,
                actor_authority: Some(actor_authority),
            },
        )
        .await
        .map_err(ResolutionError::from)?;

    // CAS report to terminal status.
    let resolved = state
        .db
        .resolve_moderation_report(
            community_id,
            report_id,
            terminal_status,
            actor_pubkey,
            Some(action_id),
        )
        .await
        .map_err(ResolutionError::from)?;

    if !resolved {
        return Err(ResolutionError::NotOpen("concurrent_close".to_string()));
    }

    // Best-effort reporter notice.
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
/// For HTTP `delete`/`kick`/`ban`/`timeout`. Claims report via CAS
/// (`open → processing`), runs enforcement, finalizes to `resolved`.
///
/// The `tenant` is constructed from the report's community provenance.
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

    // Derive target bytes from the report row.
    let (target_pubkey_opt, target_event_id_opt) =
        decode_report_target(&report.report.target_kind, &report.report.target)?;

    let audit_action = enforcement_audit_action(action);

    // Claim: CAS open → processing.
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
    action_record: &AdminActionRecord,
) -> Result<EnforcementResolved, ResolutionError> {
    let action_id = action_record.id;

    // Already finalized by a prior run.
    if action_record.state == "succeeded" {
        return Ok(EnforcementResolved { action_id });
    }

    // A failed action can only be retried by the caller; surface the error.
    if action_record.state == "failed" {
        return Err(ResolutionError::EnforcementFailed {
            action_id,
            error: action_record.error_message.clone().unwrap_or_default(),
        });
    }

    // Advance to enforcing if still pending.
    if action_record.state == "pending" {
        let _ = state.db.begin_enforcing_action(action_id).await;
    }

    // Run durable mutation if not already committed.
    if action_record.step_marker.is_none() {
        let result = run_enforcement_mutation(
            state,
            community_id,
            action,
            reason,
            timeout_until,
            actor_pubkey,
            target_pubkey,
            target_event_id,
            channel_id,
        )
        .await;

        match result {
            Ok(()) => {
                // Commit step marker. If this call fails, re-drive will retry
                // the mutation (idempotent) and re-commit.
                let _ = state.db.commit_action_mutation_step(action_id).await;
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
    let _ = state
        .db
        .finalize_action_success(action_id, community_id, report_id, "resolved", actor_pubkey)
        .await;

    // Best-effort artifact/notice delivery (delivery states — never reopen report).
    deliver_post_enforcement(
        state,
        tenant,
        action,
        reason,
        actor_pubkey,
        target_pubkey,
        target_event_id,
        channel_id,
        reporter_pubkey_hex,
        report_id,
        action_id,
    )
    .await;

    info!(action_id = %action_id, report_id = %report_id, action = %action, "enforcement resolved");
    Ok(EnforcementResolved { action_id })
}

async fn run_enforcement_mutation(
    state: &Arc<AppState>,
    community_id: buzz_core::tenant::CommunityId,
    action: &str,
    reason: Option<&str>,
    timeout_until: Option<DateTime<Utc>>,
    actor_pubkey: &[u8],
    target_pubkey: Option<&[u8]>,
    target_event_id: Option<&[u8]>,
    channel_id: Option<Uuid>,
) -> anyhow::Result<()> {
    match action {
        "ban" => {
            let target =
                target_pubkey.ok_or_else(|| anyhow::anyhow!("ban requires target_pubkey"))?;
            state
                .db
                .ban_community_member(community_id, target, actor_pubkey, reason, None)
                .await
                .map_err(|e| anyhow::anyhow!("ban failed: {e}"))?;
        }
        "timeout" => {
            let target =
                target_pubkey.ok_or_else(|| anyhow::anyhow!("timeout requires target_pubkey"))?;
            let until =
                timeout_until.ok_or_else(|| anyhow::anyhow!("timeout requires timeout_until"))?;
            state
                .db
                .timeout_community_member(community_id, target, actor_pubkey, until, reason)
                .await
                .map_err(|e| anyhow::anyhow!("timeout failed: {e}"))?;
        }
        "kick" => {
            let target =
                target_pubkey.ok_or_else(|| anyhow::anyhow!("kick requires target_pubkey"))?;
            let ch = channel_id.ok_or_else(|| anyhow::anyhow!("kick requires channel_id"))?;
            // KickResult::AlreadyGone is idempotent success.
            let _ = state
                .db
                .deploy_kick_member(community_id, ch, target, actor_pubkey)
                .await
                .map_err(|e| anyhow::anyhow!("kick failed: {e}"))?;
        }
        "delete" => {
            let target = target_event_id
                .ok_or_else(|| anyhow::anyhow!("delete requires target_event_id"))?;
            let meta = state
                .db
                .get_thread_metadata_by_event(community_id, target)
                .await
                .map_err(|e| anyhow::anyhow!("thread metadata lookup failed: {e}"))?;
            let parent_id = meta.as_ref().and_then(|m| m.parent_event_id.clone());
            let root_id = meta.as_ref().and_then(|m| m.root_event_id.clone());
            // false = already deleted = idempotent success.
            let _ = state
                .db
                .soft_delete_event_and_update_thread(
                    community_id,
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

/// Deliver durable artifacts and best-effort notices after enforcement committed.
/// All failures are logged and do not affect report state.
#[allow(clippy::too_many_arguments)]
async fn deliver_post_enforcement(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    action: &str,
    reason: Option<&str>,
    actor_pubkey: &[u8],
    target_pubkey: Option<&[u8]>,
    target_event_id: Option<&[u8]>,
    channel_id: Option<Uuid>,
    reporter_pubkey_hex: &str,
    report_id: Uuid,
    action_id: Uuid,
) {
    // Tombstone for delete.
    if action == "delete" {
        if let (Some(ch), Some(target_id)) = (channel_id, target_event_id) {
            let tombstone = serde_json::json!({
                "type": "message_deleted",
                "actor": hex::encode(actor_pubkey),
                "target_event_id": hex::encode(target_id),
                "action_id": action_id.to_string(),
                "reason_code": reason.unwrap_or(""),
            });
            if let Err(e) = emit_system_message(tenant, state, ch, tombstone).await {
                warn!(error = %e, action_id = %action_id, "tombstone emission failed");
            }
        }
    }

    // System message for kick.
    if action == "kick" {
        if let (Some(ch), Some(target)) = (channel_id, target_pubkey) {
            let msg = serde_json::json!({
                "type": "member_removed",
                "actor": hex::encode(actor_pubkey),
                "target": hex::encode(target),
                "action_id": action_id.to_string(),
            });
            if let Err(e) = emit_system_message(tenant, state, ch, msg).await {
                warn!(error = %e, action_id = %action_id, "kick system message failed");
            }
        }
    }

    // Reporter notice DM.
    if let Ok(reporter_bytes) = hex::decode(reporter_pubkey_hex) {
        let summary = reason
            .map(|r| r.to_string())
            .unwrap_or_else(|| "Your report was reviewed and acted on.".to_string());
        if let Err(e) = send_moderation_notice(
            tenant,
            state,
            &reporter_bytes,
            ModerationNotice::ReportResolved {
                report_id,
                status: "resolved".to_string(),
                summary,
            },
        )
        .await
        {
            warn!(error = %e, action_id = %action_id, "reporter notice failed");
        }
    }
}

/// Decode the report target hex into binary.
fn decode_report_target(
    target_kind: &str,
    target_hex: &str,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), ResolutionError> {
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
