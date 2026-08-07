//! Private deployment moderation API.
//!
//! Read routes are available in all auth modes (token, disabled, nip98).
//! Mutation and staffing routes require `BUZZ_ADMIN_AUTH=nip98`.

mod auth;
mod error;

use std::sync::Arc;

use auth::{authorize, require_mutation_principal, require_operator, AdminRole, AdminSource};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Uri},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, patch, put},
    Json, Router,
};
use chrono::{DateTime, Utc};
use error::ApiError;
use serde::{Deserialize, Serialize};
use tower_http::limit::RequestBodyLimitLayer;
use uuid::Uuid;

pub(crate) fn is_admin_host(state: &crate::state::AppState, headers: &HeaderMap) -> bool {
    auth::is_admin_host(state, headers)
}

/// Build the deployment-admin routes.
///
/// Read routes are available in all auth modes.
/// Mutation routes (/reports/{id}/resolve, /feedback/{id}) and staffing routes
/// (/operators) require BUZZ_ADMIN_AUTH=nip98.
pub fn router(state: Arc<crate::state::AppState>) -> Router {
    Router::new()
        .route("/probe", get(probe))
        .route("/reports", get(reports))
        .route("/reports/{id}", get(report_detail))
        .route("/reports/{id}/resolve", axum::routing::post(resolve_report))
        .route("/feedback", get(feedback))
        .route("/feedback/{id}", get(feedback_detail))
        .route("/feedback/{id}", patch(update_feedback_status))
        .route(
            "/feedback/{id}/attachments/{sha256}",
            get(feedback_attachment),
        )
        .route("/operators", get(list_operators))
        .route("/operators/{pubkey}", put(upsert_operator))
        .route("/operators/{pubkey}", delete(delete_operator))
        .layer(middleware::from_fn(security_headers))
        // Mutation routes carry a JSON body (max ~4 KB); read-only routes have no body.
        .layer(RequestBodyLimitLayer::new(4096))
        .with_state(state)
}

async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    response
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportQuery {
    community_id: Option<Uuid>,
    status: Option<String>,
    report_type: Option<String>,
    target_kind: Option<String>,
    before: Option<DateTime<Utc>>,
    after: Option<DateTime<Utc>>,
    limit: Option<i64>,
}

fn limit(value: Option<i64>) -> Result<i64, ApiError> {
    match value.unwrap_or(50) {
        value @ 1..=200 => Ok(value),
        _ => Err(ApiError::bad_request(
            "invalid_limit",
            "limit must be between 1 and 200",
        )),
    }
}

fn validate(value: Option<&str>, allowed: &[&str], code: &'static str) -> Result<(), ApiError> {
    if value.is_some_and(|value| !allowed.contains(&value)) {
        Err(ApiError::bad_request(code, "filter is invalid"))
    } else {
        Ok(())
    }
}

/// Probe response — allows the desktop to discover the auth mode, role, and
/// available capabilities before rendering the console UI.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbeResponse {
    /// `"ok"`
    status: &'static str,
    /// Auth mode: `"nip98"` | `"token"` | `"disabled"`.
    auth_mode: &'static str,
    /// Role of the authenticated principal (`"operator"` | `"moderator"`),
    /// or `null` in token/disabled modes (no named principal).
    role: Option<&'static str>,
    /// How the role was established (`"config"` | `"owner_fallback"` | `"db"`),
    /// or `null` when role is null.
    source: Option<&'static str>,
    /// Whether mutation (report-action) endpoints are available.
    can_act: bool,
    /// Whether staffing endpoints (/operators) are available.
    can_staff: bool,
}

async fn probe(
    State(state): State<Arc<crate::state::AppState>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<ProbeResponse>, ApiError> {
    let principal = authorize(
        &state,
        &headers,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |pq| pq.as_str()),
        "GET",
        None,
    )
    .await?;

    let (auth_mode, role, source, can_act, can_staff) = match &state.config.admin {
        Some(config) => match &config.auth {
            crate::config::AdminAuth::Token(_) => ("token", None, None, false, false),
            crate::config::AdminAuth::Disabled => ("disabled", None, None, false, false),
            crate::config::AdminAuth::Nip98 => {
                // principal is Some in nip98 mode (authorize returns Ok(Some(_)))
                let p = principal
                    .as_ref()
                    .expect("nip98 mode always resolves principal");
                let role_str = match p.role {
                    AdminRole::Operator => "operator",
                    AdminRole::Moderator => "moderator",
                };
                let source_str = match p.source {
                    AdminSource::Config => "config",
                    AdminSource::OwnerFallback => "owner_fallback",
                    AdminSource::Db => "db",
                };
                let can_act = true; // both Operator and Moderator can act
                let can_staff = p.role == AdminRole::Operator;
                (
                    "nip98",
                    Some(role_str),
                    Some(source_str),
                    can_act,
                    can_staff,
                )
            }
        },
        None => return Err(ApiError::not_found()),
    };

    Ok(Json(ProbeResponse {
        status: "ok",
        auth_mode,
        role,
        source,
        can_act,
        can_staff,
    }))
}

async fn reports(
    State(state): State<Arc<crate::state::AppState>>,
    uri: Uri,
    headers: HeaderMap,
    Query(query): Query<ReportQuery>,
) -> Result<Json<Vec<buzz_db::admin_moderation::AdminReport>>, ApiError> {
    authorize(
        &state,
        &headers,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |pq| pq.as_str()),
        "GET",
        None,
    )
    .await?;
    validate(
        query.status.as_deref(),
        &["open", "resolved", "dismissed", "escalated"],
        "invalid_status",
    )?;
    validate(
        query.target_kind.as_deref(),
        &["event", "pubkey", "blob"],
        "invalid_target_kind",
    )?;
    let items = state
        .db
        .admin_list_reports(
            query.community_id,
            query.status.as_deref(),
            query.report_type.as_deref(),
            query.target_kind.as_deref(),
            query.after,
            query.before,
            None,
            limit(query.limit)?,
        )
        .await?;
    Ok(Json(items))
}

async fn report_detail(
    State(state): State<Arc<crate::state::AppState>>,
    uri: Uri,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<buzz_db::admin_moderation::AdminReportDetail>, ApiError> {
    authorize(
        &state,
        &headers,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |pq| pq.as_str()),
        "GET",
        None,
    )
    .await?;
    state
        .db
        .admin_get_report(id)
        .await?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FeedbackSummary {
    id: Uuid,
    community_id: Uuid,
    community_host: String,
    submitter_pubkey: String,
    category: Option<String>,
    body_summary: String,
    received_at: DateTime<Utc>,
}

async fn feedback(
    State(state): State<Arc<crate::state::AppState>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<Vec<FeedbackSummary>>, ApiError> {
    authorize(
        &state,
        &headers,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |pq| pq.as_str()),
        "GET",
        None,
    )
    .await?;
    let items = state
        .db
        .admin_list_feedback(100)
        .await?
        .into_iter()
        .map(|item| {
            let body_summary = summarize_body(&item.body, &item.tags);
            FeedbackSummary {
                id: item.id,
                community_id: item.community_id,
                community_host: item.community_host,
                submitter_pubkey: item.submitter_pubkey,
                category: item.category,
                body_summary,
                received_at: item.received_at,
            }
        })
        .collect();
    Ok(Json(items))
}

async fn feedback_detail(
    State(state): State<Arc<crate::state::AppState>>,
    uri: Uri,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<buzz_db::admin_moderation::AdminFeedback>, ApiError> {
    authorize(
        &state,
        &headers,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |pq| pq.as_str()),
        "GET",
        None,
    )
    .await?;
    state
        .db
        .admin_get_feedback(id)
        .await?
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

async fn feedback_attachment(
    State(state): State<Arc<crate::state::AppState>>,
    uri: Uri,
    headers: HeaderMap,
    Path((id, sha256)): Path<(Uuid, String)>,
) -> Result<Response, ApiError> {
    authorize(
        &state,
        &headers,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |pq| pq.as_str()),
        "GET",
        None,
    )
    .await?;
    if !is_sha256(&sha256) {
        return Err(ApiError::not_found());
    }

    let feedback = state
        .db
        .admin_get_feedback(id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if !feedback_references_hash(&feedback.tags, &feedback.community_host, &sha256) {
        return Err(ApiError::not_found());
    }

    // Resolve the tenant from server-owned feedback provenance, then assert the
    // resolved row still agrees with the feedback FK. Client input never names
    // a community, host, object key, extension, or upstream URL.
    let tenant = crate::tenant::bind_community(&state.db, &feedback.community_host)
        .await
        .map_err(|_| ApiError::not_found())?;
    if tenant.community().as_uuid() != &feedback.community_id {
        tracing::warn!(
            feedback_id = %feedback.id,
            feedback_community_id = %feedback.community_id,
            resolved_community_id = %tenant.community(),
            "admin feedback attachment tenant provenance mismatch"
        );
        return Err(ApiError::not_found());
    }

    let response = crate::api::media::serve_blob_for_tenant(&state, &tenant, &sha256, &headers)
        .await
        .map_err(|error| match error {
            buzz_media::MediaError::NotFound => ApiError::not_found(),
            _ => ApiError::internal(),
        })?;
    tracing::info!(
        feedback_id = %feedback.id,
        community_id = %feedback.community_id,
        attachment_sha256 = %sha256,
        "admin feedback attachment read"
    );
    Ok(response)
}

// ── Phase 2: Report resolution ────────────────────────────────────────────────

/// Request body for POST /reports/{id}/resolve.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResolveReportBody {
    /// Action to take: delete | kick | ban | timeout | dismiss | escalate.
    action: String,
    /// Client-generated idempotency key. Required for enforcement actions.
    request_id: Option<Uuid>,
    /// Seconds until timeout expiry. Required for `timeout`, rejected otherwise.
    expiration_secs: Option<u64>,
    /// Optional operator reason.
    reason: Option<String>,
}

/// POST /reports/{id}/resolve
///
/// Requires nip98 auth. Both Operator and Moderator may act.
///
/// - dismiss/escalate: decision-only (no enforcement), runs in-transaction.
/// - delete/kick/ban/timeout: server-side enforcement state machine.
async fn resolve_report(
    State(state): State<Arc<crate::state::AppState>>,
    uri: Uri,
    headers: HeaderMap,
    Path(report_id): Path<Uuid>,
    body_bytes: Bytes,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    use crate::handlers::report_resolution::{
        enforcement_audit_action, http_validate_and_derive_status, resolve_report_decision_only,
        resolve_report_with_enforcement, ResolutionError,
    };

    let principal_opt = authorize(
        &state,
        &headers,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |pq| pq.as_str()),
        "POST",
        Some(&body_bytes),
    )
    .await?;

    let principal = require_mutation_principal(principal_opt)?;

    let body: ResolveReportBody = serde_json::from_slice(&body_bytes)
        .map_err(|_e| ApiError::bad_request("invalid_body", "invalid JSON body"))?;

    // Validate action name.
    let valid_actions = ["delete", "kick", "ban", "timeout", "dismiss", "escalate"];
    if !valid_actions.contains(&body.action.as_str()) {
        return Err(ApiError::bad_request("invalid_action", "unknown action"));
    }

    // Load report globally to derive target provenance.
    let report_detail = state
        .db
        .admin_get_report(report_id)
        .await?
        .ok_or_else(ApiError::not_found)?;

    // Compute timeout_until if needed.
    let timeout_until: Option<DateTime<Utc>> = match body.expiration_secs {
        Some(secs) => Some(Utc::now() + chrono::Duration::seconds(secs as i64)),
        None => None,
    };

    // Validate action/target matrix and derive HTTP terminal status.
    let _derived_status = http_validate_and_derive_status(
        &body.action,
        &report_detail.report.target_kind,
        report_detail.report.channel_id,
        timeout_until,
    )
    .map_err(|msg| ApiError::bad_request("invalid_action_for_target", &msg))?;

    let actor_pubkey: Vec<u8> = principal.pubkey.to_vec();
    let actor_role_str = match principal.role {
        AdminRole::Operator => "operator",
        AdminRole::Moderator => "moderator",
    };
    let actor_authority = match principal.role {
        AdminRole::Operator => "relay_operator",
        AdminRole::Moderator => "relay_moderator",
    };

    // Bind tenant from server-owned report provenance (never from client input).
    let tenant = crate::tenant::bind_community(&state.db, &report_detail.report.community_host)
        .await
        .map_err(|_| ApiError::internal())?;

    match body.action.as_str() {
        "dismiss" | "escalate" => {
            // Decision-only: CAS open→terminal + audit row in one transaction.
            let audit_action = enforcement_audit_action(&body.action);
            let terminal_status = if body.action == "escalate" {
                "escalated"
            } else {
                "dismissed"
            };

            // Derive target fields from the report row.
            let (target_pubkey_bytes, target_event_id_bytes) = decode_report_target_hex(
                &report_detail.report.target_kind,
                &report_detail.report.target,
            )
            .map_err(|_| ApiError::internal())?;

            let reporter_bytes = hex::decode(&report_detail.report.reporter_pubkey)
                .map_err(|_| ApiError::internal())?;

            resolve_report_decision_only(
                &state,
                &tenant,
                report_id,
                terminal_status,
                audit_action,
                &actor_pubkey,
                actor_authority,
                target_pubkey_bytes.as_deref(),
                target_event_id_bytes.as_deref(),
                report_detail.report.channel_id,
                body.reason.as_deref(),
                &reporter_bytes,
            )
            .await
            .map_err(|e| match e {
                ResolutionError::NotFound => ApiError::not_found(),
                ResolutionError::NotOpen(status) => {
                    ApiError::conflict(&format!("report is not open (current status: {status})"))
                }
                ResolutionError::InvalidAction(msg) => {
                    ApiError::bad_request("invalid_action", &msg)
                }
                _ => ApiError::internal(),
            })?;

            Ok(axum::http::Response::builder()
                .status(200)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"status": terminal_status}).to_string(),
                ))
                .unwrap())
        }
        _ => {
            // Enforcement actions require a request_id.
            let request_id = body.request_id.ok_or_else(|| {
                ApiError::bad_request(
                    "missing_request_id",
                    "requestId is required for enforcement actions",
                )
            })?;

            let result = resolve_report_with_enforcement(
                &state,
                &tenant,
                &report_detail,
                &body.action,
                body.reason.as_deref(),
                timeout_until,
                request_id,
                &actor_pubkey,
                actor_role_str,
                actor_authority,
            )
            .await
            .map_err(|e| match e {
                ResolutionError::NotFound => ApiError::not_found(),
                ResolutionError::NotOpen(status) => ApiError::conflict(&format!(
                    "report is not open (current status: {status})"
                )),
                ResolutionError::InvalidAction(msg) => ApiError::bad_request("invalid_action", &msg),
                ResolutionError::EnforcementFailed { action_id, error } => {
                    ApiError::unprocessable(&format!(
                        "enforcement failed (action_id={action_id}): {error}"
                    ))
                }
                ResolutionError::Internal(msg) => {
                    tracing::error!(report_id = %report_id, error = %msg, "resolve_report internal error");
                    ApiError::internal()
                }
            })?;

            Ok(axum::http::Response::builder()
                .status(200)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "status": "resolved",
                        "actionId": result.action_id.to_string(),
                    })
                    .to_string(),
                ))
                .unwrap())
        }
    }
}

/// PATCH /feedback/{id}
///
/// Update product_feedback status. Requires nip98 auth.
async fn update_feedback_status(
    State(state): State<Arc<crate::state::AppState>>,
    uri: Uri,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body_bytes: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal_opt = authorize(
        &state,
        &headers,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |pq| pq.as_str()),
        "PATCH",
        Some(&body_bytes),
    )
    .await?;

    let _principal = require_mutation_principal(principal_opt)?;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct FeedbackStatusBody {
        status: String,
    }

    let body: FeedbackStatusBody = serde_json::from_slice(&body_bytes)
        .map_err(|_| ApiError::bad_request("invalid_body", "invalid JSON body"))?;

    let allowed = ["new", "reviewed", "archived"];
    if !allowed.contains(&body.status.as_str()) {
        return Err(ApiError::bad_request(
            "invalid_status",
            "status must be new|reviewed|archived",
        ));
    }

    let updated = state.db.update_feedback_status(id, &body.status).await?;
    if !updated {
        return Err(ApiError::not_found());
    }

    Ok(Json(serde_json::json!({"status": body.status})))
}

// ── Phase 2: Staffing endpoints ───────────────────────────────────────────────

/// Effective principal entry returned by GET /operators.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperatorEntry {
    /// Hex-encoded pubkey.
    pubkey: String,
    /// Effective role: `"operator"` | `"moderator"`.
    effective_role: String,
    /// Sources contributing to this principal's grant.
    sources: Vec<String>,
}

/// GET /operators
///
/// List all effective principals (union of config and DB). Source-aware.
/// Requires nip98 auth + Operator role.
async fn list_operators(
    State(state): State<Arc<crate::state::AppState>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<Vec<OperatorEntry>>, ApiError> {
    let principal_opt = authorize(
        &state,
        &headers,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |pq| pq.as_str()),
        "GET",
        None,
    )
    .await?;

    let principal = require_mutation_principal(principal_opt)?;
    require_operator(&principal)?;

    let config = state
        .config
        .admin
        .as_ref()
        .ok_or_else(ApiError::not_found)?;
    let _ = config; // admin config present — we already passed auth

    // Build effective principal set.
    let mut entries: Vec<OperatorEntry> = vec![];

    // 1. Config-backed operators (RELAY_OPERATOR_PUBKEYS).
    for hex_key in &state.config.relay_operator_pubkeys {
        entries.push(OperatorEntry {
            pubkey: hex_key.clone(),
            effective_role: "operator".to_string(),
            sources: vec!["config".to_string()],
        });
    }

    // 2. Owner fallback B: implicit operator when RELAY_OPERATOR_PUBKEYS is empty.
    if state.config.relay_operator_pubkeys.is_empty() {
        if let Some(owner_hex) = &state.config.relay_owner_pubkey {
            entries.push(OperatorEntry {
                pubkey: owner_hex.clone(),
                effective_role: "operator".to_string(),
                sources: vec!["owner_fallback".to_string()],
            });
        }
    }

    // 3. DB rows. Config outranks DB: if a DB entry is already covered by config,
    //    add "db" to its sources rather than creating a duplicate.
    let db_rows = state.db.list_relay_operators().await?;
    let config_pubkeys: std::collections::HashSet<&str> = state
        .config
        .relay_operator_pubkeys
        .iter()
        .map(String::as_str)
        .collect();

    for row in db_rows {
        let hex = hex::encode(&row.pubkey);
        if config_pubkeys.contains(hex.as_str()) {
            // Config already grants Operator; annotate sources but don't demote.
            if let Some(e) = entries.iter_mut().find(|e| e.pubkey == hex) {
                e.sources.push("db".to_string());
            }
        } else {
            entries.push(OperatorEntry {
                pubkey: hex,
                effective_role: row.role.clone(),
                sources: vec!["db".to_string()],
            });
        }
    }

    Ok(Json(entries))
}

/// Request body for PUT /operators/{pubkey}.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpsertOperatorBody {
    role: String,
}

/// PUT /operators/{pubkey}
///
/// Idempotent upsert of a DB operator/moderator row.
/// Returns 409 if the target pubkey is config-backed (immutable through the API).
/// Requires nip98 auth + Operator role.
async fn upsert_operator(
    State(state): State<Arc<crate::state::AppState>>,
    uri: Uri,
    headers: HeaderMap,
    Path(pubkey_hex): Path<String>,
    body_bytes: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal_opt = authorize(
        &state,
        &headers,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |pq| pq.as_str()),
        "PUT",
        Some(&body_bytes),
    )
    .await?;

    let principal = require_mutation_principal(principal_opt)?;
    require_operator(&principal)?;

    // Decode target pubkey.
    let target_bytes = decode_hex_pubkey(&pubkey_hex)?;

    // Reject if config-backed (immutable through the API).
    if is_config_backed_pubkey(&state.config, &pubkey_hex) {
        return Err(ApiError::conflict(
            "pubkey is backed by config (RELAY_OPERATOR_PUBKEYS or owner fallback) — immutable through the API",
        ));
    }

    let body: UpsertOperatorBody = serde_json::from_slice(&body_bytes)
        .map_err(|_| ApiError::bad_request("invalid_body", "invalid JSON body"))?;

    if !["operator", "moderator"].contains(&body.role.as_str()) {
        return Err(ApiError::bad_request(
            "invalid_role",
            "role must be operator|moderator",
        ));
    }

    state
        .db
        .upsert_relay_operator(&target_bytes, &body.role, &principal.pubkey)
        .await?;

    Ok(Json(
        serde_json::json!({"pubkey": pubkey_hex, "role": body.role}),
    ))
}

/// DELETE /operators/{pubkey}
///
/// Remove a DB operator/moderator row.
/// Returns 409 if the target pubkey is config-backed.
/// Requires nip98 auth + Operator role.
async fn delete_operator(
    State(state): State<Arc<crate::state::AppState>>,
    uri: Uri,
    headers: HeaderMap,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal_opt = authorize(
        &state,
        &headers,
        uri.path_and_query()
            .map_or_else(|| uri.path(), |pq| pq.as_str()),
        "DELETE",
        None,
    )
    .await?;

    let principal = require_mutation_principal(principal_opt)?;
    require_operator(&principal)?;

    // Reject if config-backed.
    if is_config_backed_pubkey(&state.config, &pubkey_hex) {
        return Err(ApiError::conflict(
            "pubkey is backed by config (RELAY_OPERATOR_PUBKEYS or owner fallback) — immutable through the API",
        ));
    }

    let target_bytes = decode_hex_pubkey(&pubkey_hex)?;
    let removed = state.db.remove_relay_operator(&target_bytes).await?;
    if !removed {
        return Err(ApiError::not_found());
    }

    Ok(Json(serde_json::json!({"deleted": pubkey_hex})))
}

// ── Staffing helpers ──────────────────────────────────────────────────────────

/// Returns true if the hex pubkey is covered by a config-backed grant
/// (RELAY_OPERATOR_PUBKEYS or owner-fallback B).
fn is_config_backed_pubkey(config: &crate::config::Config, pubkey_hex: &str) -> bool {
    if config
        .relay_operator_pubkeys
        .iter()
        .any(|k| k == pubkey_hex)
    {
        return true;
    }
    // Owner fallback B: only when RELAY_OPERATOR_PUBKEYS is empty.
    if config.relay_operator_pubkeys.is_empty() {
        if let Some(owner) = &config.relay_owner_pubkey {
            if owner == pubkey_hex {
                return true;
            }
        }
    }
    false
}

/// Decode a 64-character hex string into 32 bytes, returning 404 on failure.
fn decode_hex_pubkey(hex_str: &str) -> Result<Vec<u8>, ApiError> {
    if hex_str.len() != 64 {
        return Err(ApiError::not_found());
    }
    hex::decode(hex_str).map_err(|_| ApiError::not_found())
}

/// Decode a hex-encoded report target into (pubkey_bytes, event_id_bytes).
fn decode_report_target_hex(
    target_kind: &str,
    target_hex: &str,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), String> {
    match target_kind {
        "event" => {
            let bytes = hex::decode(target_hex).map_err(|e| e.to_string())?;
            Ok((None, Some(bytes)))
        }
        "pubkey" => {
            let bytes = hex::decode(target_hex).map_err(|e| e.to_string())?;
            Ok((Some(bytes), None))
        }
        "blob" => Ok((None, None)),
        other => Err(format!("unknown target_kind: {other}")),
    }
}

fn feedback_references_hash(tags: &serde_json::Value, community_host: &str, sha256: &str) -> bool {
    tags.as_array()
        .into_iter()
        .flatten()
        .filter_map(|tag| tag.as_array())
        .filter(|tag| tag.first().and_then(|value| value.as_str()) == Some("imeta"))
        .any(|tag| {
            let fields = tag
                .iter()
                .skip(1)
                .filter_map(|value| value.as_str()?.split_once(' '))
                .collect::<std::collections::HashMap<_, _>>();
            fields.get("x") == Some(&sha256)
                && fields
                    .get("url")
                    .is_some_and(|url| attachment_url_matches(url, community_host, sha256))
        })
}

fn attachment_url_matches(url: &str, community_host: &str, sha256: &str) -> bool {
    let parsed = if url.starts_with('/') {
        url::Url::parse(&format!("https://{community_host}{url}"))
    } else {
        url::Url::parse(url)
    };
    let Ok(url) = parsed else {
        return false;
    };
    let authority = url.port().map_or_else(
        || url.host_str().unwrap_or_default().to_string(),
        |port| format!("{}:{port}", url.host_str().unwrap_or_default()),
    );
    let Some(media_name) = url.path().strip_prefix("/media/") else {
        return false;
    };
    let Some((url_hash, extension)) = media_name.split_once('.') else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && buzz_core::tenant::normalize_host(&authority)
            == buzz_core::tenant::normalize_host(community_host)
        && url_hash == sha256
        && crate::api::media::is_safe_ext(extension)
        && url.query().is_none()
        && url.fragment().is_none()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| matches!(character, '0'..='9' | 'a'..='f'))
}

fn summarize_body(body: &str, tags: &serde_json::Value) -> String {
    const MAX_CHARS: usize = 240;
    let attachment_urls = tags
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|tag| tag.as_array())
        .filter(|tag| tag.first().and_then(|value| value.as_str()) == Some("imeta"))
        .flat_map(|tag| tag.iter().skip(1))
        .filter_map(|value| value.as_str()?.strip_prefix("url "))
        .collect::<std::collections::HashSet<_>>();
    let body = body
        .lines()
        .filter(|line| {
            let line = line.trim();
            let url = line
                .strip_suffix(')')
                .and_then(|line| line.rsplit_once("]("))
                .and_then(|(label, url)| {
                    (label.starts_with('[') || label.starts_with("![")).then_some(url)
                });
            url.is_none_or(|url| !attachment_urls.contains(url))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut chars = body.trim().chars();
    let mut summary = chars.by_ref().take(MAX_CHARS).collect::<String>();
    if chars.next().is_some() {
        summary.push('…');
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use auth::ADMIN_API_PREFIX;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    const TOKEN: &str = "5f0e1d2c3b4a59687786958493a2b1c0decadebeefcafe0123456789abcdef01";

    async fn test_state() -> Arc<crate::state::AppState> {
        let mut config = crate::config::Config::from_env().expect("default config loads");
        config.require_relay_membership = false;
        config.redis_url = "redis://127.0.0.1:1".to_string();
        let mut token = [0u8; 32];
        hex::decode_to_slice(TOKEN, &mut token).expect("test token is hex");
        config.admin = Some(crate::config::AdminConfig {
            host: "admin.example".to_string(),
            auth: crate::config::AdminAuth::Token(crate::config::AdminToken::from_bytes(token)),
            web_dir: None,
        });
        let pool = sqlx::PgPool::connect_lazy(&config.database_url).expect("lazy pg pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (state, _audit_shutdown) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        Arc::new(state)
    }

    async fn disabled_mode_state() -> Arc<crate::state::AppState> {
        let mut config = crate::config::Config::from_env().expect("default config loads");
        config.require_relay_membership = false;
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.admin = Some(crate::config::AdminConfig {
            host: "admin.example".to_string(),
            auth: crate::config::AdminAuth::Disabled,
            web_dir: None,
        });
        let pool = sqlx::PgPool::connect_lazy(&config.database_url).expect("lazy pg pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (state, _audit_shutdown) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        Arc::new(state)
    }

    const HASH: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    /// Every route the admin API mounts. Each must enforce the credential.
    fn mounted_routes() -> Vec<String> {
        let id = Uuid::nil();
        vec![
            "/reports".to_string(),
            format!("/reports/{id}"),
            "/feedback".to_string(),
            format!("/feedback/{id}"),
            format!("/feedback/{id}/attachments/{HASH}"),
        ]
    }

    fn authorized(uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .uri(uri)
            .header(header::HOST, "admin.example")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
    }

    fn status_request(builder: axum::http::request::Builder) -> Request<Body> {
        builder.body(Body::empty()).expect("request")
    }

    async fn status_for(
        state: Arc<crate::state::AppState>,
        request: Request<Body>,
    ) -> axum::response::Response {
        router(state).oneshot(request).await.expect("response")
    }

    #[tokio::test]
    async fn every_route_rejects_a_missing_credential_before_database_access() {
        let state = test_state().await;
        for uri in mounted_routes() {
            let response = status_for(
                state.clone(),
                Request::builder()
                    .uri(&uri)
                    .header(header::HOST, "admin.example")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn every_route_rejects_a_wrong_credential_before_database_access() {
        let state = test_state().await;
        let wrong = "f".repeat(64);
        for uri in mounted_routes() {
            let response = status_for(
                state.clone(),
                Request::builder()
                    .uri(&uri)
                    .header(header::HOST, "admin.example")
                    .header(header::AUTHORIZATION, format!("Bearer {wrong}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn malformed_credentials_all_collapse_to_the_same_challenge() {
        let state = test_state().await;
        for value in [
            format!("Basic {TOKEN}"),
            TOKEN.to_string(),
            "Bearer ".to_string(),
            "Bearer".to_string(),
            format!("Bearer {}", &TOKEN[..63]),
            format!("Bearer {TOKEN}00"),
            format!("Bearer {}", "z".repeat(64)),
        ] {
            let response = status_for(
                state.clone(),
                Request::builder()
                    .uri("/reports")
                    .header(header::HOST, "admin.example")
                    .header(header::AUTHORIZATION, &value)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{value}");
            assert_eq!(
                response
                    .headers()
                    .get(header::WWW_AUTHENTICATE)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer"),
                "{value}"
            );
        }
    }

    #[tokio::test]
    async fn duplicate_authorization_headers_are_rejected() {
        let response = status_for(
            test_state().await,
            Request::builder()
                .uri("/reports")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn lowercase_bearer_scheme_is_accepted() {
        // Use /probe (no DB dependency) to verify that a lowercase "bearer" scheme
        // is accepted and auth succeeds. A 200 from probe confirms auth passed.
        let response = status_for(
            test_state().await,
            Request::builder()
                .uri("/probe")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, format!("bearer {TOKEN}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_valid_credential_on_the_wrong_host_is_forbidden_not_unauthorized() {
        let response = status_for(
            test_state().await,
            Request::builder()
                .uri(format!("/reports/{}", Uuid::nil()))
                .header(header::HOST, "community.example")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_valid_credential_with_a_mismatched_origin_is_forbidden() {
        let response = status_for(
            test_state().await,
            status_request(
                authorized(&format!("/reports/{}", Uuid::nil()))
                    .header(header::ORIGIN, "https://attacker.example"),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_valid_credential_on_the_admin_host_without_an_origin_is_served() {
        // Use /probe (no DB dependency) to confirm auth succeeds without an Origin header.
        let response = status_for(test_state().await, status_request(authorized("/probe"))).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_unauthenticated_request_on_the_wrong_host_reveals_no_host_oracle() {
        let state = test_state().await;
        let wrong_host = status_for(
            state.clone(),
            Request::builder()
                .uri("/reports")
                .header(header::HOST, "community.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        let right_host = status_for(
            state,
            Request::builder()
                .uri("/reports")
                .header(header::HOST, "admin.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(wrong_host.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(right_host.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn report_detail_rejects_unknown_report() {
        let response = status_for(
            test_state().await,
            status_request(authorized(&format!("/reports/{}", Uuid::nil()))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn feedback_attachment_rejects_unknown_feedback() {
        let response = status_for(
            test_state().await,
            status_request(authorized(&format!(
                "/feedback/{}/attachments/{HASH}",
                Uuid::nil()
            ))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn feedback_attachment_rejects_write_methods() {
        let state = test_state().await;
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let response = status_for(
                state.clone(),
                status_request(
                    authorized(&format!("/feedback/{}/attachments/{HASH}", Uuid::nil()))
                        .method(method),
                ),
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method}"
            );
        }
    }

    #[test]
    fn report_filters_reject_unknown_values() {
        assert!(validate(Some("open"), &["open"], "invalid_status").is_ok());
        assert!(validate(Some("unknown"), &["open"], "invalid_status").is_err());
    }

    #[test]
    fn feedback_summary_is_unicode_safe_and_marks_truncation() {
        let body = "🐝".repeat(241);
        let summary = summarize_body(&body, &serde_json::Value::Null);
        assert_eq!(summary.chars().count(), 241);
        assert!(summary.ends_with('…'));
    }

    #[test]
    fn feedback_summary_omits_imeta_attachment_lines() {
        let url = "http://localhost:3000/media/abc.png";
        let tags = serde_json::json!([["imeta", format!("url {url}"), "m image/png"]]);
        assert_eq!(
            summarize_body(&format!("Useful context.\n![image]({url})"), &tags),
            "Useful context."
        );
    }

    fn attachment_tags(host: &str, x: &str, url_hash: &str) -> serde_json::Value {
        serde_json::json!([[
            "imeta",
            format!("url https://{host}/media/{url_hash}.png"),
            "m image/png",
            format!("x {x}"),
            "size 100"
        ]])
    }

    #[test]
    fn feedback_attachment_requires_matching_imeta_hash_and_source_host() {
        let tags = attachment_tags("community.example", HASH, HASH);
        assert!(feedback_references_hash(&tags, "community.example", HASH));

        let unreferenced = "f".repeat(64);
        assert!(!feedback_references_hash(
            &tags,
            "community.example",
            &unreferenced
        ));
        assert!(!feedback_references_hash(
            &tags,
            "other-community.example",
            HASH
        ));
    }

    #[test]
    fn feedback_attachment_rejects_cross_field_and_path_substitution() {
        let other_hash = "f".repeat(64);
        assert!(!feedback_references_hash(
            &attachment_tags("community.example", HASH, &other_hash),
            "community.example",
            HASH
        ));

        for url in [
            format!("https://community.example/media/{HASH}.png?token=leak"),
            format!("https://community.example/media/{HASH}.thumb.jpg"),
            format!("https://community.example/media/{HASH}.png/extra"),
            format!("https://evil.example/media/{HASH}.png"),
        ] {
            assert!(!attachment_url_matches(&url, "community.example", HASH));
        }
    }

    #[test]
    fn feedback_attachment_accepts_valid_relative_source_url() {
        assert!(attachment_url_matches(
            &format!("/media/{HASH}.png"),
            "community.example",
            HASH
        ));
    }

    #[test]
    fn feedback_attachment_hash_is_exact_lowercase_sha256() {
        assert!(is_sha256(HASH));
        assert!(!is_sha256(&HASH.to_uppercase()));
        assert!(!is_sha256(&HASH[..63]));
        assert!(!is_sha256(&format!("{HASH}.png")));
    }

    #[tokio::test]
    async fn disabled_mode_allows_unauthenticated_requests_on_the_admin_host() {
        let state = disabled_mode_state().await;
        for uri in mounted_routes() {
            let response = status_for(
                state.clone(),
                Request::builder()
                    .uri(&uri)
                    .header(header::HOST, "admin.example")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
            // The routes return 200 (or 404 for unknown resources) — never 401.
            // 404 is fine here: there is no real DB, so the row lookups fail.
            assert_ne!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{uri} must not return 401 in disabled mode"
            );
        }
    }

    #[tokio::test]
    async fn disabled_mode_still_requires_the_correct_host() {
        let state = disabled_mode_state().await;
        let response = status_for(
            state,
            Request::builder()
                .uri("/reports")
                .header(header::HOST, "community.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "wrong host must still be rejected in disabled mode"
        );
    }

    #[tokio::test]
    async fn disabled_mode_still_requires_a_matching_origin() {
        let state = disabled_mode_state().await;
        let response = status_for(
            state,
            Request::builder()
                .uri("/reports")
                .header(header::HOST, "admin.example")
                .header(header::ORIGIN, "https://attacker.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "mismatched origin must still be rejected in disabled mode"
        );
    }

    // ── NIP-98 mode helpers and tests ─────────────────────────────────────

    /// Replay guard that always returns `true` — every event is "fresh".
    /// Used in NIP-98 tests that don't specifically test replay protection.
    struct AlwaysFreshReplayGuard;

    impl buzz_auth::Nip98ReplayGuard for AlwaysFreshReplayGuard {
        fn try_mark_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            _event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            Box::pin(async { Ok(true) })
        }
    }

    /// Replay guard that rejects any event ID it has seen before.
    /// Used to test that the replay guard is actually invoked and enforced.
    struct TrackingReplayGuard {
        seen: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
    }

    impl TrackingReplayGuard {
        fn new() -> Self {
            Self {
                seen: std::sync::Mutex::new(std::collections::HashSet::new()),
            }
        }
    }

    impl buzz_auth::Nip98ReplayGuard for TrackingReplayGuard {
        fn try_mark_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            let bytes = event_id.to_bytes();
            let is_fresh = self.seen.lock().unwrap().insert(bytes);
            Box::pin(async move { Ok(is_fresh) })
        }
    }

    /// Build a test AppState in nip98 mode with the given operator pubkeys
    /// (populated in relay_operator_pubkeys config) and an AlwaysFreshReplayGuard.
    async fn nip98_state(pubkeys: Vec<String>) -> Arc<crate::state::AppState> {
        nip98_state_with_replay(pubkeys, Arc::new(AlwaysFreshReplayGuard)).await
    }

    async fn nip98_state_with_replay(
        pubkeys: Vec<String>,
        replay: Arc<dyn buzz_auth::Nip98ReplayGuard>,
    ) -> Arc<crate::state::AppState> {
        let mut config = crate::config::Config::from_env().expect("default config loads");
        config.require_relay_membership = false;
        config.redis_url = "redis://127.0.0.1:1".to_string();
        // Populate relay_operator_pubkeys so resolve_admin_principal can grant
        // Operator/Config to the test pubkeys without a DB lookup.
        config.relay_operator_pubkeys = pubkeys;
        // Ensure relay_operator_api_origin is set (required when pubkeys is non-empty).
        if !config.relay_operator_pubkeys.is_empty() {
            config.relay_operator_api_origin = Some("https://admin.example".to_string());
        }
        config.admin = Some(crate::config::AdminConfig {
            host: "admin.example".to_string(),
            auth: crate::config::AdminAuth::Nip98,
            web_dir: None,
        });
        let pool = sqlx::PgPool::connect_lazy(&config.database_url).expect("lazy pg pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (mut state, _audit_shutdown) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        state.nip98_replay = replay;
        Arc::new(state)
    }

    /// Build a NIP-98 Authorization header value for a GET to the given path
    /// on `admin.example` (the test host). The path should be the handler-level
    /// path (e.g. `/reports`); this helper prefixes it with `ADMIN_API_PREFIX`
    /// to match the canonical URL the auth layer constructs in production.
    fn make_nostr_auth(keys: &nostr::Keys, path: &str) -> String {
        use nostr::{EventBuilder, Kind, Tag};
        let url = format!("https://admin.example{ADMIN_API_PREFIX}{path}");
        let tags = vec![
            Tag::parse(["u", &url]).unwrap(),
            Tag::parse(["method", "GET"]).unwrap(),
        ];
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign");
        let json = serde_json::to_string(&event).expect("serialize");
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        format!("Nostr {}", BASE64.encode(json.as_bytes()))
    }

    #[tokio::test]
    async fn nip98_mode_rejects_missing_credential_with_nostr_challenge() {
        let keys = nostr::Keys::generate();
        let state = nip98_state(vec![keys.public_key().to_hex()]).await;
        let response = status_for(
            state,
            Request::builder()
                .uri("/reports")
                .header(header::HOST, "admin.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Nostr"),
            "nip98 mode must advertise Nostr challenge"
        );
    }

    #[tokio::test]
    async fn nip98_mode_valid_event_from_operator_pubkey_is_served() {
        let keys = nostr::Keys::generate();
        let state = nip98_state(vec![keys.public_key().to_hex()]).await;
        // Use /probe (no DB dependency) — config-backed operator resolves without DB.
        let auth = make_nostr_auth(&keys, "/probe");
        let response = status_for(
            state,
            Request::builder()
                .uri("/probe")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        // 200 from probe confirms the event was authenticated and operator was resolved.
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[ignore = "requires Postgres — DB lookup returns None for unknown key → 403"]
    async fn nip98_mode_valid_event_unknown_pubkey_is_403() {
        let operator = nostr::Keys::generate();
        let unknown = nostr::Keys::generate();
        let state = nip98_state(vec![operator.public_key().to_hex()]).await;
        let auth = make_nostr_auth(&unknown, "/reports");
        let response = status_for(
            state,
            Request::builder()
                .uri("/reports")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        // NIP-98 signature is valid but the pubkey has no operator/moderator
        // grant — that is an authorization failure (403), not an auth failure.
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn nip98_mode_duplicate_authorization_headers_are_401() {
        let keys = nostr::Keys::generate();
        let state = nip98_state(vec![keys.public_key().to_hex()]).await;
        let auth = make_nostr_auth(&keys, "/reports");
        let response = status_for(
            state,
            Request::builder()
                .uri("/reports")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth.clone())
                .header(header::AUTHORIZATION, auth)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn nip98_mode_wrong_url_in_event_is_401() {
        let keys = nostr::Keys::generate();
        let state = nip98_state(vec![keys.public_key().to_hex()]).await;
        // Sign for /feedback but send to /reports — u-tag mismatch.
        let auth = make_nostr_auth(&keys, "/feedback");
        let response = status_for(
            state,
            Request::builder()
                .uri("/reports")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn nip98_mode_replay_is_rejected() {
        let keys = nostr::Keys::generate();
        let tracking = Arc::new(TrackingReplayGuard::new());
        let state =
            nip98_state_with_replay(vec![keys.public_key().to_hex()], tracking.clone()).await;
        // Use /probe (no DB dependency) to verify first request succeeds
        // and second (same event ID) is rejected by the replay guard.
        let auth = make_nostr_auth(&keys, "/probe");
        // First request succeeds.
        let first = status_for(
            state.clone(),
            Request::builder()
                .uri("/probe")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth.clone())
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        // Second request with the same event ID must be rejected.
        let second = status_for(
            state,
            Request::builder()
                .uri("/probe")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn nip98_mode_valid_credential_on_wrong_host_is_forbidden_not_unauthorized() {
        let keys = nostr::Keys::generate();
        let state = nip98_state(vec![keys.public_key().to_hex()]).await;
        let auth = make_nostr_auth(&keys, "/reports");
        let response = status_for(
            state,
            Request::builder()
                .uri("/reports")
                .header(header::HOST, "community.example")
                .header(header::AUTHORIZATION, auth)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ── Regression pins — token-mode and disabled-mode unchanged ──────────

    #[tokio::test]
    async fn token_mode_regression_pin_valid_credential_is_served() {
        // Use /probe (no DB dependency) to confirm token mode serves valid credentials.
        let response = status_for(test_state().await, status_request(authorized("/probe"))).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn token_mode_regression_pin_missing_credential_is_401() {
        let state = test_state().await;
        let response = status_for(
            state,
            Request::builder()
                .uri("/reports")
                .header(header::HOST, "admin.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer"),
            "token mode must advertise Bearer challenge"
        );
    }

    #[tokio::test]
    async fn disabled_mode_regression_pin_unauthenticated_request_is_served() {
        let state = disabled_mode_state().await;
        // Use /probe (no DB dependency) to confirm disabled mode allows unauthenticated requests.
        let response = status_for(
            state,
            Request::builder()
                .uri("/probe")
                .header(header::HOST, "admin.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── Query-bearing NIP-98 requests ────────────────────────────────────

    #[tokio::test]
    async fn nip98_mode_query_bearing_request_signed_with_full_url_is_served() {
        // Verify that the signed u-tag must include the query string; the relay
        // verifies against the full path-and-query, not just the path component.
        // We use /probe with a dummy query string (no DB dependency) to test the
        // URL-binding without hitting Postgres.
        let keys = nostr::Keys::generate();
        let state = nip98_state(vec![keys.public_key().to_hex()]).await;
        let auth = make_nostr_auth(&keys, "/probe?mode=check");
        let response = status_for(
            state,
            Request::builder()
                .uri("/probe?mode=check")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        // 200 — full URL matched; not 401.
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn nip98_mode_path_only_event_for_query_bearing_request_is_401() {
        // A credential signed for just /probe must not authenticate a
        // request sent to /probe?mode=check: the u-tag would not match the
        // full canonical URL.
        let keys = nostr::Keys::generate();
        let state = nip98_state(vec![keys.public_key().to_hex()]).await;
        let auth = make_nostr_auth(&keys, "/probe");
        let response = status_for(
            state,
            Request::builder()
                .uri("/probe?mode=check")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Phase 1 acceptance tests ─────────────────────────────────────────
    //
    // Method-substitution and payload-tag checks are exercised via
    // authorize() directly (see auth::tests) — the admin API calls
    // authorize() per-handler after routing, so a POST to a GET-only route
    // returns 405 from the router before any auth code runs. The HTTP-level
    // integration tests for mutation endpoints live in Phase 2 once those
    // routes exist.

    // ── token/disabled mode probe tests ─────────────────────────────────

    #[tokio::test]
    async fn probe_in_token_mode_returns_no_role_and_no_capabilities() {
        let state = test_state().await; // token mode
        let response = status_for(state.clone(), status_request(authorized("/probe"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        // Body should report no role and can_act=false.
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let probe: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(probe["authMode"], "token");
        assert!(probe["role"].is_null(), "token mode has no role");
        assert_eq!(probe["canAct"], false);
        assert_eq!(probe["canStaff"], false);
    }

    #[tokio::test]
    async fn probe_in_disabled_mode_returns_no_role_and_no_capabilities() {
        let state = disabled_mode_state().await;
        let response = status_for(
            state,
            Request::builder()
                .uri("/probe")
                .header(header::HOST, "admin.example")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let probe: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(probe["authMode"], "disabled");
        assert!(probe["role"].is_null(), "disabled mode has no role");
        assert_eq!(probe["canAct"], false);
        assert_eq!(probe["canStaff"], false);
    }

    /// Fallback B: when RELAY_OPERATOR_PUBKEYS is empty, RELAY_OWNER_PUBKEY is
    /// the implicit Operator and the probe returns role=operator, source=owner_fallback.
    #[tokio::test]
    async fn probe_in_nip98_mode_with_owner_fallback_b_returns_operator_role() {
        let owner_keys = nostr::Keys::generate();
        let mut config = crate::config::Config::from_env().expect("default config");
        config.require_relay_membership = false;
        config.redis_url = "redis://127.0.0.1:1".to_string();
        // Empty operator list — activates fallback B.
        config.relay_operator_pubkeys = vec![];
        config.relay_owner_pubkey = Some(owner_keys.public_key().to_hex());
        config.admin = Some(crate::config::AdminConfig {
            host: "admin.example".to_string(),
            auth: crate::config::AdminAuth::Nip98,
            web_dir: None,
        });
        let pool = sqlx::PgPool::connect_lazy(&config.database_url).expect("lazy pg pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (mut state, _) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        state.nip98_replay = Arc::new(AlwaysFreshReplayGuard);
        let state = Arc::new(state);

        let auth_header = make_nostr_auth(&owner_keys, "/probe");
        let response = status_for(
            state,
            Request::builder()
                .uri("/probe")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth_header)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let probe: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(probe["authMode"], "nip98");
        assert_eq!(probe["role"], "operator");
        assert_eq!(probe["source"], "owner_fallback");
        assert_eq!(probe["canAct"], true);
        assert_eq!(probe["canStaff"], true);
    }

    /// Fallback B does NOT activate when RELAY_OPERATOR_PUBKEYS is non-empty:
    /// the owner key is then treated as an unknown pubkey → DB lookup → 403.
    #[tokio::test]
    #[ignore = "requires Postgres — owner key not in config, falls to DB lookup → 403"]
    async fn probe_owner_fallback_b_disabled_when_operator_pubkeys_nonempty() {
        let owner_keys = nostr::Keys::generate();
        let other_operator = nostr::Keys::generate();
        // Non-empty RELAY_OPERATOR_PUBKEYS — owner fallback should NOT apply.
        let state = nip98_state(vec![other_operator.public_key().to_hex()]).await;

        // Inject RELAY_OWNER_PUBKEY into the state config manually.
        // We need a fresh state with both set.
        let mut config = crate::config::Config::from_env().expect("default config");
        config.require_relay_membership = false;
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.relay_operator_pubkeys = vec![other_operator.public_key().to_hex()];
        config.relay_operator_api_origin = Some("https://admin.example".to_string());
        config.relay_owner_pubkey = Some(owner_keys.public_key().to_hex());
        config.admin = Some(crate::config::AdminConfig {
            host: "admin.example".to_string(),
            auth: crate::config::AdminAuth::Nip98,
            web_dir: None,
        });
        drop(state); // not used
        let pool = sqlx::PgPool::connect_lazy(&config.database_url).expect("lazy pg pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (mut state, _) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        state.nip98_replay = Arc::new(AlwaysFreshReplayGuard);
        let state = Arc::new(state);

        // Owner key signs a valid NIP-98 credential, but fallback B is OFF.
        let auth_header = make_nostr_auth(&owner_keys, "/probe");
        let response = status_for(
            state,
            Request::builder()
                .uri("/probe")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth_header)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        // Should be 403: valid NIP-98 credential, but no grant.
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ── Phase 2: mutation routes require nip98 ────────────────────────────

    /// Build a NIP-98 POST body-bearing Authorization header with `payload` sha256.
    fn make_nostr_auth_post(keys: &nostr::Keys, path: &str, body: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        use nostr::{EventBuilder, Kind, Tag};
        use sha2::{Digest, Sha256};

        let url = format!("https://admin.example{ADMIN_API_PREFIX}{path}");
        let payload_hash = hex::encode(Sha256::digest(body));
        let tags = vec![
            Tag::parse(["u", &url]).unwrap(),
            Tag::parse(["method", "POST"]).unwrap(),
            Tag::parse(["payload", &payload_hash]).unwrap(),
        ];
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign");
        let json = serde_json::to_string(&event).expect("serialize");
        format!("Nostr {}", BASE64.encode(json.as_bytes()))
    }

    fn make_nostr_auth_patch(keys: &nostr::Keys, path: &str, body: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        use nostr::{EventBuilder, Kind, Tag};
        use sha2::{Digest, Sha256};

        let url = format!("https://admin.example{ADMIN_API_PREFIX}{path}");
        let payload_hash = hex::encode(Sha256::digest(body));
        let tags = vec![
            Tag::parse(["u", &url]).unwrap(),
            Tag::parse(["method", "PATCH"]).unwrap(),
            Tag::parse(["payload", &payload_hash]).unwrap(),
        ];
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign");
        let json = serde_json::to_string(&event).expect("serialize");
        format!("Nostr {}", BASE64.encode(json.as_bytes()))
    }

    fn make_nostr_auth_put(keys: &nostr::Keys, path: &str, body: &[u8]) -> String {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        use nostr::{EventBuilder, Kind, Tag};
        use sha2::{Digest, Sha256};

        let url = format!("https://admin.example{ADMIN_API_PREFIX}{path}");
        let payload_hash = hex::encode(Sha256::digest(body));
        let tags = vec![
            Tag::parse(["u", &url]).unwrap(),
            Tag::parse(["method", "PUT"]).unwrap(),
            Tag::parse(["payload", &payload_hash]).unwrap(),
        ];
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign");
        let json = serde_json::to_string(&event).expect("serialize");
        format!("Nostr {}", BASE64.encode(json.as_bytes()))
    }

    fn make_nostr_auth_delete(keys: &nostr::Keys, path: &str) -> String {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        use nostr::{EventBuilder, Kind, Tag};

        let url = format!("https://admin.example{ADMIN_API_PREFIX}{path}");
        let tags = vec![
            Tag::parse(["u", &url]).unwrap(),
            Tag::parse(["method", "DELETE"]).unwrap(),
        ];
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign");
        let json = serde_json::to_string(&event).expect("serialize");
        format!("Nostr {}", BASE64.encode(json.as_bytes()))
    }

    /// POST /reports/{id}/resolve in token mode → 403 (mutations require nip98).
    #[tokio::test]
    async fn mutation_routes_in_token_mode_return_403() {
        let state = test_state().await; // token mode
        let id = Uuid::nil();
        let body = r#"{"action":"dismiss"}"#.as_bytes().to_vec();
        let response = status_for(
            state,
            Request::builder()
                .method("POST")
                .uri(format!("/reports/{id}/resolve"))
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await;
        // Token mode: valid token passes auth, but require_mutation_principal
        // returns 403 because there is no AdminPrincipal in token mode.
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "mutations must require nip98"
        );
    }

    /// PATCH /feedback/{id} in token mode → 403.
    #[tokio::test]
    async fn feedback_status_patch_in_token_mode_returns_403() {
        let state = test_state().await;
        let id = Uuid::nil();
        let body = r#"{"status":"reviewed"}"#.as_bytes().to_vec();
        let response = status_for(
            state,
            Request::builder()
                .method("PATCH")
                .uri(format!("/feedback/{id}"))
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "patch must require nip98"
        );
    }

    /// GET /operators in token mode → 403.
    #[tokio::test]
    async fn list_operators_in_token_mode_returns_403() {
        let state = test_state().await;
        let response = status_for(
            state,
            Request::builder()
                .method("GET")
                .uri("/operators")
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "operators must require nip98"
        );
    }

    /// Moderator cannot access staffing endpoints.
    #[tokio::test]
    #[ignore = "requires Postgres — moderator DB lookup"]
    async fn moderator_cannot_access_staffing_endpoints() {
        // This test needs DB to resolve moderator role.
        // Covered by negative-matrix integration test suite.
    }

    /// Config-backed pubkey upsert → 409 Conflict.
    #[tokio::test]
    async fn upsert_config_backed_pubkey_returns_409() {
        let operator_keys = nostr::Keys::generate();
        let target_keys = nostr::Keys::generate();
        let target_hex = target_keys.public_key().to_hex();
        // Put target in config — makes it config-backed and immutable.
        let mut config = crate::config::Config::from_env().expect("default config");
        config.require_relay_membership = false;
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.relay_operator_pubkeys =
            vec![operator_keys.public_key().to_hex(), target_hex.clone()];
        config.relay_operator_api_origin = Some("https://admin.example".to_string());
        config.admin = Some(crate::config::AdminConfig {
            host: "admin.example".to_string(),
            auth: crate::config::AdminAuth::Nip98,
            web_dir: None,
        });
        let pool = sqlx::PgPool::connect_lazy(&config.database_url).expect("lazy pg pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (mut state, _) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        state.nip98_replay = Arc::new(AlwaysFreshReplayGuard);
        let state = Arc::new(state);

        let path = format!("/operators/{target_hex}");
        let body = r#"{"role":"moderator"}"#.as_bytes();
        let auth_header = make_nostr_auth_put(&operator_keys, &path, body);

        let response = status_for(
            state,
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth_header)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_vec()))
                .expect("request"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "config-backed pubkey must return 409"
        );
    }

    /// Config-backed pubkey delete → 409 Conflict.
    #[tokio::test]
    async fn delete_config_backed_pubkey_returns_409() {
        let operator_keys = nostr::Keys::generate();
        let target_keys = nostr::Keys::generate();
        let target_hex = target_keys.public_key().to_hex();
        let mut config = crate::config::Config::from_env().expect("default config");
        config.require_relay_membership = false;
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.relay_operator_pubkeys =
            vec![operator_keys.public_key().to_hex(), target_hex.clone()];
        config.relay_operator_api_origin = Some("https://admin.example".to_string());
        config.admin = Some(crate::config::AdminConfig {
            host: "admin.example".to_string(),
            auth: crate::config::AdminAuth::Nip98,
            web_dir: None,
        });
        let pool = sqlx::PgPool::connect_lazy(&config.database_url).expect("lazy pg pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (mut state, _) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        state.nip98_replay = Arc::new(AlwaysFreshReplayGuard);
        let state = Arc::new(state);

        let path = format!("/operators/{target_hex}");
        let auth_header = make_nostr_auth_delete(&operator_keys, &path);

        let response = status_for(
            state,
            Request::builder()
                .method("DELETE")
                .uri(path)
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth_header)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "config-backed pubkey delete must return 409"
        );
    }

    /// Owner-fallback B config-backed pubkey upsert → 409.
    #[tokio::test]
    async fn upsert_owner_fallback_b_pubkey_returns_409() {
        // Owner fallback B: RELAY_OPERATOR_PUBKEYS empty, owner key is implicit operator.
        let owner_keys = nostr::Keys::generate();
        let owner_hex = owner_keys.public_key().to_hex();
        let mut config = crate::config::Config::from_env().expect("default config");
        config.require_relay_membership = false;
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.relay_operator_pubkeys = vec![]; // activates fallback B
        config.relay_owner_pubkey = Some(owner_hex.clone());
        config.admin = Some(crate::config::AdminConfig {
            host: "admin.example".to_string(),
            auth: crate::config::AdminAuth::Nip98,
            web_dir: None,
        });
        let pool = sqlx::PgPool::connect_lazy(&config.database_url).expect("lazy pg pool");
        let db = buzz_db::Db::from_pool(pool.clone());
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).expect("media storage");
        let (mut state, _) = crate::state::AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            nostr::Keys::generate(),
            media_storage,
        );
        state.nip98_replay = Arc::new(AlwaysFreshReplayGuard);
        let state = Arc::new(state);

        // Try to upsert the owner key (config-backed via fallback B) — should return 409.
        let path = format!("/operators/{owner_hex}");
        let body = r#"{"role":"moderator"}"#.as_bytes();
        let auth_header = make_nostr_auth_put(&owner_keys, &path, body);

        let response = status_for(
            state,
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth_header)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_vec()))
                .expect("request"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "owner fallback B key must return 409 on upsert"
        );
    }

    /// Method-substitution: a POST credential cannot authenticate a PATCH.
    #[tokio::test]
    async fn nip98_mutation_method_substitution_returns_401() {
        let keys = nostr::Keys::generate();
        let state = nip98_state(vec![keys.public_key().to_hex()]).await;
        let id = Uuid::nil();
        let body = r#"{"status":"reviewed"}"#.as_bytes();

        // Sign a PATCH credential but send as POST — method mismatch → 401.
        let auth_header = make_nostr_auth_post(&keys, &format!("/feedback/{id}"), body);

        let response = status_for(
            state,
            Request::builder()
                .method("PATCH")
                .uri(format!("/feedback/{id}"))
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth_header)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_vec()))
                .expect("request"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "method substitution must be rejected"
        );
    }

    /// Body substitution: credential signed for one body, different body sent → 401.
    #[tokio::test]
    async fn nip98_mutation_body_substitution_returns_401() {
        let keys = nostr::Keys::generate();
        let state = nip98_state(vec![keys.public_key().to_hex()]).await;
        let id = Uuid::nil();
        let original_body = r#"{"status":"reviewed"}"#.as_bytes();
        let tampered_body = r#"{"status":"archived"}"#.as_bytes();

        // Credential is signed for `original_body` but we send `tampered_body`.
        let auth_header = make_nostr_auth_patch(&keys, &format!("/feedback/{id}"), original_body);

        let response = status_for(
            state,
            Request::builder()
                .method("PATCH")
                .uri(format!("/feedback/{id}"))
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth_header)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(tampered_body.to_vec()))
                .expect("request"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "body substitution must be rejected"
        );
    }

    /// Missing payload tag on a body-bearing POST → 401.
    #[tokio::test]
    async fn nip98_mutation_missing_payload_tag_returns_401() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        use nostr::{EventBuilder, Kind, Tag};

        let keys = nostr::Keys::generate();
        let state = nip98_state(vec![keys.public_key().to_hex()]).await;
        let id = Uuid::nil();
        let body = r#"{"action":"dismiss"}"#.as_bytes();

        // Sign NIP-98 for the URL and method but omit the `payload` tag.
        let url = format!("https://admin.example{ADMIN_API_PREFIX}/reports/{id}/resolve");
        let tags = vec![
            Tag::parse(["u", &url]).unwrap(),
            Tag::parse(["method", "POST"]).unwrap(),
            // Intentionally no payload tag.
        ];
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(&keys)
            .expect("sign");
        let json = serde_json::to_string(&event).expect("serialize");
        let auth_header = format!("Nostr {}", BASE64.encode(json.as_bytes()));

        let response = status_for(
            state,
            Request::builder()
                .method("POST")
                .uri(format!("/reports/{id}/resolve"))
                .header(header::HOST, "admin.example")
                .header(header::AUTHORIZATION, auth_header)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_vec()))
                .expect("request"),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "missing payload tag must be rejected"
        );
    }

    // ── Phase 2: DB-backed acceptance tests ───────────────────────────────
    //
    // These tests require Postgres and are tagged #[ignore]. They exercise the
    // full enforcement state machine including racing moderators, retry
    // idempotency, and community 9044 vs processing report.

    #[tokio::test]
    #[ignore = "requires Postgres — racing moderators, exactly one claim"]
    async fn racing_moderators_one_succeeds_one_gets_409() {
        // Two concurrent POST /reports/{id}/resolve with different request_ids
        // against the same open report. Exactly one must succeed (200) and one
        // must return 409 (report not open). No orphan audit row.
        todo!("implement once full e2e stack is available")
    }

    #[tokio::test]
    #[ignore = "requires Postgres — same request_id retry returns existing action record"]
    async fn same_request_id_retry_returns_existing_action() {
        // POST /reports/{id}/resolve with the same requestId twice.
        // Both should return 200 with the same actionId.
        todo!("implement once full e2e stack is available")
    }

    #[tokio::test]
    #[ignore = "requires Postgres — community 9044 against processing report fails cleanly"]
    async fn community_9044_against_processing_report_fails_cleanly() {
        // A community 9044 event against a processing report must fail the CAS
        // on status='open' and return an error. The enforcement must not be
        // duplicated.
        todo!("implement once full e2e stack is available")
    }

    #[tokio::test]
    #[ignore = "requires Postgres — cancel rejected after mutation success"]
    async fn cancel_after_mutation_success_is_rejected() {
        // After an enforcement action reaches mutation_committed step_marker,
        // attempting to cancel the action record must fail (cancel is only
        // legal pre-mutation).
        todo!("implement once full e2e stack is available")
    }

    #[tokio::test]
    #[ignore = "requires Postgres — worker crash re-drive convergence"]
    async fn worker_crash_redrive_converges_to_exactly_one_enforcement() {
        // Simulate a crash after mutation_committed but before finalization.
        // Re-drive from persisted step state must produce exactly one
        // enforcement, one report transition, one audit chain, one reporter notice.
        todo!("implement once full e2e stack is available")
    }
}
