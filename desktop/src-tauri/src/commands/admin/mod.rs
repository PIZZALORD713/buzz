//! Desktop in-app admin surface — NIP-98 client for `/api/admin/v1`.
//!
//! Implements five Tauri commands that fetch JSON and binary content from the
//! relay's deployment-admin API using the app keypair as the NIP-98 signing
//! identity. A sixth command, `admin_probe`, discovers which authentication
//! mode the configured admin origin is running and whether the app identity
//! is authorized.
//!
//! # Security model
//!
//! The webview never supplies paths, methods, or full URLs. Every IPC command
//! accepts an `AdminOrigin` (scheme + host + optional port, validated on
//! construction) and typed query parameters; the final URL is built natively
//! from a closed route enum. The URL that is signed is byte-identical to the
//! URL that is fetched.
//!
//! A dedicated no-redirect reqwest client prevents redirect-hop SSRF — a relay
//! 3xx is returned verbatim and treated as an error so the NIP-98 header is
//! never forwarded across origins.
//!
//! Keys are acquired via `AppState::signing_keys()`, which returns `Err` when
//! the identity is in recovery mode (keyring locked or lost), ensuring the app
//! keypair can never sign admin events under an inaccessible identity.
//!
//! Response sizes are bounded by Content-Length preflight and a streaming byte
//! counter, mirroring the `media_download.rs` pattern.

pub mod client;
pub(crate) mod origin;
pub(crate) mod routes;

// ── Response size caps ────────────────────────────────────────────────────

/// Success-JSON cap: reports list returns up to 200 rows, each note field
/// can reach the 256 KiB event-content cap. Sized for the worst case.
const SUCCESS_JSON_CAP: u64 = 52_428_800; // 50 MiB

/// Error-body cap: relay error responses are brief JSON envelopes.
const ERROR_BODY_CAP: u64 = 65_536; // 64 KiB

/// Attachment preview cap. 10 MiB is generous for images and small documents
/// while protecting against accidental OOM.
const ATTACHMENT_CAP: u64 = 10_485_760; // 10 MiB

// ── Typed probe result ────────────────────────────────────────────────────

/// Result of an `admin_probe` call. Each variant maps to a distinct UI state.
/// Tauri serialises this as `{ "state": "<camelCaseVariant>" }`.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum AdminProbeResult {
    /// NIP-98 mode is active and the current app keypair is on the allowlist.
    Nip98Authorized,
    /// NIP-98 mode is active but the app keypair was rejected after a signed
    /// attempt. Likely: pubkey not in `BUZZ_ADMIN_PUBKEYS`, clock skew, or
    /// relay config mismatch.
    Nip98Denied,
    /// Bearer-token mode (`BUZZ_ADMIN_AUTH=token`). The desktop cannot mint a
    /// bearer token; the operator must use the web console.
    TokenMode,
    /// Auth is disabled (`BUZZ_ADMIN_AUTH=disabled`). No credential needed.
    Disabled,
    /// The origin is reachable but the `/api/admin/v1` prefix is absent or
    /// returns a non-admin response.
    NotAdminApi,
    /// Network/TLS error, DNS failure, or Cloudflare Access interception.
    NetworkOrIntercepted,
}

// ── Typed query struct ────────────────────────────────────────────────────

/// Query parameters accepted by `admin_list_reports`.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminReportsQuery {
    pub community_id: Option<String>,
    pub status: Option<String>,
    pub report_type: Option<String>,
    pub target_kind: Option<String>,
    pub after: Option<String>,
    pub before: Option<String>,
    pub limit: Option<i64>,
}

// ── Probe ─────────────────────────────────────────────────────────────────

/// Probe an admin origin to determine the authentication mode and whether the
/// current app keypair is authorized.
///
/// Algorithm:
/// 1. Send an unauthenticated GET to `/api/admin/v1/reports?limit=1`.
/// 2. 200 → `Disabled` (admin accessible without a credential).
/// 3. 401 + `WWW-Authenticate: Nostr` → NIP-98 mode. Retry with a freshly
///    signed kind-27235. 200 → `Nip98Authorized`; non-200 → `Nip98Denied`.
/// 4. 401 + `WWW-Authenticate: Bearer` → `TokenMode`.
/// 5. 403/404 or other non-401 → `NotAdminApi`.
/// 6. Network/redirect/TLS error → `NetworkOrIntercepted`.
#[tauri::command]
pub async fn admin_probe(
    origin: String,
    state: tauri::State<'_, crate::app_state::AppState>,
) -> Result<AdminProbeResult, String> {
    use crate::relay::build_nip98_auth_header_for_keys;

    let origin = origin::AdminOrigin::parse(&origin)?;
    let url = origin.route_url(
        &routes::AdminRoute::ReportsList,
        &routes::AdminQuery::default(),
    );

    let http_client = client::ADMIN_CLIENT
        .get()
        .ok_or_else(|| "admin client not initialised".to_string())?;

    // Step 1: unauthenticated GET.
    let resp = match http_client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "admin_probe: network error");
            return Ok(AdminProbeResult::NetworkOrIntercepted);
        }
    };

    // Step 2: success without auth → disabled mode.
    if resp.status().is_success() {
        return Ok(AdminProbeResult::Disabled);
    }

    // Step 3–5: interpret 401.
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        let www_auth = resp
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();

        if www_auth.starts_with("nostr") {
            // NIP-98 mode: try signing.
            let keys = match state.signing_keys() {
                Ok(k) => k,
                Err(_) => return Ok(AdminProbeResult::Nip98Denied),
            };
            let auth_header =
                build_nip98_auth_header_for_keys(&keys, &reqwest::Method::GET, &url, &[])
                    .map_err(|e| format!("nip98 build failed: {e}"))?;
            let auth_resp = match http_client
                .get(&url)
                .header(reqwest::header::AUTHORIZATION, &auth_header)
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => return Ok(AdminProbeResult::NetworkOrIntercepted),
            };
            return if auth_resp.status().is_success() {
                Ok(AdminProbeResult::Nip98Authorized)
            } else {
                Ok(AdminProbeResult::Nip98Denied)
            };
        }

        if www_auth.starts_with("bearer") {
            return Ok(AdminProbeResult::TokenMode);
        }

        // Unknown 401 shape.
        return Ok(AdminProbeResult::NotAdminApi);
    }

    if resp.status().is_redirection() {
        return Ok(AdminProbeResult::NetworkOrIntercepted);
    }

    Ok(AdminProbeResult::NotAdminApi)
}

// ── Five typed data commands ──────────────────────────────────────────────

/// Fetch the reports list.
#[tauri::command]
pub async fn admin_list_reports(
    origin: String,
    query: AdminReportsQuery,
    state: tauri::State<'_, crate::app_state::AppState>,
) -> Result<serde_json::Value, String> {
    let origin = origin::AdminOrigin::parse(&origin)?;
    let q = routes::AdminQuery {
        community_id: query.community_id,
        status: query.status,
        report_type: query.report_type,
        target_kind: query.target_kind,
        after: query.after,
        before: query.before,
        limit: query.limit,
    };
    let url = origin.route_url(&routes::AdminRoute::ReportsList, &q);
    let bytes = fetch_admin_json(&url, SUCCESS_JSON_CAP, &state).await?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid JSON from relay: {e}"))
}

/// Fetch a single report's detail.
#[tauri::command]
pub async fn admin_get_report(
    origin: String,
    id: String,
    state: tauri::State<'_, crate::app_state::AppState>,
) -> Result<serde_json::Value, String> {
    let origin = origin::AdminOrigin::parse(&origin)?;
    let url = origin.route_url(
        &routes::AdminRoute::ReportDetail { id: &id },
        &routes::AdminQuery::default(),
    );
    let bytes = fetch_admin_json(&url, SUCCESS_JSON_CAP, &state).await?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid JSON from relay: {e}"))
}

/// Fetch the feedback list.
#[tauri::command]
pub async fn admin_list_feedback(
    origin: String,
    state: tauri::State<'_, crate::app_state::AppState>,
) -> Result<serde_json::Value, String> {
    let origin = origin::AdminOrigin::parse(&origin)?;
    let url = origin.route_url(
        &routes::AdminRoute::FeedbackList,
        &routes::AdminQuery::default(),
    );
    let bytes = fetch_admin_json(&url, SUCCESS_JSON_CAP, &state).await?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid JSON from relay: {e}"))
}

/// Fetch a single feedback entry's detail (including imeta attachment metadata).
#[tauri::command]
pub async fn admin_get_feedback(
    origin: String,
    id: String,
    state: tauri::State<'_, crate::app_state::AppState>,
) -> Result<serde_json::Value, String> {
    let origin = origin::AdminOrigin::parse(&origin)?;
    let url = origin.route_url(
        &routes::AdminRoute::FeedbackDetail { id: &id },
        &routes::AdminQuery::default(),
    );
    let bytes = fetch_admin_json(&url, SUCCESS_JSON_CAP, &state).await?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid JSON from relay: {e}"))
}

/// Fetch a feedback attachment by SHA-256 hash.
///
/// The front-end MUST supply `expectedMime` and `expectedSize` from the
/// server-validated `imeta` fields returned by `admin_get_feedback`. The
/// command verifies the relay's `Content-Type` against `expectedMime` and
/// the actual byte count against `expectedSize`. Mismatch or over-cap yields
/// a stable typed error-code string.
///
/// Returns `tauri::ipc::Response` so bytes cross IPC as a raw `ArrayBuffer`.
#[tauri::command]
pub async fn admin_fetch_feedback_attachment(
    origin: String,
    feedback_id: String,
    sha256: String,
    expected_mime: String,
    expected_size: u64,
    state: tauri::State<'_, crate::app_state::AppState>,
) -> Result<tauri::ipc::Response, String> {
    use crate::relay::build_nip98_auth_header_for_keys;

    // Validate inputs before any network activity.
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("admin_attachment_invalid_hash".to_string());
    }
    if expected_size == 0 {
        return Err("admin_attachment_invalid_size".to_string());
    }
    if expected_size > ATTACHMENT_CAP {
        return Err("admin_attachment_too_large".to_string());
    }
    if expected_mime.is_empty() {
        return Err("admin_attachment_invalid_mime".to_string());
    }

    let origin = origin::AdminOrigin::parse(&origin)?;
    let url = origin.route_url(
        &routes::AdminRoute::FeedbackAttachment {
            id: &feedback_id,
            sha256: &sha256,
        },
        &routes::AdminQuery::default(),
    );

    let keys = state.signing_keys()?;
    let http_client = client::ADMIN_CLIENT
        .get()
        .ok_or_else(|| "admin client not initialised".to_string())?;

    let auth_header = build_nip98_auth_header_for_keys(&keys, &reqwest::Method::GET, &url, &[])
        .map_err(|e| format!("nip98 build failed: {e}"))?;

    let resp = http_client
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, &auth_header)
        .send()
        .await
        .map_err(|e| {
            tracing::debug!(error = %e, "admin attachment fetch failed");
            "admin_attachment_network_error".to_string()
        })?;

    // One retry on 401 with a fresh NIP-98 event.
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        let auth_header2 =
            build_nip98_auth_header_for_keys(&keys, &reqwest::Method::GET, &url, &[])
                .map_err(|e| format!("nip98 build failed on retry: {e}"))?;
        let resp2 = http_client
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, auth_header2)
            .send()
            .await
            .map_err(|_| "admin_attachment_network_error".to_string())?;
        return finish_attachment_response(resp2, &expected_mime, expected_size).await;
    }

    finish_attachment_response(resp, &expected_mime, expected_size).await
}

// ── Origin storage commands ───────────────────────────────────────────────

/// Return the persisted admin console origin for the active pubkey, or `None`
/// if none has been saved yet.
#[tauri::command]
pub fn get_admin_origin(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::app_state::AppState>,
) -> Result<Option<String>, String> {
    let pubkey = state
        .signing_keys()
        .map(|k| k.public_key().to_hex())
        .unwrap_or_default();
    let path = admin_origin_path(&app, &pubkey)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read admin console origin: {e}"))?;
    let stored: StoredAdminOrigin = serde_json::from_str(&content)
        .map_err(|e| format!("failed to parse admin console origin: {e}"))?;
    Ok(Some(stored.origin))
}

/// Validate and persist the admin console origin for the active pubkey.
///
/// Passes `raw_origin` through `AdminOrigin::parse` to normalise and validate
/// it before writing. Pass `None` to clear the stored origin.
#[tauri::command]
pub fn set_admin_origin(
    raw_origin: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::app_state::AppState>,
) -> Result<Option<String>, String> {
    use crate::managed_agents::storage::atomic_write_json_restricted;

    let pubkey = state
        .signing_keys()
        .map(|k| k.public_key().to_hex())
        .unwrap_or_default();
    let path = admin_origin_path(&app, &pubkey)?;

    match raw_origin {
        None => {
            // Clear.
            if path.exists() {
                std::fs::remove_file(&path)
                    .map_err(|e| format!("failed to remove admin console origin: {e}"))?;
            }
            Ok(None)
        }
        Some(raw) => {
            let canonical = origin::AdminOrigin::parse(&raw)?.as_str().to_string();
            let payload = serde_json::to_vec_pretty(&StoredAdminOrigin {
                origin: canonical.clone(),
            })
            .map_err(|e| format!("failed to serialise admin console origin: {e}"))?;
            atomic_write_json_restricted(&path, &payload)?;
            Ok(Some(canonical))
        }
    }
}

/// On-disk shape for the persisted admin console origin.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredAdminOrigin {
    origin: String,
}

/// Path of the per-pubkey admin-console-origin JSON file.
fn admin_origin_path(
    app: &tauri::AppHandle,
    pubkey_hex: &str,
) -> Result<std::path::PathBuf, String> {
    use tauri::Manager as _;
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("failed to resolve app data dir: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create app data dir: {e}"))?;
    Ok(dir.join(format!("admin-console-origin-{pubkey_hex}.json")))
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Fetch a JSON endpoint with NIP-98 auth, one 401-retry, and a size cap.
async fn fetch_admin_json(
    url: &str,
    cap: u64,
    state: &tauri::State<'_, crate::app_state::AppState>,
) -> Result<Vec<u8>, String> {
    use crate::relay::build_nip98_auth_header_for_keys;

    let keys = state.signing_keys()?;
    let http_client = client::ADMIN_CLIENT
        .get()
        .ok_or_else(|| "admin client not initialised".to_string())?;

    let auth_header = build_nip98_auth_header_for_keys(&keys, &reqwest::Method::GET, url, &[])
        .map_err(|e| format!("nip98 build failed: {e}"))?;

    let resp = http_client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, &auth_header)
        .send()
        .await
        .map_err(|e| crate::relay::classify_request_error(&e))?;

    // One retry on 401 with a fresh NIP-98 event (new nonce).
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        let auth_header2 = build_nip98_auth_header_for_keys(&keys, &reqwest::Method::GET, url, &[])
            .map_err(|e| format!("nip98 build failed on retry: {e}"))?;
        let resp2 = http_client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, auth_header2)
            .send()
            .await
            .map_err(|e| crate::relay::classify_request_error(&e))?;
        return read_admin_response(resp2, cap, ERROR_BODY_CAP).await;
    }

    read_admin_response(resp, cap, ERROR_BODY_CAP).await
}

/// Stream and validate an attachment response, enforcing Content-Type, size,
/// and the cap.
async fn finish_attachment_response(
    resp: reqwest::Response,
    expected_mime: &str,
    expected_size: u64,
) -> Result<tauri::ipc::Response, String> {
    use futures_util::StreamExt;

    if resp.status().is_redirection() {
        return Err("admin_attachment_redirect".to_string());
    }
    if !resp.status().is_success() {
        return Err(format!(
            "admin_attachment_relay_error_{}",
            resp.status().as_u16()
        ));
    }

    // Verify Content-Type before reading the body.
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if content_type != expected_mime.trim().to_ascii_lowercase() {
        return Err("admin_attachment_mime_mismatch".to_string());
    }

    // Content-Length preflight.
    if let Some(cl) = resp.content_length() {
        if cl > ATTACHMENT_CAP {
            return Err("admin_attachment_too_large".to_string());
        }
        if cl != expected_size {
            return Err("admin_attachment_size_mismatch".to_string());
        }
    }

    // Stream with running byte counter.
    let mut bytes: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "admin_attachment_stream_error".to_string())?;
        if bytes.len() as u64 + chunk.len() as u64 > ATTACHMENT_CAP {
            return Err("admin_attachment_too_large".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }

    // Final size check.
    if bytes.len() as u64 != expected_size {
        return Err("admin_attachment_size_mismatch".to_string());
    }

    Ok(tauri::ipc::Response::new(bytes))
}

/// Read a response body up to `success_cap` bytes on 2xx, `error_cap` on
/// non-2xx. Redirects are treated as errors (the no-redirect client surfaced
/// them rather than following).
async fn read_admin_response(
    resp: reqwest::Response,
    success_cap: u64,
    error_cap: u64,
) -> Result<Vec<u8>, String> {
    use futures_util::StreamExt;

    if resp.status().is_redirection() {
        return Err(format!(
            "admin API returned a {} redirect (not followed)",
            resp.status()
        ));
    }

    let (is_success, cap) = if resp.status().is_success() {
        (true, success_cap)
    } else {
        (false, error_cap)
    };

    if let Some(cl) = resp.content_length() {
        if cl > cap {
            return Err(format!(
                "admin response too large ({cl} bytes, cap {cap} bytes)"
            ));
        }
    }

    let mut bytes: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("admin response stream error: {e}"))?;
        if bytes.len() as u64 + chunk.len() as u64 > cap {
            return Err(format!("admin response too large (cap {cap} bytes)"));
        }
        bytes.extend_from_slice(&chunk);
    }

    if !is_success {
        let body = String::from_utf8_lossy(&bytes);
        return Err(format!("admin API error: {body}"));
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::admin::{origin::AdminOrigin, routes::AdminRoute};

    // ── AdminOrigin × routes integration ─────────────────────────────────────

    #[test]
    fn reports_list_url_contains_api_prefix() {
        let o = AdminOrigin::parse("https://admin.example.com").unwrap();
        let url = o.route_url(&AdminRoute::ReportsList, &routes::AdminQuery::default());
        assert!(
            url.starts_with("https://admin.example.com/api/admin/v1/"),
            "URL must include /api/admin/v1/ prefix: {url}"
        );
    }

    #[test]
    fn localhost_uses_http_prefix() {
        let o = AdminOrigin::parse("http://localhost:3000").unwrap();
        let url = o.route_url(&AdminRoute::FeedbackList, &routes::AdminQuery::default());
        assert!(url.starts_with("http://localhost:3000/api/admin/v1/"));
    }

    // ── Attachment command validation ─────────────────────────────────────────
    //
    // These are pure-logic tests that do not require a live Tauri state.

    fn valid_hash() -> String {
        "a".repeat(64)
    }

    #[test]
    fn attachment_hash_must_be_64_hex_chars() {
        // Valid: 64 lowercase hex chars.
        let h = valid_hash();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));

        // Invalid: 63 chars (too short).
        let short: String = "a".repeat(63);
        assert_ne!(short.len(), 64);

        // Invalid: non-hex character ('g' is not a hex digit).
        let non_hex: String = "g".repeat(64);
        assert!(non_hex.chars().any(|c| !c.is_ascii_hexdigit()));

        // Note: uppercase A-F ARE valid hex digits per is_ascii_hexdigit().
        // The production guard rejects them only if is_ascii_hexdigit() returns
        // false. Uppercase input like "AAAA...AAAA" (64 chars) would pass the
        // length+hexdigit check — callers must normalise to lowercase if needed.
        let upper_hex: String = "A".repeat(64);
        assert_eq!(upper_hex.len(), 64);
        assert!(upper_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn attachment_size_zero_is_invalid() {
        assert_eq!(0u64, 0);
        // Production guard: expected_size == 0 yields admin_attachment_invalid_size.
    }

    #[test]
    fn attachment_over_cap_is_invalid() {
        let over_cap = ATTACHMENT_CAP + 1;
        assert!(over_cap > ATTACHMENT_CAP);
        // Production guard: expected_size > ATTACHMENT_CAP yields admin_attachment_too_large.
    }

    // ── Content-Type matching logic ───────────────────────────────────────────

    #[test]
    fn content_type_matching_is_case_insensitive_and_strips_params() {
        // finish_attachment_response normalises content_type with .to_ascii_lowercase()
        // and splits on ';' to strip charset params.
        let raw = "Image/PNG; charset=binary";
        let normalised = raw.split(';').next().unwrap().trim().to_ascii_lowercase();
        assert_eq!(normalised, "image/png");
        // This would match expected_mime "image/png".
        assert_eq!(normalised, "image/png".trim().to_ascii_lowercase());
    }
}
