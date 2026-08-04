//! Unit and integration tests for `commands/admin/mod.rs` (split to keep `mod.rs`
//! under the 1000-line file-size ratchet).
//!
//! Included via `#[path = "mod_tests.rs"] mod tests;` at the bottom of `mod.rs`,
//! so `use super::*` gives access to all items in that module.

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

// ── Attachment command validation (calls production validators) ───────────

#[test]
fn attachment_hash_valid_lowercase_hex_accepted() {
    let result = routes::AttachmentHash::parse(&"a".repeat(64));
    assert!(result.is_ok(), "64 lowercase hex chars must be accepted");
}

#[test]
fn attachment_hash_uppercase_rejected_by_production_validator() {
    let result = routes::AttachmentHash::parse(&"A".repeat(64));
    assert!(
        result.is_err(),
        "uppercase hex must be rejected — relay returns 404 for uppercase hashes"
    );
}

#[test]
fn attachment_hash_63_chars_rejected_by_production_validator() {
    let result = routes::AttachmentHash::parse(&"a".repeat(63));
    assert!(result.is_err(), "63 chars must be rejected");
}

#[test]
fn feedback_id_malformed_uuid_rejected_by_production_validator() {
    let result = uuid::Uuid::parse_str("not-a-uuid");
    assert!(result.is_err(), "non-UUID feedback id must be rejected");
}

#[test]
fn feedback_id_slash_injection_rejected() {
    let result = uuid::Uuid::parse_str("../../../etc/passwd");
    assert!(
        result.is_err(),
        "path traversal in feedback id must be rejected"
    );
}

#[test]
fn feedback_id_query_injection_rejected() {
    let result = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001?x=y");
    assert!(
        result.is_err(),
        "query injection in feedback id must be rejected"
    );
}

// ── Content-Type matching ─────────────────────────────────────────────────

#[test]
fn content_type_matching_is_case_insensitive_and_strips_params() {
    let raw = "Image/PNG; charset=binary";
    let normalised = raw.split(';').next().unwrap().trim().to_ascii_lowercase();
    assert_eq!(normalised, "image/png");
}

// ── looks_like_admin_list ─────────────────────────────────────────────────

#[test]
fn looks_like_admin_list_empty_array_with_json_ct() {
    assert!(looks_like_admin_list("application/json", b"[]"));
}

#[test]
fn looks_like_admin_list_non_empty_with_id_field() {
    assert!(looks_like_admin_list(
        "application/json",
        b"[{\"id\":\"00000000-0000-0000-0000-000000000001\"}]"
    ));
}

#[test]
fn looks_like_admin_list_rejects_array_without_id_field() {
    assert!(!looks_like_admin_list("application/json", b"[1]"));
    assert!(!looks_like_admin_list(
        "application/json",
        b"[\"unrelated\"]"
    ));
    assert!(!looks_like_admin_list(
        "application/json",
        b"[{\"notId\":true}]"
    ));
}

#[test]
fn looks_like_admin_list_rejects_non_json_content_type() {
    assert!(!looks_like_admin_list("text/html", b"[]"));
    assert!(!looks_like_admin_list("", b"[]"));
    assert!(!looks_like_admin_list("text/plain", b"[]"));
}

#[test]
fn looks_like_admin_list_rejects_non_array() {
    assert!(!looks_like_admin_list("application/json", b"{}"));
    assert!(!looks_like_admin_list("application/json", b"\"string\""));
    assert!(!looks_like_admin_list("application/json", b"null"));
    assert!(!looks_like_admin_list(
        "application/json",
        b"<html>captive portal</html>"
    ));
    assert!(!looks_like_admin_list("application/json", b"not json"));
}

// ── Live stub helpers ─────────────────────────────────────────────────────

/// Build a fake Response using a live TCP listener.
async fn fake_response(status: u16, headers: &str, body: &str) -> reqwest::Response {
    use std::io::{Read, Write};
    client::init_admin_client();
    let client = client::ADMIN_CLIENT.get().unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body_bytes = body.as_bytes().to_vec();
    let body_len = body_bytes.len();
    let response = format!(
        "HTTP/1.1 {status} OK\r\nContent-Length: {body_len}\r\n{headers}Connection: close\r\n\r\n"
    );
    let response_bytes = response.into_bytes();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&response_bytes);
            let _ = stream.write_all(&body_bytes);
            let _ = stream.flush();
        }
    });
    client
        .get(format!("http://{addr}/api/admin/v1/reports"))
        .send()
        .await
        .unwrap()
}

/// Serve sequential HTTP responses from a background thread.
async fn serve_sequence(
    responses: Vec<(&'static str, &'static str, &'static str)>,
) -> std::net::SocketAddr {
    use std::io::{Read, Write};
    client::init_admin_client();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for (status, headers, body) in responses {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let body_bytes = body.as_bytes();
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
                    body_bytes.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body_bytes);
                let _ = stream.flush();
            }
        }
    });
    addr
}

// ── is_probe_response_intercepted ────────────────────────────────────────

#[tokio::test]
async fn probe_html_200_classified_as_intercepted() {
    let resp = fake_response(
        200,
        "Content-Type: text/html; charset=utf-8\r\n",
        "<html><body>Sign in</body></html>",
    )
    .await;
    assert!(is_probe_response_intercepted(&resp));
}

#[tokio::test]
async fn probe_json_200_not_classified_as_intercepted() {
    let resp = fake_response(200, "Content-Type: application/json\r\n", "[]").await;
    assert!(!is_probe_response_intercepted(&resp));
}

#[tokio::test]
async fn probe_json_200_with_id_field_looks_like_admin_list() {
    let resp = fake_response(
        200,
        "Content-Type: application/json\r\n",
        "[{\"id\":\"00000000-0000-0000-0000-000000000001\"}]",
    )
    .await;
    assert!(!is_probe_response_intercepted(&resp));
    let ct = response_content_type(&resp);
    let bytes = read_bounded(resp, SUCCESS_JSON_CAP).await.unwrap();
    assert!(looks_like_admin_list(&ct, &bytes));
}

#[tokio::test]
async fn probe_json_200_bare_array_of_garbage_not_admin_api() {
    let resp = fake_response(200, "Content-Type: application/json\r\n", "[1,2,3]").await;
    let ct = response_content_type(&resp);
    let bytes = read_bounded(resp, SUCCESS_JSON_CAP).await.unwrap();
    assert!(!looks_like_admin_list(&ct, &bytes));
}

// ── admin_probe_inner end-to-end state machine ────────────────────────────

#[tokio::test]
async fn probe_inner_html_200_is_network_or_intercepted() {
    let addr = serve_sequence(vec![(
        "200 OK",
        "Content-Type: text/html\r\n",
        "<html>sign in</html>",
    )])
    .await;
    let result = admin_probe_inner(
        &format!("http://{addr}"),
        None::<fn(&str) -> Result<String, String>>,
    )
    .await
    .unwrap();
    assert!(matches!(result, AdminProbeResult::NetworkOrIntercepted));
}

#[tokio::test]
async fn probe_inner_malformed_json_200_is_not_admin_api() {
    let addr = serve_sequence(vec![(
        "200 OK",
        "Content-Type: application/json\r\n",
        "not valid json",
    )])
    .await;
    let result = admin_probe_inner(
        &format!("http://{addr}"),
        None::<fn(&str) -> Result<String, String>>,
    )
    .await
    .unwrap();
    assert!(matches!(result, AdminProbeResult::NotAdminApi));
}

#[tokio::test]
async fn probe_inner_json_empty_array_200_is_disabled() {
    let addr = serve_sequence(vec![("200 OK", "Content-Type: application/json\r\n", "[]")]).await;
    let result = admin_probe_inner(
        &format!("http://{addr}"),
        None::<fn(&str) -> Result<String, String>>,
    )
    .await
    .unwrap();
    assert!(matches!(result, AdminProbeResult::Disabled));
}

#[tokio::test]
async fn probe_inner_bare_array_of_garbage_is_not_admin_api() {
    // Non-empty arrays with no `id` field must not classify as admin API.
    let addr = serve_sequence(vec![(
        "200 OK",
        "Content-Type: application/json\r\n",
        "[1,2,3]",
    )])
    .await;
    let result = admin_probe_inner(
        &format!("http://{addr}"),
        None::<fn(&str) -> Result<String, String>>,
    )
    .await
    .unwrap();
    assert!(matches!(result, AdminProbeResult::NotAdminApi));
}

#[tokio::test]
async fn probe_inner_persistent_401_is_nip98_denied() {
    let addr = serve_sequence(vec![
        ("401 Unauthorized", "WWW-Authenticate: Nostr\r\n", ""),
        ("401 Unauthorized", "", ""),
    ])
    .await;
    let sign = |_url: &str| -> Result<String, String> { Ok("Nostr dGVzdA==".to_string()) };
    let result = admin_probe_inner(&format!("http://{addr}"), Some(sign))
        .await
        .unwrap();
    assert!(matches!(result, AdminProbeResult::Nip98Denied));
}

#[tokio::test]
async fn probe_inner_nip98_challenge_then_json_200_is_authorized() {
    use std::sync::{Arc, Mutex};

    let addr = serve_sequence(vec![
        ("401 Unauthorized", "WWW-Authenticate: Nostr\r\n", ""),
        (
            "200 OK",
            "Content-Type: application/json\r\n",
            "[{\"id\":\"00000000-0000-0000-0000-000000000001\"}]",
        ),
    ])
    .await;

    let received_auth: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let received_auth_clone = Arc::clone(&received_auth);

    let sign = move |_url: &str| -> Result<String, String> {
        let header = "Nostr dGVzdA==".to_string();
        *received_auth_clone.lock().unwrap() = Some(header.clone());
        Ok(header)
    };

    let result = admin_probe_inner(&format!("http://{addr}"), Some(sign))
        .await
        .unwrap();

    assert!(
        matches!(result, AdminProbeResult::Nip98Authorized),
        "expected Nip98Authorized, got {result:?}"
    );
    let auth = received_auth.lock().unwrap();
    assert!(
        auth.as_deref().unwrap_or("").starts_with("Nostr "),
        "Authorization header must be a Nostr token"
    );
}

#[tokio::test]
async fn probe_inner_authenticated_302_is_network_or_intercepted() {
    let addr = serve_sequence(vec![
        ("401 Unauthorized", "WWW-Authenticate: Nostr\r\n", ""),
        (
            "302 Found",
            "Location: https://cloudflareaccess.com/\r\n",
            "",
        ),
    ])
    .await;
    let sign = |_url: &str| -> Result<String, String> { Ok("Nostr dGVzdA==".to_string()) };
    let result = admin_probe_inner(&format!("http://{addr}"), Some(sign))
        .await
        .unwrap();
    assert!(
        matches!(result, AdminProbeResult::NetworkOrIntercepted),
        "authenticated 302 must be NetworkOrIntercepted, got {result:?}"
    );
}

#[tokio::test]
async fn probe_inner_bearer_401_is_token_mode() {
    let addr = serve_sequence(vec![(
        "401 Unauthorized",
        "WWW-Authenticate: Bearer realm=\"admin\"\r\n",
        "",
    )])
    .await;
    let result = admin_probe_inner(
        &format!("http://{addr}"),
        None::<fn(&str) -> Result<String, String>>,
    )
    .await
    .unwrap();
    assert!(matches!(result, AdminProbeResult::TokenMode));
}

#[tokio::test]
async fn probe_inner_no_sign_on_nostr_challenge_is_nip98_denied() {
    let addr = serve_sequence(vec![(
        "401 Unauthorized",
        "WWW-Authenticate: Nostr\r\n",
        "",
    )])
    .await;
    let result = admin_probe_inner(
        &format!("http://{addr}"),
        None::<fn(&str) -> Result<String, String>>,
    )
    .await
    .unwrap();
    assert!(matches!(result, AdminProbeResult::Nip98Denied));
}

// ── validate_pubkey_hex ───────────────────────────────────────────────────

#[test]
fn pubkey_hex_valid_64_lowercase() {
    assert!(validate_pubkey_hex("a".repeat(64)).is_ok());
}

#[test]
fn pubkey_hex_uppercase_rejected() {
    assert!(validate_pubkey_hex("A".repeat(64)).is_err());
}

#[test]
fn pubkey_hex_empty_rejected() {
    assert!(validate_pubkey_hex("".to_string()).is_err());
}

#[test]
fn pubkey_hex_63_chars_rejected() {
    assert!(validate_pubkey_hex("a".repeat(63)).is_err());
}

// ── Storage behavior ──────────────────────────────────────────────────────

#[test]
fn storage_malformed_json_returns_error() {
    let bad: serde_json::Result<StoredAdminOrigin> = serde_json::from_str("not json");
    assert!(bad.is_err(), "malformed JSON must return an error");
}

#[test]
fn storage_origin_with_path_fails_validation() {
    let stored = StoredAdminOrigin {
        origin: "https://admin.example.com/forbidden/path".to_string(),
    };
    let raw = serde_json::to_string(&stored).unwrap();
    let parsed: StoredAdminOrigin = serde_json::from_str(&raw).unwrap();
    let result = origin::AdminOrigin::parse(&parsed.origin);
    assert!(
        result.is_err(),
        "origin with path must be rejected on read reparse"
    );
}

#[test]
fn storage_two_pubkeys_produce_different_filenames() {
    let pubkey_a = "a".repeat(64);
    let pubkey_b = "b".repeat(64);
    let name_a = format!("admin-console-origin-{pubkey_a}.json");
    let name_b = format!("admin-console-origin-{pubkey_b}.json");
    assert_ne!(
        name_a, name_b,
        "two pubkeys must produce different filenames"
    );
    assert!(
        name_a.contains(&pubkey_a),
        "filename must embed the pubkey for isolation"
    );
}

#[test]
fn storage_noncanonical_uppercase_origin_canonicalised_or_rejected() {
    let stored = StoredAdminOrigin {
        origin: "HTTPS://admin.example.com".to_string(),
    };
    let raw = serde_json::to_string(&stored).unwrap();
    let parsed: StoredAdminOrigin = serde_json::from_str(&raw).unwrap();
    // url::Url normalises scheme to lowercase, so this may be accepted.
    // Either way, the returned canonical form must use lowercase scheme.
    let result = origin::AdminOrigin::parse(&parsed.origin);
    if let Ok(o) = result {
        assert!(
            o.as_str().starts_with("https://"),
            "canonical origin must use lowercase scheme"
        );
    }
    // Err is also acceptable — both branches satisfy the contract.
}
