//! Blossom kind:24242 compatibility wrappers over the canonical verifier.

use axum::http::{
    uri::{Authority, Scheme},
    Method,
};
use buzz_auth::{
    verify_blossom_authorization, CanonicalBlossomRequest, EvidenceError, SystemEvidenceClock,
};

use crate::error::MediaError;

/// Blossom kind:24242 verbs Buzz currently accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlossomVerb {
    Upload,
    Get,
}

/// Verify common kind:24242 Blossom auth event validity:
///   1. Schnorr signature
///   2. kind == 24242
///   3. `t` tag matches `verb`
///   4. `expiration` tag in the future
///   5. `created_at` in the past (with 5s clock-skew tolerance)
///   6. If `server` tags present, our domain must appear in at least one
///
/// Does NOT check verb-specific scope tags (`x` for upload, `x` OR `server`
/// for get). Call this BEFORE trusting the event's pubkey for scope resolution.
pub fn verify_blossom_auth_event_for_verb(
    auth_event: &nostr::Event,
    verb: BlossomVerb,
    server_domain: Option<&str>,
    max_age_secs: u64,
) -> Result<(), MediaError> {
    let object = match (verb, exact_optional_object_scope(auth_event)?) {
        (_, Some(object)) => object,
        (BlossomVerb::Get, None) => "0".repeat(64),
        (BlossomVerb::Upload, None) => return Err(MediaError::MissingTag("x")),
    };
    let method = match verb {
        BlossomVerb::Upload => Method::PUT,
        BlossomVerb::Get => Method::GET,
    };
    verify_canonical(auth_event, method, server_domain, &object, max_age_secs)
}

/// Verify common upload auth event validity.
///
/// Kept as the upload-shaped public wrapper for existing callers; new verb-aware
/// code should prefer [`verify_blossom_auth_event_for_verb`].
pub fn verify_blossom_auth_event(
    auth_event: &nostr::Event,
    server_domain: Option<&str>,
    max_age_secs: u64,
) -> Result<(), MediaError> {
    verify_blossom_auth_event_for_verb(auth_event, BlossomVerb::Upload, server_domain, max_age_secs)
}

/// Normalize a Blossom `server` tag value (or a bound tenant host) into the
/// canonical host form used as the community lookup key.
///
/// A `server` tag may be a bare authority (`relay.example:3100`, what the stock
/// CLI emits) or a full URL (`https://relay.example/`). We strip an optional
/// scheme and path down to the authority, then apply the one shared
/// [`buzz_core::tenant::normalize_host`] rule so the comparison agrees with how
/// the WS/HTTP/git doors resolve tenants.
fn canonical_authority(server_domain: Option<&str>) -> Result<Authority, MediaError> {
    let normalized = server_domain
        .map(buzz_core::tenant::normalize_host)
        .unwrap_or_else(|| "localhost".to_owned());
    normalized.parse().map_err(|_| MediaError::ServerMismatch)
}

fn exact_object_scope(auth_event: &nostr::Event) -> Result<String, MediaError> {
    exact_optional_object_scope(auth_event)?.ok_or(MediaError::MissingTag("x"))
}

fn exact_optional_object_scope(auth_event: &nostr::Event) -> Result<Option<String>, MediaError> {
    let mut scopes = auth_event
        .tags
        .iter()
        .filter(|tag| tag.kind().to_string() == "x");
    let first = scopes.next().map(|tag| {
        tag.content()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or(MediaError::InvalidAuthEvent)
    });
    if scopes.next().is_some() {
        return Err(MediaError::InvalidAuthEvent);
    }
    first.transpose()
}

fn verify_canonical(
    auth_event: &nostr::Event,
    method: Method,
    server_domain: Option<&str>,
    sha256: &str,
    maximum_age_seconds: u64,
) -> Result<(), MediaError> {
    let now = nostr::Timestamp::now().as_secs();
    let created = auth_event.created_at.as_secs();
    if maximum_age_seconds == 0
        || created > now.saturating_add(5)
        || now > created.saturating_add(maximum_age_seconds)
    {
        return Err(MediaError::TimestampOutOfWindow);
    }
    let path = if method == Method::PUT {
        "/upload".to_owned()
    } else {
        format!("/media/{sha256}")
    };
    let request = CanonicalBlossomRequest::from_server_parts(
        &Scheme::HTTPS,
        &canonical_authority(server_domain)?,
        &method,
        &path.parse().map_err(|_| MediaError::InvalidAuthEvent)?,
        sha256,
    )
    .map_err(map_evidence_error)?;
    verify_blossom_authorization(auth_event, &request, &SystemEvidenceClock)
        .map(|_| ())
        .map_err(map_evidence_error)
}

fn map_evidence_error(error: EvidenceError) -> MediaError {
    match error {
        EvidenceError::Expired => MediaError::TokenExpired,
        _ => MediaError::InvalidAuthEvent,
    }
}

/// Verify a kind:24242 Blossom upload auth event, including the x tag hash check.
///
/// Calls [`verify_blossom_auth_event`] first, then verifies that at least one
/// `x` tag matches `sha256` (BUD-11 §6: "at least one x tag matches").
pub fn verify_blossom_upload_auth(
    auth_event: &nostr::Event,
    sha256: &str,
    server_domain: Option<&str>,
    max_age_secs: u64,
) -> Result<(), MediaError> {
    if exact_object_scope(auth_event)? != sha256 {
        return Err(MediaError::HashMismatch);
    }
    verify_canonical(auth_event, Method::PUT, server_domain, sha256, max_age_secs)
}

/// Verify a kind:24242 Blossom get auth event for one requested blob.
///
/// BUD-01 permits either blob-scoped authorization (`x` tag matches `sha256`)
/// or server-scoped authorization (`server` tag matches this relay host). The
/// latter intentionally grants reads for all blobs on the host until expiration;
/// callers must still apply relay membership after this verifier returns.
pub fn verify_blossom_get_auth(
    auth_event: &nostr::Event,
    sha256: &str,
    server_domain: Option<&str>,
    max_age_secs: u64,
) -> Result<(), MediaError> {
    verify_canonical(auth_event, Method::GET, server_domain, sha256, max_age_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

    fn build_valid_auth(keys: &Keys, sha256: &str) -> nostr::Event {
        let now = Timestamp::now().as_secs();
        let exp_str = (now + 300).to_string();
        let tags = vec![
            Tag::parse(["t", "upload"]).unwrap(),
            Tag::parse(["x", sha256]).unwrap(),
            Tag::parse(["expiration", &exp_str]).unwrap(),
        ];
        EventBuilder::new(Kind::from(24242), "Upload buzz-media")
            .tags(tags)
            .sign_with_keys(keys)
            .unwrap()
    }

    #[test]
    fn test_verify_valid() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let event = build_valid_auth(&keys, &sha256);
        assert!(verify_blossom_upload_auth(&event, &sha256, None, 600).is_ok());
    }

    #[test]
    fn test_verify_auth_event_valid() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let event = build_valid_auth(&keys, &sha256);
        assert!(verify_blossom_auth_event(&event, None, 600).is_ok());
    }

    fn build_get_auth(keys: &Keys, tags: Vec<Tag>) -> nostr::Event {
        EventBuilder::new(Kind::from(24242), "Get buzz-media")
            .tags(tags)
            .sign_with_keys(keys)
            .unwrap()
    }

    #[test]
    fn test_verify_get_accepts_matching_x_without_server_tag() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let now = Timestamp::now().as_secs();
        let exp_str = (now + 300).to_string();
        let event = build_get_auth(
            &keys,
            vec![
                Tag::parse(["t", "get"]).unwrap(),
                Tag::parse(["x", &sha256]).unwrap(),
                Tag::parse(["expiration", &exp_str]).unwrap(),
            ],
        );

        assert!(verify_blossom_get_auth(&event, &sha256, Some("relay.example"), 600).is_ok());
    }

    #[test]
    fn test_verify_get_accepts_matching_server_without_x_tag() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let now = Timestamp::now().as_secs();
        let exp_str = (now + 300).to_string();
        let event = build_get_auth(
            &keys,
            vec![
                Tag::parse(["t", "get"]).unwrap(),
                Tag::parse(["server", "https://Relay.Example./media/ignored"]).unwrap(),
                Tag::parse(["expiration", &exp_str]).unwrap(),
            ],
        );

        assert!(verify_blossom_get_auth(&event, &sha256, Some("relay.example"), 600).is_ok());
        assert!(verify_blossom_auth_event_for_verb(
            &event,
            BlossomVerb::Get,
            Some("relay.example"),
            600,
        )
        .is_ok());
    }

    #[test]
    fn compatibility_maximum_age_can_only_shorten_the_canonical_bound() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let now = Timestamp::now().as_secs();
        let expiration = (now + 300).to_string();
        let event = EventBuilder::new(Kind::from(24242), "Upload buzz-media")
            .tags([
                Tag::parse(["t", "upload"]).unwrap(),
                Tag::parse(["x", sha256.as_str()]).unwrap(),
                Tag::parse(["expiration", expiration.as_str()]).unwrap(),
            ])
            .custom_created_at(Timestamp::from(now.saturating_sub(2)))
            .sign_with_keys(&keys)
            .unwrap();

        assert!(verify_blossom_upload_auth(&event, &sha256, None, 10).is_ok());
        assert!(matches!(
            verify_blossom_upload_auth(&event, &sha256, None, 1),
            Err(MediaError::TimestampOutOfWindow)
        ));
        assert!(matches!(
            verify_blossom_upload_auth(&event, &sha256, None, 0),
            Err(MediaError::TimestampOutOfWindow)
        ));
    }

    #[test]
    fn test_verify_get_rejects_upload_verb() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let event = build_valid_auth(&keys, &sha256);

        assert!(matches!(
            verify_blossom_get_auth(&event, &sha256, Some("relay.example"), 600),
            Err(MediaError::InvalidAuthEvent)
        ));
    }

    #[test]
    fn test_verify_get_requires_x_or_server_scope() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let other_hash = "b".repeat(64);
        let now = Timestamp::now().as_secs();
        let exp_str = (now + 300).to_string();
        let event = build_get_auth(
            &keys,
            vec![
                Tag::parse(["t", "get"]).unwrap(),
                Tag::parse(["x", &other_hash]).unwrap(),
                Tag::parse(["expiration", &exp_str]).unwrap(),
            ],
        );

        assert!(matches!(
            verify_blossom_get_auth(&event, &sha256, Some("relay.example"), 600),
            Err(MediaError::InvalidAuthEvent)
        ));
    }

    #[test]
    fn test_verify_get_rejects_wrong_server_scope() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let now = Timestamp::now().as_secs();
        let exp_str = (now + 300).to_string();
        let event = build_get_auth(
            &keys,
            vec![
                Tag::parse(["t", "get"]).unwrap(),
                Tag::parse(["server", "other.example"]).unwrap(),
                Tag::parse(["expiration", &exp_str]).unwrap(),
            ],
        );

        assert!(matches!(
            verify_blossom_get_auth(&event, &sha256, Some("relay.example"), 600),
            Err(MediaError::InvalidAuthEvent)
        ));
    }

    #[test]
    fn test_verify_hash_mismatch() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let event = build_valid_auth(&keys, &sha256);
        let wrong_hash = "b".repeat(64);
        assert!(matches!(
            verify_blossom_upload_auth(&event, &wrong_hash, None, 600),
            Err(MediaError::HashMismatch)
        ));
    }

    #[test]
    fn test_verify_wrong_kind() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let now = Timestamp::now().as_secs();
        let exp_str = (now + 300).to_string();
        let tags = vec![
            Tag::parse(["t", "upload"]).unwrap(),
            Tag::parse(["x", &sha256]).unwrap(),
            Tag::parse(["expiration", &exp_str]).unwrap(),
        ];
        let event = EventBuilder::new(Kind::from(27235), "wrong kind")
            .tags(tags)
            .sign_with_keys(&keys)
            .unwrap();
        assert!(matches!(
            verify_blossom_upload_auth(&event, &sha256, None, 600),
            Err(MediaError::InvalidAuthEvent)
        ));
    }

    #[test]
    fn test_verify_multi_x_tags() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let other_hash = "b".repeat(64);
        let now = Timestamp::now().as_secs();
        let exp_str = (now + 300).to_string();
        let tags = vec![
            Tag::parse(["t", "upload"]).unwrap(),
            Tag::parse(["x", &other_hash]).unwrap(),
            Tag::parse(["x", &sha256]).unwrap(),
            Tag::parse(["expiration", &exp_str]).unwrap(),
        ];
        let event = EventBuilder::new(Kind::from(24242), "Upload multi-x")
            .tags(tags)
            .sign_with_keys(&keys)
            .unwrap();
        // Ambiguous object scopes fail closed, including when one value matches.
        assert!(matches!(
            verify_blossom_upload_auth(&event, &sha256, None, 600),
            Err(MediaError::InvalidAuthEvent)
        ));
    }

    #[test]
    fn test_server_tag_enforcement() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let now = Timestamp::now().as_secs();
        let exp_str = (now + 300).to_string();
        let tags = vec![
            Tag::parse(["t", "upload"]).unwrap(),
            Tag::parse(["x", &sha256]).unwrap(),
            Tag::parse(["expiration", &exp_str]).unwrap(),
            Tag::parse(["server", "other.example.com"]).unwrap(),
        ];
        let event = EventBuilder::new(Kind::from(24242), "Upload scoped")
            .tags(tags)
            .sign_with_keys(&keys)
            .unwrap();
        // Should fail — server tag present but doesn't match our domain
        assert!(matches!(
            verify_blossom_upload_auth(&event, &sha256, Some("buzz.example.com"), 600),
            Err(MediaError::InvalidAuthEvent)
        ));
        // Should pass when our domain matches
        assert!(
            verify_blossom_upload_auth(&event, &sha256, Some("other.example.com"), 600).is_ok()
        );
        // Should fail when server_domain is None — fail closed
        assert!(matches!(
            verify_blossom_upload_auth(&event, &sha256, None, 600),
            Err(MediaError::InvalidAuthEvent)
        ));
    }

    #[test]
    fn test_no_server_tags_always_passes() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let event = build_valid_auth(&keys, &sha256);
        // No server tags → passes regardless of our domain
        assert!(verify_blossom_upload_auth(&event, &sha256, Some("any.domain.com"), 600).is_ok());
    }

    /// A `server` tag is matched against the *bound tenant host* under the
    /// shared `normalize_host` rule, so equivalent host spellings agree — the
    /// stock CLI's bare `host:port`, an explicit default port, a trailing dot,
    /// mixed case, and a full URL all match the same bound host. This is the
    /// regression guard for the multi-tenant media blocker: a non-primary
    /// tenant must accept its own server-tagged client.
    #[test]
    fn test_server_tag_normalized_against_bound_host() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let now = Timestamp::now().as_secs();
        let exp_str = (now + 300).to_string();
        let build = |server: &str| {
            let tags = vec![
                Tag::parse(["t", "upload"]).unwrap(),
                Tag::parse(["x", &sha256]).unwrap(),
                Tag::parse(["expiration", &exp_str]).unwrap(),
                Tag::parse(["server", server]).unwrap(),
            ];
            EventBuilder::new(Kind::from(24242), "Upload scoped")
                .tags(tags)
                .sign_with_keys(&keys)
                .unwrap()
        };

        // Non-primary tenant host with explicit non-default port (the live
        // repro: tenant B on 127.0.0.1:3100). Stock CLI tags `host:port`.
        assert!(verify_blossom_upload_auth(
            &build("127.0.0.1:3100"),
            &sha256,
            Some("127.0.0.1:3100"),
            600
        )
        .is_ok());

        // Equivalence under normalize_host: explicit default port, trailing
        // dot, mixed case, and a full URL all collapse to the bound host.
        for tag in [
            "Relay.Example:443",
            "relay.example.",
            "RELAY.EXAMPLE",
            "https://relay.example/",
        ] {
            assert!(
                verify_blossom_upload_auth(&build(tag), &sha256, Some("relay.example"), 600)
                    .is_ok(),
                "server tag {tag:?} should match bound host relay.example"
            );
        }

        // A different tenant host still fails closed.
        assert!(matches!(
            verify_blossom_upload_auth(
                &build("127.0.0.1:3100"),
                &sha256,
                Some("127.0.0.1:3200"),
                600
            ),
            Err(MediaError::InvalidAuthEvent)
        ));
    }

    #[test]
    fn test_empty_content_rejected() {
        let keys = Keys::generate();
        let sha256 = "a".repeat(64);
        let now = Timestamp::now().as_secs();
        let exp_str = (now + 300).to_string();
        let tags = vec![
            Tag::parse(["t", "upload"]).unwrap(),
            Tag::parse(["x", &sha256]).unwrap(),
            Tag::parse(["expiration", &exp_str]).unwrap(),
        ];
        // Empty content — BUD-11 requires a human-readable string
        let event = EventBuilder::new(Kind::from(24242), "")
            .tags(tags)
            .sign_with_keys(&keys)
            .unwrap();
        assert!(matches!(
            verify_blossom_auth_event(&event, None, 600),
            Err(MediaError::InvalidAuthEvent)
        ));
    }
}
