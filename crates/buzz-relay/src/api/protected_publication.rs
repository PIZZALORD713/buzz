//! Private route-bound inputs for protected Git and media publication callers.

use buzz_auth::{
    AuthContext, BlossomAction, CanonicalBlossomRequest, CanonicalGitSmartHttpRequest,
    GitSmartHttpOperation, RouteCapability,
};
use buzz_db::authorization_version::{
    AuthorizationProtectedObjectKind, ProtectedPublicationCoordinate,
    ProtectedPublicationOperationIdentity,
};
use nostr::PublicKey;

use crate::authorization_runtime::{
    FinalizedProtectedPublicationAuthorization, ProtectedPublicationAuthorizationError,
    ProtectedPublicationAuthorizationHandle, ProtectedPublicationAuthorizationIntent,
    ProtectedPublicationEvidence, ProtectedPublicationObserver, VerifiedProtectedPublicationRoute,
};

/// Enforce the protected-door ordering invariant shared by Git and media:
/// origin-sealed protected finalization must succeed before any legacy
/// membership, moderation, or repository-admission query is allowed to run.
pub(crate) async fn finalize_before_legacy_admission<T, E, F, FFut, A, AFut>(
    finalize: F,
    admit: A,
) -> Result<T, E>
where
    F: FnOnce() -> FFut,
    FFut: std::future::Future<Output = Result<T, E>>,
    A: FnOnce() -> AFut,
    AFut: std::future::Future<Output = Result<(), E>>,
{
    let finalized = finalize().await?;
    admit().await?;
    Ok(finalized)
}

/// Preserve the only safe post-stage publication order shared by protected
/// Git and media mutations.
///
/// The commit closure is the operation-specific restore boundary: it owns the
/// external Pending/fence lifecycle and returns only after the canonical DB
/// transaction has reached a terminal restore state. Cache/projection work is
/// therefore unreachable before a committed witness exists, and the final
/// recheck is the last asynchronous authority step before response creation.
pub(crate) async fn commit_observe_project_revalidate<
    C,
    W,
    E,
    Commit,
    CommitFuture,
    Validate,
    Observe,
    ObserveFuture,
    Project,
    ProjectFuture,
    Revalidate,
    RevalidateFuture,
>(
    commit: Commit,
    validate: Validate,
    observe: Observe,
    project: Project,
    revalidate: Revalidate,
) -> Result<(), E>
where
    Commit: FnOnce() -> CommitFuture,
    CommitFuture: std::future::Future<Output = Result<C, E>>,
    Validate: FnOnce(&C) -> Result<(), E>,
    Observe: FnOnce(C) -> ObserveFuture,
    ObserveFuture: std::future::Future<Output = Result<W, E>>,
    Project: FnOnce() -> ProjectFuture,
    ProjectFuture: std::future::Future<Output = Result<(), E>>,
    Revalidate: FnOnce(W) -> RevalidateFuture,
    RevalidateFuture: std::future::Future<Output = Result<(), E>>,
{
    let committed = commit().await?;
    validate(&committed)?;
    let live = observe(committed).await?;
    project().await?;
    revalidate(live).await
}

pub(crate) fn verify_git_proxy_direct_evidence(
    verifier: &buzz_auth::TrustedProxyAssertionVerifier,
    headers: &axum::http::HeaderMap,
    domain: buzz_core::CommunityId,
    authorization: &buzz_auth::VerifiedGitSmartHttpAuthorization,
) -> Result<buzz_auth::VerifiedDirectEvidence, buzz_auth::EvidenceError> {
    let binding = authorization.evidence_binding(domain)?;
    let assertion = verifier.verify(headers, &binding)?;
    buzz_auth::verify_git_smart_http_direct(authorization, &binding, assertion)
}

pub(crate) fn verify_media_proxy_direct_evidence(
    verifier: &buzz_auth::TrustedProxyAssertionVerifier,
    headers: &axum::http::HeaderMap,
    domain: buzz_core::CommunityId,
    authorization: &buzz_auth::VerifiedBlossomAuthorization,
) -> Result<buzz_auth::VerifiedDirectEvidence, buzz_auth::EvidenceError> {
    let binding = authorization.evidence_binding(domain)?;
    let assertion = verifier.verify(headers, &binding)?;
    buzz_auth::verify_blossom_direct(authorization, &binding, assertion)
}

#[derive(Clone)]
enum ProtectedPublicationRouteTarget {
    Git {
        owner: Box<str>,
        repository: Box<str>,
        operation: GitSmartHttpOperation,
    },
    Media {
        requested_path: Box<str>,
        object_sha256: Box<str>,
        action: BlossomAction,
    },
}

/// Finalized authority, optional mutation identity, and live observer installed
/// by root composition for one protected publication request.
///
/// Every present input is already sealed by its owning layer. Transport code
/// may consume it, but cannot rebuild authority from request fields.
#[derive(Clone)]
pub struct ProtectedPublicationAccess {
    context: AuthContext,
    coordinate: ProtectedPublicationCoordinate,
    operation: Option<ProtectedPublicationOperationIdentity>,
    observer: ProtectedPublicationObserver,
    route: ProtectedPublicationRouteTarget,
}

impl ProtectedPublicationAccess {
    pub(crate) fn from_git(
        finalized: FinalizedProtectedPublicationAuthorization,
        route: &CanonicalGitSmartHttpRequest,
    ) -> Result<Self, ProtectedPublicationAuthorizationError> {
        let (context, coordinate, operation, observer) = finalized.into_parts();
        let (capability, mutates) = match route.operation() {
            GitSmartHttpOperation::AdvertiseUploadPack | GitSmartHttpOperation::UploadPack => {
                (RouteCapability::GitRead, false)
            }
            GitSmartHttpOperation::AdvertiseReceivePack => (RouteCapability::GitWrite, false),
            GitSmartHttpOperation::ReceivePack => (RouteCapability::GitWrite, true),
        };
        if coordinate.object_kind() != AuthorizationProtectedObjectKind::Repository
            || coordinate.authorization_domain() != context.authorization_domain()
            || context.capability() != capability
            || mutates != operation.is_some()
        {
            return Err(ProtectedPublicationAuthorizationError::RouteMismatch);
        }
        Ok(Self {
            context,
            coordinate,
            operation,
            observer,
            route: ProtectedPublicationRouteTarget::Git {
                owner: route.owner().into(),
                repository: route.repository().into(),
                operation: route.operation(),
            },
        })
    }

    pub(crate) fn from_media(
        finalized: FinalizedProtectedPublicationAuthorization,
        route: &CanonicalBlossomRequest,
    ) -> Result<Self, ProtectedPublicationAuthorizationError> {
        let (context, coordinate, operation, observer) = finalized.into_parts();
        let (capability, mutates) = match route.action() {
            BlossomAction::Upload => (RouteCapability::MediaWrite, true),
            BlossomAction::Get | BlossomAction::Head => (RouteCapability::MediaRead, false),
        };
        if coordinate.object_kind() != AuthorizationProtectedObjectKind::Media
            || coordinate.authorization_domain() != context.authorization_domain()
            || context.capability() != capability
            || mutates != operation.is_some()
        {
            return Err(ProtectedPublicationAuthorizationError::RouteMismatch);
        }
        Ok(Self {
            context,
            coordinate,
            operation,
            observer,
            route: ProtectedPublicationRouteTarget::Media {
                requested_path: route.requested_path().into(),
                object_sha256: route.object_sha256().into(),
                action: route.action(),
            },
        })
    }

    pub(crate) const fn context(&self) -> &AuthContext {
        &self.context
    }

    pub(crate) const fn operation(&self) -> Option<ProtectedPublicationOperationIdentity> {
        self.operation
    }

    pub(crate) const fn coordinate(&self) -> &ProtectedPublicationCoordinate {
        &self.coordinate
    }

    pub(crate) const fn observer(&self) -> &ProtectedPublicationObserver {
        &self.observer
    }

    pub(crate) fn matches_git(
        &self,
        domain: buzz_core::CommunityId,
        actor: PublicKey,
        owner: &str,
        repository: &str,
        operation: GitSmartHttpOperation,
    ) -> bool {
        let repository = repository.strip_suffix(".git").unwrap_or(repository);
        self.context.authorization_domain() == domain
            && self.context.actor_pubkey() == actor
            && matches!(
                &self.route,
                ProtectedPublicationRouteTarget::Git {
                    owner: sealed_owner,
                    repository: sealed_repository,
                    operation: sealed_operation,
                } if sealed_owner.as_ref() == owner
                    && sealed_repository.as_ref() == repository
                    && *sealed_operation == operation
            )
    }

    pub(crate) fn matches_media(
        &self,
        domain: buzz_core::CommunityId,
        actor: PublicKey,
        requested_path: &str,
        object_sha256: &str,
        action: BlossomAction,
    ) -> bool {
        self.context.authorization_domain() == domain
            && self.context.actor_pubkey() == actor
            && matches!(
                &self.route,
                ProtectedPublicationRouteTarget::Media {
                    requested_path: sealed_path,
                    object_sha256: sealed_object,
                    action: sealed_action,
                } if sealed_path.as_ref() == requested_path
                    && sealed_object.as_ref() == object_sha256
                    && *sealed_action == action
            )
    }
}

pub(crate) async fn authorize_git_publication(
    handle: &ProtectedPublicationAuthorizationHandle,
    domain: buzz_core::CommunityId,
    authorization: &buzz_auth::VerifiedGitSmartHttpAuthorization,
    direct: buzz_auth::VerifiedDirectEvidence,
) -> Result<ProtectedPublicationAccess, ProtectedPublicationAuthorizationError> {
    let capability = match authorization.operation() {
        GitSmartHttpOperation::AdvertiseUploadPack | GitSmartHttpOperation::UploadPack => {
            RouteCapability::GitRead
        }
        GitSmartHttpOperation::AdvertiseReceivePack | GitSmartHttpOperation::ReceivePack => {
            RouteCapability::GitWrite
        }
    };
    let intent = match authorization.operation() {
        GitSmartHttpOperation::ReceivePack => ProtectedPublicationAuthorizationIntent::Mutation,
        GitSmartHttpOperation::AdvertiseUploadPack
        | GitSmartHttpOperation::AdvertiseReceivePack
        | GitSmartHttpOperation::UploadPack => ProtectedPublicationAuthorizationIntent::Read,
    };
    let binding = authorization
        .evidence_binding(domain)
        .map_err(|_| ProtectedPublicationAuthorizationError::RouteMismatch)?;
    let route = VerifiedProtectedPublicationRoute::from_verified_transport(
        domain,
        authorization.actor_pubkey(),
        uuid::Uuid::new_v4(),
        capability,
        AuthorizationProtectedObjectKind::Repository,
        intent,
        binding,
    )?;
    let finalized = handle
        .authorize(ProtectedPublicationEvidence::Direct(direct), route)
        .await?;
    ProtectedPublicationAccess::from_git(finalized, authorization.request())
}

pub(crate) async fn authorize_media_publication(
    handle: &ProtectedPublicationAuthorizationHandle,
    domain: buzz_core::CommunityId,
    authorization: &buzz_auth::VerifiedBlossomAuthorization,
    direct: buzz_auth::VerifiedDirectEvidence,
) -> Result<ProtectedPublicationAccess, ProtectedPublicationAuthorizationError> {
    let (capability, intent) = match authorization.action() {
        BlossomAction::Upload => (
            RouteCapability::MediaWrite,
            ProtectedPublicationAuthorizationIntent::Mutation,
        ),
        BlossomAction::Get | BlossomAction::Head => (
            RouteCapability::MediaRead,
            ProtectedPublicationAuthorizationIntent::Read,
        ),
    };
    let binding = authorization
        .evidence_binding(domain)
        .map_err(|_| ProtectedPublicationAuthorizationError::RouteMismatch)?;
    let route = VerifiedProtectedPublicationRoute::from_verified_transport(
        domain,
        authorization.actor_pubkey(),
        uuid::Uuid::new_v4(),
        capability,
        AuthorizationProtectedObjectKind::Media,
        intent,
        binding,
    )?;
    let finalized = handle
        .authorize(ProtectedPublicationEvidence::Direct(direct), route)
        .await?;
    ProtectedPublicationAccess::from_media(finalized, authorization.request())
}

impl std::fmt::Debug for ProtectedPublicationAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProtectedPublicationAccess([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use axum::http::{
        header::{HeaderName, HeaderValue},
        uri::{Authority, PathAndQuery, Scheme},
        HeaderMap, Method,
    };
    use base64::Engine as _;
    use buzz_auth::{
        AssertionVerificationPolicy, CanonicalBlossomRequest, CanonicalGitSmartHttpRequest,
        EvidenceClock, StaticJwksAssertionVerifier,
    };
    use chrono::{DateTime, Utc};
    use hmac::{Hmac, KeyInit, Mac};
    use jsonwebtoken::{
        encode,
        jwk::{Jwk, JwkSet},
        Algorithm, EncodingKey, Header,
    };
    use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{
        commit_observe_project_revalidate, finalize_before_legacy_admission,
        verify_git_proxy_direct_evidence, verify_media_proxy_direct_evidence,
    };

    const ED25519_PRIVATE_KEY_DER_BASE64: &str =
        "MC4CAQAwBQYDK2VwBCIEIJYzuhA5S4AMIyFs+Eq6O8W0+YMwR6Q1pOLwBRgneKns";
    const PROVENANCE_KEY: [u8; 32] = [19; 32];
    const ASSERTION_HEADER: &str = "x-buzz-identity";
    const PROVENANCE_HEADER: &str = "x-buzz-identity-proof";

    #[tokio::test]
    async fn protected_publication_terminal_order_is_exact() {
        let trace = Arc::new(std::sync::Mutex::new(Vec::new()));
        commit_observe_project_revalidate(
            {
                let trace = trace.clone();
                move || async move {
                    trace.lock().expect("trace").push("restore-commit");
                    Ok::<_, &'static str>(11_u8)
                }
            },
            {
                let trace = trace.clone();
                move |committed| {
                    trace.lock().expect("trace").push("validate-digest");
                    if *committed == 11 {
                        Ok(())
                    } else {
                        Err("digest")
                    }
                }
            },
            {
                let trace = trace.clone();
                move |committed| async move {
                    trace.lock().expect("trace").push("observe-committed");
                    Ok(committed + 1)
                }
            },
            {
                let trace = trace.clone();
                move || async move {
                    trace.lock().expect("trace").push("cache-projection");
                    Ok(())
                }
            },
            {
                let trace = trace.clone();
                move |live| async move {
                    assert_eq!(live, 12);
                    trace.lock().expect("trace").push("final-revalidate");
                    Ok(())
                }
            },
        )
        .await
        .expect("complete protected publication");

        assert_eq!(
            *trace.lock().expect("trace"),
            [
                "restore-commit",
                "validate-digest",
                "observe-committed",
                "cache-projection",
                "final-revalidate",
            ]
        );
    }

    #[tokio::test]
    async fn protected_publication_failure_never_reaches_later_visibility_steps() {
        for fail_at in 0..5 {
            let trace = Arc::new(std::sync::Mutex::new(Vec::new()));
            let result = commit_observe_project_revalidate(
                {
                    let trace = trace.clone();
                    move || async move {
                        trace.lock().expect("trace").push("restore-commit");
                        if fail_at == 0 {
                            Err("commit")
                        } else {
                            Ok(11_u8)
                        }
                    }
                },
                {
                    let trace = trace.clone();
                    move |_| {
                        trace.lock().expect("trace").push("validate-digest");
                        if fail_at == 1 {
                            Err("digest")
                        } else {
                            Ok(())
                        }
                    }
                },
                {
                    let trace = trace.clone();
                    move |committed| async move {
                        trace.lock().expect("trace").push("observe-committed");
                        if fail_at == 2 {
                            Err("observe")
                        } else {
                            Ok(committed + 1)
                        }
                    }
                },
                {
                    let trace = trace.clone();
                    move || async move {
                        trace.lock().expect("trace").push("cache-projection");
                        if fail_at == 3 {
                            Err("projection")
                        } else {
                            Ok(())
                        }
                    }
                },
                {
                    let trace = trace.clone();
                    move |_| async move {
                        trace.lock().expect("trace").push("final-revalidate");
                        if fail_at == 4 {
                            Err("revalidate")
                        } else {
                            Ok(())
                        }
                    }
                },
            )
            .await;

            assert!(result.is_err(), "failure {fail_at} must fail closed");
            assert_eq!(
                trace.lock().expect("trace").len(),
                fail_at + 1,
                "failure {fail_at} reached a later visibility step"
            );
        }
    }

    struct FixedClock(DateTime<Utc>);

    impl EvidenceClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn encoding_key() -> EncodingKey {
        EncodingKey::from_ed_der(
            &base64::engine::general_purpose::STANDARD
                .decode(ED25519_PRIVATE_KEY_DER_BASE64)
                .expect("decode fixture Ed25519 key"),
        )
    }

    fn proxy_verifier(now: DateTime<Utc>) -> buzz_auth::TrustedProxyAssertionVerifier {
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "W5IdGgO6kT9y_Lknfulx05osPx0NTwHpGNJixSlFLmQ",
            "kid": "fixture-ed25519",
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "EdDSA",
        }))
        .expect("fixture public JWK");
        StaticJwksAssertionVerifier::with_clock(
            AssertionVerificationPolicy::new(
                "https://issuer.example",
                "buzz-relay",
                "employee_id",
                std::time::Duration::from_secs(300),
                std::time::Duration::from_secs(30),
            )
            .expect("valid assertion policy"),
            JwkSet { keys: vec![jwk] },
            Arc::new(FixedClock(now)),
        )
        .expect("valid assertion verifier")
        .trusted_proxy(ASSERTION_HEADER, PROVENANCE_HEADER, PROVENANCE_KEY)
        .expect("valid proxy verifier")
    }

    fn jwt(now: DateTime<Utc>) -> String {
        let claims = serde_json::json!({
            "iss": "https://issuer.example",
            "aud": "buzz-relay",
            "employee_id": "opaque-transport-subject",
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": now.timestamp() + 120,
        });
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("fixture-ed25519".to_owned());
        encode(&header, &claims, &encoding_key()).expect("sign fixture assertion")
    }

    fn framed_coordinates(parts: &[&[u8]]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for part in parts {
            encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
            encoded.extend_from_slice(part);
        }
        encoded
    }

    fn framed_fingerprint(label: &[u8], value: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update((label.len() as u64).to_be_bytes());
        digest.update(label);
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
        digest.finalize().into()
    }

    fn proxy_headers(
        domain: buzz_core::CommunityId,
        token: &str,
        request: &[u8],
        target: &[u8],
        transport_context: &[u8],
    ) -> HeaderMap {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&PROVENANCE_KEY)
            .expect("valid provenance key");
        mac.update(b"buzz:nip-fi:trusted-proxy:v1");
        mac.update(&(ASSERTION_HEADER.len() as u64).to_be_bytes());
        mac.update(ASSERTION_HEADER.as_bytes());
        mac.update(&(token.len() as u64).to_be_bytes());
        mac.update(token.as_bytes());
        mac.update(domain.as_uuid().as_bytes());
        mac.update(&framed_fingerprint(b"buzz:nip-fi:request:v1", request));
        mac.update(&framed_fingerprint(b"buzz:nip-fi:target:v1", target));
        mac.update(&framed_fingerprint(
            b"buzz:nip-fi:transport-context:v1",
            transport_context,
        ));
        let proof = hex::encode(mac.finalize().into_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(ASSERTION_HEADER),
            HeaderValue::from_str(token).expect("assertion header"),
        );
        headers.insert(
            HeaderName::from_static(PROVENANCE_HEADER),
            HeaderValue::from_str(&proof).expect("provenance header"),
        );
        headers
    }

    #[test]
    fn configured_trusted_proxy_header_mac_composes_with_git_and_blossom_extractors() {
        let now = DateTime::from_timestamp(1_900_000_000, 0).expect("fixture time");
        let clock = FixedClock(now);
        let verifier = proxy_verifier(now);
        let domain = buzz_core::CommunityId::from_uuid(Uuid::from_u128(0xabc));
        let token = jwt(now);
        let authority: Authority = "relay.example".parse().expect("fixture authority");
        let actor = Keys::generate();

        let owner = "a".repeat(64);
        let git_path = format!("/git/{owner}/repository/git-upload-pack");
        let git_path_and_query: PathAndQuery = git_path.parse().expect("Git path");
        let git_route = CanonicalGitSmartHttpRequest::from_server_parts(
            &Scheme::HTTPS,
            &authority,
            &owner,
            "repository",
            &Method::POST,
            &git_path_and_query,
        )
        .expect("canonical Git route");
        let signed_git_root = format!("https://relay.example/git/{owner}/repository");
        let git_event = EventBuilder::new(Kind::HttpAuth, "")
            .tags([
                Tag::parse(["u", signed_git_root.as_str()]).expect("Git u tag"),
                Tag::parse(["method", "GET"]).expect("Git method tag"),
            ])
            .custom_created_at(Timestamp::from(now.timestamp() as u64))
            .sign_with_keys(&actor)
            .expect("sign Git session");
        let git_authorization = buzz_auth::verify_git_smart_http_authorization(
            &serde_json::to_string(&git_event).expect("serialize Git event"),
            &git_route,
            &clock,
        )
        .expect("origin-sealed Git authorization");
        let git_request = framed_coordinates(&[
            b"POST",
            b"upload-pack",
            git_path_and_query.as_str().as_bytes(),
        ]);
        let git_target = framed_coordinates(&[b"repository", owner.as_bytes(), b"repository"]);
        let git_context =
            framed_coordinates(&[b"git-smart-http-session-v1", b"https", b"relay.example"]);
        let git_headers = proxy_headers(domain, &token, &git_request, &git_target, &git_context);
        verify_git_proxy_direct_evidence(&verifier, &git_headers, domain, &git_authorization)
            .expect("configured proxy MAC must compose with Git direct evidence");

        let other_git_path = format!("/git/{owner}/other/git-upload-pack");
        let other_git_path_and_query: PathAndQuery =
            other_git_path.parse().expect("other Git path");
        let other_git_route = CanonicalGitSmartHttpRequest::from_server_parts(
            &Scheme::HTTPS,
            &authority,
            &owner,
            "other",
            &Method::POST,
            &other_git_path_and_query,
        )
        .expect("other canonical Git route");
        let other_signed_git_root = format!("https://relay.example/git/{owner}/other");
        let other_git_event = EventBuilder::new(Kind::HttpAuth, "")
            .tags([
                Tag::parse(["u", other_signed_git_root.as_str()]).expect("other Git u tag"),
                Tag::parse(["method", "GET"]).expect("other Git method tag"),
            ])
            .custom_created_at(Timestamp::from(now.timestamp() as u64))
            .sign_with_keys(&actor)
            .expect("sign other Git session");
        let other_git_authorization = buzz_auth::verify_git_smart_http_authorization(
            &serde_json::to_string(&other_git_event).expect("serialize other Git event"),
            &other_git_route,
            &clock,
        )
        .expect("origin-sealed other Git authorization");
        verify_git_proxy_direct_evidence(&verifier, &git_headers, domain, &other_git_authorization)
            .expect_err("repository-A proxy authority cannot authorize repository B");

        let object = "b".repeat(64);
        let media_path: PathAndQuery = "/upload".parse().expect("media path");
        let media_route = CanonicalBlossomRequest::from_server_parts(
            &Scheme::HTTPS,
            &authority,
            &Method::PUT,
            &media_path,
            &object,
        )
        .expect("canonical Blossom route");
        let expiration = (now.timestamp() + 50).to_string();
        let media_event = EventBuilder::new(Kind::from(24242), "upload")
            .tags([
                Tag::parse(["t", "upload"]).expect("Blossom action tag"),
                Tag::parse(["expiration", expiration.as_str()]).expect("expiration tag"),
                Tag::parse(["x", object.as_str()]).expect("object tag"),
                Tag::parse(["server", "relay.example"]).expect("server tag"),
            ])
            .custom_created_at(Timestamp::from(now.timestamp() as u64))
            .sign_with_keys(&actor)
            .expect("sign Blossom event");
        let media_authorization =
            buzz_auth::verify_blossom_authorization(&media_event, &media_route, &clock)
                .expect("origin-sealed Blossom authorization");
        let media_request = framed_coordinates(&[b"PUT", b"upload", b"/upload"]);
        let media_target = framed_coordinates(&[b"media", object.as_bytes()]);
        let media_context = framed_coordinates(&[b"blossom-v1", b"https", b"relay.example"]);
        let media_headers = proxy_headers(
            domain,
            &token,
            &media_request,
            &media_target,
            &media_context,
        );
        verify_media_proxy_direct_evidence(&verifier, &media_headers, domain, &media_authorization)
            .expect("configured proxy MAC must compose with Blossom direct evidence");
        let mut duplicate_provenance = media_headers.clone();
        let proof = duplicate_provenance
            .get(PROVENANCE_HEADER)
            .expect("fixture provenance header")
            .clone();
        duplicate_provenance.append(PROVENANCE_HEADER, proof);
        verify_media_proxy_direct_evidence(
            &verifier,
            &duplicate_provenance,
            domain,
            &media_authorization,
        )
        .expect_err("repeated proxy MAC header must fail closed");

        let other_object = "c".repeat(64);
        let other_media_route = CanonicalBlossomRequest::from_server_parts(
            &Scheme::HTTPS,
            &authority,
            &Method::PUT,
            &media_path,
            &other_object,
        )
        .expect("other canonical Blossom route");
        let other_media_event = EventBuilder::new(Kind::from(24242), "upload")
            .tags([
                Tag::parse(["t", "upload"]).expect("other Blossom action tag"),
                Tag::parse(["expiration", expiration.as_str()]).expect("other expiration tag"),
                Tag::parse(["x", other_object.as_str()]).expect("other object tag"),
                Tag::parse(["server", "relay.example"]).expect("other server tag"),
            ])
            .custom_created_at(Timestamp::from(now.timestamp() as u64))
            .sign_with_keys(&actor)
            .expect("sign other Blossom event");
        let other_media_authorization =
            buzz_auth::verify_blossom_authorization(&other_media_event, &other_media_route, &clock)
                .expect("origin-sealed other Blossom authorization");
        verify_media_proxy_direct_evidence(
            &verifier,
            &media_headers,
            domain,
            &other_media_authorization,
        )
        .expect_err("media-object-A proxy authority cannot authorize media object B");

        verify_media_proxy_direct_evidence(&verifier, &git_headers, domain, &media_authorization)
            .expect_err("Git-bound proxy headers cannot authorize a Blossom route");
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum GateFailure {
        MissingOrInvalidProxyProvenance,
        ProtectedAuthorityUnavailable,
        StaleProtectedAuthorization,
    }

    async fn assert_failure_skips_admission(failure: GateFailure) {
        let admission_calls = AtomicUsize::new(0);
        let result = finalize_before_legacy_admission(
            || async { Err::<(), _>(failure) },
            || async {
                admission_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert_eq!(result, Err(failure));
        assert_eq!(admission_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missing_or_invalid_proxy_provenance_makes_zero_admission_calls() {
        assert_failure_skips_admission(GateFailure::MissingOrInvalidProxyProvenance).await;
    }

    #[tokio::test]
    async fn unavailable_protected_authority_makes_zero_admission_calls() {
        assert_failure_skips_admission(GateFailure::ProtectedAuthorityUnavailable).await;
    }

    #[tokio::test]
    async fn stale_protected_authorization_makes_zero_admission_calls() {
        assert_failure_skips_admission(GateFailure::StaleProtectedAuthorization).await;
    }
}
