//! Deployment-operator HTTP APIs.
//!
//! These routes are outside the Nostr event data plane. They still use NIP-98
//! request signing and replay protection, but they do not run through event
//! ingest, relay membership, channel scoping, storage, or fan-out.

use std::{net::IpAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, Extension, Path, Query, RawQuery, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower_http::limit::RequestBodyLimitLayer;
use uuid::Uuid;

#[cfg(test)]
use buzz_auth::{Nip98ReplayGuard, OperatorLifecycleVerifier, VerifiedProvisionBindingIntent};
use buzz_core::{CommunityId, TenantContext};
use buzz_db::{
    authorization_restore::ProvisionBindingExecution,
    identity_lifecycle::IdentityLifecycleObservation,
    operator_lifecycle::{
        ExactActiveOperatorTarget, ExactRetiredOperatorTarget, ExpectedOperatorPendingReplacement,
        OperatorAuthenticationDenialReason, OperatorLifecycleIntent, OperatorLifecycleOperation,
        RequestedOperatorReplacement,
    },
};

use crate::handlers::community_provisioning::{
    normalize_candidate_host, validate_pubkey_hex, ProvisionCommunityRequest,
};
use crate::state::AppState;

use crate::operator_runtime::{
    OperatorInvocationError, OperatorLifecycleRuntime, OperatorPrebodyGateError,
};

use super::{api_error, bridge, internal_error};

/// Query parameters for `GET /operator/communities`.
#[derive(Debug, Deserialize)]
pub struct ListCommunitiesQuery {
    owner_pubkey: String,
}

#[cfg(test)]
mod lifecycle_tests {
    use std::{
        collections::{HashMap, HashSet},
        convert::Infallible,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        task::Poll,
    };

    use async_trait::async_trait;
    use axum::{
        body::{to_bytes, Body, Bytes},
        extract::ConnectInfo,
        http::{header, HeaderValue, Request, StatusCode},
        Router,
    };
    use base64::Engine;
    use nostr::{EventBuilder, Keys, Kind, Tag};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::authorization_runtime::ProviderFreeV1Composition;
    use crate::operator_runtime::{
        OperatorLifecycleExecutor, OperatorLifecycleRuntime, OPERATOR_RATE_LIMIT_WINDOW,
    };
    use buzz_auth::{
        Nip98ReplayGuard, NipFiMode, OperatorLifecycleAction, OperatorLifecycleGrantError,
        OperatorLifecycleVerifier, VerifiedOperatorLifecycleGrant,
    };
    use buzz_core::CommunityId;
    use buzz_db::{
        authorization_restore::ProvisionBindingExecution,
        identity_lifecycle::{
            IdentityLifecycleObservation, IdentityLifecycleTransition,
            PersistedIdentityLifecycleOutcome,
        },
        operator_lifecycle::{
            OperatorAuthenticationDenialReason, OperatorLifecycleError, OperatorLifecycleIntent,
            OperatorPreauthDenialPersistenceError, OperatorPreauthDenialWrite,
        },
        DbError,
    };

    use super::{
        lifecycle_error, lifecycle_router, parse_lifecycle_intent, verify_provision_binding_intent,
        OPERATOR_APPROVAL_HEADER, OPERATOR_PROVISION_DOMAIN_HEADER,
        OPERATOR_REPLACEMENT_PROOF_HEADER,
    };
    use crate::operator_runtime::OperatorInvocationError;

    struct AlwaysFreshReplayGuard;

    impl Nip98ReplayGuard for AlwaysFreshReplayGuard {
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

        fn try_mark_all_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            event_ids: &'a [nostr::EventId],
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            Box::pin(async move {
                let valid_cardinality = (1..=3).contains(&event_ids.len());
                let distinct = event_ids
                    .iter()
                    .enumerate()
                    .all(|(index, event_id)| !event_ids[..index].contains(event_id));
                if valid_cardinality && distinct {
                    Ok(true)
                } else {
                    Err(buzz_auth::AuthError::Internal(
                        "invalid NIP-98 proof-set replay claim".to_owned(),
                    ))
                }
            })
        }
    }

    #[derive(Default)]
    struct SeenOnceReplayGuard(Mutex<HashSet<(String, [u8; 32])>>);

    impl Nip98ReplayGuard for SeenOnceReplayGuard {
        fn try_mark_in_scope<'a>(
            &'a self,
            scope: &'a str,
            event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            Box::pin(async move {
                let mut seen = self.0.lock().expect("replay set");
                Ok(seen.insert((scope.to_owned(), event_id.to_bytes())))
            })
        }

        fn try_mark_all_in_scope<'a>(
            &'a self,
            scope: &'a str,
            event_ids: &'a [nostr::EventId],
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            Box::pin(async move {
                if !(1..=3).contains(&event_ids.len())
                    || event_ids
                        .iter()
                        .enumerate()
                        .any(|(index, event_id)| event_ids[..index].contains(event_id))
                {
                    return Err(buzz_auth::AuthError::Internal(
                        "invalid NIP-98 proof-set replay claim".to_owned(),
                    ));
                }
                let keys = event_ids
                    .iter()
                    .map(|event_id| (scope.to_owned(), event_id.to_bytes()))
                    .collect::<Vec<_>>();
                let mut seen = self.0.lock().expect("replay set");
                if keys.iter().any(|key| seen.contains(key)) {
                    return Ok(false);
                }
                seen.extend(keys);
                Ok(true)
            })
        }
    }

    struct TestExecutor {
        calls: AtomicUsize,
        provisions: AtomicUsize,
        denials: AtomicUsize,
        denial_fails: AtomicBool,
        denial_is_corrupt: AtomicBool,
        denial_capacity_exhausted: AtomicBool,
        healthy: AtomicBool,
        domain_health: Mutex<HashMap<CommunityId, bool>>,
        modes: Mutex<HashMap<CommunityId, NipFiMode>>,
        seen_operations: Mutex<HashMap<Uuid, IdentityLifecycleTransition>>,
    }

    #[async_trait]
    impl OperatorLifecycleExecutor for TestExecutor {
        fn mode(&self, domain: CommunityId) -> NipFiMode {
            self.modes
                .lock()
                .expect("test mode map")
                .get(&domain)
                .copied()
                .unwrap_or(NipFiMode::Enforce)
        }

        fn domain_healthy(&self, domain: CommunityId) -> bool {
            self.domain_health
                .lock()
                .expect("test health map")
                .get(&domain)
                .copied()
                .unwrap_or(true)
        }

        async fn execute(
            &self,
            grant: &VerifiedOperatorLifecycleGrant,
            intent: &OperatorLifecycleIntent,
        ) -> Result<IdentityLifecycleObservation, OperatorLifecycleError> {
            assert_eq!(grant.intent_digest(), intent.intent_digest());
            self.calls.fetch_add(1, Ordering::SeqCst);
            let transition = match intent.action() {
                OperatorLifecycleAction::Retire => IdentityLifecycleTransition::Retire,
                OperatorLifecycleAction::Disable => IdentityLifecycleTransition::Disable,
                OperatorLifecycleAction::Revoke => IdentityLifecycleTransition::Revoke,
                OperatorLifecycleAction::Rotate => IdentityLifecycleTransition::Rotate,
                OperatorLifecycleAction::Recover => IdentityLifecycleTransition::Recover,
                OperatorLifecycleAction::Enable => IdentityLifecycleTransition::Enable,
            };
            let original = self
                .seen_operations
                .lock()
                .expect("test operation map")
                .insert(intent.operation_id(), transition);
            if original.is_none() {
                Ok(IdentityLifecycleObservation::Applied {
                    transition,
                    binding: None,
                })
            } else {
                assert_eq!(original, Some(transition));
                Ok(IdentityLifecycleObservation::ExactReplay {
                    transition,
                    original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                    binding: None,
                })
            }
        }

        async fn record_preauth_denial(
            &self,
            _intent: &OperatorLifecycleIntent,
            _reason: OperatorAuthenticationDenialReason,
        ) -> Result<OperatorPreauthDenialWrite, OperatorPreauthDenialPersistenceError> {
            self.denials.fetch_add(1, Ordering::SeqCst);
            if self.denial_capacity_exhausted.load(Ordering::SeqCst) {
                return Ok(OperatorPreauthDenialWrite::CapacityExhausted);
            }
            if self.denial_is_corrupt.load(Ordering::SeqCst) {
                return Err(OperatorPreauthDenialPersistenceError::CorruptStoredResult);
            }
            if self.denial_fails.load(Ordering::SeqCst) {
                Err(OperatorPreauthDenialPersistenceError::Unavailable)
            } else {
                Ok(OperatorPreauthDenialWrite::Inserted)
            }
        }

        async fn record_provision_preauth_denial(
            &self,
            _domain: CommunityId,
            _body: &[u8],
            _reason: OperatorAuthenticationDenialReason,
        ) -> Result<OperatorPreauthDenialWrite, OperatorPreauthDenialPersistenceError> {
            self.denials.fetch_add(1, Ordering::SeqCst);
            if self.denial_capacity_exhausted.load(Ordering::SeqCst) {
                return Ok(OperatorPreauthDenialWrite::CapacityExhausted);
            }
            if self.denial_is_corrupt.load(Ordering::SeqCst) {
                return Err(OperatorPreauthDenialPersistenceError::CorruptStoredResult);
            }
            if self.denial_fails.load(Ordering::SeqCst) {
                Err(OperatorPreauthDenialPersistenceError::Unavailable)
            } else {
                Ok(OperatorPreauthDenialWrite::Inserted)
            }
        }

        async fn provision(
            &self,
            _intent: &buzz_auth::VerifiedProvisionBindingIntent,
        ) -> Result<ProvisionBindingExecution, OperatorInvocationError> {
            self.provisions.fetch_add(1, Ordering::SeqCst);
            Ok(ProvisionBindingExecution::ExactReplay {
                original_outcome: PersistedIdentityLifecycleOutcome::Applied,
                binding: None,
            })
        }

        fn healthy(&self) -> bool {
            self.healthy.load(Ordering::SeqCst)
        }
    }

    fn runtime_with_verifier(
        verifier: OperatorLifecycleVerifier,
    ) -> (Arc<OperatorLifecycleRuntime>, Arc<TestExecutor>) {
        runtime_with_verifier_and_replay(verifier, Arc::new(AlwaysFreshReplayGuard))
    }

    fn runtime_with_verifier_and_replay(
        verifier: OperatorLifecycleVerifier,
        replay_guard: Arc<dyn Nip98ReplayGuard>,
    ) -> (Arc<OperatorLifecycleRuntime>, Arc<TestExecutor>) {
        let executor = Arc::new(TestExecutor {
            calls: AtomicUsize::new(0),
            provisions: AtomicUsize::new(0),
            denials: AtomicUsize::new(0),
            denial_fails: AtomicBool::new(false),
            denial_is_corrupt: AtomicBool::new(false),
            denial_capacity_exhausted: AtomicBool::new(false),
            healthy: AtomicBool::new(true),
            domain_health: Mutex::new(HashMap::new()),
            modes: Mutex::new(HashMap::new()),
            seen_operations: Mutex::new(HashMap::new()),
        });
        let runtime = Arc::new(
            OperatorLifecycleRuntime::new(
                "https://operator.example",
                Arc::new(verifier),
                replay_guard,
                executor.clone(),
            )
            .expect("runtime"),
        );
        (runtime, executor)
    }

    fn test_runtime() -> (Arc<OperatorLifecycleRuntime>, Keys, Keys, Arc<TestExecutor>) {
        let signer = Keys::generate();
        let approver = Keys::generate();
        let verifier = OperatorLifecycleVerifier::requiring_independent_approval(vec![
            signer.public_key(),
            approver.public_key(),
        ])
        .expect("verifier");
        let (runtime, executor) = runtime_with_verifier(verifier);
        (runtime, signer, approver, executor)
    }

    fn replay_protected_runtime() -> (Arc<OperatorLifecycleRuntime>, Keys, Keys, Arc<TestExecutor>)
    {
        let signer = Keys::generate();
        let approver = Keys::generate();
        let verifier = OperatorLifecycleVerifier::requiring_independent_approval(vec![
            signer.public_key(),
            approver.public_key(),
        ])
        .expect("verifier");
        let (runtime, executor) =
            runtime_with_verifier_and_replay(verifier, Arc::new(SeenOnceReplayGuard::default()));
        (runtime, signer, approver, executor)
    }

    fn operation(operation_id: Uuid) -> Value {
        json!({
            "operation_id": operation_id,
            "correlation_id": Uuid::new_v4(),
            "attempt_id": Uuid::new_v4(),
        })
    }

    fn active_binding() -> Value {
        json!({
            "binding_id": Uuid::new_v4(),
            "binding_version": 7,
            "expected_lifecycle_revision": 1,
            "principal_fingerprint": "11".repeat(32),
            "event_author_pubkey": "22".repeat(32),
        })
    }

    fn retired_binding() -> Value {
        json!({
            "binding_id": Uuid::new_v4(),
            "binding_version": 7,
            "expected_lifecycle_revision": 2,
            "principal_fingerprint": "11".repeat(32),
            "event_author_pubkey": "22".repeat(32),
        })
    }

    fn replacement() -> Value {
        json!({
            "event_author_pubkey": "33".repeat(32),
            "expires_at": "2099-01-01T00:00:00Z",
        })
    }

    fn set_mode(executor: &TestExecutor, domain: CommunityId, mode: NipFiMode) {
        executor
            .modes
            .lock()
            .expect("test mode map")
            .insert(domain, mode);
    }

    fn set_domain_health(executor: &TestExecutor, domain: CommunityId, healthy: bool) {
        executor
            .domain_health
            .lock()
            .expect("test health map")
            .insert(domain, healthy);
    }

    fn provision_body(domain: CommunityId, operation_id: Uuid, selected_key: &Keys) -> String {
        json!({
            "authorization_domain": domain.as_uuid(),
            "operation_id": operation_id,
            "policy_revision": 7_u64,
            "policy_digest": "44".repeat(32),
            "issuer": "https://issuer.example",
            "subject": "opaque-subject",
            "selected_event_author_pubkey": selected_key.public_key().to_hex(),
        })
        .to_string()
    }

    fn body(action: &str, operation_id: Uuid) -> String {
        let operation = operation(operation_id);
        match action {
            "retire" => json!({
                "operation": operation,
                "expected_revision": 1,
                "target": active_binding(),
            }),
            "disable" => json!({
                "operation": operation,
                "expected_revision": 1,
                "principal_fingerprint": "11".repeat(32),
                "expected_active_binding": active_binding(),
            }),
            "revoke" => json!({
                "operation": operation,
                "expected_revision": 1,
                "event_author_pubkey": "22".repeat(32),
                "expected_active_binding": active_binding(),
            }),
            "rotate" => json!({
                "operation": operation,
                "expected_revision": 1,
                "target": active_binding(),
                "replacement": replacement(),
            }),
            "recover" => json!({
                "operation": operation,
                "expected_revision": 3,
                "pending": {"target": retired_binding(), "fact_generation": 3},
                "replacement": replacement(),
            }),
            "enable" => json!({
                "operation": operation,
                "expected_revision": 4,
                "principal_fingerprint": "11".repeat(32),
                "disabled_fact_generation": 4,
                "pending": {"target": retired_binding(), "fact_generation": 3},
                "replacement": replacement(),
            }),
            _ => unreachable!("closed test action"),
        }
        .to_string()
    }

    fn app(runtime: Arc<OperatorLifecycleRuntime>) -> Router {
        lifecycle_router(Some(runtime)).expect("configured router")
    }

    fn test_peer() -> ConnectInfo<std::net::SocketAddr> {
        ConnectInfo(std::net::SocketAddr::from(([192, 0, 2, 10], 41000)))
    }

    fn with_peer(mut request: Request<Body>, address: [u8; 4]) -> Request<Body> {
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((address, 41000))));
        request
    }

    fn counted_body(chunks: Vec<Vec<u8>>, polls: Arc<AtomicUsize>) -> Body {
        let mut chunks = chunks.into_iter();
        Body::from_stream(futures::stream::poll_fn(move |_| {
            polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(
                chunks
                    .next()
                    .map(|chunk| Ok::<Bytes, Infallible>(Bytes::from(chunk))),
            )
        }))
    }

    fn unsigned_lifecycle_request(
        action: &str,
        community: Uuid,
        host: &str,
        origin: Option<&str>,
        body: Body,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!(
                "/operator/communities/{community}/identity-lifecycle/{action}"
            ))
            .header(header::HOST, host)
            .extension(test_peer());
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        request.body(body).expect("unsigned lifecycle request")
    }

    fn request(action: &str, community: Uuid, body: String) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(format!(
                "/operator/communities/{community}/identity-lifecycle/{action}"
            ))
            .header(header::HOST, "operator.example")
            .header(header::AUTHORIZATION, "Nostr YQ==")
            .header(header::CONTENT_TYPE, "application/json")
            .extension(test_peer())
            .body(Body::from(body))
            .expect("request")
    }

    fn nip98_header(keys: &Keys, url: &str, body: &[u8], intent_digest: [u8; 32]) -> String {
        let payload: [u8; 32] = Sha256::digest(body).into();
        let intent_digest = hex::encode(intent_digest);
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags([
                Tag::parse(["u", url]).expect("u tag"),
                Tag::parse(["method", "POST"]).expect("method tag"),
                Tag::parse(["payload", hex::encode(payload).as_str()]).expect("payload tag"),
                Tag::parse(["buzz-intent", intent_digest.as_str()]).expect("intent tag"),
            ])
            .sign_with_keys(keys)
            .expect("sign proof");
        let json = serde_json::to_string(&event).expect("proof json");
        format!(
            "Nostr {}",
            base64::engine::general_purpose::STANDARD.encode(json)
        )
    }

    fn test_framed_digest(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update((domain.len() as u64).to_be_bytes());
        digest.update(domain);
        for field in fields {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field);
        }
        digest.finalize().into()
    }

    fn signed_request(
        action: &str,
        community: Uuid,
        body: String,
        signer: &Keys,
        approver: Option<&Keys>,
        replacement: Option<&Keys>,
    ) -> Request<Body> {
        let path = format!("/operator/communities/{community}/identity-lifecycle/{action}");
        let url = format!("https://operator.example{path}");
        let intent_digest =
            parse_lifecycle_intent(CommunityId::from_uuid(community), action, body.as_bytes())
                .expect("typed signed intent")
                .intent_digest();
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, "operator.example")
            .header(
                header::AUTHORIZATION,
                nip98_header(signer, &url, body.as_bytes(), intent_digest),
            );
        if let Some(approver) = approver {
            request = request.header(
                OPERATOR_APPROVAL_HEADER,
                nip98_header(approver, &url, body.as_bytes(), intent_digest),
            );
        }
        if let Some(replacement) = replacement {
            request = request.header(
                OPERATOR_REPLACEMENT_PROOF_HEADER,
                nip98_header(replacement, &url, body.as_bytes(), intent_digest),
            );
        }
        request
            .header(header::CONTENT_TYPE, "application/json")
            .extension(test_peer())
            .body(Body::from(body))
            .expect("request")
    }

    fn signed_provision_request(
        domain: CommunityId,
        operation_id: Uuid,
        selected_key: &Keys,
        signer: &Keys,
        approver: Option<&Keys>,
    ) -> Request<Body> {
        let body = provision_body(domain, operation_id, selected_key);
        let body_digest: [u8; 32] = Sha256::digest(body.as_bytes()).into();
        let intent_digest = test_framed_digest(
            b"buzz:operator-provision-binding-intent:v2",
            &[
                domain.as_uuid().as_bytes(),
                operation_id.as_bytes(),
                &7_u64.to_be_bytes(),
                &[0x44; 32],
                b"https://issuer.example",
                b"opaque-subject",
                &selected_key.public_key().to_bytes(),
                &body_digest,
            ],
        );
        let path = "/operator/identity-bindings/provision";
        let url = format!("https://operator.example{path}");
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, "operator.example")
            .header(
                OPERATOR_PROVISION_DOMAIN_HEADER,
                domain.as_uuid().to_string(),
            )
            .header(
                header::AUTHORIZATION,
                nip98_header(signer, &url, body.as_bytes(), intent_digest),
            );
        if let Some(approver) = approver {
            request = request.header(
                OPERATOR_APPROVAL_HEADER,
                nip98_header(approver, &url, body.as_bytes(), intent_digest),
            );
        }
        request
            .header(header::CONTENT_TYPE, "application/json")
            .extension(test_peer())
            .body(Body::from(body))
            .expect("provision request")
    }

    async fn json_body(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    async fn assert_uniform_unavailable(
        response: axum::response::Response,
        polls: &AtomicUsize,
        executor: &TestExecutor,
    ) {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
        let bytes = to_bytes(response.into_body(), 1024).await.expect("body");
        assert_eq!(
            bytes.as_ref(),
            br#"{"error":"operator endpoint unavailable"}"#
        );
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn optional_router_is_404_when_operator_verifier_is_unconfigured() {
        let mut app = Router::new();
        if let Some(configured) = lifecycle_router(None) {
            app = app.merge(configured);
        }
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/operator/communities/{}/identity-lifecycle/retire",
                        Uuid::new_v4()
                    ))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let provision = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/identity-bindings/provision")
                    .body(Body::empty())
                    .expect("provision request"),
            )
            .await
            .expect("provision response");
        assert_eq!(provision.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn transport_posture_and_health_failures_are_identical_before_body_poll() {
        let domain = Uuid::new_v4();

        for (host, origin) in [
            ("wrong.example", None),
            ("operator.example", Some("https://wrong.example")),
        ] {
            let (runtime, _signer, _approver, executor) = test_runtime();
            let polls = Arc::new(AtomicUsize::new(0));
            let request = unsigned_lifecycle_request(
                "retire",
                domain,
                host,
                origin,
                counted_body(
                    vec![body("retire", Uuid::new_v4()).into_bytes()],
                    Arc::clone(&polls),
                ),
            );
            let response = app(runtime).oneshot(request).await.expect("response");
            assert_uniform_unavailable(response, &polls, &executor).await;
        }

        for mode in [NipFiMode::Off, NipFiMode::DenyProtected] {
            let (runtime, _signer, _approver, executor) = test_runtime();
            set_mode(&executor, CommunityId::from_uuid(domain), mode);
            let polls = Arc::new(AtomicUsize::new(0));
            let request = unsigned_lifecycle_request(
                "retire",
                domain,
                "operator.example",
                None,
                counted_body(
                    vec![body("retire", Uuid::new_v4()).into_bytes()],
                    Arc::clone(&polls),
                ),
            );
            let response = app(runtime).oneshot(request).await.expect("response");
            assert_uniform_unavailable(response, &polls, &executor).await;
        }

        let (runtime, _signer, _approver, executor) = test_runtime();
        set_domain_health(&executor, CommunityId::from_uuid(domain), false);
        let polls = Arc::new(AtomicUsize::new(0));
        let request = unsigned_lifecycle_request(
            "retire",
            domain,
            "operator.example",
            None,
            counted_body(
                vec![body("retire", Uuid::new_v4()).into_bytes()],
                Arc::clone(&polls),
            ),
        );
        let response = app(runtime).oneshot(request).await.expect("response");
        assert_uniform_unavailable(response, &polls, &executor).await;
    }

    #[tokio::test]
    async fn request_authority_accepts_uri_only_host_only_and_canonically_equal_both() {
        let domain = Uuid::new_v4();
        let path = format!("/operator/communities/{domain}/identity-lifecycle/retire");
        for (uri, host) in [
            (path.clone(), Some("OPERATOR.EXAMPLE:443")),
            (format!("https://OPERATOR.EXAMPLE:443{path}"), None),
            (
                format!("https://operator.example{path}"),
                Some("OPERATOR.EXAMPLE:443"),
            ),
        ] {
            let (runtime, _signer, _approver, executor) = test_runtime();
            let polls = Arc::new(AtomicUsize::new(0));
            let mut request = Request::builder().method("POST").uri(uri);
            if let Some(host) = host {
                request = request.header(header::HOST, host);
            }
            let response = app(runtime)
                .oneshot(
                    request
                        .extension(test_peer())
                        .body(counted_body(
                            vec![body("retire", Uuid::new_v4()).into_bytes()],
                            Arc::clone(&polls),
                        ))
                        .expect("authority request"),
                )
                .await
                .expect("authority response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(polls.load(Ordering::SeqCst) > 0);
            assert_eq!(executor.denials.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn request_authority_rejects_duplicates_mismatch_and_wrong_scheme_prebody() {
        let domain = Uuid::new_v4();
        let path = format!("/operator/communities/{domain}/identity-lifecycle/retire");
        let cases = [
            (path.clone(), None, None),
            (
                format!("https://operator.example{path}"),
                Some("wrong.example"),
                None,
            ),
            (format!("http://operator.example{path}"), None, None),
            (path.clone(), Some("operator.example:444"), None),
            (path, Some("operator.example"), Some("OPERATOR.EXAMPLE:443")),
        ];
        for (uri, host, duplicate_host) in cases {
            let (runtime, _signer, _approver, executor) = test_runtime();
            let polls = Arc::new(AtomicUsize::new(0));
            let mut request = Request::builder()
                .method("POST")
                .uri(uri)
                .extension(test_peer())
                .body(counted_body(
                    vec![body("retire", Uuid::new_v4()).into_bytes()],
                    Arc::clone(&polls),
                ))
                .expect("authority request");
            if let Some(host) = host {
                request
                    .headers_mut()
                    .insert(header::HOST, HeaderValue::from_str(host).expect("host"));
            }
            if let Some(duplicate_host) = duplicate_host {
                request.headers_mut().append(
                    header::HOST,
                    HeaderValue::from_str(duplicate_host).expect("duplicate host"),
                );
            }
            let response = app(runtime).oneshot(request).await.expect("response");
            assert_uniform_unavailable(response, &polls, &executor).await;
        }
    }

    #[tokio::test]
    async fn missing_connect_info_keeps_operator_routes_unavailable_without_polling() {
        let (runtime, _signer, _approver, executor) = test_runtime();
        let domain = Uuid::new_v4();
        let polls = Arc::new(AtomicUsize::new(0));
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "/operator/communities/{domain}/identity-lifecycle/retire"
            ))
            .header(header::HOST, "operator.example")
            .body(counted_body(
                vec![body("retire", Uuid::new_v4()).into_bytes()],
                Arc::clone(&polls),
            ))
            .expect("request without connection metadata");
        let response = app(runtime).oneshot(request).await.expect("response");
        assert_uniform_unavailable(response, &polls, &executor).await;
    }

    #[tokio::test]
    async fn provision_domain_header_is_required_unique_utf8_nonnil_and_prebody() {
        let (runtime, _signer, _approver, executor) = test_runtime();
        let app = app(runtime);
        let valid_domain = Uuid::new_v4();
        let invalid_headers = [
            None,
            Some(HeaderValue::from_static("not-a-uuid")),
            Some(HeaderValue::from_static(
                "00000000-0000-0000-0000-000000000000",
            )),
            Some(HeaderValue::from_bytes(&[0xff]).expect("opaque header")),
        ];
        for header_value in invalid_headers {
            let polls = Arc::new(AtomicUsize::new(0));
            let mut request = Request::builder()
                .method("POST")
                .uri("/operator/identity-bindings/provision")
                .header(header::HOST, "operator.example")
                .extension(test_peer());
            if let Some(header_value) = header_value {
                request = request.header(OPERATOR_PROVISION_DOMAIN_HEADER, header_value);
            }
            let response = app
                .clone()
                .oneshot(
                    request
                        .body(counted_body(
                            vec![json!({"authorization_domain": valid_domain})
                                .to_string()
                                .into_bytes()],
                            Arc::clone(&polls),
                        ))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(polls.load(Ordering::SeqCst), 0);
        }

        let polls = Arc::new(AtomicUsize::new(0));
        let mut duplicate = Request::builder()
            .method("POST")
            .uri("/operator/identity-bindings/provision")
            .header(header::HOST, "operator.example")
            .header(OPERATOR_PROVISION_DOMAIN_HEADER, valid_domain.to_string())
            .extension(test_peer())
            .body(counted_body(
                vec![json!({"authorization_domain": valid_domain})
                    .to_string()
                    .into_bytes()],
                Arc::clone(&polls),
            ))
            .expect("duplicate request");
        duplicate.headers_mut().append(
            OPERATOR_PROVISION_DOMAIN_HEADER,
            HeaderValue::from_str(&Uuid::new_v4().to_string()).expect("domain header"),
        );
        let response = app.oneshot(duplicate).await.expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn provision_body_domain_must_match_prebody_domain_after_bounded_read() {
        let (runtime, _signer, _approver, executor) = test_runtime();
        let header_domain = Uuid::new_v4();
        let body_domain = Uuid::new_v4();
        let polls = Arc::new(AtomicUsize::new(0));
        let response = app(runtime)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/identity-bindings/provision")
                    .header(header::HOST, "operator.example")
                    .header(OPERATOR_PROVISION_DOMAIN_HEADER, header_domain.to_string())
                    .extension(test_peer())
                    .body(counted_body(
                        vec![json!({"authorization_domain": body_domain})
                            .to_string()
                            .into_bytes()],
                        Arc::clone(&polls),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(polls.load(Ordering::SeqCst) > 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failed_verification_quota_is_shared_by_peer_across_all_operator_routes() {
        let (runtime, signer, approver, executor) = test_runtime();
        let app = app(runtime);
        let domain = Uuid::new_v4();
        let actions = ["retire", "disable", "revoke", "rotate", "recover", "enable"];
        for index in 0..60 {
            let request = if index % 7 == 6 {
                let selected_key = Keys::generate();
                Request::builder()
                    .method("POST")
                    .uri("/operator/identity-bindings/provision")
                    .header(header::HOST, "operator.example")
                    .header(OPERATOR_PROVISION_DOMAIN_HEADER, domain.to_string())
                    .header("forwarded", format!("for=198.51.100.{index}"))
                    .header("x-forwarded-for", format!("203.0.113.{index}"))
                    .extension(test_peer())
                    .body(Body::from(provision_body(
                        CommunityId::from_uuid(domain),
                        Uuid::new_v4(),
                        &selected_key,
                    )))
                    .expect("provision request")
            } else {
                let mut request = unsigned_lifecycle_request(
                    actions[index % 7],
                    domain,
                    "operator.example",
                    None,
                    Body::from(body(actions[index % 7], Uuid::new_v4())),
                );
                request.headers_mut().insert(
                    "x-forwarded-for",
                    HeaderValue::from_str(&format!("203.0.113.{index}"))
                        .expect("forwarded address"),
                );
                request
            };
            let response = app.clone().oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let polls = Arc::new(AtomicUsize::new(0));
        let limited = app
            .clone()
            .oneshot(unsigned_lifecycle_request(
                "retire",
                domain,
                "operator.example",
                None,
                counted_body(
                    vec![body("retire", Uuid::new_v4()).into_bytes()],
                    Arc::clone(&polls),
                ),
            ))
            .await
            .expect("limited response");
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            limited.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            limited.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("60"))
        );
        let bytes = to_bytes(limited.into_body(), 1024).await.expect("body");
        assert_eq!(
            bytes.as_ref(),
            br#"{"error":"operator request rate limited"}"#
        );
        assert!(polls.load(Ordering::SeqCst) > 0);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 60);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 0);

        let other_peer = with_peer(
            unsigned_lifecycle_request(
                "retire",
                domain,
                "operator.example",
                None,
                Body::from(body("retire", Uuid::new_v4())),
            ),
            [192, 0, 2, 11],
        );
        assert_eq!(
            app.clone()
                .oneshot(other_peer)
                .await
                .expect("other peer response")
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(unsigned_lifecycle_request(
                    "retire",
                    Uuid::new_v4(),
                    "operator.example",
                    None,
                    Body::from(body("retire", Uuid::new_v4())),
                ))
                .await
                .expect("other domain response")
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.oneshot(signed_request(
                "retire",
                domain,
                body("retire", Uuid::new_v4()),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("authenticated response")
            .status(),
            StatusCode::OK,
            "unsigned peer quota must not consume authenticated actor capacity"
        );
    }

    #[tokio::test]
    async fn malformed_bounded_bodies_are_peer_limited_without_spending_actor_capacity() {
        let (runtime, signer, approver, executor) = test_runtime();
        let app = app(runtime);
        let domain = Uuid::new_v4();
        for index in 0..60 {
            let request = if index % 2 == 0 {
                unsigned_lifecycle_request(
                    "retire",
                    domain,
                    "operator.example",
                    None,
                    Body::from("{"),
                )
            } else {
                Request::builder()
                    .method("POST")
                    .uri("/operator/identity-bindings/provision")
                    .header(header::HOST, "operator.example")
                    .header(OPERATOR_PROVISION_DOMAIN_HEADER, domain.to_string())
                    .extension(test_peer())
                    .body(Body::from("{"))
                    .expect("malformed provision request")
            };
            assert_eq!(
                app.clone()
                    .oneshot(request)
                    .await
                    .expect("malformed response")
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let limited = app
            .clone()
            .oneshot(unsigned_lifecycle_request(
                "retire",
                domain,
                "operator.example",
                None,
                Body::empty(),
            ))
            .await
            .expect("limited malformed response");
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            limited.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("60"))
        );
        assert_eq!(
            app.oneshot(signed_request(
                "retire",
                domain,
                body("retire", Uuid::new_v4()),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("verified response")
            .status(),
            StatusCode::OK
        );
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn verified_actor_quota_isolated_by_actor_and_domain() {
        let (runtime, signer, approver, executor) = test_runtime();
        let app = app(runtime);
        let domain = CommunityId::from_uuid(Uuid::new_v4());

        for _ in 0..60 {
            assert_eq!(
                app.clone()
                    .oneshot(signed_request(
                        "retire",
                        *domain.as_uuid(),
                        body("retire", Uuid::new_v4()),
                        &signer,
                        Some(&approver),
                        None,
                    ))
                    .await
                    .expect("actor response")
                    .status(),
                StatusCode::OK
            );
        }

        let limited_operation = Uuid::new_v4();
        let limited_body = body("retire", limited_operation);
        let path = format!(
            "/operator/communities/{}/identity-lifecycle/retire",
            domain.as_uuid()
        );
        let url = format!("https://operator.example{path}");
        let intent_digest = parse_lifecycle_intent(domain, "retire", limited_body.as_bytes())
            .expect("typed limited intent")
            .intent_digest();
        let authorization = nip98_header(&signer, &url, limited_body.as_bytes(), intent_digest);
        let approval = nip98_header(&approver, &url, limited_body.as_bytes(), intent_digest);
        let limited_request = || {
            Request::builder()
                .method("POST")
                .uri(path.clone())
                .header(header::HOST, "operator.example")
                .header(header::AUTHORIZATION, authorization.clone())
                .header(OPERATOR_APPROVAL_HEADER, approval.clone())
                .header(header::CONTENT_TYPE, "application/json")
                .extension(test_peer())
                .body(Body::from(limited_body.clone()))
                .expect("limited request")
        };
        assert_eq!(
            app.clone()
                .oneshot(limited_request())
                .await
                .expect("limited actor response")
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        tokio::time::advance(OPERATOR_RATE_LIMIT_WINDOW).await;
        assert_eq!(
            app.clone()
                .oneshot(limited_request())
                .await
                .expect("same proof after equality reset")
                .status(),
            StatusCode::OK,
            "the rejected request must not burn its atomic proof set"
        );
        assert_eq!(
            app.clone()
                .oneshot(signed_request(
                    "retire",
                    *domain.as_uuid(),
                    body("retire", Uuid::new_v4()),
                    &approver,
                    Some(&signer),
                    None,
                ))
                .await
                .expect("different actor response")
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.oneshot(signed_request(
                "retire",
                Uuid::new_v4(),
                body("retire", Uuid::new_v4()),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("different domain response")
            .status(),
            StatusCode::OK
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 63);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn provision_actor_quota_precedes_its_atomic_replay_claim() {
        let (runtime, signer, approver, executor) = test_runtime();
        let app = app(runtime);
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        for _ in 0..60 {
            assert_eq!(
                app.clone()
                    .oneshot(signed_request(
                        "retire",
                        *domain.as_uuid(),
                        body("retire", Uuid::new_v4()),
                        &signer,
                        Some(&approver),
                        None,
                    ))
                    .await
                    .expect("actor response")
                    .status(),
                StatusCode::OK
            );
        }

        let operation_id = Uuid::new_v4();
        let selected_key = Keys::generate();
        let provision_body = provision_body(domain, operation_id, &selected_key);
        let body_digest: [u8; 32] = Sha256::digest(provision_body.as_bytes()).into();
        let intent_digest = test_framed_digest(
            b"buzz:operator-provision-binding-intent:v2",
            &[
                domain.as_uuid().as_bytes(),
                operation_id.as_bytes(),
                &7_u64.to_be_bytes(),
                &[0x44; 32],
                b"https://issuer.example",
                b"opaque-subject",
                &selected_key.public_key().to_bytes(),
                &body_digest,
            ],
        );
        let path = "/operator/identity-bindings/provision";
        let url = format!("https://operator.example{path}");
        let authorization = nip98_header(&signer, &url, provision_body.as_bytes(), intent_digest);
        let approval = nip98_header(&approver, &url, provision_body.as_bytes(), intent_digest);
        let provision_request = || {
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::HOST, "operator.example")
                .header(
                    OPERATOR_PROVISION_DOMAIN_HEADER,
                    domain.as_uuid().to_string(),
                )
                .header(header::AUTHORIZATION, authorization.clone())
                .header(OPERATOR_APPROVAL_HEADER, approval.clone())
                .header(header::CONTENT_TYPE, "application/json")
                .extension(test_peer())
                .body(Body::from(provision_body.clone()))
                .expect("provision request")
        };

        assert_eq!(
            app.clone()
                .oneshot(provision_request())
                .await
                .expect("limited provision response")
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        tokio::time::advance(OPERATOR_RATE_LIMIT_WINDOW).await;
        assert_eq!(
            app.oneshot(provision_request())
                .await
                .expect("provision retry response")
                .status(),
            StatusCode::OK,
            "the limited provision request must retain its atomic proof set"
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 60);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 1);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn lifecycle_replay_flood_releases_actor_reservations() {
        let (runtime, signer, approver, executor) = replay_protected_runtime();
        let app = app(runtime);
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let replay_body = body("retire", Uuid::new_v4());
        let path = format!(
            "/operator/communities/{}/identity-lifecycle/retire",
            domain.as_uuid()
        );
        let url = format!("https://operator.example{path}");
        let intent_digest = parse_lifecycle_intent(domain, "retire", replay_body.as_bytes())
            .expect("typed replay intent")
            .intent_digest();
        let authorization = nip98_header(&signer, &url, replay_body.as_bytes(), intent_digest);
        let approval = nip98_header(&approver, &url, replay_body.as_bytes(), intent_digest);
        let replay_request = || {
            Request::builder()
                .method("POST")
                .uri(path.clone())
                .header(header::HOST, "operator.example")
                .header(header::AUTHORIZATION, authorization.clone())
                .header(OPERATOR_APPROVAL_HEADER, approval.clone())
                .header(header::CONTENT_TYPE, "application/json")
                .extension(test_peer())
                .body(Body::from(replay_body.clone()))
                .expect("replay request")
        };

        assert_eq!(
            app.clone()
                .oneshot(replay_request())
                .await
                .expect("initial response")
                .status(),
            StatusCode::OK
        );
        for _ in 0..60 {
            assert_eq!(
                app.clone()
                    .oneshot(replay_request())
                    .await
                    .expect("replay response")
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            app.oneshot(signed_request(
                "retire",
                *domain.as_uuid(),
                body("retire", Uuid::new_v4()),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("fresh response")
            .status(),
            StatusCode::OK,
            "rejected replays must not consume actor capacity"
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 2);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 60);
    }

    #[tokio::test]
    async fn provision_replay_flood_releases_actor_reservations() {
        let (runtime, signer, approver, executor) = replay_protected_runtime();
        let app = app(runtime);
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let operation_id = Uuid::new_v4();
        let selected_key = Keys::generate();
        let replay_body = provision_body(domain, operation_id, &selected_key);
        let body_digest: [u8; 32] = Sha256::digest(replay_body.as_bytes()).into();
        let intent_digest = test_framed_digest(
            b"buzz:operator-provision-binding-intent:v2",
            &[
                domain.as_uuid().as_bytes(),
                operation_id.as_bytes(),
                &7_u64.to_be_bytes(),
                &[0x44; 32],
                b"https://issuer.example",
                b"opaque-subject",
                &selected_key.public_key().to_bytes(),
                &body_digest,
            ],
        );
        let path = "/operator/identity-bindings/provision";
        let url = format!("https://operator.example{path}");
        let authorization = nip98_header(&signer, &url, replay_body.as_bytes(), intent_digest);
        let approval = nip98_header(&approver, &url, replay_body.as_bytes(), intent_digest);
        let replay_request = || {
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::HOST, "operator.example")
                .header(
                    OPERATOR_PROVISION_DOMAIN_HEADER,
                    domain.as_uuid().to_string(),
                )
                .header(header::AUTHORIZATION, authorization.clone())
                .header(OPERATOR_APPROVAL_HEADER, approval.clone())
                .header(header::CONTENT_TYPE, "application/json")
                .extension(test_peer())
                .body(Body::from(replay_body.clone()))
                .expect("provision replay request")
        };

        assert_eq!(
            app.clone()
                .oneshot(replay_request())
                .await
                .expect("initial provision response")
                .status(),
            StatusCode::OK
        );
        for _ in 0..60 {
            assert_eq!(
                app.clone()
                    .oneshot(replay_request())
                    .await
                    .expect("provision replay response")
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            app.oneshot(signed_provision_request(
                domain,
                Uuid::new_v4(),
                &Keys::generate(),
                &signer,
                Some(&approver),
            ))
            .await
            .expect("fresh provision response")
            .status(),
            StatusCode::OK,
            "rejected provision replays must not consume actor capacity"
        );
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 2);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 60);
    }

    #[tokio::test]
    async fn unavailable_requests_do_not_consume_peer_or_actor_quota() {
        let (runtime, signer, approver, executor) = test_runtime();
        let app = app(runtime);
        let domain = CommunityId::from_uuid(Uuid::new_v4());

        for _ in 0..80 {
            assert_eq!(
                app.clone()
                    .oneshot(unsigned_lifecycle_request(
                        "retire",
                        *domain.as_uuid(),
                        "wrong.example",
                        None,
                        Body::from(body("retire", Uuid::new_v4())),
                    ))
                    .await
                    .expect("wrong-host response")
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        for mode in [NipFiMode::Off, NipFiMode::DenyProtected] {
            set_mode(&executor, domain, mode);
            assert_eq!(
                app.clone()
                    .oneshot(unsigned_lifecycle_request(
                        "retire",
                        *domain.as_uuid(),
                        "operator.example",
                        None,
                        Body::from(body("retire", Uuid::new_v4())),
                    ))
                    .await
                    .expect("mode response")
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        set_mode(&executor, domain, NipFiMode::Enforce);
        set_domain_health(&executor, domain, false);
        assert_eq!(
            app.clone()
                .oneshot(unsigned_lifecycle_request(
                    "retire",
                    *domain.as_uuid(),
                    "operator.example",
                    None,
                    Body::from(body("retire", Uuid::new_v4())),
                ))
                .await
                .expect("health response")
                .status(),
            StatusCode::NOT_FOUND
        );
        set_domain_health(&executor, domain, true);

        for _ in 0..60 {
            assert_eq!(
                app.clone()
                    .oneshot(unsigned_lifecycle_request(
                        "retire",
                        *domain.as_uuid(),
                        "operator.example",
                        None,
                        Body::from(body("retire", Uuid::new_v4())),
                    ))
                    .await
                    .expect("failed verification response")
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            app.oneshot(signed_request(
                "retire",
                *domain.as_uuid(),
                body("retire", Uuid::new_v4()),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("verified response")
            .status(),
            StatusCode::OK
        );
        assert_eq!(executor.denials.load(Ordering::SeqCst), 60);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn request_body_limit_allows_exact_boundary_and_rejects_larger_bodies() {
        let domain = Uuid::new_v4();

        let (runtime, _signer, _approver, _executor) = test_runtime();
        let exact_polls = Arc::new(AtomicUsize::new(0));
        let exact = app(runtime)
            .oneshot(unsigned_lifecycle_request(
                "retire",
                domain,
                "operator.example",
                None,
                counted_body(vec![vec![b'x'; 64 * 1024]], Arc::clone(&exact_polls)),
            ))
            .await
            .expect("exact response");
        assert_eq!(exact.status(), StatusCode::BAD_REQUEST);
        assert!(exact_polls.load(Ordering::SeqCst) > 0);

        let (runtime, _signer, _approver, _executor) = test_runtime();
        let length_polls = Arc::new(AtomicUsize::new(0));
        let length = Request::builder()
            .method("POST")
            .uri(format!(
                "/operator/communities/{domain}/identity-lifecycle/retire"
            ))
            .header(header::HOST, "operator.example")
            .header(header::CONTENT_LENGTH, (64 * 1024 + 1).to_string())
            .extension(test_peer())
            .body(counted_body(
                vec![vec![b'x'; 64 * 1024 + 1]],
                Arc::clone(&length_polls),
            ))
            .expect("length request");
        let response = app(runtime).oneshot(length).await.expect("length response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let (runtime, _signer, _approver, _executor) = test_runtime();
        let chunked_polls = Arc::new(AtomicUsize::new(0));
        let chunked = unsigned_lifecycle_request(
            "retire",
            domain,
            "operator.example",
            None,
            counted_body(
                vec![vec![b'x'; 32 * 1024], vec![b'y'; 32 * 1024 + 1]],
                Arc::clone(&chunked_polls),
            ),
        );
        let response = app(runtime)
            .oneshot(chunked)
            .await
            .expect("chunked response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(chunked_polls.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn stock_production_composition_is_strictly_off_without_io() {
        let signer = Keys::generate();
        let verifier = OperatorLifecycleVerifier::new(vec![signer.public_key()]).expect("verifier");
        let runtime = OperatorLifecycleRuntime::production(
            "https://operator.example",
            Arc::new(verifier),
            Arc::new(AlwaysFreshReplayGuard),
            ProviderFreeV1Composition::default(),
        )
        .expect("production runtime");
        assert!(matches!(
            runtime.preflight(CommunityId::from_uuid(Uuid::new_v4())),
            Err(OperatorInvocationError::NotConfigured)
        ));
    }

    #[tokio::test]
    async fn off_lifecycle_domain_is_404_without_credential_audit_or_execution() {
        let (runtime, signer, approver, executor) = test_runtime();
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        set_mode(&executor, domain, NipFiMode::Off);
        executor.healthy.store(false, Ordering::SeqCst);
        let response = app(runtime)
            .oneshot(signed_request(
                "retire",
                *domain.as_uuid(),
                body("retire", Uuid::new_v4()),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn deny_protected_lifecycle_domain_is_uniform_404_without_side_effects() {
        let (runtime, signer, approver, executor) = test_runtime();
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        set_mode(&executor, domain, NipFiMode::DenyProtected);
        executor.healthy.store(false, Ordering::SeqCst);
        let response = app(runtime)
            .oneshot(signed_request(
                "retire",
                *domain.as_uuid(),
                body("retire", Uuid::new_v4()),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unhealthy_enforce_domain_fails_before_missing_credential_audit() {
        let (runtime, _signer, _approver, executor) = test_runtime();
        let domain = Uuid::new_v4();
        set_domain_health(&executor, CommunityId::from_uuid(domain), false);
        let response = app(runtime)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/operator/communities/{domain}/identity-lifecycle/retire"
                    ))
                    .header(header::HOST, "operator.example")
                    .extension(test_peer())
                    .body(Body::from(body("retire", Uuid::new_v4())))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unrelated_unhealthy_domain_does_not_block_enforced_domain() {
        let (runtime, signer, approver, executor) = test_runtime();
        set_domain_health(&executor, CommunityId::from_uuid(Uuid::new_v4()), false);
        let healthy_domain = Uuid::new_v4();
        let response = app(runtime)
            .oneshot(signed_request(
                "retire",
                healthy_domain,
                body("retire", Uuid::new_v4()),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn off_and_deny_provision_domains_are_zero_io() {
        for mode in [NipFiMode::Off, NipFiMode::DenyProtected] {
            let (runtime, signer, approver, executor) = test_runtime();
            let domain = CommunityId::from_uuid(Uuid::new_v4());
            set_mode(&executor, domain, mode);
            executor.healthy.store(false, Ordering::SeqCst);
            let response = app(runtime)
                .oneshot(signed_provision_request(
                    domain,
                    Uuid::new_v4(),
                    &Keys::generate(),
                    &signer,
                    Some(&approver),
                ))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
            assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
            assert_eq!(executor.provisions.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn off_mode_precedes_full_provision_body_and_credential_validation() {
        let (runtime, _signer, _approver, executor) = test_runtime();
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        set_mode(&executor, domain, NipFiMode::Off);
        let response = app(runtime)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/identity-bindings/provision")
                    .header(header::HOST, "operator.example")
                    .header(
                        OPERATOR_PROVISION_DOMAIN_HEADER,
                        domain.as_uuid().to_string(),
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(test_peer())
                    .body(Body::from(
                        json!({"authorization_domain": domain.as_uuid()}).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn enforce_provision_route_verifies_and_executes_once() {
        let (runtime, signer, approver, executor) = test_runtime();
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let operation_id = Uuid::new_v4();
        let response = app(runtime)
            .oneshot(signed_provision_request(
                domain,
                operation_id,
                &Keys::generate(),
                &signer,
                Some(&approver),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 1);
        assert_eq!(
            json_body(response).await["operation_id"],
            operation_id.to_string()
        );
    }

    #[tokio::test]
    async fn provision_missing_and_duplicate_credentials_use_the_dedicated_denial_lane() {
        let (runtime, signer, approver, executor) = test_runtime();
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let body = provision_body(domain, Uuid::new_v4(), &Keys::generate());
        let missing = app(Arc::clone(&runtime))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/identity-bindings/provision")
                    .header(header::HOST, "operator.example")
                    .header(
                        OPERATOR_PROVISION_DOMAIN_HEADER,
                        domain.as_uuid().to_string(),
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(test_peer())
                    .body(Body::from(body))
                    .expect("missing credential request"),
            )
            .await
            .expect("missing credential response");
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let mut duplicate = signed_provision_request(
            domain,
            Uuid::new_v4(),
            &Keys::generate(),
            &signer,
            Some(&approver),
        );
        duplicate.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Nostr Yg=="),
        );
        let duplicate = app(runtime)
            .oneshot(duplicate)
            .await
            .expect("duplicate credential response");
        assert_eq!(duplicate.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 2);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn incomplete_provision_denial_does_not_latch_and_valid_retry_succeeds() {
        let (runtime, signer, approver, executor) = test_runtime();
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let incomplete = json!({"authorization_domain": domain.as_uuid()}).to_string();
        let denied = app(Arc::clone(&runtime))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/identity-bindings/provision")
                    .header(header::HOST, "operator.example")
                    .header(
                        OPERATOR_PROVISION_DOMAIN_HEADER,
                        domain.as_uuid().to_string(),
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(test_peer())
                    .body(Body::from(incomplete))
                    .expect("incomplete request"),
            )
            .await
            .expect("denied response");
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert!(runtime.healthy().await);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 1);

        let accepted = app(runtime)
            .oneshot(signed_provision_request(
                domain,
                Uuid::new_v4(),
                &Keys::generate(),
                &signer,
                Some(&approver),
            ))
            .await
            .expect("accepted response");
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn saturated_preauth_capacity_is_health_neutral_and_does_not_block_lifecycle() {
        let (runtime, signer, approver, executor) = test_runtime();
        executor
            .denial_capacity_exhausted
            .store(true, Ordering::SeqCst);
        let domain = Uuid::new_v4();
        let denied = app(Arc::clone(&runtime))
            .oneshot(unsigned_lifecycle_request(
                "retire",
                domain,
                "operator.example",
                None,
                Body::from(body("retire", Uuid::new_v4())),
            ))
            .await
            .expect("denied response");
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert!(runtime.healthy().await);

        let accepted = app(runtime)
            .oneshot(signed_request(
                "retire",
                domain,
                body("retire", Uuid::new_v4()),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("accepted response");
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn provision_denial_audit_failure_preserves_unauthorized_and_latches_health() {
        let (runtime, _signer, _approver, executor) = test_runtime();
        executor.denial_fails.store(true, Ordering::SeqCst);
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let response = app(Arc::clone(&runtime))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/identity-bindings/provision")
                    .header(header::HOST, "operator.example")
                    .header(
                        OPERATOR_PROVISION_DOMAIN_HEADER,
                        domain.as_uuid().to_string(),
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(test_peer())
                    .body(Body::from(provision_body(
                        domain,
                        Uuid::new_v4(),
                        &Keys::generate(),
                    )))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 1);
        assert_eq!(executor.provisions.load(Ordering::SeqCst), 0);
        assert!(!runtime.healthy().await);
    }

    #[tokio::test]
    async fn corrupt_denial_result_latches_health_and_blocks_later_valid_work() {
        let (runtime, signer, approver, executor) = test_runtime();
        executor.denial_is_corrupt.store(true, Ordering::SeqCst);
        let domain = Uuid::new_v4();
        let denied = app(Arc::clone(&runtime))
            .oneshot(unsigned_lifecycle_request(
                "retire",
                domain,
                "operator.example",
                None,
                Body::from(body("retire", Uuid::new_v4())),
            ))
            .await
            .expect("denial response");
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert!(!runtime.healthy().await);

        executor.denial_is_corrupt.store(false, Ordering::SeqCst);
        let blocked = app(runtime)
            .oneshot(signed_request(
                "retire",
                domain,
                body("retire", Uuid::new_v4()),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("blocked response");
        assert_eq!(blocked.status(), StatusCode::NOT_FOUND);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn all_six_actions_parse_to_closed_typed_intents() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        for action in ["retire", "disable", "revoke", "rotate", "recover", "enable"] {
            let intent =
                parse_lifecycle_intent(domain, action, body(action, Uuid::new_v4()).as_bytes())
                    .expect("typed intent");
            assert_eq!(
                intent.action(),
                buzz_auth::OperatorLifecycleAction::from_path_segment(action).unwrap()
            );
            assert_ne!(intent.intent_digest(), [0; 32]);
        }
    }

    #[tokio::test]
    async fn configured_router_exposes_only_the_six_closed_actions() {
        let (runtime, _signer, _approver, executor) = test_runtime();
        let response = app(runtime)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/operator/communities/{}/identity-lifecycle/admission-loss",
                        Uuid::new_v4()
                    ))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn provision_helper_returns_opaque_policy_bound_intent() {
        let signer = Keys::generate();
        let selected_key = Keys::generate();
        let verifier = OperatorLifecycleVerifier::new(vec![signer.public_key()]).expect("verifier");
        let url = "https://operator.example/operator/identity-bindings/provision";
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let operation_id = Uuid::new_v4();
        let policy_revision = 7_u64;
        let policy_digest = [0x44; 32];
        let issuer = "https://issuer.example";
        let subject = "opaque-subject";
        let selected_event_author_pubkey = selected_key.public_key().to_bytes();
        let body = json!({
            "authorization_domain": domain.as_uuid(),
            "operation_id": operation_id,
            "policy_revision": policy_revision,
            "policy_digest": hex::encode(policy_digest),
            "issuer": issuer,
            "subject": subject,
            "selected_event_author_pubkey": hex::encode(selected_event_author_pubkey),
        })
        .to_string();
        let body_digest: [u8; 32] = Sha256::digest(body.as_bytes()).into();
        let intent_digest = test_framed_digest(
            b"buzz:operator-provision-binding-intent:v2",
            &[
                domain.as_uuid().as_bytes(),
                operation_id.as_bytes(),
                &policy_revision.to_be_bytes(),
                &policy_digest,
                issuer.as_bytes(),
                subject.as_bytes(),
                &selected_event_author_pubkey,
                &body_digest,
            ],
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&nip98_header(&signer, url, body.as_bytes(), intent_digest))
                .expect("header"),
        );
        let verified = verify_provision_binding_intent(
            &verifier,
            &AlwaysFreshReplayGuard,
            url,
            domain,
            &headers,
            body.as_bytes(),
        )
        .await
        .expect("verified provision intent");
        assert_ne!(verified.intent_digest(), [0; 32]);
        assert_eq!(
            format!("{verified:?}"),
            "VerifiedProvisionBindingIntent([REDACTED])"
        );
    }

    #[tokio::test]
    async fn stock_policy_accepts_one_configured_signer_without_approval() {
        let signer = Keys::generate();
        let verifier = OperatorLifecycleVerifier::new(vec![signer.public_key()]).expect("verifier");
        let (runtime, executor) = runtime_with_verifier(verifier);
        let response = app(runtime)
            .oneshot(signed_request(
                "retire",
                Uuid::new_v4(),
                body("retire", Uuid::new_v4()),
                &signer,
                None,
                None,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn independent_policy_requires_and_audits_missing_approval() {
        let (runtime, signer, _approver, executor) = test_runtime();
        let response = app(runtime)
            .oneshot(signed_request(
                "retire",
                Uuid::new_v4(),
                body("retire", Uuid::new_v4()),
                &signer,
                None,
                None,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn missing_header_preserves_unauthorized_when_denial_recording_fails() {
        let (runtime, _signer, _approver, executor) = test_runtime();
        executor.denial_fails.store(true, Ordering::SeqCst);
        let community = Uuid::new_v4();
        let response = app(Arc::clone(&runtime))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/operator/communities/{community}/identity-lifecycle/retire"
                    ))
                    .header(header::HOST, "operator.example")
                    .extension(test_peer())
                    .body(Body::from(body("retire", Uuid::new_v4())))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 1);
        assert!(!runtime.healthy().await);
    }

    #[tokio::test]
    async fn verifier_denial_preserves_forbidden_when_denial_recording_fails() {
        let (runtime, _signer, approver, executor) = test_runtime();
        executor.denial_fails.store(true, Ordering::SeqCst);
        let outsider = Keys::generate();
        let response = app(Arc::clone(&runtime))
            .oneshot(signed_request(
                "retire",
                Uuid::new_v4(),
                body("retire", Uuid::new_v4()),
                &outsider,
                Some(&approver),
                None,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 1);
        assert!(!runtime.healthy().await);
    }

    #[tokio::test]
    async fn all_six_signed_routes_invoke_the_executor_once() {
        let (runtime, signer, approver, executor) = test_runtime();
        let community = Uuid::new_v4();
        for (index, action) in ["retire", "disable", "revoke", "rotate", "recover", "enable"]
            .into_iter()
            .enumerate()
        {
            let replacement_keys =
                matches!(action, "rotate" | "recover" | "enable").then(Keys::generate);
            let mut request_json: Value =
                serde_json::from_str(&body(action, Uuid::new_v4())).expect("action json");
            if let Some(replacement_keys) = &replacement_keys {
                request_json["replacement"]["event_author_pubkey"] =
                    Value::String(replacement_keys.public_key().to_hex());
            }
            let response = app(Arc::clone(&runtime))
                .oneshot(signed_request(
                    action,
                    community,
                    request_json.to_string(),
                    &signer,
                    Some(&approver),
                    replacement_keys.as_ref(),
                ))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK, "action {action}");
            assert_eq!(json_body(response).await["status"], "applied");
            assert_eq!(
                executor.calls.load(Ordering::SeqCst),
                index + 1,
                "action {action} must invoke exactly once"
            );
        }
        assert_eq!(executor.denials.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn duplicate_authorization_approval_and_replacement_headers_are_audited() {
        let (runtime, signer, approver, executor) = test_runtime();
        let community = Uuid::new_v4();

        let mut duplicate_authorization = signed_request(
            "retire",
            community,
            body("retire", Uuid::new_v4()),
            &signer,
            Some(&approver),
            None,
        );
        duplicate_authorization.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Nostr Yg=="),
        );
        let response = app(Arc::clone(&runtime))
            .oneshot(duplicate_authorization)
            .await
            .expect("duplicate authorization response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut duplicate_approval = signed_request(
            "retire",
            community,
            body("retire", Uuid::new_v4()),
            &signer,
            Some(&approver),
            None,
        );
        duplicate_approval.headers_mut().append(
            OPERATOR_APPROVAL_HEADER,
            HeaderValue::from_static("Nostr Yg=="),
        );
        let response = app(Arc::clone(&runtime))
            .oneshot(duplicate_approval)
            .await
            .expect("duplicate approval response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let replacement_keys = Keys::generate();
        let mut rotate_json: Value =
            serde_json::from_str(&body("rotate", Uuid::new_v4())).expect("rotate json");
        rotate_json["replacement"]["event_author_pubkey"] =
            Value::String(replacement_keys.public_key().to_hex());
        let mut duplicate_replacement = signed_request(
            "rotate",
            community,
            rotate_json.to_string(),
            &signer,
            Some(&approver),
            Some(&replacement_keys),
        );
        duplicate_replacement.headers_mut().append(
            OPERATOR_REPLACEMENT_PROOF_HEADER,
            HeaderValue::from_static("Nostr Yg=="),
        );
        let response = app(runtime)
            .oneshot(duplicate_replacement)
            .await
            .expect("duplicate replacement response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn lifecycle_error_status_mapping_is_closed() {
        for (error, expected) in [
            (
                OperatorInvocationError::NotConfigured,
                StatusCode::NOT_FOUND,
            ),
            (OperatorInvocationError::PolicyDenied, StatusCode::FORBIDDEN),
            (
                OperatorInvocationError::InvalidRequest,
                StatusCode::BAD_REQUEST,
            ),
            (
                OperatorInvocationError::AuthenticationRejected,
                StatusCode::UNAUTHORIZED,
            ),
            (
                OperatorInvocationError::AuthenticationForbidden,
                StatusCode::FORBIDDEN,
            ),
            (
                OperatorInvocationError::ApprovalDenied,
                StatusCode::FORBIDDEN,
            ),
            (
                OperatorInvocationError::IntentConflict,
                StatusCode::CONFLICT,
            ),
            (
                OperatorInvocationError::RateLimited,
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                OperatorInvocationError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                OperatorInvocationError::Failed,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            assert_eq!(lifecycle_error(error).0, expected);
        }
    }

    #[test]
    fn auth_and_persistence_errors_map_to_closed_http_statuses() {
        fn assert_status(error: impl Into<OperatorInvocationError>, expected: StatusCode) {
            assert_eq!(lifecycle_error(error.into()).0, expected);
        }

        assert_status(
            OperatorLifecycleGrantError::InvalidConfiguration,
            StatusCode::SERVICE_UNAVAILABLE,
        );
        assert_status(
            OperatorLifecycleGrantError::InvalidRequest,
            StatusCode::BAD_REQUEST,
        );
        assert_status(
            OperatorLifecycleGrantError::InvalidCredential,
            StatusCode::UNAUTHORIZED,
        );
        assert_status(
            OperatorLifecycleGrantError::Unauthenticated,
            StatusCode::FORBIDDEN,
        );
        assert_status(
            OperatorLifecycleGrantError::ApprovalNotIndependent,
            StatusCode::FORBIDDEN,
        );
        assert_status(
            OperatorLifecycleGrantError::Replayed,
            StatusCode::UNAUTHORIZED,
        );
        assert_status(
            OperatorLifecycleGrantError::ReplayUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        );

        assert_status(
            OperatorLifecycleError::InvalidRequest,
            StatusCode::BAD_REQUEST,
        );
        assert_status(OperatorLifecycleError::IntentConflict, StatusCode::CONFLICT);
        assert_status(
            OperatorLifecycleError::AuditUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        );
        assert_status(
            OperatorLifecycleError::CorruptStoredResult,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
        assert_status(
            OperatorLifecycleError::Storage(DbError::AuthEventRejected),
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }

    #[tokio::test]
    async fn absent_malformed_and_duplicate_authorization_are_pre_auth_denials() {
        let (runtime, _signer, _approver, executor) = test_runtime();
        let community = Uuid::new_v4();
        let request_body = body("retire", Uuid::new_v4());

        let absent = Request::builder()
            .method("POST")
            .uri(format!(
                "/operator/communities/{community}/identity-lifecycle/retire"
            ))
            .header(header::HOST, "operator.example")
            .extension(test_peer())
            .body(Body::from(request_body.clone()))
            .expect("request");
        let response = app(Arc::clone(&runtime))
            .oneshot(absent)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let malformed = Request::builder()
            .method("POST")
            .uri(format!(
                "/operator/communities/{community}/identity-lifecycle/retire"
            ))
            .header(header::HOST, "operator.example")
            .header(header::AUTHORIZATION, "Bearer not-nip98")
            .extension(test_peer())
            .body(Body::from(request_body.clone()))
            .expect("request");
        let response = app(Arc::clone(&runtime))
            .oneshot(malformed)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut duplicate = request("retire", community, request_body);
        duplicate.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Nostr Yg=="),
        );
        let response = app(runtime).oneshot(duplicate).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn replacement_actions_require_and_verify_the_third_exact_proof() {
        let (runtime, signer, approver, executor) = test_runtime();
        let replacement_keys = Keys::generate();
        let community = Uuid::new_v4();
        let mut request_json: Value =
            serde_json::from_str(&body("rotate", Uuid::new_v4())).expect("rotate json");
        request_json["replacement"]["event_author_pubkey"] =
            Value::String(replacement_keys.public_key().to_hex());
        let request_body = request_json.to_string();

        let missing = app(Arc::clone(&runtime))
            .oneshot(signed_request(
                "rotate",
                community,
                request_body.clone(),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("missing-proof response");
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 1);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);

        let verified = app(runtime)
            .oneshot(signed_request(
                "rotate",
                community,
                request_body,
                &signer,
                Some(&approver),
                Some(&replacement_keys),
            ))
            .await
            .expect("verified response");
        assert_eq!(verified.status(), StatusCode::OK);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejected_configured_auth_is_audited_before_executor() {
        let (runtime, _signer, approver, executor) = test_runtime();
        let outsider = Keys::generate();
        let response = app(runtime)
            .oneshot(signed_request(
                "retire",
                Uuid::new_v4(),
                body("retire", Uuid::new_v4()),
                &outsider,
                Some(&approver),
                None,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.denials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exact_replay_reaches_durable_executor_again() {
        let (runtime, signer, approver, executor) = test_runtime();
        let community = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let request_body = body("retire", operation_id);

        let first = app(Arc::clone(&runtime))
            .oneshot(signed_request(
                "retire",
                community,
                request_body.clone(),
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("first response");
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(json_body(first).await["status"], "applied");

        let replay = app(runtime)
            .oneshot(signed_request(
                "retire",
                community,
                request_body,
                &signer,
                Some(&approver),
                None,
            ))
            .await
            .expect("replay response");
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(json_body(replay).await["status"], "exact_replay");
        assert_eq!(executor.calls.load(Ordering::SeqCst), 2);
    }
}

/// Query parameters for `GET /operator/communities/availability`.
#[derive(Debug, Deserialize)]
pub struct CommunityAvailabilityQuery {
    host: String,
}

#[derive(Debug, Deserialize)]
struct TransferCommunityRequest {
    community_id: String,
    new_owner_pubkey: String,
    expected_owner_pubkey: String,
}

#[derive(Debug, Serialize)]
struct TransferCommunityResponse {
    community_id: String,
    new_owner_pubkey: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_owner: Option<String>,
}

const OPERATOR_REPLAY_SCOPE: &str = "operator-management";

/// Shared deployment-global operator auth prelude. The canonical management
/// origin and replay namespace are configuration, never tenant registry state
/// or an inbound proxy `Host` header.
async fn authorize_operator_request(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    raw_query: Option<&str>,
    body: Option<&[u8]>,
) -> Result<nostr::PublicKey, (StatusCode, Json<Value>)> {
    let origin = state
        .config
        .relay_operator_api_origin
        .as_deref()
        .ok_or_else(|| internal_error("operator API origin is not configured"))?;
    let path_with_query = match raw_query {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path.to_string(),
    };
    let url = format!("{origin}{path_with_query}");
    let (pubkey, event_id_bytes) = bridge::verify_bridge_auth_with_options(
        headers,
        method,
        &url,
        body,
        true, // operator endpoints always require NIP-98; no X-Pubkey dev fallback
        body.is_some(),
    )?;
    check_operator_replay(state, event_id_bytes).await?;

    let pubkey_hex = pubkey.to_hex();
    if !state
        .config
        .relay_operator_pubkeys
        .iter()
        .any(|pk| pk == &pubkey_hex)
    {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "actor not authorized: not a relay operator",
        ));
    }

    Ok(pubkey)
}

async fn check_operator_replay(
    state: &AppState,
    event_id_bytes: [u8; 32],
) -> Result<(), (StatusCode, Json<Value>)> {
    let event_id = nostr::EventId::from_byte_array(event_id_bytes);
    match state
        .nip98_replay
        .try_mark_in_scope(
            OPERATOR_REPLAY_SCOPE,
            &event_id,
            buzz_auth::DEFAULT_REPLAY_TTL_SECS,
        )
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(api_error(
            StatusCode::UNAUTHORIZED,
            "NIP-98: replay detected",
        )),
        Err(error) => {
            tracing::warn!(
                scope = OPERATOR_REPLAY_SCOPE,
                error = %error,
                "operator NIP-98 replay guard failed; rejecting request fail-closed"
            );
            Err(api_error(
                StatusCode::UNAUTHORIZED,
                "NIP-98: replay check unavailable",
            ))
        }
    }
}

/// Create a community host and atomically bootstrap its initial owner.
///
/// `POST /operator/communities`, NIP-98 signed by a pubkey in
/// `RELAY_OPERATOR_PUBKEYS`, body:
///
/// ```json
/// { "host": "acme.communities.buzz.xyz", "initial_owner_pubkey": "<hex>" }
/// ```
///
/// The request is authenticated against `RELAY_OPERATOR_API_ORIGIN` and does
/// not bind the inbound host to a tenant. The operator allowlist is the
/// authority for this deployment-root control-plane surface.
pub async fn provision_community(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let pubkey = authorize_operator_request(
        &state,
        &headers,
        "POST",
        "/operator/communities",
        None,
        Some(&body),
    )
    .await?;

    let request: ProvisionCommunityRequest = serde_json::from_slice(&body).map_err(|e| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid provision-community JSON: {e}"),
        )
    })?;

    match crate::handlers::community_provisioning::provision_community(&state, &pubkey, request)
        .await
    {
        Ok(response) => Ok(Json(serde_json::to_value(response).map_err(|e| {
            tracing::error!("failed to serialize provision-community response: {e}");
            internal_error("operator provision response serialization failed")
        })?)),
        Err(msg) if msg.starts_with("actor not authorized") => {
            Err(api_error(StatusCode::FORBIDDEN, &msg))
        }
        Err(msg) if msg == "community already exists" || msg.starts_with("limit_reached:") => {
            Err(api_error(StatusCode::CONFLICT, &msg))
        }
        Err(msg)
            if msg.starts_with("failed to create community:")
                || msg.starts_with("community provisioned but owner bootstrap failed:") =>
        {
            tracing::error!(error = %msg, "operator community persistence failed");
            Err(internal_error("operator community persistence failed"))
        }
        Err(msg) => Err(api_error(StatusCode::BAD_REQUEST, &msg)),
    }
}

/// Owner assertion supplied by the trusted operator client.
#[derive(Debug, Deserialize)]
pub struct ArchiveCommunityRequest {
    host: String,
    owner_pubkey: String,
}

/// Idempotently archive a community owned by the asserted end-user identity.
pub async fn archive_community(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    const PATH: &str = "/operator/communities/archive";
    authorize_operator_request(&state, &headers, "POST", PATH, None, Some(&body)).await?;
    let request: ArchiveCommunityRequest = serde_json::from_slice(&body).map_err(|e| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid archive-community JSON: {e}"),
        )
    })?;
    let normalized_host = normalize_candidate_host(&request.host)
        .map_err(|msg| api_error(StatusCode::BAD_REQUEST, &msg))?;
    let deployment_host = buzz_core::tenant::relay_url_authority(&state.config.relay_url);
    if normalized_host == deployment_host {
        return Err(api_error(
            StatusCode::CONFLICT,
            "the deployment community cannot be archived",
        ));
    }
    let owner = validate_pubkey_hex(&request.owner_pubkey).ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid owner_pubkey: expected 64-char hex pubkey",
        )
    })?;
    let record = state
        .db
        .archive_community_owned_by(&normalized_host, &owner, &deployment_host)
        .await
        .map_err(|e| internal_error(&format!("archive community: {e}")))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "community not found"))?;
    let tenant = TenantContext::resolved(record.id, &record.host);
    let closed = match state.disconnect_community_clusterwide(&tenant).await {
        Ok(closed) => closed,
        Err(error) => {
            tracing::warn!(community = %record.id, host = %record.host, %error, "community archived but disconnect propagation is pending");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "community_id": record.id.to_string(),
                    "host": record.host,
                    "archived_at": record.archived_at,
                    "status": "archived",
                    "propagation": "pending",
                    "error": "connection propagation pending — retry this request",
                })),
            ));
        }
    };
    tracing::info!(community = %record.id, host = %record.host, local_connections_closed = closed, "community archived");
    Ok(Json(serde_json::json!({
        "community_id": record.id.to_string(),
        "host": record.host,
        "archived_at": record.archived_at,
        "status": "archived",
    })))
}

/// Idempotently restore an archived community owned by the asserted end-user identity.
pub async fn unarchive_community(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    const PATH: &str = "/operator/communities/unarchive";
    authorize_operator_request(&state, &headers, "POST", PATH, None, Some(&body)).await?;
    let request: ArchiveCommunityRequest = serde_json::from_slice(&body).map_err(|e| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid unarchive-community JSON: {e}"),
        )
    })?;
    let normalized_host = normalize_candidate_host(&request.host)
        .map_err(|msg| api_error(StatusCode::BAD_REQUEST, &msg))?;
    let owner = validate_pubkey_hex(&request.owner_pubkey).ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid owner_pubkey: expected 64-char hex pubkey",
        )
    })?;
    let record = state
        .db
        .unarchive_community_owned_by(&normalized_host, &owner)
        .await
        .map_err(|e| internal_error(&format!("unarchive community: {e}")))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "community not found"))?;
    tracing::info!(community = %record.id, host = %record.host, "community unarchived");
    Ok(Json(serde_json::json!({
        "community_id": record.id.to_string(),
        "host": record.host,
        "archived_at": null,
        "status": "active",
    })))
}

/// List communities where a pubkey currently holds the `owner` role.
pub async fn list_owned_communities(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<ListCommunitiesQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    authorize_operator_request(
        &state,
        &headers,
        "GET",
        "/operator/communities",
        raw_query.as_deref(),
        None,
    )
    .await?;

    let owner_pubkey = validate_pubkey_hex(&query.owner_pubkey).ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid owner_pubkey: expected 64-char hex pubkey",
        )
    })?;

    let rows = state
        .db
        .list_communities_owned_by(&owner_pubkey)
        .await
        .map_err(|e| internal_error(&format!("list owned communities: {e}")))?;

    Ok(Json(serde_json::json!({
        "owner_pubkey": owner_pubkey,
        "communities": rows.into_iter().map(|row| serde_json::json!({
            "community_id": row.id.to_string(),
            "host": row.host,
            "created_at": row.created_at,
            "archived_at": row.archived_at,
        })).collect::<Vec<_>>(),
    })))
}

/// Transfer ownership of a community to a new owner pubkey.
///
/// `POST /operator/communities/transfer`, NIP-98 signed by a pubkey in
/// `RELAY_OPERATOR_PUBKEYS`, body:
///
/// ```json
/// { "community_id": "<uuid>", "new_owner_pubkey": "<hex>" }
/// ```
///
/// The previous owner is demoted to `member` (not `admin`). The transfer is
/// instant and atomic at the database layer. Publication of the updated
/// NIP-43 membership list is best-effort, matching the provision path.
pub async fn transfer_community(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _pubkey = authorize_operator_request(
        &state,
        &headers,
        "POST",
        "/operator/communities/transfer",
        None,
        Some(&body),
    )
    .await?;

    let request: TransferCommunityRequest = serde_json::from_slice(&body).map_err(|e| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid transfer-community JSON: {e}"),
        )
    })?;

    let community_uuid = Uuid::parse_str(&request.community_id).map_err(|e| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid community_id: {e}"),
        )
    })?;

    let new_owner_pubkey = validate_pubkey_hex(&request.new_owner_pubkey).ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "invalid new_owner_pubkey: expected 64-char hex pubkey",
        )
    })?;

    let expected_owner_pubkey =
        validate_pubkey_hex(&request.expected_owner_pubkey).ok_or_else(|| {
            api_error(
                StatusCode::BAD_REQUEST,
                "invalid expected_owner_pubkey: expected 64-char hex pubkey",
            )
        })?;

    let community = CommunityId::from_uuid(community_uuid);

    let result = state
        .db
        .transfer_ownership(community, &new_owner_pubkey, &expected_owner_pubkey)
        .await
        .map_err(|e| internal_error(&format!("transfer ownership: {e}")))?;

    let (status, previous_owner) = match result {
        buzz_db::relay_members::TransferResult::Transferred { previous_owner } => {
            ("transferred", previous_owner)
        }
        buzz_db::relay_members::TransferResult::AlreadyOwner => ("already_owner", None),
        buzz_db::relay_members::TransferResult::NoOwner => {
            return Err(api_error(
                StatusCode::NOT_FOUND,
                "community has no owner to transfer from",
            ));
        }
        buzz_db::relay_members::TransferResult::OwnerConflict => {
            return Err(api_error(
                StatusCode::CONFLICT,
                "owner_conflict: the current owner no longer matches expected_owner_pubkey",
            ));
        }
        buzz_db::relay_members::TransferResult::LimitReached => {
            return Err(api_error(
                StatusCode::CONFLICT,
                "limit_reached: transferee already owns the maximum number of communities",
            ));
        }
    };

    // Best-effort NIP-43 membership snapshot publication — same pattern as
    // provision_community. The DB mutation is already committed; a publication
    // failure must not turn a success into an HTTP error.
    if state.config.require_relay_membership {
        if let Some(host) = state
            .db
            .lookup_community_host(community)
            .await
            .map_err(|e| internal_error(&format!("lookup community host: {e}")))?
        {
            let tenant = TenantContext::resolved(community, host);
            if let Err(error) =
                crate::handlers::side_effects::publish_nip43_membership_list(&tenant, &state).await
            {
                tracing::warn!(
                    community = %community,
                    error = %error,
                    "ownership transferred but NIP-43 membership snapshot publication failed"
                );
            }
        }
    }

    let response = TransferCommunityResponse {
        community_id: request.community_id,
        new_owner_pubkey,
        status,
        previous_owner,
    };

    Ok(Json(serde_json::to_value(response).map_err(|e| {
        tracing::error!("failed to serialize transfer-community response: {e}");
        internal_error("operator transfer response serialization failed")
    })?))
}
/// Check whether a community host is available, returning the relay-canonical
/// normalized authority used by create.
pub async fn community_availability(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<CommunityAvailabilityQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    authorize_operator_request(
        &state,
        &headers,
        "GET",
        "/operator/communities/availability",
        raw_query.as_deref(),
        None,
    )
    .await?;

    let normalized_host = normalize_candidate_host(&query.host)
        .map_err(|msg| api_error(StatusCode::BAD_REQUEST, &msg))?;
    let existing = state
        .db
        .lookup_community_by_host_for_management(&normalized_host)
        .await
        .map_err(|e| internal_error(&format!("check community availability: {e}")))?;

    Ok(Json(serde_json::json!({
        "host": query.host,
        "normalized_host": normalized_host,
        "available": existing.is_none(),
        "community_id": existing.map(|record| record.id.to_string()),
    })))
}

const MAX_LIFECYCLE_AUTHORIZATION_BYTES: usize = 8 * 1024;
const MAX_LIFECYCLE_REQUEST_BYTES: usize = 64 * 1024;
const OPERATOR_PROVISION_PATH: &str = "/operator/identity-bindings/provision";
const OPERATOR_PROVISION_DOMAIN_HEADER: &str = "x-buzz-authorization-domain";

#[derive(Clone, Copy)]
struct PreflightOperatorRequest {
    domain: CommunityId,
    peer: IpAddr,
}

/// Return the six-action lifecycle plus separate provision subrouter only when
/// the complete operator verifier and executor are configured. The caller must
/// merge the returned router into the existing deployment-operator API. `None`
/// deliberately installs no route, leaving the entire surface 404.
pub fn lifecycle_router(runtime: Option<Arc<OperatorLifecycleRuntime>>) -> Option<Router> {
    runtime.map(|runtime| {
        Router::new()
            .route(
                "/operator/communities/{community_id}/identity-lifecycle/retire",
                post(retire_identity),
            )
            .route(
                "/operator/communities/{community_id}/identity-lifecycle/disable",
                post(disable_identity),
            )
            .route(
                "/operator/communities/{community_id}/identity-lifecycle/revoke",
                post(revoke_identity),
            )
            .route(
                "/operator/communities/{community_id}/identity-lifecycle/rotate",
                post(rotate_identity),
            )
            .route(
                "/operator/communities/{community_id}/identity-lifecycle/recover",
                post(recover_identity),
            )
            .route(
                "/operator/communities/{community_id}/identity-lifecycle/enable",
                post(enable_identity),
            )
            .route(OPERATOR_PROVISION_PATH, post(provision_identity_binding))
            .route_layer(RequestBodyLimitLayer::new(MAX_LIFECYCLE_REQUEST_BYTES))
            .route_layer(middleware::from_fn(operator_prebody_gate))
            .layer(Extension(runtime))
    })
}

async fn operator_prebody_gate(
    Extension(runtime): Extension<Arc<OperatorLifecycleRuntime>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Axum's method fallback remains the sole 405 authority. Only POST can
    // enter an operator handler or count as a pre-authentication attempt.
    if request.method() != axum::http::Method::POST {
        return next.run(request).await;
    }
    let uri_scheme = request.uri().scheme_str();
    let uri_authority = request
        .uri()
        .authority()
        .map(|authority| authority.as_str());
    let headers = request.headers();
    let host = match exact_single_header(headers, header::HOST.as_str()) {
        Ok(host) => host,
        Err(()) => return operator_endpoint_unavailable(),
    };
    let origin = match exact_single_header(headers, header::ORIGIN.as_str()) {
        Ok(origin) => origin,
        Err(()) => return operator_endpoint_unavailable(),
    };
    if !runtime.transport_matches(uri_scheme, uri_authority, host, origin) {
        return operator_endpoint_unavailable();
    }
    let peer = match request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
    {
        Some(ConnectInfo(peer)) => peer.ip(),
        None => return operator_endpoint_unavailable(),
    };

    let domain = match operator_prebody_domain(request.uri().path(), headers) {
        Ok(domain) => domain,
        Err(()) => return lifecycle_error(OperatorInvocationError::InvalidRequest).into_response(),
    };
    match runtime.admit_prebody(domain) {
        Ok(()) => {}
        Err(OperatorPrebodyGateError::Unavailable) => return operator_endpoint_unavailable(),
    }

    request
        .extensions_mut()
        .insert(PreflightOperatorRequest { domain, peer });
    next.run(request).await
}

fn exact_single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map(Some).map_err(|_| ())
}

fn operator_prebody_domain(path: &str, headers: &HeaderMap) -> Result<CommunityId, ()> {
    if path == OPERATOR_PROVISION_PATH {
        let raw = exact_single_header(headers, OPERATOR_PROVISION_DOMAIN_HEADER)?.ok_or(())?;
        return nonnil_community_id(raw);
    }

    let suffix = path.strip_prefix("/operator/communities/").ok_or(())?;
    let (raw_domain, action) = suffix.split_once("/identity-lifecycle/").ok_or(())?;
    if !matches!(
        action,
        "retire" | "disable" | "revoke" | "rotate" | "recover" | "enable"
    ) {
        return Err(());
    }
    nonnil_community_id(raw_domain)
}

fn nonnil_community_id(raw: &str) -> Result<CommunityId, ()> {
    let domain = Uuid::parse_str(raw).map_err(|_| ())?;
    if domain.is_nil() {
        return Err(());
    }
    Ok(CommunityId::from_uuid(domain))
}

fn operator_endpoint_unavailable() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "operator endpoint unavailable"})),
    )
        .into_response()
}

fn operator_rate_limited() -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({"error": "operator request rate limited"})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    response
}

fn invalid_operator_request_or_rate_limited(
    runtime: &OperatorLifecycleRuntime,
    preflight: PreflightOperatorRequest,
) -> Response {
    match runtime.admit_failed_request(preflight.domain, preflight.peer) {
        Ok(()) => lifecycle_error(OperatorInvocationError::InvalidRequest).into_response(),
        Err(OperatorInvocationError::RateLimited) => operator_rate_limited(),
        Err(_) => operator_endpoint_unavailable(),
    }
}

#[derive(Deserialize)]
struct ProvisionDomainWire {
    authorization_domain: Uuid,
}

async fn provision_identity_binding(
    Extension(runtime): Extension<Arc<OperatorLifecycleRuntime>>,
    Extension(preflight): Extension<PreflightOperatorRequest>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, Response> {
    // Resolve only the server-selected domain before reading any proof. Serde
    // rejects duplicate domain fields; every other coordinate is ignored here
    // and independently parsed/exact-matched by the verifier after the gate.
    let coordinates: ProvisionDomainWire = serde_json::from_slice(&body)
        .map_err(|_| invalid_operator_request_or_rate_limited(&runtime, preflight))?;
    if coordinates.authorization_domain.is_nil() {
        return Err(invalid_operator_request_or_rate_limited(
            &runtime, preflight,
        ));
    }
    let domain = CommunityId::from_uuid(coordinates.authorization_domain);
    if domain != preflight.domain {
        return Err(invalid_operator_request_or_rate_limited(
            &runtime, preflight,
        ));
    }
    let (authorization, approval, replacement) =
        match lifecycle_proofs_for_action(&headers, runtime.requires_independent_approval(), false)
        {
            Ok(proofs) => proofs,
            Err(reason) => {
                if matches!(
                    runtime
                        .record_provision_preauth_denial(preflight.peer, domain, &body, reason)
                        .await,
                    Err(OperatorInvocationError::RateLimited)
                ) {
                    return Err(operator_rate_limited());
                }
                return Err(
                    api_error(StatusCode::UNAUTHORIZED, "operator authentication failed")
                        .into_response(),
                );
            }
        };
    debug_assert!(replacement.is_none());
    let observation = runtime
        .provision(
            preflight.peer,
            &authorization,
            approval.as_deref(),
            "/operator/identity-bindings/provision",
            &body,
            domain,
        )
        .await
        .map_err(|error| match error {
            OperatorInvocationError::RateLimited => operator_rate_limited(),
            other => lifecycle_error(other).into_response(),
        })?;
    let (status, value) = match observation.execution {
        ProvisionBindingExecution::Applied { .. } => (
            StatusCode::OK,
            serde_json::json!({"operation_id": observation.operation_id, "status": "applied"}),
        ),
        ProvisionBindingExecution::NoOp { .. } => (
            StatusCode::OK,
            serde_json::json!({"operation_id": observation.operation_id, "status": "no_op"}),
        ),
        ProvisionBindingExecution::ExactReplay { .. } => (
            StatusCode::OK,
            serde_json::json!({"operation_id": observation.operation_id, "status": "exact_replay"}),
        ),
        ProvisionBindingExecution::Denied { .. } => (
            StatusCode::CONFLICT,
            serde_json::json!({"operation_id": observation.operation_id, "status": "denied"}),
        ),
    };
    Ok((status, Json(value)).into_response())
}

macro_rules! lifecycle_handler {
    ($name:ident, $action:literal) => {
        async fn $name(
            Path(community_id): Path<String>,
            Extension(runtime): Extension<Arc<OperatorLifecycleRuntime>>,
            Extension(preflight): Extension<PreflightOperatorRequest>,
            headers: HeaderMap,
            body: axum::body::Bytes,
        ) -> Result<Response, Response> {
            lifecycle_transition(community_id, $action, runtime, preflight, headers, body).await
        }
    };
}

lifecycle_handler!(retire_identity, "retire");
lifecycle_handler!(disable_identity, "disable");
lifecycle_handler!(revoke_identity, "revoke");
lifecycle_handler!(rotate_identity, "rotate");
lifecycle_handler!(recover_identity, "recover");
lifecycle_handler!(enable_identity, "enable");

async fn lifecycle_transition(
    community_id: String,
    action: &'static str,
    runtime: Arc<OperatorLifecycleRuntime>,
    preflight: PreflightOperatorRequest,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, Response> {
    // Build the bounded credential-free intent before looking at either proof.
    // This gives every pre-auth denial exact redaction-safe audit coordinates.
    let domain_uuid = Uuid::parse_str(&community_id)
        .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest).into_response())?;
    let domain = CommunityId::from_uuid(domain_uuid);
    if domain != preflight.domain {
        return Err(lifecycle_error(OperatorInvocationError::InvalidRequest).into_response());
    }
    let intent = parse_lifecycle_intent(domain, action, &body)
        .map_err(|_| invalid_operator_request_or_rate_limited(&runtime, preflight))?;
    let (authorization_event_json, approval_event_json, replacement_proof_event_json) =
        match lifecycle_proofs_for_action(
            &headers,
            runtime.requires_independent_approval(),
            intent.replacement_event_author_pubkey().is_some(),
        ) {
            Ok(proofs) => proofs,
            Err(reason) => {
                if matches!(
                    runtime
                        .record_preauth_denial(preflight.peer, &intent, reason)
                        .await,
                    Err(OperatorInvocationError::RateLimited)
                ) {
                    return Err(operator_rate_limited());
                }
                return Err(
                    api_error(StatusCode::UNAUTHORIZED, "operator authentication failed")
                        .into_response(),
                );
            }
        };
    let path = format!("/operator/communities/{community_id}/identity-lifecycle/{action}");
    let observation = runtime
        .invoke(
            preflight.peer,
            &authorization_event_json,
            approval_event_json.as_deref(),
            replacement_proof_event_json.as_deref(),
            &path,
            &body,
            &intent,
        )
        .await
        .map_err(|error| match error {
            OperatorInvocationError::RateLimited => operator_rate_limited(),
            other => lifecycle_error(other).into_response(),
        })?;
    let operation_id = intent.operation_id();
    let (status, value) = match observation {
        IdentityLifecycleObservation::Applied { .. } => (
            StatusCode::OK,
            serde_json::json!({"operation_id": operation_id, "status": "applied"}),
        ),
        IdentityLifecycleObservation::NoOp { .. } => (
            StatusCode::OK,
            serde_json::json!({"operation_id": operation_id, "status": "no_op"}),
        ),
        IdentityLifecycleObservation::ExactReplay { .. } => (
            StatusCode::OK,
            serde_json::json!({"operation_id": operation_id, "status": "exact_replay"}),
        ),
        IdentityLifecycleObservation::Denied { .. } => (
            StatusCode::CONFLICT,
            serde_json::json!({
                "operation_id": operation_id,
                "status": "denied",
            }),
        ),
    };
    Ok((status, Json(value)).into_response())
}

const OPERATOR_APPROVAL_HEADER: &str = "x-buzz-operator-approval";
const OPERATOR_REPLACEMENT_PROOF_HEADER: &str = "x-buzz-replacement-proof";

/// Verify one explicit binding-provision payload with the same immutable
/// operator policy used by lifecycle routes.
///
/// The caller must pass the configured canonical
/// `.../operator/identity-bindings/provision` URL and server-resolved domain,
/// then hand the returned opaque intent to the canonical enrollment boundary.
/// The legacy community-bootstrap path must not discard this value or treat it
/// as a caller-selected approval flag.
#[cfg(test)]
pub(crate) async fn verify_provision_binding_intent(
    verifier: &OperatorLifecycleVerifier,
    replay_guard: &dyn Nip98ReplayGuard,
    expected_url: &str,
    authorization_domain: CommunityId,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<VerifiedProvisionBindingIntent, (StatusCode, Json<Value>)> {
    let (authorization, approval, replacement) =
        lifecycle_proofs_for_action(headers, verifier.requires_independent_approval(), false)
            .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "operator authentication failed"))?;
    debug_assert!(replacement.is_none());
    let candidate = verifier
        .verify_provision_candidate(
            &authorization,
            approval.as_deref(),
            expected_url,
            body,
            authorization_domain,
        )
        .await
        .map_err(|error| lifecycle_error(OperatorInvocationError::from(error)))?;
    candidate
        .claim_replay(replay_guard)
        .await
        .map_err(|error| lifecycle_error(OperatorInvocationError::from(error)))
}

fn lifecycle_proofs_for_action(
    headers: &HeaderMap,
    requires_independent_approval: bool,
    requires_replacement: bool,
) -> Result<(String, Option<String>, Option<String>), OperatorAuthenticationDenialReason> {
    let authorization = decode_single_nip98_header(headers, header::AUTHORIZATION.as_str())?;
    let approval = if requires_independent_approval {
        Some(decode_single_nip98_header(
            headers,
            OPERATOR_APPROVAL_HEADER,
        )?)
    } else if headers.contains_key(OPERATOR_APPROVAL_HEADER) {
        return Err(OperatorAuthenticationDenialReason::InvalidCredential);
    } else {
        None
    };
    let replacement = if requires_replacement {
        Some(decode_single_nip98_header(
            headers,
            OPERATOR_REPLACEMENT_PROOF_HEADER,
        )?)
    } else if headers.contains_key(OPERATOR_REPLACEMENT_PROOF_HEADER) {
        return Err(OperatorAuthenticationDenialReason::InvalidCredential);
    } else {
        None
    };
    Ok((authorization, approval, replacement))
}

fn decode_single_nip98_header(
    headers: &HeaderMap,
    name: &str,
) -> Result<String, OperatorAuthenticationDenialReason> {
    use base64::Engine as _;

    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or(OperatorAuthenticationDenialReason::MissingCredential)?;
    if values.next().is_some() {
        return Err(OperatorAuthenticationDenialReason::InvalidCredential);
    }
    let value = value
        .to_str()
        .map_err(|_| OperatorAuthenticationDenialReason::InvalidCredential)?;
    let payload = value
        .strip_prefix("Nostr ")
        .ok_or(OperatorAuthenticationDenialReason::InvalidCredential)?;
    if payload.is_empty() || value.len() > MAX_LIFECYCLE_AUTHORIZATION_BYTES {
        return Err(OperatorAuthenticationDenialReason::InvalidCredential);
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|_| OperatorAuthenticationDenialReason::InvalidCredential)?;
    if decoded.is_empty() || decoded.len() > MAX_LIFECYCLE_AUTHORIZATION_BYTES {
        return Err(OperatorAuthenticationDenialReason::InvalidCredential);
    }
    String::from_utf8(decoded).map_err(|_| OperatorAuthenticationDenialReason::InvalidCredential)
}

fn lifecycle_error(error: OperatorInvocationError) -> (StatusCode, Json<Value>) {
    let (status, message) = match error {
        OperatorInvocationError::NotConfigured => (
            StatusCode::NOT_FOUND,
            "operator lifecycle is not configured",
        ),
        OperatorInvocationError::PolicyDenied => (StatusCode::FORBIDDEN, "operator action denied"),
        OperatorInvocationError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            "invalid operator lifecycle request",
        ),
        OperatorInvocationError::AuthenticationRejected => {
            (StatusCode::UNAUTHORIZED, "operator authentication failed")
        }
        OperatorInvocationError::AuthenticationForbidden
        | OperatorInvocationError::ApprovalDenied => {
            (StatusCode::FORBIDDEN, "operator action denied")
        }
        OperatorInvocationError::IntentConflict => {
            (StatusCode::CONFLICT, "operation identity conflict")
        }
        OperatorInvocationError::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "operator request rate limited",
        ),
        OperatorInvocationError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "operator service unavailable",
        ),
        OperatorInvocationError::Failed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "operator execution failed",
        ),
    };
    api_error(status, message)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleOperationWire {
    operation_id: Uuid,
    correlation_id: Uuid,
    attempt_id: Uuid,
}

impl LifecycleOperationWire {
    fn typed(
        self,
        domain: CommunityId,
    ) -> Result<OperatorLifecycleOperation, (StatusCode, Json<Value>)> {
        OperatorLifecycleOperation::new(
            domain,
            self.operation_id,
            self.correlation_id,
            self.attempt_id,
        )
        .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(try_from = "String")]
struct LifecycleHex32([u8; 32]);

impl TryFrom<String> for LifecycleHex32 {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut output = [0; 32];
        hex::decode_to_slice(value, &mut output).map_err(|_| "expected 32-byte hex")?;
        Ok(Self(output))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveBindingWire {
    binding_id: Uuid,
    binding_version: u64,
    expected_lifecycle_revision: u64,
    principal_fingerprint: LifecycleHex32,
    event_author_pubkey: LifecycleHex32,
}

impl ActiveBindingWire {
    fn typed(self) -> Result<ExactActiveOperatorTarget, (StatusCode, Json<Value>)> {
        ExactActiveOperatorTarget::new(
            self.binding_id,
            self.binding_version,
            self.expected_lifecycle_revision,
            self.principal_fingerprint.0,
            self.event_author_pubkey.0,
        )
        .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetiredBindingWire {
    binding_id: Uuid,
    binding_version: u64,
    expected_lifecycle_revision: u64,
    principal_fingerprint: LifecycleHex32,
    event_author_pubkey: LifecycleHex32,
}

impl RetiredBindingWire {
    fn typed(self) -> Result<ExactRetiredOperatorTarget, (StatusCode, Json<Value>)> {
        ExactRetiredOperatorTarget::new(
            self.binding_id,
            self.binding_version,
            self.expected_lifecycle_revision,
            self.principal_fingerprint.0,
            self.event_author_pubkey.0,
        )
        .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingReplacementWire {
    target: RetiredBindingWire,
    fact_generation: u64,
}

impl PendingReplacementWire {
    fn typed(self) -> Result<ExpectedOperatorPendingReplacement, (StatusCode, Json<Value>)> {
        ExpectedOperatorPendingReplacement::new(self.target.typed()?, self.fact_generation)
            .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestedReplacementWire {
    event_author_pubkey: LifecycleHex32,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl RequestedReplacementWire {
    fn typed(self) -> Result<RequestedOperatorReplacement, (StatusCode, Json<Value>)> {
        RequestedOperatorReplacement::new(self.event_author_pubkey.0, self.expires_at)
            .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetireWire {
    operation: LifecycleOperationWire,
    expected_revision: u64,
    target: ActiveBindingWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisableWire {
    operation: LifecycleOperationWire,
    expected_revision: u64,
    principal_fingerprint: LifecycleHex32,
    expected_active_binding: Option<ActiveBindingWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeWire {
    operation: LifecycleOperationWire,
    expected_revision: u64,
    event_author_pubkey: LifecycleHex32,
    expected_active_binding: Option<ActiveBindingWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateWire {
    operation: LifecycleOperationWire,
    expected_revision: u64,
    target: ActiveBindingWire,
    replacement: RequestedReplacementWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverWire {
    operation: LifecycleOperationWire,
    expected_revision: u64,
    pending: PendingReplacementWire,
    replacement: RequestedReplacementWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnableWire {
    operation: LifecycleOperationWire,
    expected_revision: u64,
    principal_fingerprint: LifecycleHex32,
    disabled_fact_generation: u64,
    pending: PendingReplacementWire,
    replacement: RequestedReplacementWire,
}

fn parse_lifecycle_intent(
    domain: CommunityId,
    action: &str,
    body: &[u8],
) -> Result<OperatorLifecycleIntent, (StatusCode, Json<Value>)> {
    match action {
        "retire" => {
            let wire: RetireWire = serde_json::from_slice(body)
                .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))?;
            OperatorLifecycleIntent::retire(
                wire.operation.typed(domain)?,
                wire.expected_revision,
                wire.target.typed()?,
            )
            .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))
        }
        "disable" => {
            let wire: DisableWire = serde_json::from_slice(body)
                .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))?;
            OperatorLifecycleIntent::disable(
                wire.operation.typed(domain)?,
                wire.expected_revision,
                wire.principal_fingerprint.0,
                wire.expected_active_binding
                    .map(ActiveBindingWire::typed)
                    .transpose()?,
            )
            .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))
        }
        "revoke" => {
            let wire: RevokeWire = serde_json::from_slice(body)
                .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))?;
            OperatorLifecycleIntent::revoke(
                wire.operation.typed(domain)?,
                wire.expected_revision,
                wire.event_author_pubkey.0,
                wire.expected_active_binding
                    .map(ActiveBindingWire::typed)
                    .transpose()?,
            )
            .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))
        }
        "rotate" => {
            let wire: RotateWire = serde_json::from_slice(body)
                .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))?;
            OperatorLifecycleIntent::rotate(
                wire.operation.typed(domain)?,
                wire.expected_revision,
                wire.target.typed()?,
                wire.replacement.typed()?,
            )
            .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))
        }
        "recover" => {
            let wire: RecoverWire = serde_json::from_slice(body)
                .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))?;
            OperatorLifecycleIntent::recover(
                wire.operation.typed(domain)?,
                wire.expected_revision,
                wire.pending.typed()?,
                wire.replacement.typed()?,
            )
            .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))
        }
        "enable" => {
            let wire: EnableWire = serde_json::from_slice(body)
                .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))?;
            OperatorLifecycleIntent::enable(
                wire.operation.typed(domain)?,
                wire.expected_revision,
                wire.principal_fingerprint.0,
                wire.disabled_fact_generation,
                wire.pending.typed()?,
                wire.replacement.typed()?,
            )
            .map_err(|_| lifecycle_error(OperatorInvocationError::InvalidRequest))
        }
        _ => Err(lifecycle_error(OperatorInvocationError::InvalidRequest)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::{to_bytes, Body},
        http::{header, Request, StatusCode},
    };
    use base64::Engine;
    use nostr::{EventBuilder, Keys, Kind, Tag};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use uuid::Uuid;

    use buzz_core::{kind::KIND_NIP43_MEMBERSHIP_LIST, CommunityId};
    use buzz_db::event::EventQuery;

    use crate::router::build_router;
    use crate::state::AppState;

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

        fn try_mark_all_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            event_ids: &'a [nostr::EventId],
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            Box::pin(async move {
                if !(1..=3).contains(&event_ids.len())
                    || event_ids
                        .iter()
                        .enumerate()
                        .any(|(index, event_id)| event_ids[..index].contains(event_id))
                {
                    return Err(buzz_auth::AuthError::Internal(
                        "invalid atomic NIP-98 proof set".to_owned(),
                    ));
                }
                Ok(true)
            })
        }
    }

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1
    const INGRESS_HOST: &str = "operator-ingress.example";

    fn nip98_auth_header(keys: &Keys, url: &str, method: &str, body: Option<&[u8]>) -> String {
        let mut tags = vec![
            Tag::parse(["u", url]).expect("u tag"),
            Tag::parse(["method", method]).expect("method tag"),
        ];
        if let Some(body) = body {
            let hash: [u8; 32] = Sha256::digest(body).into();
            let hash_hex = hex::encode(hash);
            tags.push(Tag::parse(["payload", hash_hex.as_str()]).expect("payload tag"));
        }
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign NIP-98 event");
        let event_json = serde_json::to_string(&event).expect("serialize NIP-98 event");
        let encoded = base64::engine::general_purpose::STANDARD.encode(event_json.as_bytes());
        format!("Nostr {encoded}")
    }

    fn nip98_auth_header_without_payload(keys: &Keys, url: &str, method: &str) -> String {
        let tags = vec![
            Tag::parse(["u", url]).expect("u tag"),
            Tag::parse(["method", method]).expect("method tag"),
        ];
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign NIP-98 event");
        let event_json = serde_json::to_string(&event).expect("serialize NIP-98 event");
        let encoded = base64::engine::general_purpose::STANDARD.encode(event_json.as_bytes());
        format!("Nostr {encoded}")
    }

    async fn operator_test_state(operator_keys: &[Keys]) -> Option<Arc<AppState>> {
        let mut config = crate::config::Config::from_env().ok()?;
        config.database_url = TEST_DB_URL.to_string();
        config.redis_url = "redis://127.0.0.1:1".to_string();
        config.relay_url = "wss://tenant.example".to_string();
        config.relay_operator_api_origin = Some(format!("http://{INGRESS_HOST}"));
        config.relay_operator_pubkeys = operator_keys
            .iter()
            .map(|keys| keys.public_key().to_hex())
            .collect();
        config.require_relay_membership = true;

        let pool = sqlx::PgPool::connect(TEST_DB_URL).await.ok()?;
        let db = buzz_db::Db::from_pool(pool.clone());

        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .ok()?;
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .ok()?,
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).ok()?;
        let (mut state, _audit_shutdown) = AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            Keys::generate(),
            media_storage,
        );
        state.nip98_replay = Arc::new(AlwaysFreshReplayGuard);
        Some(Arc::new(state))
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        serde_json::from_slice(&bytes).expect("response JSON")
    }

    async fn signed_operator_request(
        state: Arc<AppState>,
        keys: &Keys,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> axum::response::Response {
        let url = format!("http://{INGRESS_HOST}{path}");
        let auth = nip98_auth_header(keys, &url, method, body.as_deref().map(str::as_bytes));
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, INGRESS_HOST)
            .header(header::AUTHORIZATION, auth);
        if body.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        build_router(state)
            .oneshot(
                request
                    .body(body.map_or_else(Body::empty, Body::from))
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    async fn provision_community(
        state: Arc<AppState>,
        operator: &Keys,
        host: &str,
        owner: &Keys,
    ) -> axum::response::Response {
        let body = serde_json::json!({
            "host": host,
            "initial_owner_pubkey": owner.public_key().to_hex(),
            "create_only": true,
        })
        .to_string();
        signed_operator_request(state, operator, "POST", "/operator/communities", Some(body)).await
    }

    fn is_member_tag(tag: &Tag, pubkey: &str, role: &str) -> bool {
        let values = tag.as_slice();
        values.first().is_some_and(|value| value == "member")
            && values.get(1).is_some_and(|value| value == pubkey)
            && values.get(2).is_some_and(|value| value == role)
    }

    async fn assert_snapshot_roles(
        state: &AppState,
        community: CommunityId,
        expected: &[(&str, &str)],
    ) {
        let snapshot = state
            .db
            .query_events(&EventQuery {
                kinds: Some(vec![KIND_NIP43_MEMBERSHIP_LIST as i32]),
                global_only: true,
                limit: Some(1),
                ..EventQuery::for_community(community)
            })
            .await
            .expect("query membership snapshot")
            .into_iter()
            .next()
            .expect("membership snapshot published");
        for &(pubkey, role) in expected {
            assert!(
                snapshot
                    .event
                    .tags
                    .iter()
                    .any(|tag| is_member_tag(tag, pubkey, role)),
                "missing {role} snapshot tag for {pubkey}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn non_allowlisted_operator_key_gets_403() {
        let operator = Keys::generate();
        let outsider = Keys::generate();
        let Some(state) = operator_test_state(&[operator]).await else {
            return;
        };
        let body = format!(
            r#"{{"host":"community-{}.example"}}"#,
            Uuid::new_v4().simple()
        );
        let url = format!("http://{INGRESS_HOST}/operator/communities");
        let auth = nip98_auth_header(&outsider, &url, "POST", Some(body.as_bytes()));

        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/communities")
                    .header(header::HOST, INGRESS_HOST)
                    .header(header::AUTHORIZATION, auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn post_operator_body_requires_payload_tag() {
        let operator = Keys::generate();
        let Some(state) = operator_test_state(std::slice::from_ref(&operator)).await else {
            return;
        };
        let body = format!(
            r#"{{"host":"community-{}.example"}}"#,
            Uuid::new_v4().simple()
        );
        let url = format!("http://{INGRESS_HOST}/operator/communities");
        let auth = nip98_auth_header_without_payload(&operator, &url, "POST");

        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/communities")
                    .header(header::HOST, INGRESS_HOST)
                    .header(header::AUTHORIZATION, auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = read_json(response).await;
        assert!(
            json.get("error")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .contains("missing payload tag"),
            "unexpected response: {json:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn unmapped_management_host_can_check_availability() {
        let operator = Keys::generate();
        let Some(state) = operator_test_state(std::slice::from_ref(&operator)).await else {
            return;
        };
        let host = format!("community-{}.example", Uuid::new_v4().simple());
        let query = format!("host={host}");
        let url = format!("http://{INGRESS_HOST}/operator/communities/availability?{query}");
        let auth = nip98_auth_header(&operator, &url, "GET", None);

        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/operator/communities/availability?{query}"))
                    .header(header::HOST, INGRESS_HOST)
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let json = read_json(response).await;
        assert_eq!(json.get("available").and_then(Value::as_bool), Some(true));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn unmapped_management_host_can_list_owned_communities() {
        let operator = Keys::generate();
        let owner = Keys::generate();
        let Some(state) = operator_test_state(std::slice::from_ref(&operator)).await else {
            return;
        };
        let owner_hex = owner.public_key().to_hex();
        let query = format!("owner_pubkey={owner_hex}");
        let url = format!("http://{INGRESS_HOST}/operator/communities?{query}");
        let auth = nip98_auth_header(&operator, &url, "GET", None);

        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/operator/communities?{query}"))
                    .header(header::HOST, INGRESS_HOST)
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let json = read_json(response).await;
        assert_eq!(
            json.get("owner_pubkey").and_then(Value::as_str),
            Some(owner_hex.as_str())
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn unarchive_restores_admission_and_is_idempotent_without_changing_ownership() {
        let operator = Keys::generate();
        let owner = Keys::generate();
        let outsider = Keys::generate();
        let Some(state) = operator_test_state(std::slice::from_ref(&operator)).await else {
            return;
        };
        let host = format!("community-{}.example", Uuid::new_v4().simple());
        assert_eq!(
            provision_community(Arc::clone(&state), &operator, &host, &owner)
                .await
                .status(),
            StatusCode::OK
        );
        let owner_hex = owner.public_key().to_hex();
        let archived = state
            .db
            .archive_community_owned_by(&host, &owner_hex, "protected.example")
            .await
            .expect("archive community")
            .expect("owned community");
        assert!(state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("archived admission lookup")
            .is_none());

        let request = |host: &str, owner_pubkey: String| {
            serde_json::json!({
                "host": host,
                "owner_pubkey": owner_pubkey,
            })
            .to_string()
        };
        let wrong_owner = signed_operator_request(
            Arc::clone(&state),
            &operator,
            "POST",
            "/operator/communities/unarchive",
            Some(request(&host, outsider.public_key().to_hex())),
        )
        .await;
        assert_eq!(wrong_owner.status(), StatusCode::NOT_FOUND);
        assert_eq!(read_json(wrong_owner).await["error"], "community not found");
        let unknown = signed_operator_request(
            Arc::clone(&state),
            &operator,
            "POST",
            "/operator/communities/unarchive",
            Some(request("missing.example", owner_hex.clone())),
        )
        .await;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        assert_eq!(read_json(unknown).await["error"], "community not found");

        for attempt in 0..2 {
            let response = signed_operator_request(
                Arc::clone(&state),
                &operator,
                "POST",
                "/operator/communities/unarchive",
                Some(request(&host, owner_hex.clone())),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "attempt {attempt}");
            let json = read_json(response).await;
            assert_eq!(json["community_id"], archived.id.to_string());
            assert_eq!(json["host"], host);
            assert!(json["archived_at"].is_null());
            assert_eq!(json["status"], "active");
        }

        let active = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("restored admission lookup")
            .expect("active community");
        assert_eq!(active.id, archived.id);
        let owner_member = state
            .db
            .get_relay_member(active.id, &owner_hex)
            .await
            .expect("owner lookup")
            .expect("owner remains");
        assert_eq!(owner_member.role, "owner");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn archive_publish_failure_is_retryable_and_preserves_timestamp() {
        let operator = Keys::generate();
        let owner = Keys::generate();
        let Some(state) = operator_test_state(std::slice::from_ref(&operator)).await else {
            return;
        };
        let host = format!("community-{}.example", Uuid::new_v4().simple());
        let owner_hex = owner.public_key().to_hex();
        let create_body = serde_json::json!({
            "host": host,
            "initial_owner_pubkey": owner_hex,
            "create_only": true,
        })
        .to_string();
        let create_url = format!("http://{INGRESS_HOST}/operator/communities");
        let create_auth =
            nip98_auth_header(&operator, &create_url, "POST", Some(create_body.as_bytes()));
        let create_response = build_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/communities")
                    .header(header::HOST, INGRESS_HOST)
                    .header(header::AUTHORIZATION, create_auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(create_body))
                    .expect("create request"),
            )
            .await
            .expect("create response");
        assert_eq!(create_response.status(), StatusCode::OK);

        let archive_body = serde_json::json!({
            "host": host,
            "owner_pubkey": owner.public_key().to_hex(),
        })
        .to_string();
        let archive_url = format!("http://{INGRESS_HOST}/operator/communities/archive");
        let archive_once = |state: Arc<AppState>| {
            let auth = nip98_auth_header(
                &operator,
                &archive_url,
                "POST",
                Some(archive_body.as_bytes()),
            );
            let body = archive_body.clone();
            async move {
                build_router(state)
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/operator/communities/archive")
                            .header(header::HOST, INGRESS_HOST)
                            .header(header::AUTHORIZATION, auth)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(body))
                            .expect("archive request"),
                    )
                    .await
                    .expect("archive response")
            }
        };

        let first = archive_once(Arc::clone(&state)).await;
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
        let first_json = read_json(first).await;
        assert_eq!(first_json["status"], "archived");
        assert_eq!(first_json["propagation"], "pending");
        let first_archived_at = first_json["archived_at"].clone();
        assert!(!first_archived_at.is_null());
        assert!(state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("active lookup")
            .is_none());

        assert_eq!(
            state
                .community_disconnect_publish_attempts
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        let second = archive_once(Arc::clone(&state)).await;
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        let second_json = read_json(second).await;
        assert_eq!(second_json["archived_at"], first_archived_at);
        assert_eq!(
            state
                .community_disconnect_publish_attempts
                .load(std::sync::atomic::Ordering::Relaxed),
            2,
            "idempotent archive retry must republish the disconnect"
        );

        let owned = state
            .db
            .list_communities_owned_by(&owner.public_key().to_hex())
            .await
            .expect("owned communities");
        let row = owned
            .iter()
            .find(|row| row.host == host)
            .expect("archived row");
        assert_eq!(
            serde_json::to_value(row.archived_at).expect("timestamp JSON"),
            first_archived_at
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn happy_path_create_returns_created_and_bootstraps_owner() {
        let operator = Keys::generate();
        let owner = Keys::generate();
        let Some(state) = operator_test_state(std::slice::from_ref(&operator)).await else {
            return;
        };
        let host = format!("community-{}.example", Uuid::new_v4().simple());
        let response = provision_community(state.clone(), &operator, &host, &owner).await;

        assert_eq!(response.status(), StatusCode::OK);
        let json = read_json(response).await;
        assert_eq!(json.get("status").and_then(Value::as_str), Some("created"));
        assert_eq!(
            json.get("host").and_then(Value::as_str),
            Some(host.as_str())
        );
        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup community")
            .expect("community exists");
        let owner_hex = owner.public_key().to_hex();
        let member = state
            .db
            .get_relay_member(community.id, &owner_hex)
            .await
            .expect("lookup owner role")
            .expect("owner member exists");
        assert_eq!(member.role, "owner");

        assert_snapshot_roles(&state, community.id, &[(&owner_hex, "owner")]).await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn fresh_host_at_owner_limit_returns_limit_reached_conflict() {
        let operator = Keys::generate();
        let owner = Keys::generate();
        let Some(state) = operator_test_state(std::slice::from_ref(&operator)).await else {
            return;
        };

        for _ in 0..buzz_db::relay_members::MAX_COMMUNITIES_PER_OWNER {
            let host = format!("community-{}.example", Uuid::new_v4().simple());
            assert_eq!(
                provision_community(state.clone(), &operator, &host, &owner)
                    .await
                    .status(),
                StatusCode::OK
            );
        }

        let host = format!("community-{}.example", Uuid::new_v4().simple());
        let response = provision_community(state.clone(), &operator, &host, &owner).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let json = read_json(response).await;
        assert!(json["error"]
            .as_str()
            .is_some_and(|error| error.starts_with("limit_reached:")));
        assert!(state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("look up rejected fresh host")
            .is_none());
    }

    /// Happy path: POST /operator/communities/transfer swaps ownership, demotes
    /// the old owner to `member`, and publishes a NIP-43 snapshot reflecting the
    /// new roles.
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn happy_path_transfer_swaps_owner_and_demotes_old_to_member() {
        let operator = Keys::generate();
        let initial_owner = Keys::generate();
        let new_owner = Keys::generate();
        let Some(state) = operator_test_state(std::slice::from_ref(&operator)).await else {
            return;
        };

        let host = format!("community-{}.example", Uuid::new_v4().simple());
        let create_response =
            provision_community(state.clone(), &operator, &host, &initial_owner).await;
        assert_eq!(create_response.status(), StatusCode::OK);

        let community = state
            .db
            .lookup_community_by_host(&host)
            .await
            .expect("lookup community")
            .expect("community exists");
        let community_id = community.id.to_string();
        let initial_owner_hex = initial_owner.public_key().to_hex();
        let new_owner_hex = new_owner.public_key().to_hex();

        let transfer_body = serde_json::json!({
            "community_id": community_id,
            "new_owner_pubkey": new_owner_hex,
            "expected_owner_pubkey": initial_owner_hex,
        })
        .to_string();
        let response = signed_operator_request(
            state.clone(),
            &operator,
            "POST",
            "/operator/communities/transfer",
            Some(transfer_body),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let json = read_json(response).await;
        assert_eq!(
            json.get("status").and_then(Value::as_str),
            Some("transferred")
        );
        assert_eq!(
            json.get("new_owner_pubkey").and_then(Value::as_str),
            Some(new_owner_hex.as_str())
        );
        assert_eq!(
            json.get("previous_owner").and_then(Value::as_str),
            Some(initial_owner_hex.as_str())
        );

        // New owner is owner.
        assert_eq!(
            state
                .db
                .get_relay_member(community.id, &new_owner_hex)
                .await
                .expect("get new owner")
                .expect("new owner exists")
                .role,
            "owner"
        );
        // Old owner is member (not admin).
        assert_eq!(
            state
                .db
                .get_relay_member(community.id, &initial_owner_hex)
                .await
                .expect("get old owner")
                .expect("old owner exists")
                .role,
            "member"
        );

        assert_snapshot_roles(
            &state,
            community.id,
            &[(&new_owner_hex, "owner"), (&initial_owner_hex, "member")],
        )
        .await;
    }

    /// Transfer with an invalid community_id returns 400.
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn transfer_with_invalid_community_id_returns_400() {
        let operator = Keys::generate();
        let new_owner = Keys::generate();
        let Some(state) = operator_test_state(std::slice::from_ref(&operator)).await else {
            return;
        };
        let body = serde_json::json!({
            "community_id": "not-a-uuid",
            "new_owner_pubkey": new_owner.public_key().to_hex(),
            "expected_owner_pubkey": new_owner.public_key().to_hex(),
        })
        .to_string();
        let response = signed_operator_request(
            state,
            &operator,
            "POST",
            "/operator/communities/transfer",
            Some(body),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Transfer with an invalid new_owner_pubkey returns 400.
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn transfer_with_invalid_pubkey_returns_400() {
        let operator = Keys::generate();
        let Some(state) = operator_test_state(std::slice::from_ref(&operator)).await else {
            return;
        };
        let body = serde_json::json!({
            "community_id": Uuid::new_v4().to_string(),
            "new_owner_pubkey": "not-a-pubkey",
            "expected_owner_pubkey": "not-a-pubkey",
        })
        .to_string();
        let response = signed_operator_request(
            state,
            &operator,
            "POST",
            "/operator/communities/transfer",
            Some(body),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
