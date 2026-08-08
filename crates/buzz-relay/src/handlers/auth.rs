//! NIP-42 AUTH handler — verify challenge response, transition auth state.
//!
//! Relay membership enforcement uses the shared
//! [`crate::api::relay_members::enforce_relay_membership`] helper, which supports
//! NIP-OA owner-delegation fallback on closed relays. On open relays, the auth
//! handler calls [`crate::api::relay_members::extract_nip_oa_owner`] directly to
//! extract the owner pubkey for agent→owner backfill (observer frame auth).
//!
//! For WebSocket auth, the NIP-OA `auth` tag is extracted from the signed AUTH
//! event itself (the tag is integrity-protected by the event signature).

use std::{future::Future, sync::Arc, time::Duration};

use axum::extract::ws::Message as WsMessage;
use buzz_core::client_binding_bootstrap::{
    ClientBindingBootstrapError, ClientBindingBootstrapInputV1, ClientBindingScopeV1,
    CLIENT_BINDING_BOOTSTRAP_SUB_ID, CLIENT_BINDING_STATUS_SUB_ID,
};
use buzz_core::client_binding_status::validate_client_binding_status_event;
use nostr::{PublicKey, Timestamp};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::connection::{AuthState, ConnectionState};
use crate::protocol::RelayMessage;
use crate::state::AppState;

const CLIENT_BINDING_STATUS_PRESENTATION_TIMEOUT: Duration = Duration::from_secs(2);

/// Extract a NIP-OA `auth` tag from a verified AUTH event and serialize it as
/// the JSON-array string that [`buzz_sdk::nip_oa::verify_auth_tag`] expects.
///
/// Returns `None` if no `auth` tag is present (direct-member auth path) or if
/// more than one `auth` tag exists (per NIP-OA spec: >1 auth tag ⇒ no valid tag).
pub fn extract_auth_tag_json(event: &nostr::Event) -> Option<String> {
    let mut iter = event
        .tags
        .iter()
        .filter(|t| t.as_slice().first().map(|s| s.as_str()) == Some("auth"));
    let first = iter.next()?;
    if iter.next().is_some() {
        return None; // NIP-OA spec: treat >1 auth tag as no valid auth tag
    }
    serde_json::to_string(first.as_slice()).ok()
}

/// Handle a NIP-42 AUTH message: verify the challenge response and transition
/// the connection to authenticated state.
///
/// Pure crypto verification — no API tokens, no JWT, no DB token lookups.
#[tracing::instrument(skip_all, fields(event_id, conn_id))]
pub async fn handle_auth(event: nostr::Event, conn: Arc<ConnectionState>, state: Arc<AppState>) {
    let event_id_hex = event.id.to_hex();
    // `AuthService` intentionally consumes the event. Retain the signed bytes
    // solely so an optional client-binding scope can be parsed after ordinary
    // NIP-42 verification succeeds.
    let verified_event_for_scope = event.clone();
    let (challenge, conn_id) = {
        let auth = conn.auth_state.read().await;
        match &*auth {
            AuthState::Pending { challenge } => (challenge.clone(), conn.conn_id),
            AuthState::Authenticated(_) => {
                debug!(conn_id = %conn.conn_id, "AUTH received but already authenticated");
                conn.send(RelayMessage::ok(
                    &event_id_hex,
                    false,
                    "auth-required: already authenticated",
                ));
                return;
            }
            AuthState::Failed => {
                debug!(conn_id = %conn.conn_id, "AUTH received after failed auth");
                conn.send(RelayMessage::ok(
                    &event_id_hex,
                    false,
                    "auth-required: authentication already failed",
                ));
                return;
            }
        }
    };

    // Record the declared span fields now that we have the values.
    tracing::Span::current()
        .record("event_id", event_id_hex.as_str())
        .record("conn_id", conn_id.to_string().as_str());

    // Extract the NIP-OA auth tag before verification consumes the event.
    // The tag is integrity-protected by the event's Schnorr signature — if
    // tampered, NIP-42 verification will fail before we ever inspect it.
    let auth_tag_json = extract_auth_tag_json(&event);

    let relay_url =
        crate::api::bridge::nip42_expected_relay_url(&state.config.relay_url, &conn.tenant);
    let auth_svc = Arc::clone(&state.auth);

    metrics::counter!("buzz_auth_attempts_total", "method" => "nip42").increment(1);

    // Pure NIP-42 verification — crypto only, no DB lookups.
    match auth_svc
        .verify_auth_event(event, &challenge, &relay_url)
        .await
    {
        Ok(mut auth_ctx) => {
            let pubkey = auth_ctx.pubkey;
            let client_binding_scope = match ClientBindingScopeV1::from_verified_auth_event(
                &verified_event_for_scope,
            ) {
                Ok(scope) => Some(scope),
                Err(ClientBindingBootstrapError::MissingScopeTag) => None,
                Err(error) => {
                    // Status is optional and display-only. A malformed opt-in
                    // withholds presentation without changing AUTH.
                    warn!(conn_id = %conn_id, error = %error, "invalid client-binding scope; withholding presentation");
                    None
                }
            };

            // Community ban gate (NIP-42 seam). Runs immediately after auth
            // verification succeeds and before the allowlist and relay-membership
            // gates, per COMMUNITY_MODERATION_PLAN.md §0 decision 4 and the
            // MOD-7/M20 invariant (a ban must block connection auth even for open
            // channels — enforcement is structural, not filtered later). A banned
            // principal gets the standard protocol denial and the connection is
            // dropped with zero further processing.
            //
            // NIP-OA cascade: a ban on the authenticated pubkey blocks it directly;
            // a ban on its cryptographically-proven owner cascades to the agent
            // (owner ban ⇒ agents banned; agent ban is agent-only). The owner is
            // extracted from the self-proving auth tag with no DB round-trip.
            {
                // Fail closed on a DB error, but distinguish it from a real ban:
                // a transient blip must deny (never let a banned principal
                // through) without telling an innocent user they are banned and
                // pinning `Failed` for the connection's life on a false premise.
                // `Banned` claims the ban; `DbError` denies with `error: internal`
                // (mirrors the ingest write-path gate).
                enum BanOutcome {
                    Clear,
                    Banned,
                    DbError,
                }

                let mut outcome = match state
                    .db
                    .moderation_restriction_state(conn.tenant.community(), pubkey.as_bytes())
                    .await
                {
                    Ok(state) if state.banned => BanOutcome::Banned,
                    Ok(_) => BanOutcome::Clear,
                    Err(e) => {
                        warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), error = %e,
                              "ban-state DB lookup failed, denying (fail-closed)");
                        BanOutcome::DbError
                    }
                };

                // Cascade: check the proven NIP-OA owner only if the agent itself
                // is clear (a DB error already denies; a direct ban already blocks
                // — both skip the needless second DB read).
                if matches!(outcome, BanOutcome::Clear) {
                    if let Some(owner) = crate::api::relay_members::extract_nip_oa_owner(
                        pubkey.as_bytes(),
                        auth_tag_json.as_deref(),
                    ) {
                        outcome = match state
                            .db
                            .moderation_restriction_state(conn.tenant.community(), owner.as_bytes())
                            .await
                        {
                            Ok(state) if state.banned => BanOutcome::Banned,
                            Ok(_) => BanOutcome::Clear,
                            Err(e) => {
                                warn!(conn_id = %conn_id, owner = %owner.to_hex(), error = %e,
                                      "owner ban-state DB lookup failed, denying (fail-closed)");
                                BanOutcome::DbError
                            }
                        };
                    }
                }

                let denial: Option<(&str, &str)> = match outcome {
                    BanOutcome::Clear => None,
                    BanOutcome::Banned => {
                        Some(("banned", "blocked: you are banned from this community"))
                    }
                    BanOutcome::DbError => Some((
                        "ban_check_error",
                        "error: internal error checking restriction state",
                    )),
                };

                if let Some((metric_reason, deny_reason)) = denial {
                    warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), reason = deny_reason, "principal denied at ban seam");
                    metrics::counter!("buzz_auth_failures_total", "reason" => metric_reason)
                        .increment(1);
                    *conn.auth_state.write().await = AuthState::Failed;
                    // Decision 4: banned ⇒ OK false + immediate WebSocket close.
                    // Route the reason frame on the control channel (not `send`,
                    // which uses the data channel and would race the cancel), so
                    // the send loop drains it ahead of the Close it emits on
                    // cancel. Then cancel to close the socket immediately.
                    let _ = conn.ctrl_tx.try_send(WsMessage::Text(
                        RelayMessage::ok(&event_id_hex, false, deny_reason).into(),
                    ));
                    conn.cancel.cancel();
                    return;
                }
            }

            let identity_proof = match crate::corporate_identity::verify_corporate_identity(
                &state,
                conn.tenant.community(),
                pubkey,
                buzz_auth::ProofTransport::Nip42,
                conn.corporate_identity_jwt.as_deref(),
                auth_tag_json.as_deref(),
            )
            .await
            {
                Ok(proof) => proof,
                Err(e) => {
                    warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), error = %e, "corporate identity denied");
                    *conn.auth_state.write().await = AuthState::Failed;
                    conn.send(RelayMessage::ok(
                        &event_id_hex,
                        false,
                        &format!("restricted: {}", e.public_message()),
                    ));
                    return;
                }
            };

            // Pubkey allowlist gate — only for pubkey-only auth.
            if state.config.pubkey_allowlist_enabled
                && auth_ctx.auth_method == buzz_auth::AuthMethod::Nip42
            {
                let allowed = match state
                    .db
                    .is_pubkey_allowed(conn.tenant.community(), pubkey.as_bytes())
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), error = %e,
                              "allowlist DB lookup failed, denying (fail-closed)");
                        false
                    }
                };
                if !allowed {
                    warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), "pubkey not in allowlist");
                    metrics::counter!("buzz_auth_failures_total", "reason" => "allowlist_denied")
                        .increment(1);
                    *conn.auth_state.write().await = AuthState::Failed;
                    conn.send(RelayMessage::ok(
                        &event_id_hex,
                        false,
                        "auth-required: verification failed",
                    ));
                    return;
                }
            }

            // Relay membership gate — uses the shared helper with NIP-OA fallback.
            let nip_oa_owner = match crate::api::relay_members::enforce_relay_membership(
                &state,
                conn.tenant.community(),
                pubkey.as_bytes(),
                auth_tag_json.as_deref(),
            )
            .await
            {
                Ok(owner) => owner,
                Err(e) => {
                    warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), error = ?e, "not a relay member");
                    metrics::counter!("buzz_auth_failures_total", "reason" => "not_relay_member")
                        .increment(1);
                    *conn.auth_state.write().await = AuthState::Failed;
                    conn.send(RelayMessage::ok(
                        &event_id_hex,
                        false,
                        "restricted: not a relay member",
                    ));
                    return;
                }
            };

            let identity_decision = match crate::corporate_identity::finalize_corporate_identity(
                &state,
                conn.tenant.community(),
                pubkey,
                identity_proof,
            )
            .await
            {
                Ok(decision) => decision,
                Err(e) => {
                    warn!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), error = %e, "corporate identity finalization denied");
                    *conn.auth_state.write().await = AuthState::Failed;
                    conn.send(RelayMessage::ok(
                        &event_id_hex,
                        false,
                        &format!("restricted: {}", e.public_message()),
                    ));
                    return;
                }
            };
            // Open relay NIP-OA backfill: extract owner for agent→owner DB mapping
            // (needed for observer frame auth). Only runs on open relays — on closed
            // relays, enforce_relay_membership already handles NIP-OA delegation.
            // No feature flag needed: NIP-OA is cryptographically self-proving.
            let nip_oa_owner = nip_oa_owner.or_else(|| {
                if !state.config.require_relay_membership && auth_tag_json.is_some() {
                    crate::api::relay_members::extract_nip_oa_owner(
                        pubkey.as_bytes(),
                        auth_tag_json.as_deref(),
                    )
                } else {
                    None
                }
            });

            // Stash NIP-OA owner on the auth context only after the shared
            // backfill confirms the first-write-wins relationship.
            if let Some(owner) = nip_oa_owner {
                if crate::api::relay_members::materialize_nip_oa_owner(
                    &state,
                    &conn.tenant,
                    &pubkey,
                    &owner,
                )
                .await
                {
                    auth_ctx.agent_owner_pubkey = Some(owner);
                } else {
                    warn!(
                        conn_id = %conn_id,
                        agent = %pubkey.to_hex(),
                        nip_oa_owner = %owner.to_hex(),
                        "NIP-OA owner could not be materialized"
                    );
                }
            }

            info!(conn_id = %conn_id, pubkey = %pubkey.to_hex(), "NIP-42 auth successful");
            *conn.auth_state.write().await = AuthState::Authenticated(auth_ctx);
            state
                .conn_manager
                .set_authenticated_pubkey(conn_id, pubkey.to_bytes().to_vec());
            crate::corporate_identity::spawn_session_revalidation(
                Arc::clone(&state),
                conn.tenant.community(),
                pubkey,
                identity_decision,
                conn.cancel.clone(),
            );
            if conn.send(RelayMessage::ok(&event_id_hex, true, "")) {
                if let Some(scope) = client_binding_scope {
                    let status_state = Arc::clone(&state);
                    let status_conn = Arc::clone(&conn);
                    tokio::spawn(async move {
                        deliver_current_binding_status(&status_state, &status_conn, pubkey, scope)
                            .await;
                    });
                }
            }
        }
        Err(e) => {
            warn!(conn_id = %conn_id, error = %e, "NIP-42 auth failed");
            metrics::counter!("buzz_auth_failures_total", "reason" => "nip42_invalid").increment(1);
            *conn.auth_state.write().await = AuthState::Failed;
            conn.send(RelayMessage::ok(
                &event_id_hex,
                false,
                "auth-required: verification failed",
            ));
        }
    }
}

/// Deliver the optional relay-authenticated bootstrap and current status to
/// the exact connection that supplied the verified scope. Presentation
/// failures are deliberately isolated from the completed AUTH decision.
async fn deliver_current_binding_status(
    state: &AppState,
    conn: &ConnectionState,
    event_author_pubkey: PublicKey,
    scope: ClientBindingScopeV1,
) {
    if scope.relay_signer() != state.relay_keypair.public_key() {
        warn!(conn_id = %conn.conn_id, "client-binding scope pins a different relay signer");
        return;
    }
    if !connection_still_authenticated(conn, event_author_pubkey).await {
        return;
    }

    let authorization_domain = conn.tenant.community();
    let Some(composition) = state.provider_free_authorization() else {
        return;
    };
    let runtime = match composition.client_status_runtime(authorization_domain) {
        Ok(runtime) => runtime,
        Err(error) => {
            debug!(conn_id = %conn.conn_id, error = %error, "client-binding status runtime unavailable");
            return;
        }
    };
    let Some(current_result) = await_optional_status_presentation(
        &conn.cancel,
        runtime.current(authorization_domain, event_author_pubkey),
    )
    .await
    else {
        return;
    };
    let current = match current_result {
        Err(_) => {
            warn!(conn_id = %conn.conn_id, "client-binding status presentation timed out");
            return;
        }
        Ok(Ok(current)) => current,
        Ok(Err(error)) => {
            warn!(conn_id = %conn.conn_id, error = %error, "client-binding status presentation withheld");
            return;
        }
    };

    let now = Timestamp::now().as_secs();
    if validate_client_binding_status_event(
        &current,
        &state.relay_keypair.public_key(),
        authorization_domain,
        &event_author_pubkey,
        now,
    )
    .is_err()
    {
        warn!(conn_id = %conn.conn_id, "client-binding status expired before delivery");
        return;
    }
    let bootstrap_input = match ClientBindingBootstrapInputV1::new(
        authorization_domain,
        event_author_pubkey,
        scope.connection_epoch().clone(),
        now,
    ) {
        Ok(input) => input,
        Err(error) => {
            warn!(conn_id = %conn.conn_id, error = %error, "client-binding bootstrap presentation withheld");
            return;
        }
    };
    let bootstrap = match bootstrap_input.sign_with_relay_keys(&state.relay_keypair) {
        Ok(bootstrap) => bootstrap,
        Err(error) => {
            warn!(conn_id = %conn.conn_id, error = %error, "client-binding bootstrap presentation withheld");
            return;
        }
    };

    // Recheck ownership after every await and immediately before each send.
    // A retired connection can never publish into its replacement.
    if !connection_still_authenticated(conn, event_author_pubkey).await
        || !conn.send(RelayMessage::event(
            CLIENT_BINDING_BOOTSTRAP_SUB_ID,
            &bootstrap,
        ))
    {
        return;
    }
    let delivery_now = Timestamp::now().as_secs();
    if !connection_still_authenticated(conn, event_author_pubkey).await
        || validate_client_binding_status_event(
            &current,
            &state.relay_keypair.public_key(),
            authorization_domain,
            &event_author_pubkey,
            delivery_now,
        )
        .is_err()
    {
        return;
    }
    let _ = conn.send(RelayMessage::event(CLIENT_BINDING_STATUS_SUB_ID, &current));
}

async fn await_optional_status_presentation<T>(
    cancellation: &CancellationToken,
    presentation: impl Future<Output = T>,
) -> Option<Result<T, tokio::time::error::Elapsed>> {
    tokio::select! {
        _ = cancellation.cancelled() => None,
        result = tokio::time::timeout(
            CLIENT_BINDING_STATUS_PRESENTATION_TIMEOUT,
            presentation,
        ) => Some(result),
    }
}

async fn connection_still_authenticated(
    conn: &ConnectionState,
    event_author_pubkey: PublicKey,
) -> bool {
    if conn.cancel.is_cancelled() {
        return false;
    }
    matches!(
        &*conn.auth_state.read().await,
        AuthState::Authenticated(context) if context.pubkey == event_author_pubkey
    )
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use super::{
        await_optional_status_presentation, extract_auth_tag_json,
        CLIENT_BINDING_STATUS_PRESENTATION_TIMEOUT,
    };
    use crate::{
        authorization_runtime::{
            BaseV1AuthorizationConfiguration, BaseV1EnrollmentMode, OperationRestoreRuntime,
            ProviderFreeV1Composition,
        },
        config::Config,
        router::build_router,
        state::AppState,
    };
    use buzz_auth::AuthorizationEventCapacityPolicy;
    use buzz_core::{
        client_binding_bootstrap::{
            validate_client_binding_bootstrap_event, ClientBindingEpoch,
            CLIENT_BINDING_BOOTSTRAP_SUB_ID, CLIENT_BINDING_SCOPE_TAG,
            CLIENT_BINDING_STATUS_SUB_ID,
        },
        client_binding_status::validate_client_binding_status_event,
        CommunityId,
    };
    use buzz_db::{authorization_resolver::client_status_authority_object_key, Db};
    use futures_util::{SinkExt, StreamExt};
    use jsonwebtoken::jwk::{Jwk, JwkSet};
    use nostr::{Event, EventBuilder, Keys, Kind, Tag, Timestamp};
    use serde_json::Value;
    use sqlx::{postgres::PgPoolOptions, PgPool};
    use tokio::net::TcpListener;
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{client::IntoClientRequest, http::header::HOST, Message},
    };
    use uuid::Uuid;

    /// Build a signed NIP-98 (kind 27235) event carrying the given tags. The
    /// `auth` tag lives inside the signed event exactly as the git and
    /// WebSocket auth paths receive it.
    fn signed_event_with_tags(tags: Vec<Tag>) -> nostr::Event {
        EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(&Keys::generate())
            .expect("sign auth event")
    }

    /// A single `auth` tag is extracted verbatim as its JSON-array string —
    /// this is the exact value fed to `verify_auth_tag` on the git path.
    #[test]
    fn single_auth_tag_extracted_verbatim() {
        let owner = Keys::generate().public_key().to_hex();
        let sig = "00".repeat(64);
        let event = signed_event_with_tags(vec![
            Tag::parse(["u", "https://relay/git/x/y"]).unwrap(),
            Tag::parse(["auth", owner.as_str(), "", sig.as_str()]).unwrap(),
        ]);

        let extracted = extract_auth_tag_json(&event).expect("auth tag present");
        let expected = serde_json::to_string(&["auth", owner.as_str(), "", sig.as_str()]).unwrap();
        assert_eq!(extracted, expected);
    }

    /// No `auth` tag → `None` (the direct-member path, tag absent).
    #[test]
    fn no_auth_tag_returns_none() {
        let event =
            signed_event_with_tags(vec![Tag::parse(["u", "https://relay/git/x/y"]).unwrap()]);
        assert_eq!(extract_auth_tag_json(&event), None);
    }

    /// More than one `auth` tag → `None`. Per NIP-OA, an ambiguous set of
    /// attestations is treated as no valid attestation (fail-closed), so a
    /// second forged tag cannot smuggle an alternate delegation past the gate.
    #[test]
    fn duplicate_auth_tags_return_none() {
        let a = Keys::generate().public_key().to_hex();
        let b = Keys::generate().public_key().to_hex();
        let sig = "00".repeat(64);
        let event = signed_event_with_tags(vec![
            Tag::parse(["auth", a.as_str(), "", sig.as_str()]).unwrap(),
            Tag::parse(["auth", b.as_str(), "", sig.as_str()]).unwrap(),
        ]);
        assert_eq!(extract_auth_tag_json(&event), None);
    }

    #[tokio::test]
    async fn optional_status_presentation_observes_connection_cancellation() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            await_optional_status_presentation(&task_cancellation, async move {
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            })
            .await
        });

        started_rx.await.expect("presentation starts");
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_millis(100), task)
            .await
            .expect("cancellation wins before the presentation timeout")
            .expect("presentation task joins");
        assert!(result.is_none());
    }

    fn direct_status_configuration(
        domain: CommunityId,
        restore_bootstrap_id: Uuid,
    ) -> BaseV1AuthorizationConfiguration {
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYdk9JBoHN9Dg_E8x1sZ4k5g8hY0M7Ff5VjG8IU",
            "kid": "status-auth-integration",
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "EdDSA"
        }))
        .expect("fixture JWK");
        BaseV1AuthorizationConfiguration::enforce_direct(
            domain,
            AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10)
                .expect("valid status audit capacity"),
            1,
            BaseV1EnrollmentMode::AttestedKey,
            "https://issuer.example",
            "buzz-relay",
            "employee_id",
            JwkSet { keys: vec![jwk] },
            Some("nostr_pubkey".to_owned()),
            "x-buzz-identity",
            "x-buzz-identity-proof",
            [9_u8; 32],
            Duration::from_secs(300),
            Duration::from_secs(30),
            None,
            Duration::from_secs(60),
            restore_bootstrap_id,
        )
        .expect("complete direct status configuration")
    }

    async fn scratch_status_database() -> (PgPool, Db, CommunityId, String) {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_owned());
        let admin = PgPool::connect(&admin_url).await.expect("connect admin");
        let name = format!("s6_auth_status_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("create retained status-auth database");
        let split = admin_url.rfind('/').expect("database URL path");
        let scratch_url = format!("{}/{}", &admin_url[..split], name);
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&scratch_url)
            .await
            .expect("connect retained status-auth database");
        buzz_db::migration::run_migrations(&pool)
            .await
            .expect("migrate retained status-auth database");
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(domain.as_uuid())
            .bind(format!("status-{}.example", domain.as_uuid().simple()))
            .execute(&pool)
            .await
            .expect("insert status-auth community");
        eprintln!("retained status-auth database: {name}");
        (pool.clone(), Db::from_pool(pool), domain, scratch_url)
    }

    async fn seed_current_binding(pool: &PgPool, domain: CommunityId, author: &Keys) {
        let binding_id = Uuid::new_v4();
        let fence = [41_u8; 32];
        let mut binding_seed = pool.acquire().await.expect("seed binding connection");
        sqlx::query("SET session_replication_role=replica")
            .execute(&mut *binding_seed)
            .await
            .expect("disable lifecycle foreign-key triggers");
        sqlx::query(
            "INSERT INTO identity_bindings \
             (community_id,binding_id,issuer,subject,principal_fingerprint,event_author_pubkey, \
              binding_state,lifecycle_revision,binding_provenance,policy_revision, \
              enrollment_evidence_digest,birth_history_id,creation_operation_id, \
              creation_request_fingerprint) \
             VALUES ($1,$2,'issuer','subject',$3,$4,1,1,1,1,$5,$6,$7,$8)",
        )
        .bind(domain.as_uuid())
        .bind(binding_id)
        .bind(vec![43_u8; 32])
        .bind(author.public_key().to_bytes().as_slice())
        .bind(vec![44_u8; 32])
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(vec![45_u8; 32])
        .execute(&mut *binding_seed)
        .await
        .expect("insert active binding");
        sqlx::query("SET session_replication_role=origin")
            .execute(&mut *binding_seed)
            .await
            .expect("restore lifecycle triggers");
        drop(binding_seed);

        sqlx::query(
            "INSERT INTO authorization_invalidation_domains (community_id,current_generation) \
             VALUES ($1,0) ON CONFLICT (community_id) DO UPDATE SET current_generation=0",
        )
        .bind(domain.as_uuid())
        .execute(pool)
        .await
        .expect("activate status invalidation domain");
        let object_key = client_status_authority_object_key(domain, author.public_key());
        let mut authority_seed = pool.acquire().await.expect("seed authority connection");
        sqlx::query("SET session_replication_role=replica")
            .execute(&mut *authority_seed)
            .await
            .expect("disable authority foreign-key triggers");
        sqlx::query(
            "INSERT INTO authorization_authority_epochs \
             (community_id,object_kind,object_key,authority_epoch,fence,operation_id,request_fingerprint) \
             VALUES ($1,7,$2,1,$3,$4,$5)",
        )
        .bind(domain.as_uuid())
        .bind(object_key.as_slice())
        .bind(fence.as_slice())
        .bind(Uuid::new_v4())
        .bind(vec![46_u8; 32])
        .execute(&mut *authority_seed)
        .await
        .expect("insert status authority epoch");
        sqlx::query("SET session_replication_role=origin")
            .execute(&mut *authority_seed)
            .await
            .expect("restore authority triggers");
    }

    async fn status_auth_state(
        pool: PgPool,
        db: Db,
        scratch_url: String,
        relay_keys: Keys,
    ) -> Arc<AppState> {
        let mut config = Config::from_env().expect("default relay config loads");
        config.database_url = scratch_url;
        config.redis_url = "redis://127.0.0.1:1".to_owned();
        config.relay_url = "ws://config-host.invalid".to_owned();
        config.pubkey_allowlist_enabled = false;
        config.require_relay_membership = false;
        config.git_repo_path = std::env::temp_dir().join(format!(
            "buzz-s6-auth-status-repos-{}",
            Uuid::new_v4().simple()
        ));
        config.git_pack_cache_path = config.git_repo_path.join(".pack-cache");
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("create inert Redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("create inert pubsub manager"),
        );
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool);
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage =
            buzz_media::MediaStorage::new(&config.media).expect("create inert media storage");
        let (state, _audit_shutdown) = AppState::new(
            config,
            db,
            redis_pool,
            None::<buzz_audit::AuditService>,
            pubsub,
            auth,
            search,
            workflow_engine,
            relay_keys,
            media_storage,
        );
        Arc::new(state)
    }

    fn scoped_auth_event(
        author: &Keys,
        challenge: &str,
        relay_url: &str,
        epoch: &ClientBindingEpoch,
        relay_signer: &Keys,
    ) -> Event {
        EventBuilder::new(Kind::Authentication, "")
            .tags([
                Tag::parse(["challenge", challenge]).expect("valid challenge tag"),
                Tag::parse(["relay", relay_url]).expect("valid relay tag"),
                Tag::parse([
                    CLIENT_BINDING_SCOPE_TAG,
                    "1",
                    epoch.as_str(),
                    relay_signer.public_key().to_hex().as_str(),
                ])
                .expect("valid client-binding scope tag"),
            ])
            .custom_created_at(Timestamp::now())
            .sign_with_keys(author)
            .expect("sign scoped AUTH event")
    }

    async fn next_relay_text(
        socket: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> String {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .expect("relay response timeout")
                .expect("relay socket remains open")
                .expect("relay frame is valid");
            match frame {
                Message::Text(text) => return text.to_string(),
                Message::Ping(payload) => socket
                    .send(Message::Pong(payload))
                    .await
                    .expect("answer relay ping"),
                Message::Pong(_) => {}
                other => panic!("expected relay text frame, got {other:?}"),
            }
        }
    }

    async fn connect_status_relay(
        state: Arc<AppState>,
        host: &str,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        String,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind production AUTH loopback relay");
        let address = listener.local_addr().expect("loopback relay address");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("production AUTH loopback relay");
        });

        let mut request = format!("ws://{address}/")
            .into_client_request()
            .expect("loopback WebSocket request");
        request
            .headers_mut()
            .insert(HOST, host.parse().expect("canonical test Host"));
        let (mut socket, _) = connect_async(request)
            .await
            .expect("connect production AUTH loopback relay");
        let challenge_frame = next_relay_text(&mut socket).await;
        let challenge_wire: Value =
            serde_json::from_str(&challenge_frame).expect("AUTH challenge parses");
        let challenge = challenge_wire
            .as_array()
            .filter(|fields| fields.first().and_then(Value::as_str) == Some("AUTH"))
            .and_then(|fields| fields.get(1))
            .and_then(Value::as_str)
            .expect("relay sends one NIP-42 challenge")
            .to_owned();
        (server, socket, challenge)
    }

    fn reserved_event(frame: &str, expected_sub_id: &str) -> Event {
        let wire: Value = serde_json::from_str(frame).expect("relay frame parses");
        let fields = wire.as_array().expect("relay frame is an array");
        assert_eq!(fields.first().and_then(Value::as_str), Some("EVENT"));
        assert_eq!(fields.get(1).and_then(Value::as_str), Some(expected_sub_id));
        serde_json::from_value(fields.get(2).expect("reserved event present").clone())
            .expect("reserved event parses")
    }

    /// This is the production relay integration missing from the public fold
    /// harness: a real loopback WebSocket receives the relay challenge, sends
    /// one signed scoped NIP-42 AUTH through the normal router/connection
    /// stack, and receives the bootstrap and current status from the installed
    /// PostgreSQL-backed production runtime on that same socket.
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_production_auth_emits_bootstrap_and_current_on_same_connection() {
        let (pool, db, domain, scratch_url) = scratch_status_database().await;
        let relay_keys = Keys::generate();
        let author = Keys::generate();
        let restore_bootstrap_id = Uuid::new_v4();
        let restore =
            OperationRestoreRuntime::for_tests(db.clone(), [(domain, restore_bootstrap_id)])
                .with_database_fences_for_test(pool.clone());
        restore
            .provision_domain(domain)
            .await
            .expect("provision status restore baseline");
        let composition = ProviderFreeV1Composition::build(
            db.clone(),
            relay_keys.clone(),
            vec![direct_status_configuration(domain, restore_bootstrap_id)],
            Some(restore),
        )
        .await
        .expect("build production status composition");
        seed_current_binding(&pool, domain, &author).await;

        let state = status_auth_state(pool, db, scratch_url, relay_keys.clone()).await;
        state
            .install_provider_free_authorization(composition)
            .expect("install production status composition");

        let host = format!("status-{}.example", domain.as_uuid().simple());
        let (server, mut socket, challenge) = connect_status_relay(state, &host).await;
        let relay_url = format!("ws://{host}");
        let epoch = ClientBindingEpoch::new_v4();
        let auth_event = scoped_auth_event(&author, &challenge, &relay_url, &epoch, &relay_keys);
        let event_id = auth_event.id.to_hex();
        socket
            .send(Message::Text(
                serde_json::json!(["AUTH", auth_event]).to_string().into(),
            ))
            .await
            .expect("send scoped production AUTH");

        let ok_frame = next_relay_text(&mut socket).await;
        let bootstrap_frame = next_relay_text(&mut socket).await;
        let current_frame = next_relay_text(&mut socket).await;
        let ok: Value = serde_json::from_str(&ok_frame).expect("AUTH acknowledgement parses");
        assert_eq!(
            ok,
            serde_json::json!(["OK", event_id, true, ""]),
            "ordinary NIP-42 success must precede optional presentation",
        );
        let bootstrap = reserved_event(&bootstrap_frame, CLIENT_BINDING_BOOTSTRAP_SUB_ID);
        let current = reserved_event(&current_frame, CLIENT_BINDING_STATUS_SUB_ID);
        let now = Timestamp::now().as_secs();
        let validated_bootstrap = validate_client_binding_bootstrap_event(
            &bootstrap,
            &relay_keys.public_key(),
            &epoch,
            &author.public_key(),
            now,
        )
        .expect("production AUTH emits a trusted same-connection bootstrap");
        assert_eq!(validated_bootstrap.authorization_domain(), domain);
        validate_client_binding_status_event(
            &current,
            &relay_keys.public_key(),
            domain,
            &author.public_key(),
            now,
        )
        .expect("production AUTH emits a trusted epoch-free current status");
        assert!(!current.content.contains("connection_epoch"));

        socket.close(None).await.expect("close loopback socket");
        server.abort();
        let _ = server.await;
    }

    /// Optional status work must never stall the authenticated socket. A real
    /// PostgreSQL table lock holds the producer's evidence read past its bound;
    /// the socket must still acknowledge AUTH, parse later frames, emit no
    /// reserved presentation, and remain usable after the timeout.
    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_slow_status_producer_does_not_stall_and_times_out() {
        let (pool, db, domain, scratch_url) = scratch_status_database().await;
        let relay_keys = Keys::generate();
        let author = Keys::generate();
        let restore_bootstrap_id = Uuid::new_v4();
        let restore =
            OperationRestoreRuntime::for_tests(db.clone(), [(domain, restore_bootstrap_id)])
                .with_database_fences_for_test(pool.clone());
        restore
            .provision_domain(domain)
            .await
            .expect("provision status restore baseline");
        let composition = ProviderFreeV1Composition::build(
            db.clone(),
            relay_keys.clone(),
            vec![direct_status_configuration(domain, restore_bootstrap_id)],
            Some(restore),
        )
        .await
        .expect("build production status composition");
        seed_current_binding(&pool, domain, &author).await;

        let mut blocker = pool.acquire().await.expect("acquire status blocker");
        sqlx::query("BEGIN")
            .execute(&mut *blocker)
            .await
            .expect("begin retained status blocker");
        sqlx::query("LOCK TABLE identity_bindings IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await
            .expect("block status evidence reads");

        let state = status_auth_state(pool, db, scratch_url, relay_keys.clone()).await;
        state
            .install_provider_free_authorization(composition)
            .expect("install production status composition");
        let host = format!("status-{}.example", domain.as_uuid().simple());
        let (server, mut socket, challenge) = connect_status_relay(state, &host).await;
        let epoch = ClientBindingEpoch::new_v4();
        let auth_event = scoped_auth_event(
            &author,
            &challenge,
            format!("ws://{host}").as_str(),
            &epoch,
            &relay_keys,
        );
        let event_id = auth_event.id.to_hex();
        socket
            .send(Message::Text(
                serde_json::json!(["AUTH", auth_event]).to_string().into(),
            ))
            .await
            .expect("send scoped production AUTH");
        let ok: Value = serde_json::from_str(&next_relay_text(&mut socket).await)
            .expect("AUTH acknowledgement parses");
        assert_eq!(ok, serde_json::json!(["OK", event_id, true, ""]));

        socket
            .send(Message::Text(r#"["UNKNOWN"]"#.into()))
            .await
            .expect("send post-AUTH probe");
        let notice: Value = serde_json::from_str(&next_relay_text(&mut socket).await)
            .expect("post-AUTH notice parses");
        assert_eq!(
            notice.as_array().and_then(|v| v[0].as_str()),
            Some("NOTICE")
        );

        tokio::time::sleep(CLIENT_BINDING_STATUS_PRESENTATION_TIMEOUT + Duration::from_millis(100))
            .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), socket.next())
                .await
                .is_err(),
            "timed-out optional producer must not emit a late reserved frame",
        );
        socket
            .send(Message::Text(r#"["UNKNOWN"]"#.into()))
            .await
            .expect("send post-timeout probe");
        let notice: Value = serde_json::from_str(&next_relay_text(&mut socket).await)
            .expect("post-timeout notice parses");
        assert_eq!(
            notice.as_array().and_then(|v| v[0].as_str()),
            Some("NOTICE")
        );

        socket.close(None).await.expect("close loopback socket");
        sqlx::query("ROLLBACK")
            .execute(&mut *blocker)
            .await
            .expect("release retained status blocker");
        server.abort();
        let _ = server.await;
    }
}
