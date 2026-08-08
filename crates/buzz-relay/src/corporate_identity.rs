//! Corporate identity verification and canonical principal/key binding.
//!
//! This module is intentionally relay-local. `buzz-auth` remains the generic
//! Nostr proof layer; corporate identity is deployment policy layered after a
//! request proves control of a Nostr key.

use std::time::{Duration, Instant};
use std::{fmt, sync::Arc};

use axum::{
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Json,
};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
    Algorithm, DecodingKey, Validation,
};
use nostr::{Event, EventBuilder, FromBech32, Kind, PublicKey, Tag, Timestamp};
use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, warn};

use buzz_auth::{
    AssertionVerificationPolicy, ExactSingleHttpHeader, NostrKeyClaimPolicy, ProofTransport,
    RequestEvidenceBinding, StaticJwksAssertionVerifier, VerifiedIdentityBindingEvidence,
};
use buzz_core::{kind::KIND_USER_TRUSTED_ASSERTION, CommunityId};
use buzz_db::event::EventQuery;
use buzz_db::identity_lifecycle::{
    VerifiedIdentityBindingDenial, VerifiedIdentityBindingHandle, VerifiedIdentityBindingOutcome,
};

use crate::config::{CorporateIdentityAuthPrecedence, CorporateIdentityConfig};
use crate::state::AppState;

const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);
const JWKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const JWKS_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const JWKS_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
// Permit a bounded issuer/relay clock difference while keeping expiry enforcement explicit.
const JWT_CLOCK_SKEW_LEEWAY_SECS: u64 = 60;
const IDENTITY_ASSERTION_MAX_TTL_SECS: u64 = 60 * 60;
const IDENTITY_SESSION_REVALIDATION_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct CachedJwks {
    set: JwkSet,
    expires_at: Instant,
}

/// Validated corporate identity claims used by Buzz.
#[derive(Clone, PartialEq, Eq)]
pub struct CorporateJwtClaims {
    /// Validated identity-provider issuer.
    pub issuer: String,
    /// Stable corporate uid claim.
    pub uid: String,
    /// Human-readable verified identity claim.
    pub display_name: String,
    /// Optional operator-approved label that may be published in NIP-85.
    pub public_display_name: Option<String>,
    /// Optional pubkey carried by the IdP.
    pub pubkey: Option<PublicKey>,
    /// JWT expiration as a Unix timestamp.
    pub expires_at: u64,
}

impl fmt::Debug for CorporateJwtClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CorporateJwtClaims([REDACTED])")
    }
}

#[derive(Debug, Deserialize)]
struct RawJwtClaims {
    #[serde(flatten)]
    claims: Map<String, Value>,
}

/// Service that verifies corporate identity JWTs against configured JWKS.
#[derive(Debug)]
pub struct CorporateIdentityService {
    config: CorporateIdentityConfig,
    http: Result<reqwest::Client, String>,
    jwks: RwLock<Option<CachedJwks>>,
    refresh: Mutex<()>,
}

impl CorporateIdentityService {
    /// Build a corporate identity verifier from relay config.
    pub fn new(config: CorporateIdentityConfig) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(JWKS_CONNECT_TIMEOUT)
            .timeout(JWKS_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string());
        Self {
            config,
            http,
            jwks: RwLock::new(None),
            refresh: Mutex::new(()),
        }
    }

    /// Validate a JWT and extract the configured corporate identity claims.
    pub async fn validate_jwt(
        &self,
        token: &str,
    ) -> Result<CorporateJwtClaims, CorporateIdentityError> {
        let header = decode_header(token)
            .map_err(|e| CorporateIdentityError::InvalidJwt(format!("invalid JWT header: {e}")))?;
        if !is_allowed_jwt_algorithm(header.alg) {
            return Err(CorporateIdentityError::InvalidJwt(format!(
                "unsupported JWT algorithm: {:?}",
                header.alg
            )));
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or(CorporateIdentityError::MissingKid)?;
        let jwk = self.jwk_for_kid(kid).await?;
        validate_jwk_signature_metadata(&jwk, header.alg)?;
        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
            CorporateIdentityError::InvalidJwt(format!("invalid JWK for kid {kid}: {e}"))
        })?;

        let validation = jwt_validation(header.alg, &self.config);

        let decoded = decode::<RawJwtClaims>(token, &decoding_key, &validation)
            .map_err(|e| CorporateIdentityError::InvalidJwt(e.to_string()))?;

        let issuer = claim_string(&decoded.claims.claims, "iss")?;
        let uid = claim_string(&decoded.claims.claims, &self.config.uid_claim)?;
        let display_name = claim_string(&decoded.claims.claims, &self.config.display_claim)?;
        let public_display_name = self
            .config
            .public_display_claim
            .as_deref()
            .map(|claim| claim_string(&decoded.claims.claims, claim))
            .transpose()?;
        let pubkey =
            configured_pubkey_claim(&decoded.claims.claims, self.config.npub_claim.as_deref())?;
        let expires_at = claim_u64(&decoded.claims.claims, "exp")?;

        Ok(CorporateJwtClaims {
            issuer,
            uid,
            display_name,
            public_display_name,
            pubkey,
            expires_at,
        })
    }

    async fn verify_binding_evidence(
        &self,
        token: &str,
        community_id: CommunityId,
        signer: PublicKey,
        transport: ProofTransport,
    ) -> Result<VerifiedIdentityBindingEvidence, CorporateIdentityError> {
        let mut policy = AssertionVerificationPolicy::new(
            self.config.issuer.clone(),
            self.config.audience.clone(),
            self.config.uid_claim.clone(),
            Duration::from_secs(86_400),
            Duration::from_secs(JWT_CLOCK_SKEW_LEEWAY_SECS),
        )
        .map_err(|error| CorporateIdentityError::InvalidJwt(error.to_string()))?;
        if let Some(claim) = self.config.npub_claim.as_ref() {
            policy = policy
                .with_nostr_key_claim(
                    NostrKeyClaimPolicy::canonical_public_key(claim.clone())
                        .map_err(|error| CorporateIdentityError::InvalidJwt(error.to_string()))?,
                )
                .map_err(|error| CorporateIdentityError::InvalidJwt(error.to_string()))?;
        }

        let verifier = StaticJwksAssertionVerifier::new(policy, self.jwks_snapshot().await?)
            .map_err(|error| CorporateIdentityError::InvalidJwt(error.to_string()))?;
        let header_name = HeaderName::from_static("x-buzz-sealed-identity-assertion");
        let header_value = HeaderValue::from_str(token)
            .map_err(|_| CorporateIdentityError::InvalidJwt("ambiguous assertion".to_string()))?;
        let mut headers = HeaderMap::new();
        headers.insert(header_name.clone(), header_value);
        let assertion = ExactSingleHttpHeader::from_headers(&headers, &header_name)
            .map_err(|error| CorporateIdentityError::InvalidJwt(error.to_string()))?;
        let binding = RequestEvidenceBinding::new(
            community_id,
            transport,
            b"corporate-identity-compat-v1",
            signer.as_bytes(),
            b"client-attached-corporate-identity",
        )
        .map_err(|error| CorporateIdentityError::InvalidJwt(error.to_string()))?;
        verifier
            .verify_client_attached(&assertion, &binding)
            .and_then(|verified| verified.bind_authenticated_actor(signer))
            .map_err(|error| CorporateIdentityError::InvalidJwt(error.to_string()))
    }

    async fn jwk_for_kid(&self, kid: &str) -> Result<Jwk, CorporateIdentityError> {
        self.jwks_snapshot()
            .await?
            .find(kid)
            .cloned()
            .ok_or_else(|| CorporateIdentityError::Jwks(format!("kid not found: {kid}")))
    }

    async fn jwks_snapshot(&self) -> Result<JwkSet, CorporateIdentityError> {
        let now = Instant::now();
        {
            let cache = self.jwks.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > now {
                    return Ok(cached.set.clone());
                }
            }
        }

        // Only one request may refresh at a time. Re-check after acquiring the
        // mutex because another waiter may already have populated the cache.
        let _refresh = self.refresh.lock().await;
        let now = Instant::now();
        {
            let cache = self.jwks.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.expires_at > now {
                    return Ok(cached.set.clone());
                }
            }
        }

        let set = self.fetch_jwks().await?;
        *self.jwks.write().await = Some(CachedJwks {
            set: set.clone(),
            expires_at: Instant::now() + JWKS_CACHE_TTL,
        });
        Ok(set)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, CorporateIdentityError> {
        let client = self
            .http
            .as_ref()
            .map_err(|error| CorporateIdentityError::Jwks(error.clone()))?;
        let mut response = client
            .get(&self.config.jwks_uri)
            .send()
            .await
            .map_err(|e| CorporateIdentityError::Jwks(e.to_string()))?
            .error_for_status()
            .map_err(|e| CorporateIdentityError::Jwks(e.to_string()))?;
        if response
            .content_length()
            .is_some_and(|length| length > JWKS_MAX_RESPONSE_BYTES as u64)
        {
            return Err(CorporateIdentityError::Jwks(
                "JWKS response exceeds size limit".to_string(),
            ));
        }

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| CorporateIdentityError::Jwks(e.to_string()))?
        {
            if body.len().saturating_add(chunk.len()) > JWKS_MAX_RESPONSE_BYTES {
                return Err(CorporateIdentityError::Jwks(
                    "JWKS response exceeds size limit".to_string(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice::<JwkSet>(&body)
            .map_err(|e| CorporateIdentityError::Jwks(e.to_string()))
    }
}

fn jwt_validation(algorithm: Algorithm, config: &CorporateIdentityConfig) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.leeway = JWT_CLOCK_SKEW_LEEWAY_SECS;
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[config.audience.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation
}

/// Read-only result of cryptographically validating corporate identity.
///
/// Callers must complete admission/authorization before passing this proof to
/// [`finalize_corporate_identity`]. This ordering prevents rejected requests
/// from creating identity bindings or public assertions.
#[derive(Clone)]
pub struct CorporateIdentityProof(CorporateIdentityProofInner);

#[derive(Clone)]
enum CorporateIdentityProofInner {
    NotRequired,
    Direct {
        evidence: Arc<VerifiedIdentityBindingEvidence>,
        public_display_name: Option<String>,
        expires_at: u64,
    },
}

impl fmt::Debug for CorporateIdentityProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            CorporateIdentityProofInner::NotRequired => {
                formatter.write_str("CorporateIdentityProof::NotRequired")
            }
            CorporateIdentityProofInner::Direct { .. } => {
                formatter.write_str("CorporateIdentityProof::Direct([REDACTED])")
            }
        }
    }
}

/// Borrow origin-sealed identity evidence for an atomic admission transaction.
pub fn binding_evidence_for_proof(
    proof: &CorporateIdentityProof,
) -> Option<&VerifiedIdentityBindingEvidence> {
    match &proof.0 {
        CorporateIdentityProofInner::Direct { evidence, .. } => Some(evidence.as_ref()),
        CorporateIdentityProofInner::NotRequired => None,
    }
}

/// Outcome of corporate identity enforcement.
#[derive(Clone)]
pub struct CorporateIdentityDecision(CorporateIdentityDecisionInner);

#[derive(Clone)]
enum CorporateIdentityDecisionInner {
    NotRequired,
    Direct {
        expires_at: u64,
        binding: VerifiedIdentityBindingHandle,
    },
}

impl fmt::Debug for CorporateIdentityDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            CorporateIdentityDecisionInner::NotRequired => {
                formatter.write_str("CorporateIdentityDecision::NotRequired")
            }
            CorporateIdentityDecisionInner::Direct { .. } => {
                formatter.write_str("CorporateIdentityDecision::Direct([REDACTED])")
            }
        }
    }
}

struct SessionRevalidationPlan {
    binding: VerifiedIdentityBindingHandle,
    expires_at: Option<u64>,
}

fn session_revalidation_plan(
    decision: CorporateIdentityDecision,
) -> Option<SessionRevalidationPlan> {
    match decision.0 {
        CorporateIdentityDecisionInner::NotRequired => None,
        CorporateIdentityDecisionInner::Direct {
            expires_at,
            binding,
        } => Some(SessionRevalidationPlan {
            binding,
            expires_at: Some(expires_at),
        }),
    }
}

async fn cancel_session_at_expiry(
    expires_at: u64,
    now_secs: u64,
    cancel: tokio_util::sync::CancellationToken,
) {
    let delay = Duration::from_secs(expires_at.saturating_sub(now_secs));
    tokio::select! {
        _ = cancel.cancelled() => {}
        _ = tokio::time::sleep(delay) => cancel.cancel(),
    }
}

async fn run_session_binding_revalidation<F, Fut, E>(
    interval: Duration,
    signer: PublicKey,
    cancel: tokio_util::sync::CancellationToken,
    mut lookup: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool, E>>,
    E: std::fmt::Display,
{
    let mut interval = tokio::time::interval(interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = interval.tick() => {
                match lookup().await {
                    Ok(true) => {}
                    Ok(false) => {
                        warn!(
                            signer = %signer.to_hex(),
                            "corporate identity session evicted after binding revocation"
                        );
                        cancel.cancel();
                        return;
                    }
                    Err(error) => {
                        warn!(
                            signer = %signer.to_hex(),
                            error = %error,
                            "corporate identity session revalidation failed closed"
                        );
                        cancel.cancel();
                        return;
                    }
                }
            }
        }
    }
}

/// Revalidate a long-lived corporate identity session until it closes.
///
/// Direct sessions are cancelled at JWT expiry and when their binding stops
/// being active. Delegated sessions re-check the owner binding, so revoking an
/// owner also evicts every agent session within one bounded interval.
pub fn spawn_session_revalidation(
    state: Arc<AppState>,
    _community_id: CommunityId,
    signer: PublicKey,
    decision: CorporateIdentityDecision,
    cancel: tokio_util::sync::CancellationToken,
) {
    let Some(plan) = session_revalidation_plan(decision) else {
        return;
    };
    let SessionRevalidationPlan {
        binding,
        expires_at,
    } = plan;

    if let Some(expires_at) = expires_at {
        let expiry_cancel = cancel.clone();
        tokio::spawn(async move {
            cancel_session_at_expiry(expires_at, Timestamp::now().as_secs(), expiry_cancel).await;
        });
    }

    let lookup_state = Arc::clone(&state);
    tokio::spawn(run_session_binding_revalidation(
        IDENTITY_SESSION_REVALIDATION_INTERVAL,
        signer,
        cancel,
        move || {
            let state = Arc::clone(&lookup_state);
            let binding = binding.clone();
            async move {
                state
                    .db
                    .revalidate_verified_identity_binding(&binding)
                    .await
            }
        },
    ));
}

/// Errors produced by corporate identity verification.
#[derive(Debug, Error)]
pub enum CorporateIdentityError {
    /// No JWT was available and delegation did not apply.
    #[error("corporate identity JWT missing")]
    MissingJwt,
    /// JWT header did not include a `kid`.
    #[error("corporate identity JWT missing kid")]
    MissingKid,
    /// JWT signature or claims failed validation.
    #[error("invalid corporate identity JWT: {0}")]
    InvalidJwt(String),
    /// JWKS fetch or lookup failed.
    #[error("corporate identity JWKS unavailable: {0}")]
    Jwks(String),
    /// A configured claim is missing or not a string.
    #[error("invalid corporate identity claim {claim}: {reason}")]
    InvalidClaim {
        /// Claim name.
        claim: String,
        /// Validation reason.
        reason: String,
    },
    /// The requested principal/key binding conflicts with an active binding.
    #[error("corporate identity binding conflict")]
    BindingConflict,
    /// The JWT did not attest the signer and no existing binding matched.
    #[error("corporate identity requires an existing binding")]
    BindingRequired,
    /// The requested principal/key binding is denied by immutable lifecycle facts.
    #[error("corporate identity binding revoked")]
    BindingRevoked,
    /// Canonical lifecycle policy could not be evaluated.
    #[error("corporate identity policy unavailable")]
    PolicyUnavailable,
    /// A sealed identity was paired with different server-resolved coordinates.
    #[error("corporate identity sealed coordinate mismatch")]
    SealedCoordinateMismatch,
    /// NIP-OA delegation was present but did not satisfy corporate identity.
    #[error("corporate identity delegation denied")]
    DelegationDenied,
    /// Database operation failed.
    #[error("corporate identity database error: {0}")]
    Db(#[from] buzz_db::DbError),
}

impl CorporateIdentityError {
    /// HTTP status appropriate for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingJwt | Self::MissingKid | Self::InvalidJwt(_) | Self::Jwks(_) => {
                StatusCode::UNAUTHORIZED
            }
            Self::InvalidClaim { .. }
            | Self::BindingConflict
            | Self::BindingRequired
            | Self::BindingRevoked
            | Self::DelegationDenied => StatusCode::FORBIDDEN,
            Self::PolicyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::SealedCoordinateMismatch => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Sanitized message safe to return to clients.
    pub fn public_message(&self) -> &'static str {
        match self {
            Self::MissingJwt => "relay-verified identity required",
            Self::MissingKid | Self::InvalidJwt(_) | Self::Jwks(_) => {
                "relay identity verification failed"
            }
            Self::InvalidClaim { .. } => "relay identity claim invalid",
            Self::BindingConflict => "relay identity binding conflict",
            Self::BindingRequired => "relay identity binding required",
            Self::BindingRevoked => "relay identity binding revoked",
            Self::PolicyUnavailable => "relay identity policy unavailable",
            Self::SealedCoordinateMismatch => "relay identity unavailable",
            Self::DelegationDenied => "relay identity delegation denied",
            Self::Db(_) => "relay identity unavailable",
        }
    }

    /// Convert to the standard API error shape.
    pub fn into_api_error(self) -> (StatusCode, Json<Value>) {
        let status = self.status_code();
        let message = self.public_message();
        if status.is_server_error() {
            warn!(error = %self, "corporate identity enforcement failed");
        }
        (status, Json(serde_json::json!({ "error": message })))
    }
}

pub(crate) fn identity_binding_denial_error(
    denial: VerifiedIdentityBindingDenial,
) -> CorporateIdentityError {
    match denial {
        VerifiedIdentityBindingDenial::ExistingBindingRequired => {
            CorporateIdentityError::BindingRequired
        }
        VerifiedIdentityBindingDenial::PrincipalConflict
        | VerifiedIdentityBindingDenial::EventAuthorConflict => {
            CorporateIdentityError::BindingConflict
        }
        VerifiedIdentityBindingDenial::LifecycleDenied => CorporateIdentityError::BindingRevoked,
        VerifiedIdentityBindingDenial::PolicyUnavailable => {
            CorporateIdentityError::PolicyUnavailable
        }
    }
}

/// Convert and record a denial returned by an atomic admission transaction.
pub(crate) fn atomic_identity_denial_error(
    denial: VerifiedIdentityBindingDenial,
) -> CorporateIdentityError {
    let error = identity_binding_denial_error(denial);
    record_corporate_identity_denial(&error);
    error
}

fn ensure_identity_evidence_matches_request(
    evidence: &VerifiedIdentityBindingEvidence,
    community_id: CommunityId,
    signer: PublicKey,
) -> Result<(), CorporateIdentityError> {
    evidence
        .accepts_authorization_coordinates(community_id, signer)
        .then_some(())
        .ok_or(CorporateIdentityError::SealedCoordinateMismatch)
}

fn ensure_identity_handle_matches_request(
    binding: &VerifiedIdentityBindingHandle,
    community_id: CommunityId,
    signer: PublicKey,
) -> Result<(), CorporateIdentityError> {
    binding
        .accepts_actor(community_id, &signer)
        .then_some(())
        .ok_or(CorporateIdentityError::SealedCoordinateMismatch)
}

fn sealed_identity_expiry(
    evidence: &VerifiedIdentityBindingEvidence,
) -> Result<u64, CorporateIdentityError> {
    u64::try_from(evidence.expires_at().timestamp())
        .map_err(|_| CorporateIdentityError::InvalidJwt("invalid assertion expiry".to_string()))
}

/// Extract a corporate identity JWT from the configured request header.
pub fn identity_jwt_from_headers(
    headers: &HeaderMap,
    config: &CorporateIdentityConfig,
) -> Option<String> {
    let mut values = headers.get_all(config.jwt_header.as_str()).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let raw = value.to_str().ok()?;
    if raw.is_empty()
        || raw.contains(',')
        || raw.as_bytes().first().is_some_and(u8::is_ascii_whitespace)
        || raw.as_bytes().last().is_some_and(u8::is_ascii_whitespace)
    {
        return None;
    }
    let token = raw.strip_prefix("Bearer ").unwrap_or(raw);
    (!token.is_empty() && !token.chars().any(char::is_whitespace)).then(|| token.to_owned())
}

/// Validate corporate identity without creating bindings or assertions.
pub async fn verify_corporate_identity(
    state: &AppState,
    community_id: CommunityId,
    signer: PublicKey,
    transport: ProofTransport,
    identity_jwt: Option<&str>,
    auth_tag_json: Option<&str>,
) -> Result<CorporateIdentityProof, CorporateIdentityError> {
    let result = verify_corporate_identity_inner(
        state,
        community_id,
        signer,
        transport,
        identity_jwt,
        auth_tag_json,
    )
    .await;
    if let Err(error) = &result {
        record_corporate_identity_denial(error);
    }
    result
}

async fn verify_corporate_identity_inner(
    state: &AppState,
    community_id: CommunityId,
    signer: PublicKey,
    transport: ProofTransport,
    identity_jwt: Option<&str>,
    auth_tag_json: Option<&str>,
) -> Result<CorporateIdentityProof, CorporateIdentityError> {
    let Some(service) = state.corporate_identity.as_ref() else {
        return Ok(CorporateIdentityProof(
            CorporateIdentityProofInner::NotRequired,
        ));
    };

    // Honor the configured direct/delegated precedence, but delegated
    // corporate identity remains fail-closed until a canonical relationship
    // authority can produce sealed evidence for it.
    if select_identity_auth_path(&service.config, identity_jwt, auth_tag_json)
        == IdentityAuthPath::Delegated
    {
        return verify_delegated_corporate_identity(auth_tag_json);
    }

    if let Some(token) = identity_jwt {
        let evidence = service
            .verify_binding_evidence(token, community_id, signer, transport)
            .await?;
        let expires_at = sealed_identity_expiry(&evidence)?;
        let claims = service.validate_jwt(token).await?;
        return Ok(CorporateIdentityProof(
            CorporateIdentityProofInner::Direct {
                evidence: Arc::new(evidence),
                public_display_name: claims.public_display_name,
                expires_at,
            },
        ));
    }

    verify_delegated_corporate_identity(auth_tag_json)
}

/// Commit a previously validated proof after request authorization succeeds.
pub async fn finalize_corporate_identity(
    state: &AppState,
    community_id: CommunityId,
    signer: PublicKey,
    proof: CorporateIdentityProof,
) -> Result<CorporateIdentityDecision, CorporateIdentityError> {
    let result = finalize_corporate_identity_inner(state, community_id, signer, proof).await;
    if let Err(error) = &result {
        record_corporate_identity_denial(error);
    }
    result
}

/// Complete metrics and assertion projection for an identity result produced
/// by an atomic admission transaction.
pub async fn finalize_atomic_corporate_identity_result(
    state: &AppState,
    community_id: CommunityId,
    signer: PublicKey,
    proof: CorporateIdentityProof,
    committed_binding: Option<VerifiedIdentityBindingHandle>,
) -> Result<CorporateIdentityDecision, CorporateIdentityError> {
    let result = match proof.0 {
        CorporateIdentityProofInner::NotRequired => Ok(CorporateIdentityDecision(
            CorporateIdentityDecisionInner::NotRequired,
        )),
        CorporateIdentityProofInner::Direct {
            evidence,
            public_display_name,
            expires_at,
        } => {
            ensure_identity_evidence_matches_request(evidence.as_ref(), community_id, signer)?;
            let binding = committed_binding.ok_or_else(|| {
                buzz_db::DbError::InvalidData(
                    "atomic identity admission did not return a binding result".to_string(),
                )
            })?;
            ensure_identity_handle_matches_request(&binding, community_id, signer)?;
            metrics::counter!("buzz_corporate_identity_bindings_total", "result" => "committed")
                .increment(1);
            complete_direct_corporate_identity(
                state,
                community_id,
                signer,
                public_display_name,
                expires_at,
                binding,
            )
            .await
        }
    };
    if let Err(error) = &result {
        record_corporate_identity_denial(error);
    }
    result
}

async fn finalize_corporate_identity_inner(
    state: &AppState,
    community_id: CommunityId,
    signer: PublicKey,
    proof: CorporateIdentityProof,
) -> Result<CorporateIdentityDecision, CorporateIdentityError> {
    match proof.0 {
        CorporateIdentityProofInner::NotRequired => Ok(CorporateIdentityDecision(
            CorporateIdentityDecisionInner::NotRequired,
        )),
        CorporateIdentityProofInner::Direct {
            evidence,
            public_display_name,
            expires_at,
        } => {
            ensure_identity_evidence_matches_request(evidence.as_ref(), community_id, signer)?;
            let (binding, result) = match state
                .db
                .resolve_verified_identity_binding(evidence.as_ref())
                .await?
            {
                VerifiedIdentityBindingOutcome::Created(binding) => (binding, "created"),
                VerifiedIdentityBindingOutcome::Matched(binding) => (binding, "matched"),
                VerifiedIdentityBindingOutcome::Denied(denial) => {
                    return Err(identity_binding_denial_error(denial));
                }
            };
            ensure_identity_handle_matches_request(&binding, community_id, signer)?;
            metrics::counter!("buzz_corporate_identity_bindings_total", "result" => result)
                .increment(1);
            complete_direct_corporate_identity(
                state,
                community_id,
                signer,
                public_display_name,
                expires_at,
                binding,
            )
            .await
        }
    }
}

async fn complete_direct_corporate_identity(
    state: &AppState,
    community_id: CommunityId,
    signer: PublicKey,
    public_display_name: Option<String>,
    expires_at: u64,
    binding: VerifiedIdentityBindingHandle,
) -> Result<CorporateIdentityDecision, CorporateIdentityError> {
    if let Err(error) = ensure_identity_assertion(
        state,
        community_id,
        signer,
        public_display_name.as_deref(),
        expires_at,
    )
    .await
    {
        // The binding remains the authorization authority. A projection
        // failure removes the verified affordance but must not lock an
        // otherwise authorized user out of the relay.
        warn!(
                signer = %signer.to_hex(),
                error = %error,
                "failed to publish corporate identity assertion"
        );
        metrics::counter!("buzz_corporate_identity_assertions_total", "result" => "error")
            .increment(1);
    }

    debug!(
        signer = %signer.to_hex(),
        "corporate identity verified"
    );
    Ok(CorporateIdentityDecision(
        CorporateIdentityDecisionInner::Direct {
            expires_at,
            binding,
        },
    ))
}

fn build_identity_assertion(
    relay_keypair: &nostr::Keys,
    subject: PublicKey,
    display_name: Option<&str>,
    expires_at: u64,
    created_at: Timestamp,
) -> Result<Event, String> {
    let subject = subject.to_hex();
    let active = if display_name.is_some() {
        "true"
    } else {
        "false"
    };
    let expires_at = expires_at.to_string();
    let mut tags = vec![
        Tag::parse(["d", subject.as_str()]),
        Tag::parse(["p", subject.as_str()]),
        Tag::parse(["verified", "relay"]),
        Tag::parse(["active", active]),
        Tag::parse(["expiration", expires_at.as_str()]),
    ];
    if let Some(display_name) = display_name {
        tags.push(Tag::parse(["display_name", display_name]));
    }
    let tags = tags
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("invalid corporate identity assertion tag: {error}"))?;

    EventBuilder::new(Kind::Custom(KIND_USER_TRUSTED_ASSERTION as u16), "")
        .tags(tags)
        .custom_created_at(created_at)
        .sign_with_keys(relay_keypair)
        .map_err(|error| format!("failed to sign corporate identity assertion: {error}"))
}

fn identity_assertion_matches(
    event: &Event,
    subject: &str,
    display_name: Option<&str>,
    expires_at: u64,
) -> bool {
    let has_tag = |name: &str, value: &str| {
        event.tags.iter().any(|tag| {
            let parts = tag.as_slice();
            parts.len() == 2 && parts[0] == name && parts[1] == value
        })
    };
    has_tag("d", subject)
        && has_tag("p", subject)
        && has_tag("verified", "relay")
        && has_tag(
            "active",
            if display_name.is_some() {
                "true"
            } else {
                "false"
            },
        )
        && has_tag("expiration", &expires_at.to_string())
        && display_name.is_none_or(|name| has_tag("display_name", name))
}

async fn ensure_identity_assertion(
    state: &AppState,
    community_id: CommunityId,
    subject: PublicKey,
    display_name: Option<&str>,
    jwt_expires_at: u64,
) -> Result<(), String> {
    let subject_hex = subject.to_hex();
    let existing = state
        .db
        .query_events(&EventQuery {
            kinds: Some(vec![KIND_USER_TRUSTED_ASSERTION as i32]),
            pubkey: Some(state.relay_keypair.public_key().to_bytes().to_vec()),
            d_tag: Some(subject_hex.clone()),
            global_only: true,
            limit: Some(1),
            ..EventQuery::for_community(community_id)
        })
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .next();

    // Privacy default: do not publish any assertion unless the operator opted
    // into a public label. An inactive replacement is emitted only to retire a
    // previously published assertion after that opt-in is removed.
    if display_name.is_none() && existing.is_none() {
        return Ok(());
    }

    let now = Timestamp::now().as_secs();
    let expires_at = identity_assertion_expiration(display_name, jwt_expires_at, now);
    if existing.as_ref().is_some_and(|stored| {
        identity_assertion_matches(&stored.event, &subject_hex, display_name, expires_at)
    }) {
        return Ok(());
    }

    let created_at = existing
        .as_ref()
        .map(|stored| stored.event.created_at.as_secs().saturating_add(1))
        .unwrap_or(now)
        .max(now);
    let event = build_identity_assertion(
        &state.relay_keypair,
        subject,
        display_name,
        expires_at,
        Timestamp::from(created_at),
    )?;

    state
        .db
        .replace_parameterized_event(community_id, &event, &subject_hex, None)
        .await
        .map_err(|error| error.to_string())?;
    metrics::counter!("buzz_corporate_identity_assertions_total", "result" => "published")
        .increment(1);
    Ok(())
}

fn identity_assertion_expiration(display_name: Option<&str>, jwt_expires_at: u64, now: u64) -> u64 {
    if display_name.is_some() {
        jwt_expires_at.min(now.saturating_add(IDENTITY_ASSERTION_MAX_TTL_SECS))
    } else {
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityAuthPath {
    Direct,
    Delegated,
}

fn select_identity_auth_path(
    config: &CorporateIdentityConfig,
    identity_jwt: Option<&str>,
    auth_tag_json: Option<&str>,
) -> IdentityAuthPath {
    match (identity_jwt.is_some(), auth_tag_json.is_some()) {
        (true, true) => match config.auth_precedence {
            CorporateIdentityAuthPrecedence::Direct => IdentityAuthPath::Direct,
            CorporateIdentityAuthPrecedence::Delegated => IdentityAuthPath::Delegated,
        },
        (true, false) => IdentityAuthPath::Direct,
        (false, _) => IdentityAuthPath::Delegated,
    }
}

fn verify_delegated_corporate_identity(
    auth_tag_json: Option<&str>,
) -> Result<CorporateIdentityProof, CorporateIdentityError> {
    if auth_tag_json.is_some() {
        Err(CorporateIdentityError::DelegationDenied)
    } else {
        Err(CorporateIdentityError::MissingJwt)
    }
}

fn is_allowed_jwt_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}

fn validate_jwk_signature_metadata(
    jwk: &Jwk,
    token_algorithm: Algorithm,
) -> Result<(), CorporateIdentityError> {
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|key_use| key_use != &PublicKeyUse::Signature)
    {
        return Err(CorporateIdentityError::InvalidJwt(
            "JWK use must be sig for JWT verification".to_string(),
        ));
    }
    if jwk
        .common
        .key_operations
        .as_ref()
        .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
    {
        return Err(CorporateIdentityError::InvalidJwt(
            "JWK key_ops must include verify for JWT verification".to_string(),
        ));
    }
    if jwk
        .common
        .key_algorithm
        .is_some_and(|algorithm| !jwk_algorithm_matches(algorithm, token_algorithm))
    {
        return Err(CorporateIdentityError::InvalidJwt(format!(
            "JWT algorithm {token_algorithm:?} does not match JWK algorithm"
        )));
    }
    Ok(())
}

fn jwk_algorithm_matches(key: KeyAlgorithm, token: Algorithm) -> bool {
    matches!(
        (key, token),
        (KeyAlgorithm::RS256, Algorithm::RS256)
            | (KeyAlgorithm::RS384, Algorithm::RS384)
            | (KeyAlgorithm::RS512, Algorithm::RS512)
            | (KeyAlgorithm::PS256, Algorithm::PS256)
            | (KeyAlgorithm::PS384, Algorithm::PS384)
            | (KeyAlgorithm::PS512, Algorithm::PS512)
            | (KeyAlgorithm::ES256, Algorithm::ES256)
            | (KeyAlgorithm::ES384, Algorithm::ES384)
            | (KeyAlgorithm::EdDSA, Algorithm::EdDSA)
    )
}

fn claim_string(
    claims: &Map<String, Value>,
    claim: &str,
) -> Result<String, CorporateIdentityError> {
    let value = claims
        .get(claim)
        .ok_or_else(|| CorporateIdentityError::InvalidClaim {
            claim: claim.to_string(),
            reason: "missing".to_string(),
        })?;
    let value = value
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CorporateIdentityError::InvalidClaim {
            claim: claim.to_string(),
            reason: "must be a non-empty string".to_string(),
        })?;
    Ok(value.to_string())
}

fn configured_pubkey_claim(
    claims: &Map<String, Value>,
    claim: Option<&str>,
) -> Result<Option<PublicKey>, CorporateIdentityError> {
    match claim {
        Some(claim) => claims
            .get(claim)
            .map(|value| {
                value
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| CorporateIdentityError::InvalidClaim {
                        claim: claim.to_string(),
                        reason: "must be a non-empty string".to_string(),
                    })
                    .and_then(|raw| parse_pubkey_claim(claim, raw))
            })
            .transpose(),
        None => Ok(None),
    }
}

fn claim_u64(claims: &Map<String, Value>, claim: &str) -> Result<u64, CorporateIdentityError> {
    claims
        .get(claim)
        .and_then(Value::as_u64)
        .ok_or_else(|| CorporateIdentityError::InvalidClaim {
            claim: claim.to_string(),
            reason: "must be an unsigned integer".to_string(),
        })
}

fn parse_pubkey_claim(claim: &str, value: &str) -> Result<PublicKey, CorporateIdentityError> {
    if value.starts_with("npub1") {
        PublicKey::from_bech32(value).map_err(|e| CorporateIdentityError::InvalidClaim {
            claim: claim.to_string(),
            reason: format!("invalid npub: {e}"),
        })
    } else {
        PublicKey::from_hex(value).map_err(|e| CorporateIdentityError::InvalidClaim {
            claim: claim.to_string(),
            reason: format!("invalid pubkey hex: {e}"),
        })
    }
}

/// Create an optional service from config.
pub fn service_from_config(
    config: &CorporateIdentityConfig,
) -> Option<Arc<CorporateIdentityService>> {
    config
        .require
        .then(|| Arc::new(CorporateIdentityService::new(config.clone())))
}

fn record_corporate_identity_denial(error: &CorporateIdentityError) {
    let reason = match error {
        CorporateIdentityError::MissingJwt => "missing_jwt",
        CorporateIdentityError::MissingKid => "missing_kid",
        CorporateIdentityError::InvalidJwt(_) => "invalid_jwt",
        CorporateIdentityError::Jwks(_) => "jwks",
        CorporateIdentityError::InvalidClaim { .. } => "invalid_claim",
        CorporateIdentityError::BindingConflict => "binding_conflict",
        CorporateIdentityError::BindingRequired => "binding_required",
        CorporateIdentityError::BindingRevoked => "binding_revoked",
        CorporateIdentityError::PolicyUnavailable => "policy_unavailable",
        CorporateIdentityError::SealedCoordinateMismatch => "sealed_coordinate_mismatch",
        CorporateIdentityError::DelegationDenied => "delegation_denied",
        CorporateIdentityError::Db(_) => "db",
    };
    metrics::counter!("buzz_auth_failures_total", "reason" => "corporate_identity_denied")
        .increment(1);
    metrics::counter!("buzz_corporate_identity_denials_total", "reason" => reason).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use base64::Engine as _;
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use nostr::{Keys, ToBech32};
    use sqlx::PgPool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use uuid::Uuid;

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1

    fn test_config() -> CorporateIdentityConfig {
        CorporateIdentityConfig {
            require: true,
            jwt_header: "x-buzz-identity-token".to_string(),
            allow_delegation: true,
            auth_precedence: CorporateIdentityAuthPrecedence::Direct,
            jwks_uri: "http://127.0.0.1:9/jwks".to_string(),
            issuer: "https://idp.example".to_string(),
            audience: "buzz-relay".to_string(),
            uid_claim: "sub".to_string(),
            display_claim: "email".to_string(),
            public_display_claim: None,
            npub_claim: Some("buzz_npub".to_string()),
        }
    }

    #[test]
    fn stock_default_keeps_corporate_identity_uninstalled() {
        assert!(service_from_config(&CorporateIdentityConfig::default()).is_none());
        assert!(service_from_config(&test_config()).is_some());
    }

    #[test]
    fn opaque_disabled_proof_and_decision_are_redacted_and_have_no_binding() {
        let proof = CorporateIdentityProof(CorporateIdentityProofInner::NotRequired);
        assert_eq!(format!("{proof:?}"), "CorporateIdentityProof::NotRequired");
        assert!(binding_evidence_for_proof(&proof).is_none());

        let decision = CorporateIdentityDecision(CorporateIdentityDecisionInner::NotRequired);
        assert_eq!(
            format!("{decision:?}"),
            "CorporateIdentityDecision::NotRequired"
        );
        assert!(session_revalidation_plan(decision).is_none());
    }

    fn spawn_test_revalidation(
        signer: PublicKey,
        cancel: tokio_util::sync::CancellationToken,
        result: Result<bool, &'static str>,
    ) -> (tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
        let lookups = Arc::new(AtomicUsize::new(0));
        let task_lookups = Arc::clone(&lookups);
        let task = tokio::spawn(run_session_binding_revalidation(
            IDENTITY_SESSION_REVALIDATION_INTERVAL,
            signer,
            cancel,
            move || {
                task_lookups.fetch_add(1, Ordering::SeqCst);
                let result = result;
                async move { result }
            },
        ));
        (task, lookups)
    }

    #[tokio::test(start_paused = true)]
    async fn direct_session_stays_live_before_expiry_and_cancels_at_expiry() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let task = tokio::spawn(cancel_session_at_expiry(110, 100, cancel.clone()));
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(9)).await;
        tokio::task::yield_now().await;
        assert!(!cancel.is_cancelled());

        tokio::time::advance(Duration::from_secs(1)).await;
        cancel.cancelled().await;
        task.await.expect("expiry task");
    }

    #[tokio::test(start_paused = true)]
    async fn matching_session_binding_stays_live() {
        let signer = Keys::generate().public_key();
        let cancel = tokio_util::sync::CancellationToken::new();
        let (task, lookups) = spawn_test_revalidation(signer, cancel.clone(), Ok(true));

        while lookups.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        assert!(!cancel.is_cancelled());
        cancel.cancel();
        task.await.expect("revalidation task");
    }

    #[tokio::test(start_paused = true)]
    async fn inactive_session_binding_cancels() {
        let signer = Keys::generate().public_key();
        let cancel = tokio_util::sync::CancellationToken::new();
        let (task, _) = spawn_test_revalidation(signer, cancel.clone(), Ok(false));

        cancel.cancelled().await;
        task.await.expect("revalidation task");
    }

    #[tokio::test(start_paused = true)]
    async fn session_revalidation_database_error_cancels_fail_closed() {
        let signer = Keys::generate().public_key();
        let cancel = tokio_util::sync::CancellationToken::new();
        let (task, _) =
            spawn_test_revalidation(signer, cancel.clone(), Err("database unavailable"));

        cancel.cancelled().await;
        task.await.expect("revalidation task");
    }

    #[test]
    fn identity_projects_as_relay_signed_nip85_assertion_without_provider_details() {
        let relay = Keys::generate();
        let subject = Keys::generate().public_key();
        let event = build_identity_assertion(
            &relay,
            subject,
            Some("Example User"),
            456,
            Timestamp::from(123),
        )
        .unwrap();

        assert_eq!(event.kind.as_u16() as u32, KIND_USER_TRUSTED_ASSERTION);
        assert_eq!(event.pubkey, relay.public_key());
        assert!(event.verify_id());
        assert!(event.verify_signature());
        assert!(identity_assertion_matches(
            &event,
            &subject.to_hex(),
            Some("Example User"),
            456,
        ));
        assert!(
            !event
                .tags
                .iter()
                .any(|tag| tag.as_slice().first().is_some_and(|name| name == "uid")),
            "the public assertion must not expose the stable corporate uid"
        );
        assert!(
            !event
                .tags
                .iter()
                .any(|tag| tag.as_slice().first().is_some_and(|name| name == "issuer")),
            "the public assertion must not expose the upstream identity provider"
        );
    }

    #[test]
    fn identity_assertions_are_bounded_and_can_be_retired() {
        let relay = Keys::generate();
        let subject = Keys::generate().public_key();
        let now = 1_000;

        assert_eq!(
            identity_assertion_expiration(
                Some("Example User"),
                now + IDENTITY_ASSERTION_MAX_TTL_SECS + 1,
                now,
            ),
            now + IDENTITY_ASSERTION_MAX_TTL_SECS,
        );
        assert_eq!(
            identity_assertion_expiration(Some("Example User"), now + 60, now),
            now + 60,
        );
        assert_eq!(identity_assertion_expiration(None, u64::MAX, now), 0);

        let retired = build_identity_assertion(&relay, subject, None, 0, Timestamp::from(now))
            .expect("build inactive assertion");
        assert!(identity_assertion_matches(
            &retired,
            &subject.to_hex(),
            None,
            0,
        ));
        assert!(retired.tags.iter().any(|tag| {
            tag.as_slice().first().is_some_and(|part| part == "active")
                && tag.as_slice().get(1).is_some_and(|part| part == "false")
        }));
        assert!(!retired.tags.iter().any(|tag| {
            tag.as_slice()
                .first()
                .is_some_and(|part| part == "display_name")
        }));
    }

    #[test]
    fn direct_jwt_precedes_delegation_by_default() {
        let config = test_config();
        assert_eq!(
            select_identity_auth_path(&config, Some("jwt"), Some("auth-tag")),
            IdentityAuthPath::Direct
        );
    }

    #[test]
    fn deployment_can_select_delegated_owner_precedence() {
        let mut config = test_config();
        config.auth_precedence = CorporateIdentityAuthPrecedence::Delegated;
        assert_eq!(
            select_identity_auth_path(&config, Some("jwt"), Some("auth-tag")),
            IdentityAuthPath::Delegated
        );
        assert_eq!(
            select_identity_auth_path(&config, Some("jwt"), None),
            IdentityAuthPath::Direct
        );
    }

    #[test]
    fn rejects_hmac_jwt_algorithms_in_allowlist() {
        assert!(!is_allowed_jwt_algorithm(Algorithm::HS256));
        assert!(!is_allowed_jwt_algorithm(Algorithm::HS384));
        assert!(!is_allowed_jwt_algorithm(Algorithm::HS512));
        assert!(is_allowed_jwt_algorithm(Algorithm::RS256));
    }

    #[tokio::test]
    async fn validate_jwt_rejects_hs256_before_jwks_lookup() {
        let service = CorporateIdentityService::new(test_config());
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("hs256-kid".to_string());
        let token = encode(
            &header,
            &serde_json::json!({
                "iss": "https://idp.example",
                "aud": "buzz-relay",
                "sub": "user-1",
                "email": "user@example.com",
            }),
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("encode test jwt");

        let err = service
            .validate_jwt(&token)
            .await
            .expect_err("HS256 must be rejected");
        assert!(matches!(err, CorporateIdentityError::InvalidJwt(_)));
    }

    #[tokio::test]
    async fn validate_jwt_accepts_matching_rs256_jwk() {
        let key = rsa_private_key(include_str!("testdata/rsa_private_key_1.der.b64"));
        let token = rsa_test_jwt(&key, "rsa-key");
        let claims = validate_rsa_jwt(&token, rsa_test_jwk(&key, "rsa-key"))
            .await
            .expect("matching RSA JWT must validate");

        assert_eq!(claims.uid, "user-1");
        assert_eq!(claims.display_name, "user@example.com");
    }

    #[tokio::test]
    async fn validate_jwt_rejects_rs256_token_signed_by_wrong_key() {
        let signing_key = rsa_private_key(include_str!("testdata/rsa_private_key_1.der.b64"));
        let advertised_key = rsa_private_key(include_str!("testdata/rsa_private_key_2.der.b64"));
        let token = rsa_test_jwt(&signing_key, "rsa-key");

        let error = validate_rsa_jwt(&token, rsa_test_jwk(&advertised_key, "rsa-key"))
            .await
            .expect_err("JWT signed by another RSA key must fail");
        assert!(matches!(error, CorporateIdentityError::InvalidJwt(_)));
    }

    #[tokio::test]
    async fn validate_jwt_rejects_jwk_advertised_algorithm_mismatch() {
        let key = rsa_private_key(include_str!("testdata/rsa_private_key_1.der.b64"));
        let token = rsa_test_jwt(&key, "rsa-key");
        let mut jwk = rsa_test_jwk(&key, "rsa-key");
        jwk.common.key_algorithm = Some(KeyAlgorithm::RS512);

        let error = validate_rsa_jwt(&token, jwk)
            .await
            .expect_err("JWK alg must agree with JWT alg");
        assert!(matches!(
            error,
            CorporateIdentityError::InvalidJwt(ref message)
                if message.contains("does not match JWK algorithm")
        ));
    }

    #[tokio::test]
    async fn validate_jwt_accepts_jwk_with_omitted_algorithm() {
        let key = rsa_private_key(include_str!("testdata/rsa_private_key_1.der.b64"));
        let token = rsa_test_jwt(&key, "rsa-key");
        let mut jwk = rsa_test_jwk(&key, "rsa-key");
        jwk.common.key_algorithm = None;

        validate_rsa_jwt(&token, jwk)
            .await
            .expect("an omitted optional JWK alg must not prevent RSA verification");
    }

    #[test]
    fn validate_jwk_requires_signature_use_and_verify_operation_when_present() {
        let key = rsa_private_key(include_str!("testdata/rsa_private_key_1.der.b64"));
        let mut jwk = rsa_test_jwk(&key, "rsa-key");
        jwk.common.public_key_use = Some(PublicKeyUse::Encryption);
        assert!(matches!(
            validate_jwk_signature_metadata(&jwk, Algorithm::RS256),
            Err(CorporateIdentityError::InvalidJwt(ref message))
                if message.contains("use must be sig")
        ));

        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_operations = Some(vec![KeyOperations::Sign]);
        assert!(matches!(
            validate_jwk_signature_metadata(&jwk, Algorithm::RS256),
            Err(CorporateIdentityError::InvalidJwt(ref message))
                if message.contains("key_ops must include verify")
        ));

        jwk.common.key_operations = Some(vec![KeyOperations::Sign, KeyOperations::Verify]);
        validate_jwk_signature_metadata(&jwk, Algorithm::RS256)
            .expect("JWK key_ops containing verify must be accepted");
    }

    #[test]
    fn jwt_validation_rejects_missing_and_malformed_audience_claims() {
        let now = Timestamp::now().as_secs();
        let missing = serde_json::json!({
            "iss": "https://idp.example",
            "sub": "user-1",
            "email": "user@example.com",
            "exp": now + 3_600,
        });
        let malformed = serde_json::json!({
            "iss": "https://idp.example",
            "aud": 42,
            "sub": "user-1",
            "email": "user@example.com",
            "exp": now + 3_600,
        });

        for claims in [missing, malformed] {
            decode_test_jwt(claims, Algorithm::HS256, b"test-secret", b"test-secret")
                .expect_err("invalid audience must not enroll an identity binding");
        }
    }

    #[test]
    fn jwt_validation_requires_expiration_issuer_and_audience() {
        let now = Timestamp::now().as_secs();
        for claim in ["exp", "iss", "aud"] {
            let mut claims = valid_test_claims(now)
                .as_object()
                .expect("claims object")
                .clone();
            claims.remove(claim);
            assert!(
                decode_test_jwt(
                    Value::Object(claims),
                    Algorithm::HS256,
                    b"test-secret",
                    b"test-secret",
                )
                .is_err(),
                "missing {claim} must fail closed",
            );
        }
    }

    #[test]
    fn jwt_validation_pins_clock_skew_leeway() {
        let validation = jwt_validation(Algorithm::RS256, &test_config());
        assert_eq!(validation.leeway, JWT_CLOCK_SKEW_LEEWAY_SECS);
    }

    #[test]
    fn jwt_validation_rejects_malformed_registered_claim_types() {
        let now = Timestamp::now().as_secs();
        for (claim, value) in [
            ("iss", Value::from(42)),
            ("aud", Value::from(42)),
            ("exp", Value::String("tomorrow".to_string())),
            ("nbf", Value::String("tomorrow".to_string())),
        ] {
            let mut claims = valid_test_claims(now)
                .as_object()
                .expect("claims object")
                .clone();
            claims.insert(claim.to_string(), value);
            assert!(
                decode_test_jwt(
                    Value::Object(claims),
                    Algorithm::HS256,
                    b"test-secret",
                    b"test-secret",
                )
                .is_err(),
                "malformed {claim} must fail closed",
            );
        }
    }

    #[test]
    fn jwt_validation_rejects_future_and_malformed_not_before_claims() {
        let now = Timestamp::now().as_secs();
        let mut future = valid_test_claims(now)
            .as_object()
            .expect("claims object")
            .clone();
        future.insert("nbf".to_string(), Value::from(now + 3_600));

        let mut malformed = valid_test_claims(now)
            .as_object()
            .expect("claims object")
            .clone();
        malformed.insert("nbf".to_string(), Value::String("tomorrow".to_string()));

        for claims in [Value::Object(future), Value::Object(malformed)] {
            decode_test_jwt(claims, Algorithm::HS256, b"test-secret", b"test-secret")
                .expect_err("invalid nbf must fail closed");
        }
    }

    #[test]
    fn jwt_validation_rejects_wrong_issuer_audience_and_expiry() {
        let now = Timestamp::now().as_secs();
        for (claim, value) in [
            ("iss", Value::String("https://attacker.example".to_string())),
            ("aud", Value::String("some-other-service".to_string())),
            ("exp", Value::from(now.saturating_sub(3_600))),
        ] {
            let mut claims = valid_test_claims(now)
                .as_object()
                .expect("claims object")
                .clone();
            claims.insert(claim.to_string(), value);
            assert!(
                decode_test_jwt(
                    Value::Object(claims),
                    Algorithm::HS256,
                    b"test-secret",
                    b"test-secret",
                )
                .is_err(),
                "invalid {claim} must fail closed",
            );
        }
    }

    #[test]
    fn jwt_validation_rejects_algorithm_and_key_mismatch() {
        let claims = valid_test_claims(Timestamp::now().as_secs());

        decode_test_jwt(
            claims.clone(),
            Algorithm::HS384,
            b"test-secret",
            b"test-secret",
        )
        .expect_err("the token algorithm must match verifier policy");
        decode_test_jwt(
            claims,
            Algorithm::HS256,
            b"signing-secret",
            b"different-verification-secret",
        )
        .expect_err("a token signed by a different key must fail");
    }

    #[test]
    fn identity_header_requires_one_unambiguous_token() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-buzz-identity-token"),
            HeaderValue::from_static("Bearer token-a"),
        );

        assert_eq!(
            identity_jwt_from_headers(&headers, &config).as_deref(),
            Some("token-a")
        );

        headers.insert(
            HeaderName::from_static("x-buzz-identity-token"),
            HeaderValue::from_static("Bearer token-a, Bearer token-b"),
        );
        assert_eq!(identity_jwt_from_headers(&headers, &config), None);

        headers.insert(
            HeaderName::from_static("x-buzz-identity-token"),
            HeaderValue::from_static("Bearer token-a"),
        );
        headers.append(
            HeaderName::from_static("x-buzz-identity-token"),
            HeaderValue::from_static("Bearer token-b"),
        );
        assert_eq!(identity_jwt_from_headers(&headers, &config), None);
    }

    #[test]
    fn missing_required_claim_is_invalid() {
        let claims = Map::new();
        let err = claim_string(&claims, "sub").expect_err("missing claim");
        assert!(matches!(
            err,
            CorporateIdentityError::InvalidClaim { ref claim, .. } if claim == "sub"
        ));
    }

    #[test]
    fn configured_npub_claim_is_optional_but_malformed_value_is_invalid() {
        let mut claims = Map::new();
        assert_eq!(
            configured_pubkey_claim(&claims, Some("buzz_npub")).expect("optional claim"),
            None
        );

        claims.insert(
            "buzz_npub".to_string(),
            Value::String("not-an-npub".to_string()),
        );
        let err = configured_pubkey_claim(&claims, Some("buzz_npub"))
            .expect_err("present malformed claim must fail");
        assert!(matches!(
            err,
            CorporateIdentityError::InvalidClaim { ref claim, .. } if claim == "buzz_npub"
        ));
    }

    #[test]
    fn npub_claim_accepts_canonical_hex_and_npub() {
        let signer = Keys::generate().public_key();
        assert_eq!(
            parse_pubkey_claim("buzz_npub", &signer.to_hex()).expect("canonical hex"),
            signer
        );
        assert_eq!(
            parse_pubkey_claim("buzz_npub", &signer.to_bech32().expect("npub")).expect("npub"),
            signer
        );
    }

    #[tokio::test]
    async fn fresh_jwks_cache_miss_does_not_refetch() {
        let service = CorporateIdentityService::new(test_config());
        *service.jwks.write().await = Some(CachedJwks {
            set: JwkSet { keys: Vec::new() },
            expires_at: Instant::now() + Duration::from_secs(60),
        });

        let err = service
            .jwk_for_kid("attacker-controlled-kid")
            .await
            .expect_err("fresh cache miss should fail without network fetch");
        assert!(matches!(
            err,
            CorporateIdentityError::Jwks(ref msg) if msg.contains("kid not found")
        ));
    }

    #[tokio::test]
    async fn jwks_refresh_is_single_flight() {
        let body = r#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"test-kid","alg":"RS256","use":"sig"}]}"#;
        let response = http_response("200 OK", &["Content-Type: application/json"], body);
        let (uri, requests, server) = spawn_http_server(response).await;
        let mut config = test_config();
        config.jwks_uri = uri;
        let service = CorporateIdentityService::new(config);

        let (first, second, third, fourth) = tokio::join!(
            service.jwk_for_kid("test-kid"),
            service.jwk_for_kid("test-kid"),
            service.jwk_for_kid("test-kid"),
            service.jwk_for_kid("test-kid"),
        );
        for result in [first, second, third, fourth] {
            result.expect("all waiters should reuse the refreshed JWKS");
        }
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn jwks_response_content_length_is_capped_before_buffering() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            JWKS_MAX_RESPONSE_BYTES + 1,
        );
        let (uri, _requests, server) = spawn_http_server(response).await;
        let mut config = test_config();
        config.jwks_uri = uri;
        let service = CorporateIdentityService::new(config);

        let error = service
            .fetch_jwks()
            .await
            .expect_err("oversized JWKS must fail before buffering the body");
        assert!(matches!(
            error,
            CorporateIdentityError::Jwks(ref message) if message.contains("size limit")
        ));
        server.abort();
    }

    #[tokio::test]
    async fn jwks_streaming_response_is_capped_without_content_length() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{}",
            " ".repeat(JWKS_MAX_RESPONSE_BYTES + 1),
        );
        let (uri, _requests, server) = spawn_http_server(response).await;
        let mut config = test_config();
        config.jwks_uri = uri;
        let service = CorporateIdentityService::new(config);

        let error = service
            .fetch_jwks()
            .await
            .expect_err("streamed oversized JWKS must stop at the cap");
        assert!(matches!(
            error,
            CorporateIdentityError::Jwks(ref message) if message.contains("size limit")
        ));
        server.abort();
    }

    fn valid_test_claims(now: u64) -> Value {
        serde_json::json!({
            "iss": "https://idp.example",
            "aud": "buzz-relay",
            "sub": "user-1",
            "email": "user@example.com",
            "iat": now.saturating_sub(1),
            "exp": now + 3_600,
        })
    }

    #[tokio::test]
    async fn binding_evidence_seals_attested_actor_and_denies_mismatch() {
        let key = rsa_private_key(include_str!("testdata/rsa_private_key_1.der.b64"));
        let actor = Keys::generate().public_key();
        let now = Timestamp::now().as_secs();
        let mut claims = valid_test_claims(now)
            .as_object()
            .expect("claims object")
            .clone();
        let issued_at = now - 86_000;
        claims.insert("iat".to_string(), Value::from(issued_at));
        claims.insert("buzz_npub".to_string(), Value::String(actor.to_hex()));
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("rsa-key".to_string());
        let token = encode(
            &header,
            &Value::Object(claims),
            &EncodingKey::from_rsa_der(&key),
        )
        .expect("encode RSA test JWT");
        let service = CorporateIdentityService::new(test_config());
        *service.jwks.write().await = Some(CachedJwks {
            set: JwkSet {
                keys: vec![rsa_test_jwk(&key, "rsa-key")],
            },
            expires_at: Instant::now() + Duration::from_secs(60),
        });
        let community = CommunityId::from_uuid(uuid::Uuid::new_v4());

        let evidence = service
            .verify_binding_evidence(&token, community, actor, ProofTransport::Nip42)
            .await
            .expect("matching actor is sealed");
        assert_eq!(evidence.actor_pubkey(), actor);
        assert!(evidence.enrollment_permitted());
        assert_eq!(
            sealed_identity_expiry(&evidence).expect("sealed expiry"),
            issued_at + 86_400,
            "session/projection expiry must use iat+max_age before the longer raw exp",
        );
        assert!(evidence.accepts_authorization_coordinates(community, actor));
        assert!(!evidence.accepts_authorization_coordinates(
            CommunityId::from_uuid(uuid::Uuid::new_v4()),
            actor
        ));
        assert!(
            !evidence.accepts_authorization_coordinates(community, Keys::generate().public_key())
        );
        assert!(matches!(
            ensure_identity_evidence_matches_request(
                &evidence,
                CommunityId::from_uuid(uuid::Uuid::new_v4()),
                actor,
            ),
            Err(CorporateIdentityError::SealedCoordinateMismatch)
        ));

        let proof = CorporateIdentityProof(CorporateIdentityProofInner::Direct {
            evidence: Arc::new(evidence),
            public_display_name: Some("sensitive-display".to_string()),
            expires_at: issued_at + 86_400,
        });
        assert_eq!(
            format!("{proof:?}"),
            "CorporateIdentityProof::Direct([REDACTED])"
        );
        assert_eq!(
            binding_evidence_for_proof(&proof)
                .expect("sealed direct evidence")
                .actor_pubkey(),
            actor
        );

        let mismatch = service
            .verify_binding_evidence(
                &token,
                community,
                Keys::generate().public_key(),
                ProofTransport::Nip42,
            )
            .await
            .expect_err("mismatched actor must fail closed");
        assert!(matches!(mismatch, CorporateIdentityError::InvalidJwt(_)));
    }

    fn decode_test_jwt(
        claims: Value,
        signing_algorithm: Algorithm,
        signing_key: &[u8],
        verification_key: &[u8],
    ) -> Result<(), jsonwebtoken::errors::Error> {
        let token = encode(
            &Header::new(signing_algorithm),
            &claims,
            &EncodingKey::from_secret(signing_key),
        )?;
        decode::<RawJwtClaims>(
            &token,
            &DecodingKey::from_secret(verification_key),
            &jwt_validation(Algorithm::HS256, &test_config()),
        )?;
        Ok(())
    }

    fn rsa_private_key(encoded: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .expect("decode RSA test key")
    }

    fn rsa_test_jwk(private_key: &[u8], kid: &str) -> Jwk {
        let encoding_key = EncodingKey::from_rsa_der(private_key);
        let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256)
            .expect("derive RSA JWK from test key");
        jwk.common.key_id = Some(kid.to_string());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_operations = Some(vec![KeyOperations::Verify]);
        jwk
    }

    fn rsa_test_jwt(private_key: &[u8], kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &valid_test_claims(Timestamp::now().as_secs()),
            &EncodingKey::from_rsa_der(private_key),
        )
        .expect("encode RSA test JWT")
    }

    async fn canonical_test_state(
        database_url: &str,
        host: &str,
    ) -> (Arc<AppState>, PgPool, CommunityId) {
        let mut config = crate::config::Config::from_env().expect("load test configuration");
        config.database_url = database_url.to_owned();
        config.redis_url = "redis://127.0.0.1:1".to_owned();
        config.corporate_identity = test_config();
        let pool = PgPool::connect(database_url)
            .await
            .expect("connect test database");
        let db = buzz_db::Db::from_pool(pool.clone());
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(community_id.as_uuid())
            .bind(host)
            .execute(&pool)
            .await
            .expect("insert corporate identity test community");
        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("construct redis pool");
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .expect("construct pubsub manager"),
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage =
            buzz_media::MediaStorage::new(&config.media).expect("construct media storage");
        let (state, _audit_shutdown) = AppState::new(
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
        (Arc::new(state), pool, community_id)
    }

    #[tokio::test]
    #[ignore = "requires Postgres migrated through 0031"]
    async fn required_direct_identity_finalizes_and_rechecks_only_canonical_state() {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_owned());
        let host = format!("corporate-prefix-{}.example", Uuid::new_v4().simple());
        let (state, pool, community_id) = canonical_test_state(&database_url, &host).await;
        let actor = Keys::generate();
        let private_key = rsa_private_key(include_str!("testdata/rsa_private_key_1.der.b64"));
        let jwk = rsa_test_jwk(&private_key, "canonical-prefix-key");
        let now = Timestamp::now().as_secs();
        let mut claims = valid_test_claims(now)
            .as_object()
            .expect("claims object")
            .clone();
        claims.insert(
            "buzz_npub".to_owned(),
            Value::String(actor.public_key().to_hex()),
        );
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("canonical-prefix-key".to_owned());
        let token = encode(
            &header,
            &Value::Object(claims),
            &EncodingKey::from_rsa_der(&private_key),
        )
        .expect("sign canonical prefix JWT");
        let service = state
            .corporate_identity
            .as_ref()
            .expect("required corporate identity service");
        *service.jwks.write().await = Some(CachedJwks {
            set: JwkSet { keys: vec![jwk] },
            expires_at: Instant::now() + Duration::from_secs(60),
        });
        let evidence = service
            .verify_binding_evidence(
                &token,
                community_id,
                actor.public_key(),
                ProofTransport::Nip42,
            )
            .await
            .expect("derive installed policy digest from sealed verifier");
        state
            .db
            .install_attested_identity_enrollment_policy(
                community_id,
                1,
                evidence.enrollment_policy_digest(),
                chrono::Utc::now() - chrono::TimeDelta::minutes(1),
                Some(chrono::Utc::now() + chrono::TimeDelta::hours(1)),
                buzz_auth::AuthorizationEventCapacityPolicy::new(100, 1_048_576, 65_536)
                    .expect("bounded event capacity"),
            )
            .await
            .expect("install explicit verifier policy and capacity");

        let first_proof = verify_corporate_identity(
            &state,
            community_id,
            actor.public_key(),
            ProofTransport::Nip42,
            Some(&token),
            None,
        )
        .await
        .expect("verify required direct identity");
        let first =
            finalize_corporate_identity(&state, community_id, actor.public_key(), first_proof)
                .await
                .expect("finalize required direct identity");
        let binding = match first.0 {
            CorporateIdentityDecisionInner::Direct { binding, .. } => binding,
            CorporateIdentityDecisionInner::NotRequired => {
                panic!("required identity unexpectedly bypassed")
            }
        };
        assert!(state
            .db
            .revalidate_verified_identity_binding(&binding)
            .await
            .expect("active binding recheck"));

        let retry_proof = verify_corporate_identity(
            &state,
            community_id,
            actor.public_key(),
            ProofTransport::Nip42,
            Some(&token),
            None,
        )
        .await
        .expect("verify exact retry");
        finalize_corporate_identity(&state, community_id, actor.public_key(), retry_proof)
            .await
            .expect("finalize exact retry");

        for table in [
            "identity_bindings",
            "authorization_operation_receipts",
            "identity_lifecycle_history",
            "authorization_events",
        ] {
            let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT count(*) FROM {table} WHERE community_id=$1"
            )))
            .bind(community_id.as_uuid())
            .fetch_one(&pool)
            .await
            .expect("count canonical identity state");
            assert_eq!(count, 1, "{table} must remain exact-once after retry");
        }
        let legacy_tables_absent: bool = sqlx::query_scalar(
            "SELECT to_regclass('identity_principals') IS NULL \
             AND to_regclass('identity_revoked_keys') IS NULL",
        )
        .fetch_one(&pool)
        .await
        .expect("check removed legacy tables");
        assert!(legacy_tables_absent);
        let legacy_columns: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_schema=current_schema() AND table_name='identity_bindings' \
               AND column_name IN ('uid','pubkey','display_name','source','last_seen_at',\
                                   'revoked_at','revocation_scope','rotated_to_pubkey')",
        )
        .fetch_one(&pool)
        .await
        .expect("check removed legacy columns");
        assert_eq!(legacy_columns, 0);
    }

    async fn validate_rsa_jwt(
        token: &str,
        jwk: Jwk,
    ) -> Result<CorporateJwtClaims, CorporateIdentityError> {
        let body =
            serde_json::to_string(&JwkSet { keys: vec![jwk] }).expect("serialize RSA test JWKS");
        let response = http_response("200 OK", &["Content-Type: application/json"], &body);
        let (uri, _requests, server) = spawn_http_server(response).await;
        let mut config = test_config();
        config.jwks_uri = uri;
        config.npub_claim = None;
        let result = CorporateIdentityService::new(config)
            .validate_jwt(token)
            .await;
        server.abort();
        result
    }

    fn http_response(status: &str, headers: &[&str], body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            headers
                .iter()
                .map(|header| format!("{header}\r\n"))
                .collect::<String>(),
            body.len(),
        )
    }

    async fn spawn_http_server(
        response: String,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP server");
        let address = listener.local_addr().expect("test server address");
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                request_count.fetch_add(1, Ordering::SeqCst);
                let mut request = [0_u8; 2_048];
                let Ok(bytes_read) = stream.read(&mut request).await else {
                    return;
                };
                if bytes_read == 0 {
                    return;
                }
                if stream.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
            }
        });
        (format!("http://{address}/jwks"), requests, server)
    }

    #[test]
    fn delegation_fails_closed_without_canonical_relationship_authority() {
        let owner_keys = Keys::generate();
        let agent_keys = Keys::generate();
        let agent_pubkey = agent_keys.public_key();
        let auth_tag = buzz_sdk::nip_oa::compute_auth_tag(&owner_keys, &agent_pubkey, "").unwrap();
        let err = verify_delegated_corporate_identity(Some(&auth_tag))
            .expect_err("owner without binding should be denied");
        assert!(matches!(err, CorporateIdentityError::DelegationDenied));
    }

    #[test]
    fn missing_jwt_without_auth_tag_is_missing_jwt() {
        let err =
            verify_delegated_corporate_identity(None).expect_err("no JWT and no delegation tag");
        assert!(matches!(err, CorporateIdentityError::MissingJwt));
    }

    #[test]
    fn canonical_binding_denials_map_to_closed_relay_errors() {
        assert!(matches!(
            identity_binding_denial_error(VerifiedIdentityBindingDenial::ExistingBindingRequired),
            CorporateIdentityError::BindingRequired
        ));
        assert!(matches!(
            identity_binding_denial_error(VerifiedIdentityBindingDenial::PrincipalConflict),
            CorporateIdentityError::BindingConflict
        ));
        assert!(matches!(
            identity_binding_denial_error(VerifiedIdentityBindingDenial::EventAuthorConflict),
            CorporateIdentityError::BindingConflict
        ));
        assert!(matches!(
            identity_binding_denial_error(VerifiedIdentityBindingDenial::LifecycleDenied),
            CorporateIdentityError::BindingRevoked
        ));
        assert!(matches!(
            identity_binding_denial_error(VerifiedIdentityBindingDenial::PolicyUnavailable),
            CorporateIdentityError::PolicyUnavailable
        ));
    }
}
