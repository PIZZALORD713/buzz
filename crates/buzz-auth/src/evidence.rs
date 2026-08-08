//! Provider-free verification and sealing of protected-route evidence.
//!
//! This module is the only public route from raw JWT, NIP-42, NIP-98, or
//! delegated material to the origin-sealed values consumed by the local
//! binding resolver. It performs cryptographic and exact request binding; it
//! never decides local admission and contains no provider registry vocabulary.

use std::{fmt, future::Future, sync::Arc, time::Duration};

use base64::Engine as _;
use buzz_core::CommunityId;
use chrono::{DateTime, TimeDelta, Utc};
use hmac::{Hmac, KeyInit, Mac};
use http::{
    uri::{Authority, PathAndQuery, Scheme},
    HeaderMap, HeaderName, Method,
};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
    Algorithm, DecodingKey, Validation,
};
use nostr::{Alphabet, Event, FromBech32, Kind, PublicKey, SingleLetterTag, Tag, TagKind};
use serde::{
    de::{Error as _, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    foundation::{
        FederatedPrincipal, ProofTransport, RouteCapability, VerifiedDelegation,
        VerifiedFederatedAssertion, VerifiedNostrProof,
    },
    nip98_replay::{Nip98ReplayGuard, DEFAULT_REPLAY_TTL_SECS},
};

const PROOF_LIFETIME_SECONDS: i64 = 60;
const MIN_PROVENANCE_KEY_BYTES: usize = 32;
const MAX_IDENTITY_PART_BYTES: usize = 2048;
const MAX_CLAIM_NAME_BYTES: usize = 128;

type ProvenanceMac = Hmac<Sha256>;

/// One unambiguous HTTP header occurrence extracted from the complete header map.
///
/// The only constructor examines every occurrence of `name`. It rejects
/// duplicate header lines, comma-joined alternatives, non-UTF-8 values, and
/// leading or trailing whitespace. Callers therefore cannot mint this value
/// from one conveniently selected occurrence while hiding another.
pub struct ExactSingleHttpHeader(Box<str>);

impl ExactSingleHttpHeader {
    /// Extract exactly one unambiguous occurrence of `name` from `headers`.
    pub fn from_headers(headers: &HeaderMap, name: &HeaderName) -> Result<Self, EvidenceError> {
        let mut values = headers.get_all(name).iter();
        let value = values.next().ok_or(EvidenceError::AmbiguousAssertion)?;
        if values.next().is_some() {
            return Err(EvidenceError::AmbiguousAssertion);
        }
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.contains(&b',')
            || bytes.first().is_some_and(u8::is_ascii_whitespace)
            || bytes.last().is_some_and(u8::is_ascii_whitespace)
        {
            return Err(EvidenceError::AmbiguousAssertion);
        }
        let value = value
            .to_str()
            .map_err(|_| EvidenceError::AmbiguousAssertion)?;
        Ok(Self(value.into()))
    }

    /// Borrow the exact value after complete-map cardinality validation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ExactSingleHttpHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactSingleHttpHeader([REDACTED])")
    }
}

/// Exact absolute request target assembled only from server-resolved HTTP parts.
///
/// NIP-98 verification compares the signed `u` tag byte-for-byte with this
/// representation. In particular, `/protected` and `/protected/` remain
/// distinct targets.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalHttpRequestTarget(Box<str>);

impl CanonicalHttpRequestTarget {
    /// Assemble the one request-target representation used by routing and proof verification.
    pub fn from_server_parts(
        scheme: &Scheme,
        authority: &Authority,
        path_and_query: &PathAndQuery,
    ) -> Result<Self, EvidenceError> {
        if !matches!(scheme.as_str(), "http" | "https")
            || authority.as_str().is_empty()
            || !path_and_query.as_str().starts_with('/')
        {
            return Err(EvidenceError::InvalidBinding);
        }
        let uri = http::Uri::builder()
            .scheme(scheme.clone())
            .authority(authority.clone())
            .path_and_query(path_and_query.clone())
            .build()
            .map_err(|_| EvidenceError::InvalidBinding)?;
        Ok(Self(uri.to_string().into()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CanonicalHttpRequestTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalHttpRequestTarget([REDACTED])")
    }
}

/// Closed Git smart-HTTP operation admitted by a reusable repository session proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitSmartHttpOperation {
    /// Advertise refs and capabilities for clone/fetch.
    AdvertiseUploadPack,
    /// Advertise refs and capabilities for push.
    AdvertiseReceivePack,
    /// Stream clone/fetch negotiation and pack data.
    UploadPack,
    /// Stream push commands and pack data.
    ReceivePack,
}

impl GitSmartHttpOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::AdvertiseUploadPack => "advertise-upload-pack",
            Self::AdvertiseReceivePack => "advertise-receive-pack",
            Self::UploadPack => "upload-pack",
            Self::ReceivePack => "receive-pack",
        }
    }
}

/// Exact server-resolved Git smart-HTTP route admitted by one repository session proof.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalGitSmartHttpRequest {
    signed_repo_root: CanonicalHttpRequestTarget,
    operation: GitSmartHttpOperation,
    owner: Box<str>,
    repository: Box<str>,
    request_bytes: Box<[u8]>,
    target_bytes: Box<[u8]>,
    transport_context_bytes: Box<[u8]>,
}

impl CanonicalGitSmartHttpRequest {
    /// Validate one exact Git route and derive its stable repository target.
    #[allow(clippy::too_many_arguments)]
    pub fn from_server_parts(
        scheme: &Scheme,
        authority: &Authority,
        owner: &str,
        repo: &str,
        method: &Method,
        path_and_query: &PathAndQuery,
    ) -> Result<Self, EvidenceError> {
        if owner.len() != 64
            || !owner
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(EvidenceError::InvalidBinding);
        }
        let repo_name = repo.strip_suffix(".git").unwrap_or(repo);
        if repo_name.is_empty()
            || repo_name.len() > 64
            || repo_name.starts_with('.')
            || repo_name.contains("..")
            || !repo_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(EvidenceError::InvalidBinding);
        }

        let repo_root_path = format!("/git/{owner}/{repo}");
        let operation = match (method, path_and_query.as_str()) {
            (&Method::GET, value)
                if value == format!("{repo_root_path}/info/refs?service=git-upload-pack") =>
            {
                GitSmartHttpOperation::AdvertiseUploadPack
            }
            (&Method::GET, value)
                if value == format!("{repo_root_path}/info/refs?service=git-receive-pack") =>
            {
                GitSmartHttpOperation::AdvertiseReceivePack
            }
            (&Method::POST, value) if value == format!("{repo_root_path}/git-upload-pack") => {
                GitSmartHttpOperation::UploadPack
            }
            (&Method::POST, value) if value == format!("{repo_root_path}/git-receive-pack") => {
                GitSmartHttpOperation::ReceivePack
            }
            _ => return Err(EvidenceError::InvalidBinding),
        };
        let signed_repo_root = CanonicalHttpRequestTarget::from_server_parts(
            scheme,
            authority,
            &repo_root_path
                .parse()
                .map_err(|_| EvidenceError::InvalidBinding)?,
        )?;
        Ok(Self {
            signed_repo_root,
            operation,
            owner: owner.into(),
            repository: repo_name.into(),
            request_bytes: framed_coordinates(&[
                method.as_str().as_bytes(),
                operation.as_str().as_bytes(),
                path_and_query.as_str().as_bytes(),
            ])
            .into_boxed_slice(),
            target_bytes: framed_coordinates(&[
                b"repository",
                owner.as_bytes(),
                repo_name.as_bytes(),
            ])
            .into_boxed_slice(),
            transport_context_bytes: framed_coordinates(&[
                b"git-smart-http-session-v1",
                scheme.as_str().as_bytes(),
                authority.as_str().as_bytes(),
            ])
            .into_boxed_slice(),
        })
    }

    /// Construct the only evidence binding valid for this exact Git route.
    pub fn evidence_binding(
        &self,
        authorization_domain: CommunityId,
    ) -> Result<RequestEvidenceBinding, EvidenceError> {
        RequestEvidenceBinding::new(
            authorization_domain,
            ProofTransport::GitSmartHttpSession,
            &self.request_bytes,
            &self.target_bytes,
            &self.transport_context_bytes,
        )
    }

    /// Closed operation mapped from the actual HTTP method and path.
    pub const fn operation(&self) -> GitSmartHttpOperation {
        self.operation
    }

    /// Exact lowercase repository owner selected by routing.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Canonical repository name without the optional `.git` suffix.
    pub fn repository(&self) -> &str {
        &self.repository
    }
}

impl fmt::Debug for CanonicalGitSmartHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalGitSmartHttpRequest([REDACTED])")
    }
}

/// Closed Blossom request action bound by a protected media proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlossomAction {
    /// Upload one immutable object named by its SHA-256 digest.
    Upload,
    /// Read one immutable object.
    Get,
    /// Read metadata for one immutable object.
    Head,
}

impl BlossomAction {
    fn request_label(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Get => "get",
            Self::Head => "head",
        }
    }

    fn signed_verb(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Get | Self::Head => "get",
        }
    }
}

/// Exact server-resolved Blossom request and stable immutable-object target.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalBlossomRequest {
    action: BlossomAction,
    object_sha256: Box<str>,
    requested_path: Box<str>,
    server: Box<str>,
    request_bytes: Box<[u8]>,
    target_bytes: Box<[u8]>,
    transport_context_bytes: Box<[u8]>,
}

impl CanonicalBlossomRequest {
    /// Validate one exact Blossom upload/read route and object digest.
    pub fn from_server_parts(
        scheme: &Scheme,
        authority: &Authority,
        method: &Method,
        path_and_query: &PathAndQuery,
        object_sha256: &str,
    ) -> Result<Self, EvidenceError> {
        if object_sha256.len() != 64
            || !object_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EvidenceError::InvalidBinding);
        }
        let action = match (method, path_and_query.as_str()) {
            (&Method::PUT, "/upload" | "/media/upload") => BlossomAction::Upload,
            (&Method::GET, path) if media_path_names_hash(path, object_sha256) => {
                BlossomAction::Get
            }
            (&Method::HEAD, path) if media_path_names_hash(path, object_sha256) => {
                BlossomAction::Head
            }
            _ => return Err(EvidenceError::InvalidBinding),
        };
        let server = buzz_core::tenant::normalize_host(authority.as_str());
        if server.is_empty() {
            return Err(EvidenceError::InvalidBinding);
        }
        Ok(Self {
            action,
            object_sha256: object_sha256.into(),
            requested_path: path_and_query.as_str().into(),
            server: server.clone().into_boxed_str(),
            request_bytes: framed_coordinates(&[
                method.as_str().as_bytes(),
                action.request_label().as_bytes(),
                path_and_query.as_str().as_bytes(),
            ])
            .into_boxed_slice(),
            target_bytes: framed_coordinates(&[b"media", object_sha256.as_bytes()])
                .into_boxed_slice(),
            transport_context_bytes: framed_coordinates(&[
                b"blossom-v1",
                scheme.as_str().as_bytes(),
                server.as_bytes(),
            ])
            .into_boxed_slice(),
        })
    }

    /// Construct the only evidence binding valid for this exact Blossom route.
    pub fn evidence_binding(
        &self,
        authorization_domain: CommunityId,
    ) -> Result<RequestEvidenceBinding, EvidenceError> {
        RequestEvidenceBinding::new(
            authorization_domain,
            ProofTransport::Blossom,
            &self.request_bytes,
            &self.target_bytes,
            &self.transport_context_bytes,
        )
    }

    /// Exact protected media action.
    pub const fn action(&self) -> BlossomAction {
        self.action
    }

    /// Canonical immutable-object digest named by this route.
    pub fn object_sha256(&self) -> &str {
        &self.object_sha256
    }

    /// Exact path-and-query admitted by the server route parser.
    pub fn requested_path(&self) -> &str {
        &self.requested_path
    }
}

impl fmt::Debug for CanonicalBlossomRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalBlossomRequest([REDACTED])")
    }
}

/// Trusted time source shared by assertion and proof verification.
pub trait EvidenceClock: Send + Sync {
    /// Return the current verifier time.
    fn now(&self) -> DateTime<Utc>;
}

/// System-backed evidence clock.
#[derive(Debug, Default)]
pub struct SystemEvidenceClock;

impl EvidenceClock for SystemEvidenceClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Exact server-resolved request coordinates sealed into every evidence value.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestEvidenceBinding {
    authorization_domain: CommunityId,
    transport: ProofTransport,
    request_fingerprint: [u8; 32],
    target_fingerprint: [u8; 32],
    transport_context_fingerprint: [u8; 32],
}

impl RequestEvidenceBinding {
    /// Bind one transport and hash non-empty canonical request coordinates.
    pub fn new(
        authorization_domain: CommunityId,
        transport: ProofTransport,
        request: &[u8],
        target: &[u8],
        transport_context: &[u8],
    ) -> Result<Self, EvidenceError> {
        if authorization_domain.as_uuid().is_nil()
            || request.is_empty()
            || target.is_empty()
            || transport_context.is_empty()
        {
            return Err(EvidenceError::InvalidBinding);
        }
        Ok(Self {
            authorization_domain,
            transport,
            request_fingerprint: framed_fingerprint(b"buzz:nip-fi:request:v1", &[request]),
            target_fingerprint: framed_fingerprint(b"buzz:nip-fi:target:v1", &[target]),
            transport_context_fingerprint: framed_fingerprint(
                b"buzz:nip-fi:transport-context:v1",
                &[transport_context],
            ),
        })
    }

    /// Server-resolved authorization domain.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Whether an origin-sealed proof matches every server-resolved coordinate.
    pub fn accepts_proof(&self, proof: &VerifiedNostrProof) -> bool {
        self.authorization_domain == proof.authorization_domain()
            && self.transport == proof.transport()
            && &self.request_fingerprint == proof.request_fingerprint()
            && &self.target_fingerprint == proof.target_fingerprint()
            && &self.transport_context_fingerprint == proof.transport_context_fingerprint()
    }
}

impl fmt::Debug for RequestEvidenceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestEvidenceBinding([REDACTED])")
    }
}

/// Static, provider-free JWT verification policy.
#[derive(Clone)]
pub struct AssertionVerificationPolicy {
    issuer: String,
    audience: String,
    subject_claim: String,
    nostr_key_claim: Option<NostrKeyClaimPolicy>,
    maximum_token_age: Duration,
    clock_skew: Duration,
}

/// Closed parsing policy for one optional Nostr event-author claim.
#[derive(Clone)]
pub struct NostrKeyClaimPolicy {
    claim_name: String,
    encoding: NostrKeyClaimEncoding,
}

#[derive(Clone, Copy)]
enum NostrKeyClaimEncoding {
    LowerHex,
    CanonicalPublicKey,
}

impl NostrKeyClaimPolicy {
    /// Require a canonical lowercase 64-hex Nostr public key when present.
    pub fn lower_hex(claim_name: impl Into<String>) -> Result<Self, EvidenceError> {
        let claim_name = claim_name.into();
        if !is_safe_event_author_key_claim(&claim_name) {
            return Err(EvidenceError::InvalidConfiguration);
        }
        Ok(Self {
            claim_name,
            encoding: NostrKeyClaimEncoding::LowerHex,
        })
    }

    /// Accept either canonical lowercase hex or canonical NIP-19 `npub`.
    pub fn canonical_public_key(claim_name: impl Into<String>) -> Result<Self, EvidenceError> {
        let claim_name = claim_name.into();
        if !is_safe_event_author_key_claim(&claim_name) {
            return Err(EvidenceError::InvalidConfiguration);
        }
        Ok(Self {
            claim_name,
            encoding: NostrKeyClaimEncoding::CanonicalPublicKey,
        })
    }
}

impl fmt::Debug for NostrKeyClaimPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NostrKeyClaimPolicy([REDACTED])")
    }
}

impl AssertionVerificationPolicy {
    /// Validate exact issuer, audience, opaque subject claim, age, and skew.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        subject_claim: impl Into<String>,
        maximum_token_age: Duration,
        clock_skew: Duration,
    ) -> Result<Self, EvidenceError> {
        let issuer = issuer.into();
        let audience = audience.into();
        let subject_claim = subject_claim.into();
        if !is_exact_identity_part(&issuer)
            || !is_exact_identity_part(&audience)
            || !is_safe_subject_claim(&subject_claim)
            || maximum_token_age.is_zero()
            || maximum_token_age > Duration::from_secs(86_400)
            || clock_skew > Duration::from_secs(300)
        {
            return Err(EvidenceError::InvalidConfiguration);
        }
        Ok(Self {
            issuer,
            audience,
            subject_claim,
            nostr_key_claim: None,
            maximum_token_age,
            clock_skew,
        })
    }

    /// Configure one optional canonical Nostr event-author key claim policy.
    ///
    /// A configured claim is strictly parsed when present. Absence remains
    /// valid only for grandfathered existing-binding resolution. Canonical
    /// enrollment requires the sealed claim in
    /// [`VerifiedIdentityBindingEvidence`].
    pub fn with_nostr_key_claim(
        mut self,
        policy: NostrKeyClaimPolicy,
    ) -> Result<Self, EvidenceError> {
        if self.nostr_key_claim.is_some() || policy.claim_name == self.subject_claim {
            return Err(EvidenceError::InvalidConfiguration);
        }
        self.nostr_key_claim = Some(policy);
        Ok(self)
    }
}

impl fmt::Debug for AssertionVerificationPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AssertionVerificationPolicy([REDACTED])")
    }
}

/// Sealed assertion plus its exact token fingerprint for proof pairing.
pub struct VerifiedAssertionEvidence {
    assertion: VerifiedFederatedAssertion,
    assertion_fingerprint: [u8; 32],
    verification_policy_digest: [u8; 32],
    attested_event_author_pubkey: Option<PublicKey>,
    expires_at: DateTime<Utc>,
}

/// One verified federated assertion bound to the already-authenticated Nostr
/// actor used by the legacy corporate-identity transport compatibility path.
///
/// When the assertion carries an attested event-author claim, construction
/// requires an exact match and permits canonical enrollment. When that claim
/// is absent, the evidence is existing-binding-only and cannot create a new
/// generation.
pub struct VerifiedIdentityBindingEvidence {
    assertion: VerifiedFederatedAssertion,
    actor_pubkey: PublicKey,
    evidence_fingerprint: [u8; 32],
    verification_policy_digest: [u8; 32],
    enrollment_permitted: bool,
    expires_at: DateTime<Utc>,
}

impl VerifiedAssertionEvidence {
    /// Bind a cryptographically verified assertion to an authenticated actor.
    pub fn bind_authenticated_actor(
        self,
        actor_pubkey: PublicKey,
    ) -> Result<VerifiedIdentityBindingEvidence, EvidenceError> {
        let enrollment_permitted = match self.attested_event_author_pubkey {
            Some(attested) if attested == actor_pubkey => true,
            Some(_) => return Err(EvidenceError::InvalidAssertion),
            None => false,
        };
        Ok(VerifiedIdentityBindingEvidence {
            assertion: self.assertion,
            actor_pubkey,
            evidence_fingerprint: self.assertion_fingerprint,
            verification_policy_digest: self.verification_policy_digest,
            enrollment_permitted,
            expires_at: self.expires_at,
        })
    }

    /// Consume the wrapper after its paired Nostr proof has been constructed.
    pub fn into_assertion(self) -> VerifiedFederatedAssertion {
        self.assertion
    }
}

impl VerifiedIdentityBindingEvidence {
    /// Origin-sealed assertion.
    pub const fn assertion(&self) -> &VerifiedFederatedAssertion {
        &self.assertion
    }

    /// Nostr actor already authenticated by the calling transport.
    pub const fn actor_pubkey(&self) -> PublicKey {
        self.actor_pubkey
    }

    /// Whether caller-owned routing coordinates match this sealed evidence.
    pub fn accepts_authorization_coordinates(
        &self,
        authorization_domain: CommunityId,
        actor_pubkey: PublicKey,
    ) -> bool {
        self.assertion.authorization_domain() == authorization_domain
            && self.actor_pubkey == actor_pubkey
    }

    /// Stable digest of the exact verified assertion and its trusted ingress.
    pub const fn evidence_fingerprint(&self) -> [u8; 32] {
        self.evidence_fingerprint
    }

    /// Digest of the exact trusted verifier policy and JWKS snapshot.
    pub const fn enrollment_policy_digest(&self) -> [u8; 32] {
        self.verification_policy_digest
    }

    /// Whether the assertion itself attests this exact event-author key.
    pub const fn enrollment_permitted(&self) -> bool {
        self.enrollment_permitted
    }

    /// Exclusive verifier-owned assertion expiry.
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl fmt::Debug for VerifiedIdentityBindingEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedIdentityBindingEvidence([REDACTED])")
    }
}

impl fmt::Debug for VerifiedAssertionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedAssertionEvidence([REDACTED])")
    }
}

/// Asymmetric static-JWKS assertion verifier.
///
/// JWKS retrieval and refresh are composition concerns. This verifier accepts
/// one immutable snapshot and fails closed for absent, duplicate, or
/// algorithm-incompatible keys.
pub struct StaticJwksAssertionVerifier {
    policy: AssertionVerificationPolicy,
    jwks: JwkSet,
    verification_policy_digest: [u8; 32],
    clock: Arc<dyn EvidenceClock>,
}

impl StaticJwksAssertionVerifier {
    /// Construct a verifier from an immutable JWKS snapshot.
    pub fn new(policy: AssertionVerificationPolicy, jwks: JwkSet) -> Result<Self, EvidenceError> {
        Self::with_clock(policy, jwks, Arc::new(SystemEvidenceClock))
    }

    /// Construct with an injected trusted clock.
    pub fn with_clock(
        policy: AssertionVerificationPolicy,
        jwks: JwkSet,
        clock: Arc<dyn EvidenceClock>,
    ) -> Result<Self, EvidenceError> {
        if jwks.keys.is_empty() {
            return Err(EvidenceError::InvalidConfiguration);
        }
        let verification_policy_digest = verifier_policy_digest(&policy, &jwks)?;
        Ok(Self {
            policy,
            jwks,
            verification_policy_digest,
            clock,
        })
    }

    /// Digest an installer must bind to the corresponding enrollment policy.
    pub const fn enrollment_policy_digest(&self) -> [u8; 32] {
        self.verification_policy_digest
    }

    /// Verify a client-attached bearer assertion and seal its exact origin.
    pub fn verify_client_attached(
        &self,
        token: &ExactSingleHttpHeader,
        binding: &RequestEvidenceBinding,
    ) -> Result<VerifiedAssertionEvidence, EvidenceError> {
        self.verify_assertion(token.as_str(), binding, b"client-attached")
    }

    /// Bind this JWT verifier to an authenticated trusted-proxy boundary.
    pub fn trusted_proxy(
        self,
        assertion_header_name: impl Into<String>,
        provenance_header_name: impl Into<String>,
        provenance_key: impl AsRef<[u8]>,
    ) -> Result<TrustedProxyAssertionVerifier, EvidenceError> {
        TrustedProxyAssertionVerifier::new(
            self,
            assertion_header_name,
            provenance_header_name,
            provenance_key,
        )
    }

    fn verify_assertion(
        &self,
        token: &str,
        binding: &RequestEvidenceBinding,
        origin: &[u8],
    ) -> Result<VerifiedAssertionEvidence, EvidenceError> {
        validate_exact_token(token)?;
        validate_unique_jwt_header(token)?;
        let header = decode_header(token).map_err(|_| EvidenceError::InvalidAssertion)?;
        if !is_allowed_algorithm(header.alg) {
            return Err(EvidenceError::InvalidAssertion);
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or(EvidenceError::InvalidAssertion)?;
        let jwk = exact_jwk_for_kid(&self.jwks, kid)?;
        validate_jwk_signature_metadata(jwk, header.alg)?;
        let decoding_key =
            DecodingKey::from_jwk(jwk).map_err(|_| EvidenceError::InvalidAssertion)?;

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.set_required_spec_claims(&["iss", "aud"]);
        validation.set_issuer(&[self.policy.issuer.as_str()]);
        validation.set_audience(&[self.policy.audience.as_str()]);
        let decoded = decode::<UniqueClaims>(token, &decoding_key, &validation)
            .map_err(|_| EvidenceError::InvalidAssertion)?;

        let claims = decoded.claims.0;
        let issuer = exact_string_claim(&claims, "iss")?;
        if issuer != self.policy.issuer {
            return Err(EvidenceError::InvalidAssertion);
        }
        let audience = exact_string_claim(&claims, "aud")?;
        if audience != self.policy.audience {
            return Err(EvidenceError::InvalidAssertion);
        }
        let subject = exact_string_claim(&claims, &self.policy.subject_claim)?;
        let attested_event_author_pubkey = self
            .policy
            .nostr_key_claim
            .as_ref()
            .and_then(|policy| claims.get(&policy.claim_name))
            .map(|value| parse_event_author_claim(value, self.policy.nostr_key_claim.as_ref()))
            .transpose()?;
        let issued_at = numeric_date(&claims, "iat")?;
        let not_before = claims
            .get("nbf")
            .map(|_| numeric_date(&claims, "nbf"))
            .transpose()?
            .unwrap_or(issued_at);
        let token_expires_at = numeric_date(&claims, "exp")?;
        let now = self.clock.now();
        let skew = TimeDelta::from_std(self.policy.clock_skew)
            .map_err(|_| EvidenceError::InvalidConfiguration)?;
        let maximum_age = TimeDelta::from_std(self.policy.maximum_token_age)
            .map_err(|_| EvidenceError::InvalidConfiguration)?;
        if issued_at > now + skew || not_before > now + skew || token_expires_at <= now {
            return Err(EvidenceError::Expired);
        }
        let age_expires_at = issued_at
            .checked_add_signed(maximum_age)
            .ok_or(EvidenceError::InvalidAssertion)?;
        let expires_at = token_expires_at.min(age_expires_at);
        if expires_at <= now || not_before >= expires_at {
            return Err(EvidenceError::Expired);
        }

        let principal = FederatedPrincipal::from_verified_parts(issuer, subject)
            .ok_or(EvidenceError::InvalidAssertion)?;
        let assertion_fingerprint =
            framed_fingerprint(b"buzz:nip-fi:assertion:v1", &[origin, token.as_bytes()]);
        let assertion = VerifiedFederatedAssertion::from_verifier(
            binding.authorization_domain,
            principal,
            binding.transport,
            assertion_fingerprint,
            binding.target_fingerprint,
            binding.request_fingerprint,
            binding.transport_context_fingerprint,
            not_before,
            expires_at,
        )
        .ok_or(EvidenceError::InvalidAssertion)?;
        Ok(VerifiedAssertionEvidence {
            assertion,
            assertion_fingerprint,
            verification_policy_digest: self.verification_policy_digest,
            attested_event_author_pubkey,
            expires_at,
        })
    }
}

impl fmt::Debug for StaticJwksAssertionVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticJwksAssertionVerifier([REDACTED])")
    }
}

/// Trusted-proxy assertion verifier requiring an exact authenticated ingress MAC.
pub struct TrustedProxyAssertionVerifier {
    verifier: StaticJwksAssertionVerifier,
    assertion_header_name: HeaderName,
    provenance_header_name: HeaderName,
    provenance_key: Vec<u8>,
}

impl TrustedProxyAssertionVerifier {
    fn new(
        verifier: StaticJwksAssertionVerifier,
        assertion_header_name: impl Into<String>,
        provenance_header_name: impl Into<String>,
        provenance_key: impl AsRef<[u8]>,
    ) -> Result<Self, EvidenceError> {
        let assertion_header_name = assertion_header_name.into();
        let provenance_header_name = provenance_header_name.into();
        let provenance_key = provenance_key.as_ref();
        let assertion_header_name = HeaderName::try_from(assertion_header_name)
            .map_err(|_| EvidenceError::InvalidConfiguration)?;
        let provenance_header_name = HeaderName::try_from(provenance_header_name)
            .map_err(|_| EvidenceError::InvalidConfiguration)?;
        if assertion_header_name == provenance_header_name
            || provenance_key.len() < MIN_PROVENANCE_KEY_BYTES
        {
            return Err(EvidenceError::InvalidConfiguration);
        }
        Ok(Self {
            verifier,
            assertion_header_name,
            provenance_header_name,
            provenance_key: provenance_key.to_vec(),
        })
    }

    /// Extract and verify the exact proxy assertion and lowercase hexadecimal MAC.
    pub fn verify(
        &self,
        headers: &HeaderMap,
        binding: &RequestEvidenceBinding,
    ) -> Result<VerifiedAssertionEvidence, EvidenceError> {
        let token = ExactSingleHttpHeader::from_headers(headers, &self.assertion_header_name)?;
        let provenance_proof =
            ExactSingleHttpHeader::from_headers(headers, &self.provenance_header_name)?;
        let token = token.as_str();
        let provenance_proof = provenance_proof.as_str();
        validate_exact_token(token)?;
        if provenance_proof.len() != 64
            || !provenance_proof
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EvidenceError::UntrustedOrigin);
        }
        let proof = hex::decode(provenance_proof).map_err(|_| EvidenceError::UntrustedOrigin)?;
        let mac = provenance_mac(
            &self.provenance_key,
            self.assertion_header_name.as_str().as_bytes(),
            token.as_bytes(),
            binding,
        )?;
        mac.verify_slice(&proof)
            .map_err(|_| EvidenceError::UntrustedOrigin)?;
        self.verifier
            .verify_assertion(token, binding, b"trusted-proxy")
    }
}

impl fmt::Debug for TrustedProxyAssertionVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedProxyAssertionVerifier([REDACTED])")
    }
}

/// Direct assertion and Nostr proof sealed as one non-substitutable pair.
pub struct VerifiedDirectEvidence {
    assertion: VerifiedFederatedAssertion,
    proof: VerifiedNostrProof,
}

impl VerifiedDirectEvidence {
    /// Consume the pair for direct binding resolution.
    pub fn into_parts(self) -> (VerifiedFederatedAssertion, VerifiedNostrProof) {
        (self.assertion, self.proof)
    }
}

impl fmt::Debug for VerifiedDirectEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedDirectEvidence([REDACTED])")
    }
}

/// Verify a NIP-42 proof and pair it with one exact assertion.
pub fn verify_nip42_direct(
    event: &Event,
    expected_challenge: &str,
    relay_url: &str,
    binding: &RequestEvidenceBinding,
    assertion: VerifiedAssertionEvidence,
    clock: &dyn EvidenceClock,
) -> Result<VerifiedDirectEvidence, EvidenceError> {
    let proof = verify_nip42(
        event,
        expected_challenge,
        relay_url,
        binding,
        Some(assertion.assertion_fingerprint),
        None,
        clock.now(),
    )?;
    Ok(VerifiedDirectEvidence {
        assertion: assertion.assertion,
        proof,
    })
}

/// Verify a protected NIP-98 proof, claim its replay marker, and pair it with an assertion.
#[allow(clippy::too_many_arguments)]
pub async fn verify_nip98_direct(
    event_json: &str,
    expected_target: &CanonicalHttpRequestTarget,
    expected_method: &str,
    body: Option<&[u8]>,
    require_payload: bool,
    binding: &RequestEvidenceBinding,
    assertion: VerifiedAssertionEvidence,
    replay: &dyn Nip98ReplayGuard,
    clock: &dyn EvidenceClock,
) -> Result<VerifiedDirectEvidence, EvidenceError> {
    let event = verify_nip98(
        event_json,
        expected_target,
        expected_method,
        body,
        require_payload,
        clock.now(),
    )?;
    let scope = binding.authorization_domain.to_string();
    match replay
        .try_mark_in_scope(&scope, &event.id, DEFAULT_REPLAY_TTL_SECS)
        .await
    {
        Ok(true) => {}
        Ok(false) => return Err(EvidenceError::Replay),
        Err(_) => return Err(EvidenceError::DependencyUnavailable),
    }
    let proof = seal_nostr_proof(
        &event,
        ProofTransport::Nip98,
        binding,
        Some(assertion.assertion_fingerprint),
        None,
    )?;
    Ok(VerifiedDirectEvidence {
        assertion: assertion.assertion,
        proof,
    })
}

/// Verify one bounded reusable Git smart-HTTP session credential and pair it
/// with the exact direct assertion for the current closed Git operation.
pub fn verify_git_smart_http_direct(
    authorization: &VerifiedGitSmartHttpAuthorization,
    binding: &RequestEvidenceBinding,
    assertion: VerifiedAssertionEvidence,
) -> Result<VerifiedDirectEvidence, EvidenceError> {
    if authorization
        .request
        .evidence_binding(binding.authorization_domain())?
        != *binding
    {
        return Err(EvidenceError::InvalidBinding);
    }
    let proof = seal_nostr_proof_until(
        &authorization.event,
        ProofTransport::GitSmartHttpSession,
        binding,
        Some(assertion.assertion_fingerprint),
        None,
        authorization.expires_at,
    )?;
    Ok(VerifiedDirectEvidence {
        assertion: assertion.assertion,
        proof,
    })
}

/// Origin-verify one bounded reusable Git smart-HTTP session credential.
///
/// The signed method is deliberately and exactly `GET`: Git's credential
/// helper signs the repository-root credential once and reuses it across the
/// closed GET/POST operation set admitted by [`CanonicalGitSmartHttpRequest`].
pub fn verify_git_smart_http_authorization(
    event_json: &str,
    request: &CanonicalGitSmartHttpRequest,
    clock: &dyn EvidenceClock,
) -> Result<VerifiedGitSmartHttpAuthorization, EvidenceError> {
    let event: Event = serde_json::from_str(event_json).map_err(|_| EvidenceError::InvalidProof)?;
    if event.kind != Kind::HttpAuth {
        return Err(EvidenceError::InvalidProof);
    }
    buzz_core::verify_event(&event).map_err(|_| EvidenceError::InvalidProof)?;
    let now = clock.now();
    validate_proof_time(&event, now)?;
    if proof_expires_at(&event)? <= now {
        return Err(EvidenceError::Expired);
    }
    let url = exact_tag_content(
        &event,
        |tag| tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::U)),
        true,
    )?
    .ok_or(EvidenceError::InvalidProof)?;
    if url.as_bytes() != request.signed_repo_root.as_str().as_bytes() {
        return Err(EvidenceError::InvalidProof);
    }
    let method = exact_tag_content(&event, |tag| tag.kind() == TagKind::Method, true)?
        .ok_or(EvidenceError::InvalidProof)?;
    if method != Method::GET.as_str()
        || exact_tag_content(&event, |tag| tag.kind() == TagKind::Payload, false)?.is_some()
    {
        return Err(EvidenceError::InvalidProof);
    }
    let expires_at = proof_expires_at(&event)?;
    Ok(VerifiedGitSmartHttpAuthorization {
        event,
        request: request.clone(),
        expires_at,
    })
}

/// Origin-verified Git session credential bound to one canonical operation.
pub struct VerifiedGitSmartHttpAuthorization {
    event: Event,
    request: CanonicalGitSmartHttpRequest,
    expires_at: DateTime<Utc>,
}

impl VerifiedGitSmartHttpAuthorization {
    /// Exact event author admitted by the signature verifier.
    pub fn actor_pubkey(&self) -> PublicKey {
        self.event.pubkey
    }

    /// Closed actual Git smart-HTTP operation.
    pub const fn operation(&self) -> GitSmartHttpOperation {
        self.request.operation()
    }

    /// Borrow the immutable server-derived route joined to this proof.
    pub fn request(&self) -> &CanonicalGitSmartHttpRequest {
        &self.request
    }

    /// Construct the only evidence binding valid for this origin-sealed route.
    pub fn evidence_binding(
        &self,
        authorization_domain: CommunityId,
    ) -> Result<RequestEvidenceBinding, EvidenceError> {
        self.request.evidence_binding(authorization_domain)
    }
}

impl fmt::Debug for VerifiedGitSmartHttpAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedGitSmartHttpAuthorization([REDACTED])")
    }
}

/// Git smart-HTTP delegated evidence is unavailable until a reviewed positive
/// relationship authority source is installed.
pub fn verify_git_smart_http_delegated() -> Result<VerifiedDelegatedEvidence, EvidenceError> {
    Err(EvidenceError::DelegatedAuthorityUnavailable)
}

/// Verify one exact Blossom upload/read credential and pair it with the exact
/// direct assertion for the same media route.
pub fn verify_blossom_direct(
    authorization: &VerifiedBlossomAuthorization,
    binding: &RequestEvidenceBinding,
    assertion: VerifiedAssertionEvidence,
) -> Result<VerifiedDirectEvidence, EvidenceError> {
    if authorization
        .request
        .evidence_binding(binding.authorization_domain())?
        != *binding
    {
        return Err(EvidenceError::InvalidBinding);
    }
    let proof = seal_nostr_proof_until(
        &authorization.event,
        ProofTransport::Blossom,
        binding,
        Some(assertion.assertion_fingerprint),
        None,
        authorization.expires_at,
    )?;
    Ok(VerifiedDirectEvidence {
        assertion: assertion.assertion,
        proof,
    })
}

/// Origin-verified Blossom event bound to one canonical request target.
pub struct VerifiedBlossomAuthorization {
    event: Event,
    request: CanonicalBlossomRequest,
    expires_at: DateTime<Utc>,
}

impl VerifiedBlossomAuthorization {
    /// Exact signer proven by the event signature.
    pub const fn actor_pubkey(&self) -> PublicKey {
        self.event.pubkey
    }

    /// Exact protected media action.
    pub const fn action(&self) -> BlossomAction {
        self.request.action
    }

    /// Borrow the immutable server-derived route joined to this proof.
    pub fn request(&self) -> &CanonicalBlossomRequest {
        &self.request
    }

    /// Canonical immutable-object digest named by this authorization.
    pub fn object_sha256(&self) -> &str {
        self.request.object_sha256()
    }

    /// Construct the only evidence binding this authorization may seal.
    pub fn evidence_binding(
        &self,
        authorization_domain: CommunityId,
    ) -> Result<RequestEvidenceBinding, EvidenceError> {
        self.request.evidence_binding(authorization_domain)
    }
}

impl fmt::Debug for VerifiedBlossomAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedBlossomAuthorization([REDACTED])")
    }
}

/// Canonically verify one Blossom event before local authorization finalization.
pub fn verify_blossom_authorization(
    event: &Event,
    request: &CanonicalBlossomRequest,
    clock: &dyn EvidenceClock,
) -> Result<VerifiedBlossomAuthorization, EvidenceError> {
    if event.kind.as_u16() != 24_242 || event.content.trim().is_empty() {
        return Err(EvidenceError::InvalidProof);
    }
    buzz_core::verify_event(event).map_err(|_| EvidenceError::InvalidProof)?;
    let now = clock.now();
    validate_proof_time(event, now)?;

    let verb = exact_custom_tag_content(event, "t", true)?.ok_or(EvidenceError::InvalidProof)?;
    if verb != request.action.signed_verb() {
        return Err(EvidenceError::InvalidProof);
    }
    let expiration = exact_custom_tag_content(event, "expiration", true)?
        .ok_or(EvidenceError::InvalidProof)?
        .parse::<i64>()
        .ok()
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        .ok_or(EvidenceError::InvalidProof)?;
    if expiration <= now {
        return Err(EvidenceError::Expired);
    }

    let object_scope = exact_custom_tag_content(event, "x", false)?;
    let server_scope = exact_custom_tag_content(event, "server", false)?;
    match request.action {
        BlossomAction::Upload => {
            if object_scope != Some(request.object_sha256())
                || server_scope.is_some_and(|server| {
                    normalize_blossom_server(server) != request.server.as_ref()
                })
            {
                return Err(EvidenceError::InvalidProof);
            }
        }
        BlossomAction::Get | BlossomAction::Head => match (object_scope, server_scope) {
            (Some(object), None) if object == request.object_sha256() => {}
            (None, Some(server)) if normalize_blossom_server(server) == request.server.as_ref() => {
            }
            _ => return Err(EvidenceError::InvalidProof),
        },
    }

    let proof_expiry = proof_expires_at(event)?.min(expiration);
    if proof_expiry <= now {
        return Err(EvidenceError::Expired);
    }
    Ok(VerifiedBlossomAuthorization {
        event: event.clone(),
        request: request.clone(),
        expires_at: proof_expiry,
    })
}

/// Blossom delegated evidence is unavailable until a reviewed positive
/// relationship authority source is installed.
pub fn verify_blossom_delegated() -> Result<VerifiedDelegatedEvidence, EvidenceError> {
    Err(EvidenceError::DelegatedAuthorityUnavailable)
}

/// Authoritative local relationship state joined to a verified NIP-OA signature.
#[derive(Clone)]
pub struct AuthoritativeDelegationGrant {
    relationship_id: Uuid,
    relationship_revision: u64,
    capabilities: Vec<RouteCapability>,
    expires_at: DateTime<Utc>,
}

impl AuthoritativeDelegationGrant {
    /// Construct a grant returned by the configured canonical local relationship store.
    pub fn from_local_store(
        relationship_id: Uuid,
        relationship_revision: u64,
        mut capabilities: Vec<RouteCapability>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, EvidenceError> {
        capabilities.sort_unstable();
        capabilities.dedup();
        if relationship_id.is_nil() || relationship_revision == 0 || capabilities.is_empty() {
            return Err(EvidenceError::InvalidDelegation);
        }
        Ok(Self {
            relationship_id,
            relationship_revision,
            capabilities,
            expires_at,
        })
    }
}

impl fmt::Debug for AuthoritativeDelegationGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthoritativeDelegationGrant([REDACTED])")
    }
}

/// Narrow canonical relationship-store boundary used after signature verification.
pub trait DelegationGrantSource: Send + Sync {
    /// Fail-closed storage error.
    type Error: Send;

    /// Resolve current revision, capabilities, and exclusive expiry.
    fn current_grant<'a>(
        &'a self,
        authorization_domain: CommunityId,
        owner_pubkey: PublicKey,
        delegate_pubkey: PublicKey,
        conditions_fingerprint: [u8; 32],
    ) -> impl Future<Output = Result<Option<AuthoritativeDelegationGrant>, Self::Error>> + Send + 'a;
}

/// Delegation and Nostr proof sealed as one assertion-free pair.
pub struct VerifiedDelegatedEvidence {
    delegation: VerifiedDelegation,
    proof: VerifiedNostrProof,
}

impl VerifiedDelegatedEvidence {
    /// Consume the pair for delegated owner-bound resolution.
    pub fn into_parts(self) -> (VerifiedDelegation, VerifiedNostrProof) {
        (self.delegation, self.proof)
    }
}

impl fmt::Debug for VerifiedDelegatedEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedDelegatedEvidence([REDACTED])")
    }
}

/// Verify an assertion-free NIP-42 delegation against current local relationship state.
pub async fn verify_nip42_delegated<S: DelegationGrantSource>(
    event: &Event,
    expected_challenge: &str,
    relay_url: &str,
    auth_tag_json: &str,
    binding: &RequestEvidenceBinding,
    grants: &S,
    clock: &dyn EvidenceClock,
) -> Result<VerifiedDelegatedEvidence, EvidenceError> {
    let now = clock.now();
    let (owner, conditions, conditions_fingerprint, grant) =
        resolve_delegation(event.pubkey, auth_tag_json, binding, grants, now).await?;
    let proof = verify_nip42(
        event,
        expected_challenge,
        relay_url,
        binding,
        None,
        Some(conditions_fingerprint),
        now,
    )?;
    let delegation = seal_delegation(
        binding,
        owner,
        event.pubkey,
        &conditions,
        conditions_fingerprint,
        grant,
    )?;
    Ok(VerifiedDelegatedEvidence { delegation, proof })
}

async fn resolve_delegation<S: DelegationGrantSource>(
    delegate: PublicKey,
    auth_tag_json: &str,
    binding: &RequestEvidenceBinding,
    grants: &S,
    now: DateTime<Utc>,
) -> Result<(PublicKey, String, [u8; 32], AuthoritativeDelegationGrant), EvidenceError> {
    let owner = buzz_sdk::nip_oa::verify_auth_tag(auth_tag_json, &delegate)
        .map_err(|_| EvidenceError::InvalidDelegation)?;
    let tag: Vec<Value> =
        serde_json::from_str(auth_tag_json).map_err(|_| EvidenceError::InvalidDelegation)?;
    let conditions = tag
        .get(2)
        .and_then(Value::as_str)
        .ok_or(EvidenceError::InvalidDelegation)?
        .to_owned();
    let conditions_fingerprint = framed_fingerprint(
        b"buzz:nip-fi:delegation-conditions:v1",
        &[conditions.as_bytes()],
    );
    let grant = grants
        .current_grant(
            binding.authorization_domain,
            owner,
            delegate,
            conditions_fingerprint,
        )
        .await
        .map_err(|_| EvidenceError::DependencyUnavailable)?
        .ok_or(EvidenceError::InvalidDelegation)?;
    if grant.expires_at <= now {
        return Err(EvidenceError::Expired);
    }
    Ok((owner, conditions, conditions_fingerprint, grant))
}

fn seal_delegation(
    binding: &RequestEvidenceBinding,
    owner: PublicKey,
    delegate: PublicKey,
    _conditions: &str,
    conditions_fingerprint: [u8; 32],
    grant: AuthoritativeDelegationGrant,
) -> Result<VerifiedDelegation, EvidenceError> {
    VerifiedDelegation::from_verifier(
        binding.authorization_domain,
        owner,
        delegate,
        binding.transport,
        grant.relationship_id,
        grant.relationship_revision,
        grant.capabilities,
        conditions_fingerprint,
        binding.target_fingerprint,
        binding.request_fingerprint,
        binding.transport_context_fingerprint,
        grant.expires_at,
    )
    .ok_or(EvidenceError::InvalidDelegation)
}

fn verify_nip42(
    event: &Event,
    expected_challenge: &str,
    relay_url: &str,
    binding: &RequestEvidenceBinding,
    bound_assertion_fingerprint: Option<[u8; 32]>,
    delegation_conditions_fingerprint: Option<[u8; 32]>,
    now: DateTime<Utc>,
) -> Result<VerifiedNostrProof, EvidenceError> {
    validate_proof_time(event, now)?;
    crate::verify_nip42_authorization_proof(
        event,
        expected_challenge,
        relay_url,
        binding.authorization_domain,
        binding.request_fingerprint,
        binding.target_fingerprint,
        binding.transport_context_fingerprint,
        bound_assertion_fingerprint,
        delegation_conditions_fingerprint,
        proof_expires_at(event)?,
    )
    .map_err(|_| EvidenceError::InvalidProof)
}

fn verify_nip98(
    event_json: &str,
    expected_target: &CanonicalHttpRequestTarget,
    expected_method: &str,
    body: Option<&[u8]>,
    require_payload: bool,
    now: DateTime<Utc>,
) -> Result<Event, EvidenceError> {
    let event: Event = serde_json::from_str(event_json).map_err(|_| EvidenceError::InvalidProof)?;
    if event.kind != Kind::HttpAuth {
        return Err(EvidenceError::InvalidProof);
    }
    buzz_core::verify_event(&event).map_err(|_| EvidenceError::InvalidProof)?;
    validate_proof_time(&event, now)?;
    let url = exact_tag_content(
        &event,
        |tag| tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::U)),
        true,
    )?
    .ok_or(EvidenceError::InvalidProof)?;
    if url.as_bytes() != expected_target.as_str().as_bytes() {
        return Err(EvidenceError::InvalidProof);
    }
    let method = exact_tag_content(&event, |tag| tag.kind() == TagKind::Method, true)?
        .ok_or(EvidenceError::InvalidProof)?;
    if method != expected_method {
        return Err(EvidenceError::InvalidProof);
    }
    let payload = exact_tag_content(
        &event,
        |tag| tag.kind() == TagKind::Payload,
        require_payload,
    )?;
    if require_payload && (payload.is_none() || body.is_none()) {
        return Err(EvidenceError::InvalidProof);
    }
    if let Some(payload) = payload {
        let body = body.ok_or(EvidenceError::InvalidProof)?;
        let digest: [u8; 32] = Sha256::digest(body).into();
        if payload != hex::encode(digest) {
            return Err(EvidenceError::InvalidProof);
        }
    }
    Ok(event)
}

fn exact_tag_content(
    event: &Event,
    matches: impl Fn(&Tag) -> bool,
    required: bool,
) -> Result<Option<&str>, EvidenceError> {
    let mut matching = event.tags.iter().filter(|tag| matches(tag));
    let first = matching.next();
    if matching.next().is_some() {
        return Err(EvidenceError::InvalidProof);
    }
    match first {
        Some(tag) => tag.content().map(Some).ok_or(EvidenceError::InvalidProof),
        None if required => Err(EvidenceError::InvalidProof),
        None => Ok(None),
    }
}

fn exact_custom_tag_content<'a>(
    event: &'a Event,
    name: &str,
    required: bool,
) -> Result<Option<&'a str>, EvidenceError> {
    exact_tag_content(event, |tag| tag.kind().to_string() == name, required)
}

fn validate_proof_time(event: &Event, now: DateTime<Utc>) -> Result<(), EvidenceError> {
    let event_time = DateTime::from_timestamp(event.created_at.as_secs() as i64, 0)
        .ok_or(EvidenceError::InvalidProof)?;
    let delta = now
        .signed_duration_since(event_time)
        .num_seconds()
        .unsigned_abs();
    if delta > PROOF_LIFETIME_SECONDS as u64 {
        return Err(EvidenceError::Expired);
    }
    Ok(())
}

fn proof_expires_at(event: &Event) -> Result<DateTime<Utc>, EvidenceError> {
    DateTime::from_timestamp(event.created_at.as_secs() as i64, 0)
        .and_then(|event_time| {
            event_time.checked_add_signed(TimeDelta::seconds(PROOF_LIFETIME_SECONDS))
        })
        .ok_or(EvidenceError::InvalidProof)
}

fn seal_nostr_proof(
    event: &Event,
    transport: ProofTransport,
    binding: &RequestEvidenceBinding,
    bound_assertion_fingerprint: Option<[u8; 32]>,
    delegation_conditions_fingerprint: Option<[u8; 32]>,
) -> Result<VerifiedNostrProof, EvidenceError> {
    seal_nostr_proof_until(
        event,
        transport,
        binding,
        bound_assertion_fingerprint,
        delegation_conditions_fingerprint,
        proof_expires_at(event)?,
    )
}

fn seal_nostr_proof_until(
    event: &Event,
    transport: ProofTransport,
    binding: &RequestEvidenceBinding,
    bound_assertion_fingerprint: Option<[u8; 32]>,
    delegation_conditions_fingerprint: Option<[u8; 32]>,
    expires_at: DateTime<Utc>,
) -> Result<VerifiedNostrProof, EvidenceError> {
    if bound_assertion_fingerprint.is_some() == delegation_conditions_fingerprint.is_some() {
        return Err(EvidenceError::InvalidProof);
    }
    let event_time = DateTime::from_timestamp(event.created_at.as_secs() as i64, 0)
        .ok_or(EvidenceError::InvalidProof)?;
    let hard_expiry = event_time
        .checked_add_signed(TimeDelta::seconds(PROOF_LIFETIME_SECONDS))
        .ok_or(EvidenceError::InvalidProof)?;
    if expires_at <= event_time || expires_at > hard_expiry {
        return Err(EvidenceError::InvalidProof);
    }
    let proof = VerifiedNostrProof::from_verifier(
        binding.authorization_domain,
        event.pubkey,
        transport,
        binding.request_fingerprint,
        binding.target_fingerprint,
        binding.transport_context_fingerprint,
        bound_assertion_fingerprint,
        delegation_conditions_fingerprint,
        expires_at,
    )
    .ok_or(EvidenceError::InvalidProof)?;
    if !binding.accepts_proof(&proof) {
        return Err(EvidenceError::InvalidProof);
    }
    Ok(proof)
}

fn framed_coordinates(parts: &[&[u8]]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for part in parts {
        encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
        encoded.extend_from_slice(part);
    }
    encoded
}

fn media_path_names_hash(path_and_query: &str, object_sha256: &str) -> bool {
    let Some(path) = path_and_query.strip_prefix("/media/") else {
        return false;
    };
    if path.contains('/') || path.contains('?') || path.contains('#') {
        return false;
    }
    let mut segments = path.split('.');
    if segments.next() != Some(object_sha256) {
        return false;
    }
    let suffixes: Vec<_> = segments.collect();
    match suffixes.as_slice() {
        [] => true,
        [extension] => is_safe_media_extension(extension),
        ["thumb", "jpg"] => true,
        _ => false,
    }
}

fn is_safe_media_extension(extension: &str) -> bool {
    !extension.is_empty()
        && extension.len() <= 8
        && extension
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn normalize_blossom_server(value: &str) -> String {
    let authority = match value.split_once("://") {
        Some((_scheme, rest)) => rest.split('/').next().unwrap_or(rest),
        None => value.split('/').next().unwrap_or(value),
    };
    buzz_core::tenant::normalize_host(authority)
}

fn validate_exact_token(token: &str) -> Result<(), EvidenceError> {
    if token.is_empty() || token != token.trim() || token.contains(',') {
        return Err(EvidenceError::AmbiguousAssertion);
    }
    Ok(())
}

fn validate_unique_jwt_header(token: &str) -> Result<(), EvidenceError> {
    let encoded = token
        .split('.')
        .next()
        .ok_or(EvidenceError::InvalidAssertion)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| EvidenceError::InvalidAssertion)?;
    serde_json::from_slice::<UniqueClaims>(&decoded)
        .map(|_| ())
        .map_err(|_| EvidenceError::AmbiguousAssertion)
}

fn exact_jwk_for_kid<'a>(set: &'a JwkSet, kid: &str) -> Result<&'a Jwk, EvidenceError> {
    let mut matches = set
        .keys
        .iter()
        .filter(|jwk| jwk.common.key_id.as_deref() == Some(kid));
    let first = matches.next().ok_or(EvidenceError::InvalidAssertion)?;
    if matches.next().is_some() {
        return Err(EvidenceError::AmbiguousAssertion);
    }
    Ok(first)
}

fn is_allowed_algorithm(algorithm: Algorithm) -> bool {
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

fn validate_jwk_signature_metadata(jwk: &Jwk, algorithm: Algorithm) -> Result<(), EvidenceError> {
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|usage| usage != &PublicKeyUse::Signature)
        || jwk
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| {
                !operations.contains(&KeyOperations::Verify)
                    || operations.contains(&KeyOperations::Sign)
            })
        || jwk
            .common
            .key_algorithm
            .as_ref()
            .is_some_and(|configured| !jwk_algorithm_matches(configured, algorithm))
    {
        return Err(EvidenceError::InvalidAssertion);
    }
    Ok(())
}

fn jwk_algorithm_matches(configured: &KeyAlgorithm, actual: Algorithm) -> bool {
    matches!(
        (configured, actual),
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

fn exact_string_claim(claims: &Map<String, Value>, name: &str) -> Result<String, EvidenceError> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| is_exact_identity_part(value))
        .map(ToOwned::to_owned)
        .ok_or(EvidenceError::InvalidAssertion)
}

fn verifier_policy_digest(
    policy: &AssertionVerificationPolicy,
    jwks: &JwkSet,
) -> Result<[u8; 32], EvidenceError> {
    let mut encoded_keys = jwks
        .keys
        .iter()
        .map(|key| serde_json::to_vec(key).map_err(|_| EvidenceError::InvalidConfiguration))
        .collect::<Result<Vec<_>, _>>()?;
    encoded_keys.sort();
    if encoded_keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(EvidenceError::InvalidConfiguration);
    }
    let encoding = match policy.nostr_key_claim.as_ref().map(|claim| claim.encoding) {
        None => 0_u8,
        Some(NostrKeyClaimEncoding::LowerHex) => 1,
        Some(NostrKeyClaimEncoding::CanonicalPublicKey) => 2,
    };
    let claim_name = policy
        .nostr_key_claim
        .as_ref()
        .map_or(&[][..], |claim| claim.claim_name.as_bytes());
    let maximum_age = policy.maximum_token_age.as_secs().to_be_bytes();
    let clock_skew = policy.clock_skew.as_secs().to_be_bytes();
    let key_count = (encoded_keys.len() as u64).to_be_bytes();
    let encoding_bytes = [encoding];
    let mut digest = Sha256::new();
    for field in [
        b"buzz:nip-fi:assertion-verifier-policy:v1".as_slice(),
        policy.issuer.as_bytes(),
        policy.audience.as_bytes(),
        policy.subject_claim.as_bytes(),
        claim_name,
        &encoding_bytes,
        &maximum_age,
        &clock_skew,
        &key_count,
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    for encoded in encoded_keys {
        digest.update((encoded.len() as u64).to_be_bytes());
        digest.update(encoded);
    }
    Ok(digest.finalize().into())
}

fn parse_event_author_claim(
    value: &Value,
    policy: Option<&NostrKeyClaimPolicy>,
) -> Result<PublicKey, EvidenceError> {
    let value = value.as_str().ok_or(EvidenceError::InvalidAssertion)?;
    match policy.map(|policy| policy.encoding) {
        Some(NostrKeyClaimEncoding::CanonicalPublicKey) if value.starts_with("npub1") => {
            PublicKey::from_bech32(value).map_err(|_| EvidenceError::InvalidAssertion)
        }
        Some(NostrKeyClaimEncoding::LowerHex | NostrKeyClaimEncoding::CanonicalPublicKey) => {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(EvidenceError::InvalidAssertion);
            }
            PublicKey::from_hex(value).map_err(|_| EvidenceError::InvalidAssertion)
        }
        None => Err(EvidenceError::InvalidAssertion),
    }
}

fn numeric_date(claims: &Map<String, Value>, name: &str) -> Result<DateTime<Utc>, EvidenceError> {
    let seconds = claims
        .get(name)
        .and_then(Value::as_i64)
        .ok_or(EvidenceError::InvalidAssertion)?;
    DateTime::from_timestamp(seconds, 0).ok_or(EvidenceError::InvalidAssertion)
}

fn is_exact_identity_part(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_PART_BYTES
        && value == value.trim()
        && !value.contains(',')
        && !value.chars().any(char::is_control)
}

fn is_safe_subject_claim(claim: &str) -> bool {
    if !is_exact_identity_part(claim)
        || !claim
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return false;
    }
    let normalized: String = claim
        .chars()
        .filter(|character| !matches!(character, '_' | '-' | '.'))
        .flat_map(char::to_lowercase)
        .collect();
    !matches!(
        normalized.as_str(),
        "email"
            | "emailaddress"
            | "mail"
            | "username"
            | "preferredusername"
            | "name"
            | "fullname"
            | "display"
            | "displayname"
            | "givenname"
            | "familyname"
    )
}

fn is_safe_event_author_key_claim(claim: &str) -> bool {
    !claim.is_empty()
        && claim.len() <= MAX_CLAIM_NAME_BYTES
        && claim
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && !matches!(claim, "iss" | "sub" | "aud" | "exp" | "nbf" | "iat" | "jti")
}

fn framed_fingerprint(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update((label.len() as u64).to_be_bytes());
    digest.update(label);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

fn provenance_mac(
    key: &[u8],
    header: &[u8],
    token: &[u8],
    binding: &RequestEvidenceBinding,
) -> Result<ProvenanceMac, EvidenceError> {
    let mut mac = <ProvenanceMac as KeyInit>::new_from_slice(key)
        .map_err(|_| EvidenceError::InvalidConfiguration)?;
    mac.update(b"buzz:nip-fi:trusted-proxy:v1");
    mac.update(&(header.len() as u64).to_be_bytes());
    mac.update(header);
    mac.update(&(token.len() as u64).to_be_bytes());
    mac.update(token);
    mac.update(binding.authorization_domain.as_uuid().as_bytes());
    mac.update(&binding.request_fingerprint);
    mac.update(&binding.target_fingerprint);
    mac.update(&binding.transport_context_fingerprint);
    Ok(mac)
}

struct UniqueClaims(Map<String, Value>);

impl<'de> Deserialize<'de> for UniqueClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueClaimsVisitor;

        impl<'de> Visitor<'de> for UniqueClaimsVisitor {
            type Value = UniqueClaims;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object with unique member names")
            }

            fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut claims = Map::new();
                while let Some((name, value)) = entries.next_entry::<String, Value>()? {
                    if claims.insert(name, value).is_some() {
                        return Err(A::Error::custom("duplicate member name"));
                    }
                }
                Ok(UniqueClaims(claims))
            }
        }

        deserializer.deserialize_map(UniqueClaimsVisitor)
    }
}

/// Sanitized fail-closed evidence verification errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EvidenceError {
    /// Verifier policy or trusted-boundary configuration was invalid.
    #[error("invalid evidence configuration")]
    InvalidConfiguration,
    /// Server-resolved request coordinates were missing or invalid.
    #[error("invalid evidence binding")]
    InvalidBinding,
    /// Assertion header/value representation was ambiguous.
    #[error("ambiguous assertion")]
    AmbiguousAssertion,
    /// Trusted-proxy provenance was absent or invalid.
    #[error("untrusted assertion origin")]
    UntrustedOrigin,
    /// JWT signature, claims, key metadata, or exact identity was invalid.
    #[error("invalid assertion")]
    InvalidAssertion,
    /// NIP-42 or NIP-98 proof was invalid or mismatched.
    #[error("invalid Nostr proof")]
    InvalidProof,
    /// Delegation signature or authoritative relationship state was invalid.
    #[error("invalid delegation")]
    InvalidDelegation,
    /// No reviewed positive authority source is installed for delegated HTTP evidence.
    #[error("delegated evidence authority unavailable")]
    DelegatedAuthorityUnavailable,
    /// Evidence was at or beyond an exclusive time boundary.
    #[error("evidence expired")]
    Expired,
    /// A protected NIP-98 proof was already consumed.
    #[error("NIP-98 proof replayed")]
    Replay,
    /// A required replay or relationship dependency was unavailable.
    #[error("evidence dependency unavailable")]
    DependencyUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use nostr::{EventBuilder, Keys, RelayUrl, Tag, Timestamp, ToBech32};

    const RSA_PRIVATE_KEY_DER_BASE64: &str = "MIIEpAIBAAKCAQEAyRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXBXd/4LkvcPuUakBoAkfh+eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG/AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi+yUod+j8MtvIj812dkS4QMiRVN/by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQIDAQABAoIBAHREk0I0O9DvECKdWUpAmF3mY7oY9PNQiu44Yaf+AoSuyRpRUGTMIgc3u3eivOE8ALX0BmYUO5JtuRNZDpvt4SAwqCnVUinIf6C+eH/wSurCpapSM0BAHp4aOA7igptyOMgMPYBHNA1e9A7jE0dCxKWMl3DSWNyjQTk4zeRGEAEfbNjHrq6YCtjHSZSLmWiG80hnfnYos9hOr5JnLnyS7ZmFE/5P3XVrxLc/tQ5zum0R4cbrgzHiQP5RgfxGJaEi7XcgherCCOgurJSSbYH29Gz8u5fFbS+Yg8s+OiCss3cs1rSgJ9/eHZuzGEdUZVARH6hVMjSuwvqVTFaE8AgtleECgYEA+uLMn4kNqHlJS2A5uAnCkj90ZxEtNm3E8hAxUrhssktY5XSOAPBlxyf5RuRGIImGtUVIr4HuJSa5TX48n3Vdt9MYCprO/iYl6moNRSPt5qowIIOJmIjY2mqPDfDt/zw+fcDD3lmCJrFlzcnh0uea1CohxEbQnL3cypeLt+WbU6kCgYEAzSp19m1ajieFkqgoB0YTpt/OroDx38vvI5unInJlEeOjQ+oIAQdN2wpxBvTrRorMU6P07mFUbt1j+Co6CbNiw+X8HcCaqYLR5clbJOOWNR36PuzOpQLkfK8woupBxzW9B8gZmY8rB1mbJ+/WTPrEJy6YGmIEBkWylQ2VpW8O4O0CgYEApdbvvfFBlwD9YxbrcGz7MeNCFbMz+MucqQntIKoKJ91ImPxvtc0y6e/Rhnv0oyNlaUOwJVu0yNgNG117w0g4t/+Q38mvVC5xV7/cn7x9UMFk6MkqVir3dYGEqIl/OP1grY2Tq9HtB5iyG9L8NIamQOLMyUqqMUILxdthHyFmiGkCgYEAn9+PjpjGMPHxL0gj8Q8VbzsFtou6b1deIRRA2CHmSltltR1gYVTMwXxQeUhPMmgkMqUXzs4/WijgpthY44hK1TaZEKIuoxrS70nJ4WQLf5a9k1065fDsFZD6yGjdGxvwEmlGMZgTwqV7t1I4X0Ilqhav5hcs5apYL7gnPYPeRz0CgYALHCj/Ji8XSsDoF/MhVhnGdIs2P99NNdmo3R2Pv0CuZbDKMU559LJHUvrKS8WkuWRDuKrz1W/EQKApFjDGpdqToZqriUFQzwy7mR3ayIiogzNtHcvbDHx8oFnGY0OFksX/ye0/XGpy2SFxYRwGU98HPYeBvAQQrVjdkzfy7BmXQQ==";

    struct FixedClock(DateTime<Utc>);

    impl EvidenceClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn fixture_now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).expect("valid fixture time")
    }

    fn fixture_binding() -> RequestEvidenceBinding {
        fixture_binding_for(ProofTransport::Nip42)
    }

    fn fixture_binding_for(transport: ProofTransport) -> RequestEvidenceBinding {
        RequestEvidenceBinding::new(
            CommunityId::from_uuid(Uuid::from_u128(1)),
            transport,
            b"POST /protected",
            b"protected-object",
            b"connection-epoch",
        )
        .expect("valid binding")
    }

    #[test]
    fn request_binding_accepts_only_exact_root_proof_coordinates() {
        let actor = Keys::generate().public_key();
        for (transport, substitutes) in [
            (
                ProofTransport::GitSmartHttpSession,
                [ProofTransport::Nip98, ProofTransport::Blossom],
            ),
            (
                ProofTransport::Blossom,
                [ProofTransport::Nip98, ProofTransport::GitSmartHttpSession],
            ),
        ] {
            let binding = fixture_binding_for(transport);
            let proof = |domain,
                         transport,
                         request_fingerprint,
                         target_fingerprint,
                         transport_context_fingerprint| {
                VerifiedNostrProof::from_verifier(
                    domain,
                    actor,
                    transport,
                    request_fingerprint,
                    target_fingerprint,
                    transport_context_fingerprint,
                    Some([2; 32]),
                    None,
                    fixture_now() + TimeDelta::seconds(30),
                )
                .expect("valid fixture proof")
            };
            let exact = proof(
                binding.authorization_domain,
                transport,
                binding.request_fingerprint,
                binding.target_fingerprint,
                binding.transport_context_fingerprint,
            );
            assert!(binding.accepts_proof(&exact));

            for substitute in substitutes {
                assert!(!binding.accepts_proof(&proof(
                    binding.authorization_domain,
                    substitute,
                    binding.request_fingerprint,
                    binding.target_fingerprint,
                    binding.transport_context_fingerprint,
                )));
            }
            for changed in [
                proof(
                    CommunityId::from_uuid(Uuid::from_u128(2)),
                    transport,
                    binding.request_fingerprint,
                    binding.target_fingerprint,
                    binding.transport_context_fingerprint,
                ),
                proof(
                    binding.authorization_domain,
                    transport,
                    [12; 32],
                    binding.target_fingerprint,
                    binding.transport_context_fingerprint,
                ),
                proof(
                    binding.authorization_domain,
                    transport,
                    binding.request_fingerprint,
                    [12; 32],
                    binding.transport_context_fingerprint,
                ),
                proof(
                    binding.authorization_domain,
                    transport,
                    binding.request_fingerprint,
                    binding.target_fingerprint,
                    [12; 32],
                ),
            ] {
                assert!(!binding.accepts_proof(&changed));
            }
        }
    }

    fn rsa_private_key() -> EncodingKey {
        let private_key = STANDARD
            .decode(RSA_PRIVATE_KEY_DER_BASE64)
            .expect("decode fixture key");
        EncodingKey::from_rsa_der(&private_key)
    }

    fn rsa_jwk(private_key: &EncodingKey, kid: &str) -> Jwk {
        let mut jwk =
            Jwk::from_encoding_key(private_key, Algorithm::RS256).expect("derive public JWK");
        jwk.common.key_id = Some(kid.to_owned());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_operations = Some(vec![KeyOperations::Verify]);
        jwk
    }

    fn verifier_at(now: DateTime<Utc>) -> StaticJwksAssertionVerifier {
        let key = rsa_private_key();
        StaticJwksAssertionVerifier::with_clock(
            AssertionVerificationPolicy::new(
                "https://issuer.example",
                "buzz-relay",
                "employee_id",
                Duration::from_secs(300),
                Duration::from_secs(30),
            )
            .expect("valid policy"),
            JwkSet {
                keys: vec![rsa_jwk(&key, "key-1")],
            },
            Arc::new(FixedClock(now)),
        )
        .expect("valid verifier")
    }

    fn verifier_with_nostr_key_at(now: DateTime<Utc>) -> StaticJwksAssertionVerifier {
        let key = rsa_private_key();
        let policy = AssertionVerificationPolicy::new(
            "https://issuer.example",
            "buzz-relay",
            "employee_id",
            Duration::from_secs(300),
            Duration::from_secs(30),
        )
        .expect("valid policy")
        .with_nostr_key_claim(
            NostrKeyClaimPolicy::canonical_public_key("nostr_pubkey").expect("key claim"),
        )
        .expect("install key claim");
        StaticJwksAssertionVerifier::with_clock(
            policy,
            JwkSet {
                keys: vec![rsa_jwk(&key, "key-1")],
            },
            Arc::new(FixedClock(now)),
        )
        .expect("valid verifier")
    }

    fn jwt_at(now: DateTime<Utc>, mutate: impl FnOnce(&mut Value)) -> String {
        let key = rsa_private_key();
        let mut claims = serde_json::json!({
            "iss": "https://issuer.example",
            "aud": "buzz-relay",
            "employee_id": "opaque-123",
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": now.timestamp() + 600,
        });
        mutate(&mut claims);
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("key-1".to_owned());
        encode(&header, &claims, &key).expect("sign fixture JWT")
    }

    fn proxy_proof(
        key: &[u8],
        header: &str,
        token: &str,
        binding: &RequestEvidenceBinding,
    ) -> String {
        let mac =
            provenance_mac(key, header.as_bytes(), token.as_bytes(), binding).expect("fixture MAC");
        hex::encode(mac.finalize().into_bytes())
    }

    fn exact_assertion_header(token: &str) -> ExactSingleHttpHeader {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-buzz-identity"),
            token.parse().expect("fixture header value"),
        );
        ExactSingleHttpHeader::from_headers(&headers, &HeaderName::from_static("x-buzz-identity"))
            .expect("one assertion header")
    }

    fn protected_target(path: &str) -> CanonicalHttpRequestTarget {
        CanonicalHttpRequestTarget::from_server_parts(
            &Scheme::HTTPS,
            &"relay.example".parse().expect("fixture authority"),
            &path.parse().expect("fixture path and query"),
        )
        .expect("canonical target")
    }

    #[test]
    fn opaque_subject_policy_rejects_profile_claims() {
        for claim in [
            "email",
            "email_address",
            "username",
            "preferred_username",
            "name",
            "display-name",
            "given.name",
        ] {
            assert!(
                matches!(
                    AssertionVerificationPolicy::new(
                        "issuer",
                        "audience",
                        claim,
                        Duration::from_secs(60),
                        Duration::ZERO,
                    ),
                    Err(EvidenceError::InvalidConfiguration)
                ),
                "{claim} must not be an opaque subject adapter"
            );
        }
        assert!(AssertionVerificationPolicy::new(
            "issuer",
            "audience",
            "employee_id",
            Duration::from_secs(60),
            Duration::ZERO,
        )
        .is_ok());
    }

    #[test]
    fn attested_actor_is_sealed_and_substitution_is_rejected() {
        let now = fixture_now();
        let actor = Keys::generate().public_key();
        let binding = fixture_binding();
        let token = jwt_at(now, |claims| {
            claims["nostr_pubkey"] = Value::from(actor.to_hex());
        });
        let verifier = verifier_with_nostr_key_at(now);
        let evidence = verifier
            .verify_client_attached(&exact_assertion_header(&token), &binding)
            .expect("verified assertion")
            .bind_authenticated_actor(actor)
            .expect("exact actor");
        assert!(evidence.enrollment_permitted());
        assert!(evidence.accepts_authorization_coordinates(binding.authorization_domain(), actor));
        assert_ne!(evidence.evidence_fingerprint(), [0; 32]);
        assert_eq!(
            evidence.enrollment_policy_digest(),
            verifier.enrollment_policy_digest()
        );
        assert_eq!(
            format!("{evidence:?}"),
            "VerifiedIdentityBindingEvidence([REDACTED])"
        );

        let token = jwt_at(now, |claims| {
            claims["nostr_pubkey"] = Value::from(actor.to_hex());
        });
        assert!(verifier_with_nostr_key_at(now)
            .verify_client_attached(&exact_assertion_header(&token), &binding)
            .expect("verified assertion")
            .bind_authenticated_actor(Keys::generate().public_key())
            .is_err());
    }

    #[test]
    fn claimless_assertion_is_existing_binding_only() {
        let now = fixture_now();
        let actor = Keys::generate().public_key();
        let binding = fixture_binding();
        let token = jwt_at(now, |_| {});
        let evidence = verifier_at(now)
            .verify_client_attached(&exact_assertion_header(&token), &binding)
            .expect("verified assertion")
            .bind_authenticated_actor(actor)
            .expect("authenticated actor");
        assert!(!evidence.enrollment_permitted());
    }

    #[test]
    fn canonical_key_claim_accepts_exact_hex_or_npub_only() {
        let actor = Keys::generate().public_key();
        let policy = NostrKeyClaimPolicy::canonical_public_key("nostr_pubkey").expect("key policy");
        for encoded in [actor.to_hex(), actor.to_bech32().expect("npub")] {
            assert_eq!(
                parse_event_author_claim(&Value::from(encoded), Some(&policy))
                    .expect("canonical key"),
                actor
            );
        }
        for invalid in [
            actor.to_hex().to_ascii_uppercase(),
            format!(" {}", actor.to_hex()),
        ] {
            assert!(parse_event_author_claim(&Value::from(invalid), Some(&policy)).is_err());
        }
    }

    #[test]
    fn verifier_policy_digest_binds_jwks_and_ignores_key_order() {
        let policy = AssertionVerificationPolicy::new(
            "https://issuer.example",
            "buzz-relay",
            "employee_id",
            Duration::from_secs(300),
            Duration::from_secs(30),
        )
        .expect("valid policy")
        .with_nostr_key_claim(
            NostrKeyClaimPolicy::canonical_public_key("nostr_pubkey").expect("key claim"),
        )
        .expect("install key claim");
        let key = rsa_private_key();
        let first = rsa_jwk(&key, "first");
        let second = rsa_jwk(&key, "second");
        let forward = verifier_policy_digest(
            &policy,
            &JwkSet {
                keys: vec![first.clone(), second.clone()],
            },
        )
        .expect("forward digest");
        let reverse = verifier_policy_digest(
            &policy,
            &JwkSet {
                keys: vec![second, first.clone()],
            },
        )
        .expect("reverse digest");
        assert_eq!(forward, reverse);
        assert_ne!(
            forward,
            verifier_policy_digest(&policy, &JwkSet { keys: vec![first] }).expect("different keys")
        );
    }

    #[test]
    fn client_assertion_requires_iat_and_uses_exclusive_age_bound() {
        let now = fixture_now();
        let verifier = verifier_at(now);
        let binding = fixture_binding();
        let valid_token = jwt_at(now, |_| {});
        assert!(verifier
            .verify_client_attached(&exact_assertion_header(&valid_token), &binding)
            .is_ok());

        let missing_iat = jwt_at(now, |claims| {
            claims.as_object_mut().expect("claims object").remove("iat");
        });
        assert!(matches!(
            verifier.verify_client_attached(&exact_assertion_header(&missing_iat), &binding),
            Err(EvidenceError::InvalidAssertion)
        ));

        let age_boundary = jwt_at(now, |claims| {
            claims["iat"] = Value::from(now.timestamp() - 300);
        });
        assert!(matches!(
            verifier.verify_client_attached(&exact_assertion_header(&age_boundary), &binding),
            Err(EvidenceError::Expired)
        ));

        let audience_alternative = jwt_at(now, |claims| {
            claims["aud"] = serde_json::json!(["buzz-relay"]);
        });
        assert!(matches!(
            verifier
                .verify_client_attached(&exact_assertion_header(&audience_alternative), &binding),
            Err(EvidenceError::InvalidAssertion)
        ));

        let control_subject = jwt_at(now, |claims| {
            claims["employee_id"] = Value::from("opaque\nsubject");
        });
        assert!(matches!(
            verifier.verify_client_attached(&exact_assertion_header(&control_subject), &binding),
            Err(EvidenceError::InvalidAssertion)
        ));
    }

    #[test]
    fn trusted_proxy_requires_exact_mac_and_origin_changes_fingerprint() {
        let now = fixture_now();
        let token = jwt_at(now, |_| {});
        let binding = fixture_binding();
        let key = [9_u8; 32];
        let proxy = verifier_at(now)
            .trusted_proxy("x-buzz-identity", "x-buzz-identity-proof", key)
            .expect("valid proxy verifier");
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-buzz-identity"),
            token.parse().expect("token header"),
        );
        headers.insert(
            HeaderName::from_static("x-buzz-identity-proof"),
            "0".repeat(64).parse().expect("proof header"),
        );
        assert!(matches!(
            proxy.verify(&headers, &binding),
            Err(EvidenceError::UntrustedOrigin)
        ));
        let proof = proxy_proof(&key, "x-buzz-identity", &token, &binding);
        headers.insert(
            HeaderName::from_static("x-buzz-identity-proof"),
            proof.parse().expect("proof header"),
        );
        let proxy_assertion = proxy.verify(&headers, &binding).expect("valid proxy proof");
        let other_binding = RequestEvidenceBinding::new(
            CommunityId::from_uuid(Uuid::from_u128(1)),
            ProofTransport::Nip42,
            b"POST /other",
            b"protected-object",
            b"connection-epoch",
        )
        .expect("valid alternate binding");
        assert!(matches!(
            proxy.verify(&headers, &other_binding),
            Err(EvidenceError::UntrustedOrigin)
        ));
        let client_assertion = verifier_at(now)
            .verify_client_attached(&exact_assertion_header(&token), &binding)
            .expect("valid client assertion");
        assert_ne!(
            proxy_assertion.assertion_fingerprint,
            client_assertion.assertion_fingerprint
        );
    }

    #[test]
    fn duplicate_header_and_claim_names_fail_closed() {
        let duplicate_header = "eyJhbGciOiJSUzI1NiIsImFsZyI6IlJTMjU2Iiwia2lkIjoia2V5LTEifQ.e30.AA";
        assert_eq!(
            validate_unique_jwt_header(duplicate_header),
            Err(EvidenceError::AmbiguousAssertion)
        );
        let duplicate_claims = br#"{"sub":"a","sub":"b"}"#;
        assert!(serde_json::from_slice::<UniqueClaims>(duplicate_claims).is_err());
    }

    #[test]
    fn exact_http_header_rejects_missing_repeated_comma_and_rewritten_values() {
        let name = HeaderName::from_static("x-buzz-identity");
        assert!(matches!(
            ExactSingleHttpHeader::from_headers(&HeaderMap::new(), &name),
            Err(EvidenceError::AmbiguousAssertion)
        ));

        let mut repeated = HeaderMap::new();
        repeated.append(name.clone(), "token-a".parse().expect("header"));
        repeated.append(name.clone(), "token-a".parse().expect("header"));
        assert!(matches!(
            ExactSingleHttpHeader::from_headers(&repeated, &name),
            Err(EvidenceError::AmbiguousAssertion)
        ));

        for ambiguous in ["token-a,token-b", " token-a", "token-a "] {
            let mut headers = HeaderMap::new();
            headers.insert(
                name.clone(),
                http::HeaderValue::from_bytes(ambiguous.as_bytes()).expect("header value"),
            );
            assert!(matches!(
                ExactSingleHttpHeader::from_headers(&headers, &name),
                Err(EvidenceError::AmbiguousAssertion)
            ));
        }
    }

    #[test]
    fn trusted_proxy_rejects_duplicate_assertion_or_provenance_occurrences() {
        let now = fixture_now();
        let token = jwt_at(now, |_| {});
        let binding = fixture_binding();
        let key = [7_u8; 32];
        let proof = proxy_proof(&key, "x-buzz-identity", &token, &binding);
        let proxy = verifier_at(now)
            .trusted_proxy("x-buzz-identity", "x-buzz-identity-proof", key)
            .expect("proxy verifier");

        for duplicated_name in ["x-buzz-identity", "x-buzz-identity-proof"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                HeaderName::from_static("x-buzz-identity"),
                token.parse().expect("token header"),
            );
            headers.insert(
                HeaderName::from_static("x-buzz-identity-proof"),
                proof.parse().expect("proof header"),
            );
            headers.append(
                HeaderName::from_bytes(duplicated_name.as_bytes()).expect("header name"),
                if duplicated_name == "x-buzz-identity" {
                    token.parse().expect("duplicate token")
                } else {
                    proof.parse().expect("duplicate proof")
                },
            );
            assert!(matches!(
                proxy.verify(&headers, &binding),
                Err(EvidenceError::AmbiguousAssertion)
            ));
        }
    }

    #[test]
    fn canonical_request_target_preserves_route_significant_bytes() {
        let without_slash = protected_target("/protected");
        let with_slash = protected_target("/protected/");
        let with_query = protected_target("/protected?part=1&part=2");
        assert_eq!(without_slash.as_str(), "https://relay.example/protected");
        assert_eq!(with_slash.as_str(), "https://relay.example/protected/");
        assert_eq!(
            with_query.as_str(),
            "https://relay.example/protected?part=1&part=2"
        );
        assert_ne!(without_slash, with_slash);
    }

    #[test]
    fn nip42_pair_binds_exact_assertion_and_actor() {
        let now = Utc::now();
        let clock = FixedClock(now);
        let binding = fixture_binding();
        let assertion = verifier_at(now)
            .verify_client_attached(&exact_assertion_header(&jwt_at(now, |_| {})), &binding)
            .expect("valid assertion");
        let keys = Keys::generate();
        let relay = RelayUrl::parse("wss://relay.example").expect("relay URL");
        let event = EventBuilder::auth("challenge", relay)
            .custom_created_at(Timestamp::from(now.timestamp() as u64))
            .sign_with_keys(&keys)
            .expect("sign AUTH event");
        let pair = verify_nip42_direct(
            &event,
            "challenge",
            "wss://relay.example",
            &binding,
            assertion,
            &clock,
        )
        .expect("valid direct pair");
        let (_, proof) = pair.into_parts();
        assert_eq!(proof.actor_pubkey(), keys.public_key());
    }

    #[tokio::test]
    async fn protected_nip98_requires_payload_and_claims_replay_marker() {
        let now = fixture_now();
        let clock = FixedClock(now);
        let binding = fixture_binding_for(ProofTransport::Nip98);
        let token = jwt_at(now, |_| {});
        let keys = Keys::generate();
        let body = b"payload";
        let payload = hex::encode(Sha256::digest(body));
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags([
                Tag::parse(["u", "https://relay.example/protected"]).expect("url tag"),
                Tag::parse(["method", "POST"]).expect("method tag"),
                Tag::parse(["payload", &payload]).expect("payload tag"),
            ])
            .custom_created_at(Timestamp::from(now.timestamp() as u64))
            .sign_with_keys(&keys)
            .expect("sign NIP-98 event");
        let event_json = serde_json::to_string(&event).expect("serialize event");
        let assertion = verifier_at(now)
            .verify_client_attached(&exact_assertion_header(&token), &binding)
            .expect("valid assertion");
        let pair = verify_nip98_direct(
            &event_json,
            &protected_target("/protected"),
            "POST",
            Some(body),
            true,
            &binding,
            assertion,
            &crate::nip98_replay::AlwaysFreshReplayGuard,
            &clock,
        )
        .await
        .expect("valid NIP-98 pair");
        let (_, proof) = pair.into_parts();
        assert_eq!(proof.actor_pubkey(), keys.public_key());

        let assertion = verifier_at(now)
            .verify_client_attached(&exact_assertion_header(&token), &binding)
            .expect("valid assertion");
        assert!(matches!(
            verify_nip98_direct(
                &serde_json::to_string(
                    &EventBuilder::new(Kind::HttpAuth, "")
                        .tags([
                            Tag::parse(["u", "https://relay.example/protected"]).expect("url tag"),
                            Tag::parse(["method", "POST"]).expect("method tag"),
                        ])
                        .custom_created_at(Timestamp::from(now.timestamp() as u64))
                        .sign_with_keys(&keys)
                        .expect("sign NIP-98 event")
                )
                .expect("serialize event"),
                &protected_target("/protected"),
                "POST",
                Some(body),
                true,
                &binding,
                assertion,
                &crate::nip98_replay::AlwaysFreshReplayGuard,
                &clock,
            )
            .await,
            Err(EvidenceError::InvalidProof)
        ));
    }

    fn signed_nip98(now: DateTime<Utc>, keys: &Keys, tags: Vec<Tag>) -> String {
        serde_json::to_string(
            &EventBuilder::new(Kind::HttpAuth, "")
                .tags(tags)
                .custom_created_at(Timestamp::from(now.timestamp() as u64))
                .sign_with_keys(keys)
                .expect("sign NIP-98 event"),
        )
        .expect("serialize NIP-98 event")
    }

    fn direct_assertion(
        now: DateTime<Utc>,
        binding: &RequestEvidenceBinding,
    ) -> VerifiedAssertionEvidence {
        verifier_at(now)
            .verify_client_attached(&exact_assertion_header(&jwt_at(now, |_| {})), binding)
            .expect("valid direct assertion")
    }

    fn git_route(
        owner: &str,
        repo: &str,
        method: Method,
        path_and_query: &str,
    ) -> CanonicalGitSmartHttpRequest {
        CanonicalGitSmartHttpRequest::from_server_parts(
            &Scheme::HTTPS,
            &"relay.example".parse().expect("authority"),
            owner,
            repo,
            &method,
            &path_and_query.parse().expect("path and query"),
        )
        .expect("canonical Git request")
    }

    fn signed_git_session(
        now: DateTime<Utc>,
        keys: &Keys,
        repo_root: &str,
        method: &str,
        extra_tags: impl IntoIterator<Item = Tag>,
    ) -> String {
        let mut tags = vec![
            Tag::parse(["u", repo_root]).expect("repo-root tag"),
            Tag::parse(["method", method]).expect("method tag"),
        ];
        tags.extend(extra_tags);
        signed_nip98(now, keys, tags)
    }

    #[test]
    fn git_session_maps_only_closed_operations_and_binds_exact_target() {
        let now = fixture_now();
        let clock = FixedClock(now);
        let owner_a = "a".repeat(64);
        let owner_b = "b".repeat(64);
        let keys = Keys::generate();
        let signed = signed_git_session(
            now,
            &keys,
            &format!("https://relay.example/git/{owner_a}/repo"),
            "GET",
            [],
        );
        let cases = [
            (
                Method::GET,
                format!("/git/{owner_a}/repo/info/refs?service=git-upload-pack"),
                GitSmartHttpOperation::AdvertiseUploadPack,
            ),
            (
                Method::GET,
                format!("/git/{owner_a}/repo/info/refs?service=git-receive-pack"),
                GitSmartHttpOperation::AdvertiseReceivePack,
            ),
            (
                Method::POST,
                format!("/git/{owner_a}/repo/git-upload-pack"),
                GitSmartHttpOperation::UploadPack,
            ),
            (
                Method::POST,
                format!("/git/{owner_a}/repo/git-receive-pack"),
                GitSmartHttpOperation::ReceivePack,
            ),
        ];
        for (method, path, expected_operation) in cases {
            let request = git_route(&owner_a, "repo", method, &path);
            assert_eq!(request.operation(), expected_operation);
            let binding = request
                .evidence_binding(CommunityId::from_uuid(Uuid::from_u128(1)))
                .expect("binding");
            let authorization = verify_git_smart_http_authorization(&signed, &request, &clock)
                .expect("origin-verified session authorization");
            let pair = verify_git_smart_http_direct(
                &authorization,
                &binding,
                direct_assertion(now, &binding),
            )
            .expect("one reusable session credential admits the closed operation");
            let (_, proof) = pair.into_parts();
            assert_eq!(proof.actor_pubkey(), keys.public_key());
            assert_eq!(proof.transport(), ProofTransport::GitSmartHttpSession);
        }

        let route_a = git_route(
            &owner_a,
            "repo",
            Method::POST,
            &format!("/git/{owner_a}/repo/git-upload-pack"),
        );
        let route_b = git_route(
            &owner_b,
            "repo",
            Method::POST,
            &format!("/git/{owner_b}/repo/git-upload-pack"),
        );
        let binding_b = route_b
            .evidence_binding(CommunityId::from_uuid(Uuid::from_u128(1)))
            .expect("binding B");
        let authorization_a = verify_git_smart_http_authorization(&signed, &route_a, &clock)
            .expect("route A authorization");
        assert!(matches!(
            verify_git_smart_http_direct(
                &authorization_a,
                &binding_b,
                direct_assertion(now, &binding_b),
            ),
            Err(EvidenceError::InvalidBinding)
        ));
    }

    #[test]
    fn git_session_rejects_method_payload_repo_alias_and_expiry_boundaries() {
        let now = fixture_now();
        let owner = "a".repeat(64);
        let request = git_route(
            &owner,
            "repo",
            Method::POST,
            &format!("/git/{owner}/repo/git-upload-pack"),
        );
        let keys = Keys::generate();
        for signed in [
            signed_git_session(
                now,
                &keys,
                &format!("https://relay.example/git/{owner}/repo"),
                "POST",
                [],
            ),
            signed_git_session(
                now,
                &keys,
                &format!("https://relay.example/git/{owner}/other"),
                "GET",
                [],
            ),
            signed_git_session(
                now,
                &keys,
                &format!("https://relay.example/git/{owner}/repo"),
                "GET",
                [Tag::parse(["payload", "00"]).expect("payload tag")],
            ),
            signed_git_session(
                now,
                &keys,
                &format!("https://relay.example/git/{owner}/repo"),
                "GET",
                [Tag::parse(["method", "GET"]).expect("duplicate method")],
            ),
        ] {
            assert!(matches!(
                verify_git_smart_http_authorization(&signed, &request, &FixedClock(now),),
                Err(EvidenceError::InvalidProof)
            ));
        }

        let expired_at_equality = signed_git_session(
            now - TimeDelta::seconds(PROOF_LIFETIME_SECONDS),
            &keys,
            &format!("https://relay.example/git/{owner}/repo"),
            "GET",
            [],
        );
        assert!(matches!(
            verify_git_smart_http_authorization(&expired_at_equality, &request, &FixedClock(now),),
            Err(EvidenceError::Expired)
        ));

        for (method, path) in [
            (Method::GET, format!("/git/{owner}/repo/git-upload-pack")),
            (
                Method::POST,
                format!("/git/{owner}/repo/info/refs?service=git-upload-pack"),
            ),
            (
                Method::GET,
                format!("/git/{owner}/repo/info/refs?service=other"),
            ),
        ] {
            assert!(matches!(
                CanonicalGitSmartHttpRequest::from_server_parts(
                    &Scheme::HTTPS,
                    &"relay.example".parse().expect("authority"),
                    &owner,
                    "repo",
                    &method,
                    &path.parse().expect("path"),
                ),
                Err(EvidenceError::InvalidBinding)
            ));
        }
    }

    fn blossom_route(method: Method, path: &str, object_sha256: &str) -> CanonicalBlossomRequest {
        CanonicalBlossomRequest::from_server_parts(
            &Scheme::HTTPS,
            &"relay.example".parse().expect("authority"),
            &method,
            &path.parse().expect("path"),
            object_sha256,
        )
        .expect("canonical Blossom request")
    }

    fn signed_blossom(
        now: DateTime<Utc>,
        keys: &Keys,
        verb: &str,
        expiration: i64,
        scopes: impl IntoIterator<Item = Tag>,
    ) -> Event {
        let mut tags = vec![
            Tag::parse(["t", verb]).expect("verb tag"),
            Tag::parse(["expiration", &expiration.to_string()]).expect("expiration tag"),
        ];
        tags.extend(scopes);
        EventBuilder::new(Kind::from(24_242), "Authorize Blossom request")
            .tags(tags)
            .custom_created_at(Timestamp::from(now.timestamp() as u64))
            .sign_with_keys(keys)
            .expect("sign Blossom event")
    }

    #[test]
    fn blossom_direct_binds_exact_action_object_or_server_scope() {
        let now = fixture_now();
        let clock = FixedClock(now);
        let keys = Keys::generate();
        let hash_a = "a".repeat(64);
        let hash_b = "b".repeat(64);
        for (request, event) in [
            (
                blossom_route(Method::PUT, "/upload", &hash_a),
                signed_blossom(
                    now,
                    &keys,
                    "upload",
                    now.timestamp() + 30,
                    [Tag::parse(["x", &hash_a]).expect("object scope")],
                ),
            ),
            (
                blossom_route(Method::GET, &format!("/media/{hash_a}.jpg"), &hash_a),
                signed_blossom(
                    now,
                    &keys,
                    "get",
                    now.timestamp() + 30,
                    [Tag::parse(["x", &hash_a]).expect("object scope")],
                ),
            ),
            (
                blossom_route(Method::HEAD, &format!("/media/{hash_a}"), &hash_a),
                signed_blossom(
                    now,
                    &keys,
                    "get",
                    now.timestamp() + 30,
                    [Tag::parse(["server", "relay.example"]).expect("server scope")],
                ),
            ),
        ] {
            let binding = request
                .evidence_binding(CommunityId::from_uuid(Uuid::from_u128(1)))
                .expect("binding");
            let authorization = verify_blossom_authorization(&event, &request, &clock)
                .expect("valid canonical Blossom authorization");
            let pair =
                verify_blossom_direct(&authorization, &binding, direct_assertion(now, &binding))
                    .expect("valid Blossom pair");
            let (_, proof) = pair.into_parts();
            assert_eq!(proof.actor_pubkey(), keys.public_key());
            assert_eq!(proof.transport(), ProofTransport::Blossom);
        }

        let route_a = blossom_route(Method::GET, &format!("/media/{hash_a}"), &hash_a);
        let route_b = blossom_route(Method::GET, &format!("/media/{hash_b}"), &hash_b);
        let binding_b = route_b
            .evidence_binding(CommunityId::from_uuid(Uuid::from_u128(1)))
            .expect("binding B");
        let event_a = signed_blossom(
            now,
            &keys,
            "get",
            now.timestamp() + 30,
            [Tag::parse(["x", &hash_a]).expect("object scope")],
        );
        let authorization_a = verify_blossom_authorization(&event_a, &route_a, &clock)
            .expect("valid route A authorization");
        assert!(matches!(
            verify_blossom_direct(
                &authorization_a,
                &binding_b,
                direct_assertion(now, &binding_b),
            ),
            Err(EvidenceError::InvalidBinding)
        ));
    }

    #[test]
    fn blossom_rejects_ambiguous_scope_action_server_and_expiry() {
        let now = fixture_now();
        let keys = Keys::generate();
        let hash = "a".repeat(64);
        let request = blossom_route(Method::GET, &format!("/media/{hash}"), &hash);
        let rejects = [
            signed_blossom(
                now,
                &keys,
                "upload",
                now.timestamp() + 30,
                [Tag::parse(["x", &hash]).expect("scope")],
            ),
            signed_blossom(
                now,
                &keys,
                "get",
                now.timestamp() + 30,
                [
                    Tag::parse(["x", &hash]).expect("object scope"),
                    Tag::parse(["server", "relay.example"]).expect("server scope"),
                ],
            ),
            signed_blossom(
                now,
                &keys,
                "get",
                now.timestamp() + 30,
                [Tag::parse(["server", "other.example"]).expect("server scope")],
            ),
            signed_blossom(
                now,
                &keys,
                "get",
                now.timestamp(),
                [Tag::parse(["x", &hash]).expect("scope")],
            ),
            signed_blossom(
                now - TimeDelta::seconds(PROOF_LIFETIME_SECONDS),
                &keys,
                "get",
                now.timestamp() + 30,
                [Tag::parse(["x", &hash]).expect("scope")],
            ),
            signed_blossom(
                now,
                &keys,
                "get",
                now.timestamp() + 30,
                [
                    Tag::parse(["x", &hash]).expect("scope"),
                    Tag::parse(["x", &hash]).expect("duplicate scope"),
                ],
            ),
        ];
        for event in rejects {
            assert!(matches!(
                verify_blossom_authorization(&event, &request, &FixedClock(now)),
                Err(EvidenceError::InvalidProof | EvidenceError::Expired)
            ));
        }
        assert!(matches!(
            verify_git_smart_http_delegated(),
            Err(EvidenceError::DelegatedAuthorityUnavailable)
        ));
        assert!(matches!(
            verify_blossom_delegated(),
            Err(EvidenceError::DelegatedAuthorityUnavailable)
        ));
    }

    #[test]
    fn nip98_rejects_route_aliases_and_every_duplicate_required_tag_order() {
        let now = fixture_now();
        let keys = Keys::generate();
        let body = b"payload";
        let payload = hex::encode(Sha256::digest(body));
        let url = || Tag::parse(["u", "https://relay.example/protected"]).expect("url tag");
        let method = || Tag::parse(["method", "POST"]).expect("method tag");
        let payload_tag = || Tag::parse(["payload", payload.as_str()]).expect("payload tag");
        let rejects = vec![
            vec![
                Tag::parse(["u", "https://relay.example/protected/"]).expect("slash URL"),
                method(),
                payload_tag(),
            ],
            vec![url(), url(), method(), payload_tag()],
            vec![
                url(),
                Tag::parse(["u", "https://relay.example/other"]).expect("other URL"),
                method(),
                payload_tag(),
            ],
            vec![
                Tag::parse(["u", "https://relay.example/other"]).expect("other URL"),
                url(),
                method(),
                payload_tag(),
            ],
            vec![url(), method(), method(), payload_tag()],
            vec![
                url(),
                Tag::parse(["method", "GET"]).expect("other method"),
                method(),
                payload_tag(),
            ],
            vec![
                url(),
                method(),
                Tag::parse(["method", "GET"]).expect("other method"),
                payload_tag(),
            ],
            vec![url(), method(), payload_tag(), payload_tag()],
            vec![
                url(),
                method(),
                Tag::parse(["payload", "00"]).expect("other payload"),
                payload_tag(),
            ],
            vec![
                url(),
                method(),
                payload_tag(),
                Tag::parse(["payload", "00"]).expect("other payload"),
            ],
            vec![method(), payload_tag()],
            vec![url(), payload_tag()],
            vec![url(), method()],
        ];

        for tags in rejects {
            let event = signed_nip98(now, &keys, tags);
            assert!(matches!(
                verify_nip98(
                    &event,
                    &protected_target("/protected"),
                    "POST",
                    Some(body),
                    true,
                    now,
                ),
                Err(EvidenceError::InvalidProof)
            ));
        }

        let valid = signed_nip98(now, &keys, vec![url(), method(), payload_tag()]);
        assert!(verify_nip98(
            &valid,
            &protected_target("/protected"),
            "POST",
            Some(body),
            true,
            now,
        )
        .is_ok());

        let malformed_optional_payload = signed_nip98(
            now,
            &keys,
            vec![
                url(),
                method(),
                Tag::parse(["payload"]).expect("malformed payload tag"),
            ],
        );
        assert!(matches!(
            verify_nip98(
                &malformed_optional_payload,
                &protected_target("/protected"),
                "POST",
                None,
                false,
                now,
            ),
            Err(EvidenceError::InvalidProof)
        ));
    }

    struct FixedGrant(AuthoritativeDelegationGrant);

    impl DelegationGrantSource for FixedGrant {
        type Error = ();

        async fn current_grant(
            &self,
            _authorization_domain: CommunityId,
            _owner_pubkey: PublicKey,
            _delegate_pubkey: PublicKey,
            _conditions_fingerprint: [u8; 32],
        ) -> Result<Option<AuthoritativeDelegationGrant>, Self::Error> {
            Ok(Some(self.0.clone()))
        }
    }

    #[tokio::test]
    async fn delegated_pair_is_assertion_free_and_revision_exact() {
        let now = Utc::now();
        let clock = FixedClock(now);
        let binding = fixture_binding();
        let owner = Keys::generate();
        let delegate = Keys::generate();
        let auth_tag = buzz_sdk::nip_oa::compute_auth_tag(&owner, &delegate.public_key(), "")
            .expect("valid delegation signature");
        let event = EventBuilder::auth(
            "challenge",
            RelayUrl::parse("wss://relay.example").expect("relay URL"),
        )
        .custom_created_at(Timestamp::from(now.timestamp() as u64))
        .sign_with_keys(&delegate)
        .expect("sign AUTH event");
        let grants = FixedGrant(
            AuthoritativeDelegationGrant::from_local_store(
                Uuid::from_u128(7),
                9,
                vec![RouteCapability::AudioJoin],
                now + TimeDelta::seconds(30),
            )
            .expect("valid grant"),
        );
        let pair = verify_nip42_delegated(
            &event,
            "challenge",
            "wss://relay.example",
            &auth_tag,
            &binding,
            &grants,
            &clock,
        )
        .await
        .expect("valid delegated pair");
        let (delegation, proof) = pair.into_parts();
        assert_eq!(delegation.owner_pubkey(), owner.public_key());
        assert_eq!(delegation.delegate_pubkey(), delegate.public_key());
        assert_eq!(proof.actor_pubkey(), delegate.public_key());
    }

    #[test]
    fn debug_output_redacts_all_evidence() {
        let binding = fixture_binding();
        assert_eq!(format!("{binding:?}"), "RequestEvidenceBinding([REDACTED])");
        assert_eq!(
            format!("{:?}", verifier_at(fixture_now())),
            "StaticJwksAssertionVerifier([REDACTED])"
        );
    }
}
