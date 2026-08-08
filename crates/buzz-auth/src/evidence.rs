//! Provider-free verification and sealing of corporate identity binding evidence.
//!
//! This module verifies one exact JWT against an immutable JWKS snapshot and
//! binds it to server-resolved authorization coordinates plus an already
//! authenticated Nostr actor. It never decides local admission.

use std::{fmt, sync::Arc, time::Duration};

use base64::Engine as _;
use buzz_core::CommunityId;
use chrono::{DateTime, TimeDelta, Utc};
use http::{HeaderMap, HeaderName};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
    Algorithm, DecodingKey, Validation,
};
use nostr::{FromBech32, PublicKey};
use serde::{
    de::{Error as _, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::foundation::{
    FederatedPrincipal, ProofTransport, VerifiedFederatedAssertion, VerifiedNostrProof,
};

const MAX_IDENTITY_PART_BYTES: usize = 2048;
const MAX_CLAIM_NAME_BYTES: usize = 128;

/// One unambiguous HTTP header occurrence extracted from the complete header map.
///
/// The only constructor examines every occurrence of `name`. It rejects
/// duplicate header lines, comma-joined alternatives, non-UTF-8 values, and
/// leading or trailing whitespace.
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

    /// Borrow the exact validated header bytes as UTF-8.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ExactSingleHttpHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactSingleHttpHeader([REDACTED])")
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

    use jsonwebtoken::{encode, EncodingKey, Header};
    use nostr::{Keys, ToBech32};
    use serde_json::json;

    const TEST_SIGNING_KEY: &[u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20, 0xca, 0x81, 0x76, 0x9d, 0x87, 0xd0, 0x03, 0x9d, 0x8c, 0x55, 0xfa, 0x7d, 0xba, 0xbb,
        0xf4, 0x7b, 0x7c, 0x54, 0xca, 0x69, 0x05, 0x40, 0x50, 0x77, 0xea, 0x88, 0x24, 0x35, 0xcb,
        0xfa, 0xd3, 0x1f,
    ];

    #[derive(Debug)]
    struct FixedClock(DateTime<Utc>);

    impl EvidenceClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn fixture_jwk(kid: &str) -> Jwk {
        serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "oBAtP8MYjHmJjala5i0zw8HhuyXcYODdc9WAwCwC8hA",
            "alg": "EdDSA",
            "kid": kid,
            "use": "sig",
            "key_ops": ["verify"],
        }))
        .expect("fixture JWK")
    }

    fn fixture_policy(maximum_age: Duration, with_key: bool) -> AssertionVerificationPolicy {
        let policy = AssertionVerificationPolicy::new(
            "https://issuer.example",
            "buzz-relay",
            "employee_id",
            maximum_age,
            Duration::from_secs(30),
        )
        .expect("fixture policy");
        if with_key {
            policy
                .with_nostr_key_claim(
                    NostrKeyClaimPolicy::canonical_public_key("nostr_pubkey").expect("key claim"),
                )
                .expect("install key claim")
        } else {
            policy
        }
    }

    fn verified(
        actor: PublicKey,
        maximum_age: Duration,
        with_key: bool,
    ) -> (
        StaticJwksAssertionVerifier,
        ExactSingleHttpHeader,
        RequestEvidenceBinding,
    ) {
        let now = DateTime::from_timestamp(1_750_000_000, 0).expect("fixture time");
        let verifier = StaticJwksAssertionVerifier::with_clock(
            fixture_policy(maximum_age, with_key),
            JwkSet {
                keys: vec![fixture_jwk("fixture-key")],
            },
            Arc::new(FixedClock(now)),
        )
        .expect("fixture verifier");
        let claims = if with_key {
            json!({
                "iss": "https://issuer.example",
                "aud": "buzz-relay",
                "employee_id": "opaque-subject",
                "nostr_pubkey": actor.to_hex(),
                "iat": now.timestamp(),
                "nbf": now.timestamp(),
                "exp": now.timestamp() + 600,
            })
        } else {
            json!({
                "iss": "https://issuer.example",
                "aud": "buzz-relay",
                "employee_id": "opaque-subject",
                "iat": now.timestamp(),
                "nbf": now.timestamp(),
                "exp": now.timestamp() + 600,
            })
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("fixture-key".to_owned());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_ed_der(TEST_SIGNING_KEY),
        )
        .expect("sign fixture assertion");
        let name = HeaderName::from_static("x-buzz-identity");
        let mut headers = HeaderMap::new();
        headers.insert(name.clone(), token.parse().expect("header"));
        let exact = ExactSingleHttpHeader::from_headers(&headers, &name).expect("exact header");
        let binding = RequestEvidenceBinding::new(
            CommunityId::from_uuid(uuid::Uuid::from_u128(7)),
            ProofTransport::Nip42,
            b"fixture-request",
            b"fixture-target",
            b"fixture-transport",
        )
        .expect("binding");
        (verifier, exact, binding)
    }

    #[test]
    fn exact_header_rejects_missing_duplicate_comma_and_whitespace() {
        let name = HeaderName::from_static("x-buzz-identity");
        assert!(matches!(
            ExactSingleHttpHeader::from_headers(&HeaderMap::new(), &name),
            Err(EvidenceError::AmbiguousAssertion)
        ));
        for value in ["a,b", " value", "value "] {
            let mut headers = HeaderMap::new();
            headers.insert(name.clone(), value.parse().expect("header"));
            assert!(ExactSingleHttpHeader::from_headers(&headers, &name).is_err());
        }
        let mut duplicated = HeaderMap::new();
        duplicated.append(name.clone(), "value".parse().expect("header"));
        duplicated.append(name.clone(), "value".parse().expect("header"));
        assert!(ExactSingleHttpHeader::from_headers(&duplicated, &name).is_err());
    }

    #[test]
    fn attested_actor_is_sealed_and_substitution_is_rejected() {
        let actor = Keys::generate().public_key();
        let (verifier, token, binding) = verified(actor, Duration::from_secs(300), true);
        let assertion = verifier
            .verify_client_attached(&token, &binding)
            .expect("verified assertion");
        let evidence = assertion
            .bind_authenticated_actor(actor)
            .expect("exact actor");
        assert!(evidence.enrollment_permitted());
        assert!(evidence.accepts_authorization_coordinates(binding.authorization_domain(), actor,));
        assert_ne!(evidence.evidence_fingerprint(), [0; 32]);
        assert_ne!(evidence.enrollment_policy_digest(), [0; 32]);
        assert_eq!(
            format!("{evidence:?}"),
            "VerifiedIdentityBindingEvidence([REDACTED])"
        );

        let (verifier, token, binding) = verified(actor, Duration::from_secs(300), true);
        assert!(verifier
            .verify_client_attached(&token, &binding)
            .expect("verified assertion")
            .bind_authenticated_actor(Keys::generate().public_key())
            .is_err());
    }

    #[test]
    fn claimless_assertion_is_existing_binding_only() {
        let actor = Keys::generate().public_key();
        let (verifier, token, binding) = verified(actor, Duration::from_secs(300), false);
        let evidence = verifier
            .verify_client_attached(&token, &binding)
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
        let policy = fixture_policy(Duration::from_secs(300), true);
        let first = fixture_jwk("first");
        let second = fixture_jwk("second");
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
}
