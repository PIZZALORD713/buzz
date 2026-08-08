//! Canonical compatibility facade for verified identity bindings.
//!
//! Creation accepts only [`buzz_auth::VerifiedIdentityBindingEvidence`]. The
//! legacy issuer/uid/pubkey mutation surface is removed and cannot reach these
//! writes. A successful birth commits the shared receipt,
//! immutable lifecycle history, binding generation, and authorization event in
//! one transaction under the migration-owned P/X/Y/Q lock order.

mod operator;

pub(crate) use operator::{
    identity_principal_fingerprint, prepare_admission_loss, prepare_provision_binding,
    prepare_verified_operator_transition, AdmissionLossOperationIdentity,
    AuthenticatedLifecycleActor, ExactAdmissionLossTarget, PreparedDirectEnrollmentRejection,
    PreparedDirectEnrollmentWriteFailure, PreparedOperatorLifecycleRejection,
    PreparedOperatorLifecycleWriteFailure, RetiringBindingAuthority, TrustedAdmissionLossCause,
};
pub use operator::{
    IdentityBindingEvidence, IdentityBindingProvenance, IdentityLifecycleDenial,
    IdentityLifecycleFailure, IdentityLifecycleObservation, IdentityLifecycleTransition,
    PersistedIdentityLifecycleOutcome, PreparedAdmissionLoss, PreparedDirectEnrollment,
    PreparedProvisionBinding,
};
use std::fmt;

use buzz_auth::VerifiedIdentityBindingEvidence;
use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use nostr::PublicKey;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::authorization_events::{
    record_authorization_event_tx, record_authorization_operation_receipt_tx,
    AuthorizationActorKind, AuthorizationEventKind, AuthorizationEventOutcome,
    AuthorizationOperationKind, AuthorizationOperationOutcome, AuthorizationOperationReceipt,
    AuthorizationReasonCode, NewAuthorizationEvent,
};
use crate::authorization_policy::load_attested_enrollment_policy_tx;
use crate::{Db, DbError, Result};

/// Opaque active binding retained by an authorization or session runtime.
///
/// Fields are intentionally private: only this module can mint a handle from
/// the exact row that committed or was re-read under canonical lifecycle
/// locks. Cloning a handle does not extend either evidence or binding expiry.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedIdentityBindingHandle {
    community_id: CommunityId,
    binding_id: Uuid,
    binding_version: u64,
    lifecycle_revision: u64,
    principal_fingerprint: [u8; 32],
    event_author_pubkey: [u8; 32],
    enrollment_policy_digest: [u8; 32],
    expires_at: Option<DateTime<Utc>>,
}

impl VerifiedIdentityBindingHandle {
    /// Server-resolved authorization domain sealed into the storage row.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.community_id
    }

    /// Exclusive storage expiry, when this generation is bounded.
    pub const fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// Confirm this storage-minted handle belongs to the authenticated actor
    /// and server-resolved authorization domain without exposing coordinates.
    pub fn accepts_actor(
        &self,
        authorization_domain: CommunityId,
        actor_pubkey: &PublicKey,
    ) -> bool {
        self.community_id == authorization_domain
            && self.event_author_pubkey == actor_pubkey.to_bytes()
    }
}

impl fmt::Debug for VerifiedIdentityBindingHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedIdentityBindingHandle([REDACTED])")
    }
}

/// Closed, redaction-safe reason a verified binding request was denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedIdentityBindingDenial {
    /// Evidence without an exact attested key may resolve but never enroll.
    ExistingBindingRequired,
    /// The verified principal already owns another active generation.
    PrincipalConflict,
    /// The authenticated event-author key belongs to another principal.
    EventAuthorConflict,
    /// An immutable P/X/Y/Q fact or expiry denies this generation.
    LifecycleDenied,
    /// No current attested-key policy and configured audit capacity coexist.
    PolicyUnavailable,
}

/// Result of resolving or canonically enrolling verified identity evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedIdentityBindingOutcome {
    /// A receipt/history/event-backed generation committed now.
    Created(VerifiedIdentityBindingHandle),
    /// The exact active generation already existed.
    Matched(VerifiedIdentityBindingHandle),
    /// No state changed.
    Denied(VerifiedIdentityBindingDenial),
}

#[derive(FromRow)]
struct ActiveBindingRow {
    binding_id: Uuid,
    binding_version: i64,
    issuer: String,
    subject: String,
    principal_fingerprint: Vec<u8>,
    event_author_pubkey: Vec<u8>,
    lifecycle_revision: i64,
    expires_at: Option<DateTime<Utc>>,
}

struct VerifiedCoordinates<'a> {
    community_id: CommunityId,
    issuer: &'a str,
    subject: &'a str,
    principal_fingerprint: [u8; 32],
    event_author_pubkey: [u8; 32],
    evidence_expires_at: DateTime<Utc>,
    enrollment_permitted: bool,
}

impl Db {
    /// Resolve an existing generation or create one from origin-sealed
    /// assertion and authenticated-actor evidence.
    pub async fn resolve_verified_identity_binding(
        &self,
        evidence: &VerifiedIdentityBindingEvidence,
    ) -> Result<VerifiedIdentityBindingOutcome> {
        let mut transaction = self.pool.begin().await?;
        let outcome = resolve_verified_identity_binding_tx(&mut transaction, evidence).await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Atomically recheck an opaque authorization/session handle.
    ///
    /// This is read-only and never updates last-seen state, consumes a
    /// selector, or extends expiry.
    pub async fn revalidate_verified_identity_binding(
        &self,
        handle: &VerifiedIdentityBindingHandle,
    ) -> Result<bool> {
        let row: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM identity_bindings binding \
             WHERE binding.community_id=$1 AND binding.binding_id=$2 \
               AND binding.binding_version=$3 AND binding.lifecycle_revision=$4 \
               AND binding.binding_state=1 AND binding.principal_fingerprint=$5 \
               AND binding.event_author_pubkey=$6 \
               AND (binding.expires_at IS NULL OR binding.expires_at>clock_timestamp()) \
               AND EXISTS(SELECT 1 FROM identity_enrollment_policies policy \
                 WHERE policy.community_id=binding.community_id AND policy.enrollment_mode=1 \
                   AND policy.policy_digest=$7 AND policy.effective_at<=clock_timestamp() \
                   AND (policy.expires_at IS NULL OR policy.expires_at>clock_timestamp())) \
               AND EXISTS(SELECT 1 FROM authorization_event_capacity capacity \
                 WHERE capacity.community_id=binding.community_id \
                   AND capacity.configuration_state=2 AND capacity.health_state=1) \
               AND ($8::timestamptz IS NULL OR $8::timestamptz>clock_timestamp()))",
        )
        .bind(handle.community_id.as_uuid())
        .bind(handle.binding_id)
        .bind(i64::try_from(handle.binding_version).map_err(|_| invalid_stored_binding())?)
        .bind(i64::try_from(handle.lifecycle_revision).map_err(|_| invalid_stored_binding())?)
        .bind(handle.principal_fingerprint.as_slice())
        .bind(handle.event_author_pubkey.as_slice())
        .bind(handle.enrollment_policy_digest.as_slice())
        .bind(handle.expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }
}

pub(crate) async fn resolve_verified_identity_binding_tx(
    transaction: &mut Transaction<'_, Postgres>,
    evidence: &VerifiedIdentityBindingEvidence,
) -> Result<VerifiedIdentityBindingOutcome> {
    let coordinates = verified_coordinates(evidence)?;
    sqlx::query("SELECT identity_lifecycle_lock_coordinates_v1($1,$2,$3)")
        .bind(coordinates.community_id.as_uuid())
        .bind(coordinates.principal_fingerprint.as_slice())
        .bind(coordinates.event_author_pubkey.as_slice())
        .execute(&mut **transaction)
        .await?;

    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;
    if now >= coordinates.evidence_expires_at {
        return Ok(VerifiedIdentityBindingOutcome::Denied(
            VerifiedIdentityBindingDenial::LifecycleDenied,
        ));
    }
    let Some(policy) = load_attested_enrollment_policy_tx(
        transaction,
        coordinates.community_id,
        evidence.enrollment_policy_digest(),
    )
    .await?
    else {
        return Ok(VerifiedIdentityBindingOutcome::Denied(
            VerifiedIdentityBindingDenial::PolicyUnavailable,
        ));
    };

    let active: Vec<ActiveBindingRow> = sqlx::query_as(
        "SELECT binding_id,binding_version,issuer,subject,principal_fingerprint,\
                event_author_pubkey,lifecycle_revision,expires_at \
         FROM identity_bindings WHERE community_id=$1 AND binding_state=1 \
           AND ((issuer=$2 AND subject=$3) OR event_author_pubkey=$4) \
         ORDER BY binding_version FOR UPDATE",
    )
    .bind(coordinates.community_id.as_uuid())
    .bind(coordinates.issuer)
    .bind(coordinates.subject)
    .bind(coordinates.event_author_pubkey.as_slice())
    .fetch_all(&mut **transaction)
    .await?;

    for binding in active {
        let same_principal =
            binding.issuer == coordinates.issuer && binding.subject == coordinates.subject;
        let same_key = binding.event_author_pubkey == coordinates.event_author_pubkey;
        if same_principal && same_key {
            if binding.principal_fingerprint != coordinates.principal_fingerprint
                || binding
                    .expires_at
                    .is_some_and(|expires_at| now >= expires_at)
            {
                return Ok(VerifiedIdentityBindingOutcome::Denied(
                    VerifiedIdentityBindingDenial::LifecycleDenied,
                ));
            }
            return Ok(VerifiedIdentityBindingOutcome::Matched(handle_from_row(
                coordinates.community_id,
                binding,
                policy.digest,
                coordinates.evidence_expires_at,
            )?));
        }
        if same_principal {
            return Ok(VerifiedIdentityBindingOutcome::Denied(
                VerifiedIdentityBindingDenial::PrincipalConflict,
            ));
        }
        if same_key {
            return Ok(VerifiedIdentityBindingOutcome::Denied(
                VerifiedIdentityBindingDenial::EventAuthorConflict,
            ));
        }
    }

    let selector_conflict: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
           SELECT 1 FROM identity_lifecycle_selectors selector \
           LEFT JOIN identity_lifecycle_selector_consumptions consumption \
             ON consumption.community_id=selector.community_id \
            AND consumption.selector_id=selector.selector_id \
           WHERE selector.community_id=$1 AND ( \
             (selector.selector_kind=1 AND selector.principal_fingerprint=$2 \
               AND selector.event_author_pubkey=$3) \
             OR (selector.selector_kind=3 AND selector.event_author_pubkey=$3) \
             OR (selector.selector_kind IN (2,4) \
               AND selector.principal_fingerprint=$2 AND consumption.selector_id IS NULL)))",
    )
    .bind(coordinates.community_id.as_uuid())
    .bind(coordinates.principal_fingerprint.as_slice())
    .bind(coordinates.event_author_pubkey.as_slice())
    .fetch_one(&mut **transaction)
    .await?;
    if selector_conflict {
        return Ok(VerifiedIdentityBindingOutcome::Denied(
            VerifiedIdentityBindingDenial::LifecycleDenied,
        ));
    }
    if !coordinates.enrollment_permitted {
        return Ok(VerifiedIdentityBindingOutcome::Denied(
            VerifiedIdentityBindingDenial::ExistingBindingRequired,
        ));
    }
    let operation_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let binding_id = Uuid::new_v4();
    let history_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let actor_fingerprint = framed_digest(
        b"buzz:verified-identity-actor:v1",
        &[
            coordinates.community_id.as_uuid().as_bytes(),
            &coordinates.event_author_pubkey,
        ],
    );
    let evidence_digest = evidence.evidence_fingerprint();
    if evidence_digest == [0; 32] {
        return Err(DbError::InvalidData(
            "verified identity evidence fingerprint is invalid".to_owned(),
        ));
    }
    let request_fingerprint = framed_digest(
        b"buzz:verified-identity-enrollment-request:v1",
        &[
            coordinates.community_id.as_uuid().as_bytes(),
            operation_id.as_bytes(),
            &coordinates.principal_fingerprint,
            &coordinates.event_author_pubkey,
            &policy.revision.to_be_bytes(),
            &policy.digest,
            &evidence_digest,
        ],
    );
    // The binding sequence allocates the immutable generation first. All
    // related foreign keys are deferred, so the receipt/history/event can be
    // written afterward in this same transaction and the result digest can
    // bind the exact version returned to the caller.
    let binding_version: i64 = sqlx::query_scalar(
        "INSERT INTO identity_bindings \
         (community_id,binding_id,issuer,subject,principal_fingerprint,event_author_pubkey,\
          binding_state,lifecycle_revision,binding_provenance,policy_revision,\
          enrollment_evidence_digest,expires_at,birth_history_id,creation_operation_id,\
          creation_request_fingerprint) \
         VALUES ($1,$2,$3,$4,$5,$6,1,1,1,$7,$8,$9,$10,$11,$12) \
         RETURNING binding_version",
    )
    .bind(coordinates.community_id.as_uuid())
    .bind(binding_id)
    .bind(coordinates.issuer)
    .bind(coordinates.subject)
    .bind(coordinates.principal_fingerprint.as_slice())
    .bind(coordinates.event_author_pubkey.as_slice())
    .bind(i64::try_from(policy.revision).map_err(|_| invalid_policy())?)
    .bind(evidence_digest.as_slice())
    .bind(coordinates.evidence_expires_at)
    .bind(history_id)
    .bind(operation_id)
    .bind(request_fingerprint.as_slice())
    .fetch_one(&mut **transaction)
    .await?;
    let result_digest = framed_digest(
        b"buzz:identity-lifecycle-result:v1",
        &[
            coordinates.community_id.as_uuid().as_bytes(),
            operation_id.as_bytes(),
            binding_id.as_bytes(),
            &binding_version.to_be_bytes(),
            &coordinates.principal_fingerprint,
            &coordinates.event_author_pubkey,
        ],
    );
    record_authorization_operation_receipt_tx(
        transaction,
        &AuthorizationOperationReceipt {
            community_id: coordinates.community_id,
            operation_id,
            request_fingerprint,
            operation_kind: AuthorizationOperationKind::Enroll,
            actor_fingerprint,
            outcome: AuthorizationOperationOutcome::Applied,
            result_digest,
        },
    )
    .await?;
    let transition_digest = framed_digest(
        b"buzz:identity-lifecycle-transition:v1",
        &[
            coordinates.community_id.as_uuid().as_bytes(),
            operation_id.as_bytes(),
            binding_id.as_bytes(),
            &binding_version.to_be_bytes(),
        ],
    );
    sqlx::query(
        "INSERT INTO identity_lifecycle_history \
         (community_id,history_id,transition_kind,outcome_code,successor_binding_id,\
          successor_binding_version,successor_lifecycle_revision,successor_state,operation_id,\
          request_fingerprint,transition_digest) \
         VALUES ($1,$2,1,1,$3,$4,1,1,$5,$6,$7)",
    )
    .bind(coordinates.community_id.as_uuid())
    .bind(history_id)
    .bind(binding_id)
    .bind(binding_version)
    .bind(operation_id)
    .bind(request_fingerprint.as_slice())
    .bind(transition_digest.as_slice())
    .execute(&mut **transaction)
    .await?;
    record_authorization_event_tx(
        transaction,
        &NewAuthorizationEvent {
            community_id: coordinates.community_id,
            event_id,
            event_kind: AuthorizationEventKind::Enrolled,
            outcome: AuthorizationEventOutcome::Allowed,
            reason: AuthorizationReasonCode::Current,
            actor_kind: AuthorizationActorKind::Direct,
            actor_fingerprint,
            subject_fingerprint: coordinates.principal_fingerprint,
            operation_id,
            request_fingerprint,
            correlation_id,
            attempt_id,
            occurred_at: now,
        },
    )
    .await?;
    let binding_version = u64::try_from(binding_version).map_err(|_| invalid_stored_binding())?;
    Ok(VerifiedIdentityBindingOutcome::Created(
        VerifiedIdentityBindingHandle {
            community_id: coordinates.community_id,
            binding_id,
            binding_version,
            lifecycle_revision: 1,
            principal_fingerprint: coordinates.principal_fingerprint,
            event_author_pubkey: coordinates.event_author_pubkey,
            enrollment_policy_digest: policy.digest,
            expires_at: Some(coordinates.evidence_expires_at),
        },
    ))
}

pub(crate) fn verified_identity_matches_member(
    community_id: CommunityId,
    member_pubkey: &[u8],
    evidence: &VerifiedIdentityBindingEvidence,
) -> bool {
    evidence.assertion().authorization_domain() == community_id
        && member_pubkey == evidence.actor_pubkey().to_bytes().as_slice()
}

fn verified_coordinates(
    evidence: &VerifiedIdentityBindingEvidence,
) -> Result<VerifiedCoordinates<'_>> {
    let assertion = evidence.assertion();
    let community_id = assertion.authorization_domain();
    let principal = assertion.principal_storage_key();
    let event_author_pubkey = evidence.actor_pubkey().to_bytes();
    if community_id.as_uuid().is_nil()
        || principal.issuer().is_empty()
        || principal.subject().is_empty()
    {
        return Err(DbError::InvalidData(
            "verified identity binding evidence is invalid".to_owned(),
        ));
    }
    let principal_fingerprint = principal_fingerprint(
        community_id,
        principal.issuer().as_bytes(),
        principal.subject().as_bytes(),
    );
    Ok(VerifiedCoordinates {
        community_id,
        issuer: principal.issuer(),
        subject: principal.subject(),
        principal_fingerprint,
        event_author_pubkey,
        evidence_expires_at: evidence.expires_at(),
        enrollment_permitted: evidence.enrollment_permitted(),
    })
}

fn handle_from_row(
    community_id: CommunityId,
    row: ActiveBindingRow,
    enrollment_policy_digest: [u8; 32],
    evidence_expires_at: DateTime<Utc>,
) -> Result<VerifiedIdentityBindingHandle> {
    let binding_version =
        u64::try_from(row.binding_version).map_err(|_| invalid_stored_binding())?;
    let lifecycle_revision =
        u64::try_from(row.lifecycle_revision).map_err(|_| invalid_stored_binding())?;
    let principal_fingerprint = row
        .principal_fingerprint
        .try_into()
        .map_err(|_| invalid_stored_binding())?;
    let event_author_pubkey = row
        .event_author_pubkey
        .try_into()
        .map_err(|_| invalid_stored_binding())?;
    let expires_at = row.expires_at.map_or(evidence_expires_at, |stored| {
        stored.min(evidence_expires_at)
    });
    if row.binding_id.is_nil()
        || binding_version == 0
        || lifecycle_revision != 1
        || principal_fingerprint == [0; 32]
        || event_author_pubkey == [0; 32]
        || enrollment_policy_digest == [0; 32]
    {
        return Err(invalid_stored_binding());
    }
    Ok(VerifiedIdentityBindingHandle {
        community_id,
        binding_id: row.binding_id,
        binding_version,
        lifecycle_revision,
        principal_fingerprint,
        event_author_pubkey,
        enrollment_policy_digest,
        expires_at: Some(expires_at),
    })
}

pub(crate) fn principal_fingerprint(
    community_id: CommunityId,
    issuer: &[u8],
    subject: &[u8],
) -> [u8; 32] {
    framed_digest(
        b"buzz:identity-principal:v1",
        &[community_id.as_uuid().as_bytes(), issuer, subject],
    )
}

fn framed_digest(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest.finalize().into()
}

fn invalid_stored_binding() -> DbError {
    DbError::InvalidData("invalid canonical identity binding row".to_owned())
}

fn invalid_policy() -> DbError {
    DbError::InvalidData("invalid canonical identity enrollment policy".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{sync::Arc, time::Duration};

    use buzz_auth::{
        AssertionVerificationPolicy, AuthorizationEventCapacityPolicy, EvidenceClock,
        ExactSingleHttpHeader, NostrKeyClaimPolicy, ProofTransport, RequestEvidenceBinding,
        StaticJwksAssertionVerifier,
    };
    use http::{HeaderMap, HeaderName};
    use jsonwebtoken::{
        encode,
        jwk::{Jwk, JwkSet},
        Algorithm, EncodingKey, Header,
    };
    use nostr::Keys;
    use serde_json::json;

    use crate::{
        channel::{
            add_member_with_identity, create_channel, ChannelAdmissionOutcome, ChannelType,
            ChannelVisibility, MemberRole,
        },
        relay_invite::{
            claim_relay_invite, claim_relay_invite_with_identity, mint_relay_invite, ClaimOutcome,
        },
        relay_members::{
            claim_relay_membership_with_identity, is_relay_member, MembershipClaimOutcome,
        },
        DbConfig,
    };

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1
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

    async fn test_db() -> Db {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_owned());
        Db::new(&DbConfig {
            database_url,
            max_connections: 2,
            min_connections: 0,
            ..DbConfig::default()
        })
        .await
        .expect("connect to test DB")
    }

    async fn fresh_community(db: &Db) -> CommunityId {
        let community_id = CommunityId::from_uuid(Uuid::new_v4());
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(community_id.as_uuid())
            .bind(format!(
                "identity-lifecycle-test-{}.example",
                community_id.as_uuid().simple()
            ))
            .execute(&db.pool)
            .await
            .expect("insert test community");
        community_id
    }

    fn verified_evidence(
        community_id: CommunityId,
        actor: &Keys,
        maximum_age: Duration,
        with_key_claim: bool,
    ) -> ([u8; 32], VerifiedIdentityBindingEvidence) {
        let now = Utc::now();
        let mut policy = AssertionVerificationPolicy::new(
            "https://issuer.example",
            "buzz-relay",
            "employee_id",
            maximum_age,
            Duration::from_secs(30),
        )
        .expect("valid assertion policy");
        if with_key_claim {
            policy = policy
                .with_nostr_key_claim(
                    NostrKeyClaimPolicy::lower_hex("nostr_pubkey").expect("valid key-claim policy"),
                )
                .expect("install key-claim policy");
        }
        let signing_key = EncodingKey::from_ed_der(TEST_SIGNING_KEY);
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "oBAtP8MYjHmJjala5i0zw8HhuyXcYODdc9WAwCwC8hA",
            "alg": "EdDSA",
            "kid": "identity-lifecycle-test-key",
            "use": "sig",
            "key_ops": ["verify"],
        }))
        .expect("decode fixture JWK");
        let verifier = StaticJwksAssertionVerifier::with_clock(
            policy,
            JwkSet { keys: vec![jwk] },
            Arc::new(FixedClock(now)),
        )
        .expect("construct fixture verifier");
        let digest = verifier.enrollment_policy_digest();
        let claims = json!({
            "iss": "https://issuer.example",
            "aud": "buzz-relay",
            "employee_id": "opaque-identity-lifecycle-subject",
            "nostr_pubkey": actor.public_key().to_hex(),
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": now.timestamp() + 600,
        });
        let mut jwt_header = Header::new(Algorithm::EdDSA);
        jwt_header.kid = Some("identity-lifecycle-test-key".to_owned());
        let token = encode(&jwt_header, &claims, &signing_key).expect("sign fixture assertion");
        let mut headers = HeaderMap::new();
        let header_name = HeaderName::from_static("x-buzz-identity");
        headers.insert(
            header_name.clone(),
            token.parse().expect("valid fixture assertion header"),
        );
        let token = ExactSingleHttpHeader::from_headers(&headers, &header_name)
            .expect("extract exact fixture assertion");
        let binding = RequestEvidenceBinding::new(
            community_id,
            ProofTransport::Nip42,
            b"identity-lifecycle-test-request",
            b"identity-lifecycle-test-target",
            b"identity-lifecycle-test-transport",
        )
        .expect("valid fixture request binding");
        let evidence = verifier
            .verify_client_attached(&token, &binding)
            .expect("verify fixture assertion")
            .bind_authenticated_actor(actor.public_key())
            .expect("bind fixture actor");
        (digest, evidence)
    }

    async fn canonical_counts(db: &Db, community_id: CommunityId) -> [i64; 4] {
        let receipt: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM authorization_operation_receipts WHERE community_id=$1",
        )
        .bind(community_id.as_uuid())
        .fetch_one(&db.pool)
        .await
        .expect("count receipts");
        let history: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM identity_lifecycle_history WHERE community_id=$1",
        )
        .bind(community_id.as_uuid())
        .fetch_one(&db.pool)
        .await
        .expect("count history");
        let event: i64 =
            sqlx::query_scalar("SELECT count(*) FROM authorization_events WHERE community_id=$1")
                .bind(community_id.as_uuid())
                .fetch_one(&db.pool)
                .await
                .expect("count events");
        let binding: i64 =
            sqlx::query_scalar("SELECT count(*) FROM identity_bindings WHERE community_id=$1")
                .bind(community_id.as_uuid())
                .fetch_one(&db.pool)
                .await
                .expect("count bindings");
        [receipt, history, event, binding]
    }

    async fn install_fixture_policy(db: &Db, community_id: CommunityId, policy_digest: [u8; 32]) {
        let now = Utc::now();
        db.install_attested_identity_enrollment_policy(
            community_id,
            1,
            policy_digest,
            now - chrono::TimeDelta::minutes(1),
            Some(now + chrono::TimeDelta::hours(1)),
            AuthorizationEventCapacityPolicy::new(100, 1_048_576, 65_536)
                .expect("valid fixture capacity"),
        )
        .await
        .expect("install fixture policy and capacity");
    }

    async fn invite_use_count(db: &Db, community_id: CommunityId, invite_id: Uuid) -> i32 {
        sqlx::query_scalar("SELECT use_count FROM relay_invites WHERE community_id=$1 AND id=$2")
            .bind(community_id.as_uuid())
            .bind(invite_id)
            .fetch_one(&db.pool)
            .await
            .expect("read invite use count")
    }

    async fn active_channel_membership_count(
        db: &Db,
        community_id: CommunityId,
        channel_id: Uuid,
        member: &[u8],
    ) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM channel_members \
             WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3 AND removed_at IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(channel_id)
        .bind(member)
        .fetch_one(&db.pool)
        .await
        .expect("count active channel membership")
    }

    async fn install_identity_insert_failure(
        db: &Db,
        community_id: CommunityId,
    ) -> (String, String) {
        let suffix = community_id.as_uuid().simple();
        let function_name = format!("buzz_test_fail_identity_{suffix}");
        let trigger_name = format!("buzz_test_fail_identity_insert_{suffix}");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'injected canonical identity storage failure'; END $$"
        )))
        .execute(&db.pool)
        .await
        .expect("create identity failure function");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE TRIGGER {trigger_name} BEFORE INSERT ON identity_bindings \
             FOR EACH ROW WHEN (NEW.community_id = '{}'::uuid) \
             EXECUTE FUNCTION {function_name}()",
            community_id.as_uuid()
        )))
        .execute(&db.pool)
        .await
        .expect("create identity failure trigger");
        (function_name, trigger_name)
    }

    async fn remove_identity_insert_failure(db: &Db, function_name: &str, trigger_name: &str) {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP TRIGGER {trigger_name} ON identity_bindings"
        )))
        .execute(&db.pool)
        .await
        .expect("drop identity failure trigger");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP FUNCTION {function_name}()"
        )))
        .execute(&db.pool)
        .await
        .expect("drop identity failure function");
    }

    async fn exercise_invite_atomic_compatibility(db: &Db) {
        let domain = fresh_community(db).await;
        let actor = Keys::generate();
        let actor_hex = actor.public_key().to_hex();
        let (policy_digest, evidence) =
            verified_evidence(domain, &actor, Duration::from_secs(300), true);
        install_fixture_policy(db, domain, policy_digest).await;

        assert_eq!(
            claim_relay_invite_with_identity(
                &db.pool,
                domain,
                &[9; 32],
                &actor_hex,
                None,
                Some(&evidence),
            )
            .await
            .expect("invalid invite result"),
            ClaimOutcome::Invalid
        );
        assert_eq!(canonical_counts(db, domain).await, [0, 0, 0, 0]);

        let exhausted = mint_relay_invite(&db.pool, domain, "fixture-owner", 3600, Some(1))
            .await
            .expect("mint exhausted invite");
        let exhausted_hash = buzz_core::invite::hash_v2_code(&exhausted.code);
        let capacity_winner = Keys::generate().public_key().to_hex();
        assert!(matches!(
            claim_relay_invite(&db.pool, domain, &exhausted_hash, &capacity_winner, None,)
                .await
                .expect("consume final invite slot"),
            ClaimOutcome::Joined {
                use_count: 1,
                identity_binding: None,
                ..
            }
        ));
        assert_eq!(
            claim_relay_invite_with_identity(
                &db.pool,
                domain,
                &exhausted_hash,
                &actor_hex,
                None,
                Some(&evidence),
            )
            .await
            .expect("exhausted invite result"),
            ClaimOutcome::Exhausted
        );
        assert_eq!(invite_use_count(db, domain, exhausted.invite_id).await, 1);
        assert_eq!(canonical_counts(db, domain).await, [0, 0, 0, 0]);
        assert!(!is_relay_member(&db.pool, domain, &actor_hex)
            .await
            .expect("exhausted invite membership check"));

        let denied = mint_relay_invite(&db.pool, domain, "fixture-owner", 3600, Some(1))
            .await
            .expect("mint denied invite");
        let denied_hash = buzz_core::invite::hash_v2_code(&denied.code);
        let (_, mismatched_evidence) =
            verified_evidence(domain, &actor, Duration::from_secs(299), true);
        assert_eq!(
            claim_relay_invite_with_identity(
                &db.pool,
                domain,
                &denied_hash,
                &actor_hex,
                None,
                Some(&mismatched_evidence),
            )
            .await
            .expect("policy-denied invite result"),
            ClaimOutcome::IdentityDenied(VerifiedIdentityBindingDenial::PolicyUnavailable)
        );
        assert_eq!(invite_use_count(db, domain, denied.invite_id).await, 0);
        assert_eq!(canonical_counts(db, domain).await, [0, 0, 0, 0]);
        assert!(!is_relay_member(&db.pool, domain, &actor_hex)
            .await
            .expect("denied invite membership check"));

        let failed = mint_relay_invite(&db.pool, domain, "fixture-owner", 3600, Some(1))
            .await
            .expect("mint storage-failure invite");
        let failed_hash = buzz_core::invite::hash_v2_code(&failed.code);
        let (failure_function, failure_trigger) = install_identity_insert_failure(db, domain).await;
        let failed_claim = claim_relay_invite_with_identity(
            &db.pool,
            domain,
            &failed_hash,
            &actor_hex,
            None,
            Some(&evidence),
        )
        .await;
        remove_identity_insert_failure(db, &failure_function, &failure_trigger).await;
        assert!(matches!(failed_claim, Err(DbError::Sqlx(_))));
        assert_eq!(invite_use_count(db, domain, failed.invite_id).await, 0);
        assert_eq!(canonical_counts(db, domain).await, [0, 0, 0, 0]);
        assert!(!is_relay_member(&db.pool, domain, &actor_hex)
            .await
            .expect("storage-failed invite membership check"));

        let successful = mint_relay_invite(&db.pool, domain, "fixture-owner", 3600, Some(1))
            .await
            .expect("mint successful invite");
        let successful_hash = buzz_core::invite::hash_v2_code(&successful.code);
        assert!(matches!(
            claim_relay_invite_with_identity(
                &db.pool,
                domain,
                &successful_hash,
                &actor_hex,
                None,
                Some(&evidence),
            )
            .await
            .expect("successful invite admission"),
            ClaimOutcome::Joined {
                use_count: 1,
                identity_binding: Some(_),
                ..
            }
        ));
        assert_eq!(canonical_counts(db, domain).await, [1, 1, 1, 1]);
        assert_eq!(invite_use_count(db, domain, successful.invite_id).await, 1);
        assert!(is_relay_member(&db.pool, domain, &actor_hex)
            .await
            .expect("successful invite membership check"));
        assert!(matches!(
            claim_relay_invite_with_identity(
                &db.pool,
                domain,
                &successful_hash,
                &actor_hex,
                None,
                Some(&evidence),
            )
            .await
            .expect("successful invite retry"),
            ClaimOutcome::AlreadyMember {
                use_count: 1,
                identity_binding: Some(_),
                ..
            }
        ));
        assert_eq!(canonical_counts(db, domain).await, [1, 1, 1, 1]);
    }

    async fn exercise_relay_member_atomic_compatibility(db: &Db) {
        let domain = fresh_community(db).await;
        let actor = Keys::generate();
        let actor_hex = actor.public_key().to_hex();
        let (policy_digest, evidence) =
            verified_evidence(domain, &actor, Duration::from_secs(300), true);
        install_fixture_policy(db, domain, policy_digest).await;

        assert!(matches!(
            claim_relay_membership_with_identity(
                &db.pool,
                domain,
                &actor_hex,
                "member",
                None,
                Some(&evidence),
            )
            .await
            .expect("direct relay-member admission"),
            MembershipClaimOutcome::Joined {
                inserted: true,
                identity_binding: Some(_),
            }
        ));
        assert_eq!(canonical_counts(db, domain).await, [1, 1, 1, 1]);
        assert!(matches!(
            claim_relay_membership_with_identity(
                &db.pool,
                domain,
                &actor_hex,
                "member",
                None,
                Some(&evidence),
            )
            .await
            .expect("direct relay-member retry"),
            MembershipClaimOutcome::Joined {
                inserted: false,
                identity_binding: Some(_),
            }
        ));
        assert_eq!(canonical_counts(db, domain).await, [1, 1, 1, 1]);
        assert!(is_relay_member(&db.pool, domain, &actor_hex)
            .await
            .expect("direct relay-member membership check"));
    }

    async fn exercise_private_channel_atomic_compatibility(db: &Db) {
        let domain = fresh_community(db).await;
        let owner = Keys::generate();
        let joiner = Keys::generate();
        let joiner_key = joiner.public_key().to_bytes();
        let owner_key = owner.public_key().to_bytes();
        let (policy_digest, evidence) =
            verified_evidence(domain, &joiner, Duration::from_secs(300), true);
        install_fixture_policy(db, domain, policy_digest).await;
        let channel = create_channel(
            &db.pool,
            domain,
            "canonical-atomic-compatibility",
            ChannelType::Stream,
            ChannelVisibility::Private,
            None,
            &owner_key,
            Some(3600),
        )
        .await
        .expect("create private fixture channel");

        let unauthorized_inviter = Keys::generate().public_key().to_bytes();
        let unauthorized = add_member_with_identity(
            &db.pool,
            domain,
            channel.id,
            &joiner_key,
            MemberRole::Member,
            Some(&unauthorized_inviter),
            Some(&evidence),
        )
        .await;
        assert!(matches!(unauthorized, Err(DbError::AccessDenied(_))));
        assert_eq!(
            active_channel_membership_count(db, domain, channel.id, &joiner_key).await,
            0
        );
        assert_eq!(canonical_counts(db, domain).await, [0, 0, 0, 0]);

        let (_, mismatched_evidence) =
            verified_evidence(domain, &joiner, Duration::from_secs(299), true);
        assert!(matches!(
            add_member_with_identity(
                &db.pool,
                domain,
                channel.id,
                &joiner_key,
                MemberRole::Member,
                Some(&owner_key),
                Some(&mismatched_evidence),
            )
            .await
            .expect("policy-denied channel admission"),
            ChannelAdmissionOutcome::IdentityDenied(
                VerifiedIdentityBindingDenial::PolicyUnavailable
            )
        ));
        assert_eq!(
            active_channel_membership_count(db, domain, channel.id, &joiner_key).await,
            0
        );
        assert_eq!(canonical_counts(db, domain).await, [0, 0, 0, 0]);

        let (failure_function, failure_trigger) = install_identity_insert_failure(db, domain).await;
        let failed_add = add_member_with_identity(
            &db.pool,
            domain,
            channel.id,
            &joiner_key,
            MemberRole::Member,
            Some(&owner_key),
            Some(&evidence),
        )
        .await;
        remove_identity_insert_failure(db, &failure_function, &failure_trigger).await;
        assert!(matches!(failed_add, Err(DbError::Sqlx(_))));
        assert_eq!(
            active_channel_membership_count(db, domain, channel.id, &joiner_key).await,
            0
        );
        assert_eq!(canonical_counts(db, domain).await, [0, 0, 0, 0]);

        assert!(matches!(
            add_member_with_identity(
                &db.pool,
                domain,
                channel.id,
                &joiner_key,
                MemberRole::Member,
                Some(&owner_key),
                Some(&evidence),
            )
            .await
            .expect("successful private-channel admission"),
            ChannelAdmissionOutcome::Joined {
                identity_binding: Some(_),
                ..
            }
        ));
        assert_eq!(
            active_channel_membership_count(db, domain, channel.id, &joiner_key).await,
            1
        );
        assert_eq!(canonical_counts(db, domain).await, [1, 1, 1, 1]);
        assert!(matches!(
            add_member_with_identity(
                &db.pool,
                domain,
                channel.id,
                &joiner_key,
                MemberRole::Member,
                Some(&owner_key),
                Some(&evidence),
            )
            .await
            .expect("private-channel admission retry"),
            ChannelAdmissionOutcome::Joined {
                identity_binding: Some(_),
                ..
            }
        ));
        assert_eq!(
            active_channel_membership_count(db, domain, channel.id, &joiner_key).await,
            1
        );
        assert_eq!(canonical_counts(db, domain).await, [1, 1, 1, 1]);
    }

    #[test]
    fn handle_debug_is_redacted() {
        let handle = VerifiedIdentityBindingHandle {
            community_id: CommunityId::from_uuid(Uuid::new_v4()),
            binding_id: Uuid::new_v4(),
            binding_version: 7,
            lifecycle_revision: 1,
            principal_fingerprint: [3; 32],
            event_author_pubkey: [4; 32],
            enrollment_policy_digest: [5; 32],
            expires_at: None,
        };
        assert_eq!(
            format!("{handle:?}"),
            "VerifiedIdentityBindingHandle([REDACTED])"
        );
    }

    #[test]
    fn principal_fingerprint_is_domain_and_length_framed() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        assert_ne!(
            principal_fingerprint(domain, b"ab", b"c"),
            principal_fingerprint(domain, b"a", b"bc")
        );
        assert_ne!(
            principal_fingerprint(domain, b"issuer", b"subject"),
            principal_fingerprint(
                CommunityId::from_uuid(Uuid::new_v4()),
                b"issuer",
                b"subject"
            )
        );
    }

    #[test]
    fn handle_accepts_only_exact_actor_and_domain() {
        let actor = Keys::generate();
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let handle = VerifiedIdentityBindingHandle {
            community_id: domain,
            binding_id: Uuid::new_v4(),
            binding_version: 1,
            lifecycle_revision: 1,
            principal_fingerprint: [3; 32],
            event_author_pubkey: actor.public_key().to_bytes(),
            enrollment_policy_digest: [5; 32],
            expires_at: None,
        };
        assert!(handle.accepts_actor(domain, &actor.public_key()));
        assert!(!handle.accepts_actor(CommunityId::from_uuid(Uuid::new_v4()), &actor.public_key()));
        assert!(!handle.accepts_actor(domain, &Keys::generate().public_key()));
    }

    #[tokio::test]
    #[ignore = "requires Postgres migrated through 0031"]
    async fn canonical_enrollment_state_machine_is_atomic_and_idempotent() {
        let db = test_db().await;
        let community_id = fresh_community(&db).await;
        let actor = Keys::generate();
        let (policy_digest, evidence) =
            verified_evidence(community_id, &actor, Duration::from_secs(300), true);
        let now = Utc::now();
        db.install_attested_identity_enrollment_policy(
            community_id,
            1,
            policy_digest,
            now - chrono::TimeDelta::minutes(1),
            Some(now + chrono::TimeDelta::hours(1)),
            AuthorizationEventCapacityPolicy::new(100, 1_048_576, 65_536)
                .expect("valid fixture capacity"),
        )
        .await
        .expect("install matching policy and capacity");
        db.install_attested_identity_enrollment_policy(
            community_id,
            1,
            policy_digest,
            now - chrono::TimeDelta::minutes(1),
            Some(now + chrono::TimeDelta::hours(1)),
            AuthorizationEventCapacityPolicy::new(100, 1_048_576, 65_536)
                .expect("valid fixture capacity replay"),
        )
        .await
        .expect("exactly replay matching policy and capacity");

        let created = db
            .resolve_verified_identity_binding(&evidence)
            .await
            .expect("create canonical binding");
        let created_handle = match created {
            VerifiedIdentityBindingOutcome::Created(handle) => handle,
            other => panic!("expected created binding, got {other:?}"),
        };
        assert!(created_handle.accepts_actor(community_id, &actor.public_key()));
        assert_eq!(canonical_counts(&db, community_id).await, [1, 1, 1, 1]);

        assert!(matches!(
            db.resolve_verified_identity_binding(&evidence)
                .await
                .expect("retry canonical binding"),
            VerifiedIdentityBindingOutcome::Matched(_)
        ));
        assert_eq!(canonical_counts(&db, community_id).await, [1, 1, 1, 1]);

        let (_, mismatched_policy_evidence) =
            verified_evidence(community_id, &actor, Duration::from_secs(299), true);
        assert_eq!(
            db.resolve_verified_identity_binding(&mismatched_policy_evidence)
                .await
                .expect("deny mismatched verifier policy"),
            VerifiedIdentityBindingOutcome::Denied(
                VerifiedIdentityBindingDenial::PolicyUnavailable
            )
        );
        assert_eq!(canonical_counts(&db, community_id).await, [1, 1, 1, 1]);

        let (claimless_digest, claimless_evidence) =
            verified_evidence(community_id, &actor, Duration::from_secs(300), false);
        assert_eq!(
            db.resolve_verified_identity_binding(&claimless_evidence)
                .await
                .expect("deny claim-less evidence without matching policy"),
            VerifiedIdentityBindingOutcome::Denied(
                VerifiedIdentityBindingDenial::PolicyUnavailable
            )
        );
        db.install_attested_identity_enrollment_policy(
            community_id,
            2,
            claimless_digest,
            now - chrono::TimeDelta::minutes(1),
            Some(now + chrono::TimeDelta::hours(1)),
            AuthorizationEventCapacityPolicy::new(100, 1_048_576, 65_536)
                .expect("valid fixture capacity replay"),
        )
        .await
        .expect("install claim-less matching policy");
        assert!(matches!(
            db.resolve_verified_identity_binding(&claimless_evidence)
                .await
                .expect("claim-less exact existing match"),
            VerifiedIdentityBindingOutcome::Matched(_)
        ));
        assert_eq!(canonical_counts(&db, community_id).await, [1, 1, 1, 1]);
        assert!(db
            .revalidate_verified_identity_binding(&created_handle)
            .await
            .expect("revalidate exact handle"));

        let claimless_domain = fresh_community(&db).await;
        let (claimless_creation_digest, claimless_creation_evidence) = verified_evidence(
            claimless_domain,
            &Keys::generate(),
            Duration::from_secs(300),
            false,
        );
        db.install_attested_identity_enrollment_policy(
            claimless_domain,
            1,
            claimless_creation_digest,
            now - chrono::TimeDelta::minutes(1),
            Some(now + chrono::TimeDelta::hours(1)),
            AuthorizationEventCapacityPolicy::new(100, 1_048_576, 65_536)
                .expect("valid claim-less creation capacity"),
        )
        .await
        .expect("install claim-less creation policy");
        assert_eq!(
            db.resolve_verified_identity_binding(&claimless_creation_evidence)
                .await
                .expect("deny claim-less creation"),
            VerifiedIdentityBindingOutcome::Denied(
                VerifiedIdentityBindingDenial::ExistingBindingRequired
            )
        );
        assert_eq!(canonical_counts(&db, claimless_domain).await, [0, 0, 0, 0]);

        let missing_domain = fresh_community(&db).await;
        let (_, missing_evidence) = verified_evidence(
            missing_domain,
            &Keys::generate(),
            Duration::from_secs(300),
            true,
        );
        assert_eq!(
            db.resolve_verified_identity_binding(&missing_evidence)
                .await
                .expect("missing policy is a closed denial"),
            VerifiedIdentityBindingOutcome::Denied(
                VerifiedIdentityBindingDenial::PolicyUnavailable
            )
        );
        assert_eq!(canonical_counts(&db, missing_domain).await, [0, 0, 0, 0]);

        for (label, effective_at, expires_at) in [
            (
                "future",
                now + chrono::TimeDelta::hours(1),
                Some(now + chrono::TimeDelta::hours(2)),
            ),
            (
                "expired",
                now - chrono::TimeDelta::hours(2),
                Some(now - chrono::TimeDelta::hours(1)),
            ),
        ] {
            let domain = fresh_community(&db).await;
            let (digest, evidence) =
                verified_evidence(domain, &Keys::generate(), Duration::from_secs(300), true);
            db.install_attested_identity_enrollment_policy(
                domain,
                1,
                digest,
                effective_at,
                expires_at,
                AuthorizationEventCapacityPolicy::new(100, 1_048_576, 65_536)
                    .expect("valid unavailable-policy capacity"),
            )
            .await
            .expect("install unavailable policy fixture");
            assert_eq!(
                db.resolve_verified_identity_binding(&evidence)
                    .await
                    .expect("unavailable policy is a closed denial"),
                VerifiedIdentityBindingOutcome::Denied(
                    VerifiedIdentityBindingDenial::PolicyUnavailable
                ),
                "{label} policy must fail closed",
            );
            assert_eq!(canonical_counts(&db, domain).await, [0, 0, 0, 0]);
        }

        let unhealthy_domain = fresh_community(&db).await;
        let (unhealthy_digest, unhealthy_evidence) = verified_evidence(
            unhealthy_domain,
            &Keys::generate(),
            Duration::from_secs(300),
            true,
        );
        install_fixture_policy(&db, unhealthy_domain, unhealthy_digest).await;
        sqlx::query(
            "UPDATE authorization_event_capacity \
             SET health_state=2,failure_code=1,failure_observed_at=clock_timestamp() \
             WHERE community_id=$1",
        )
        .bind(unhealthy_domain.as_uuid())
        .execute(&db.pool)
        .await
        .expect("latch unavailable identity audit capacity");
        assert_eq!(
            db.resolve_verified_identity_binding(&unhealthy_evidence)
                .await
                .expect("unhealthy capacity is a closed denial"),
            VerifiedIdentityBindingOutcome::Denied(
                VerifiedIdentityBindingDenial::PolicyUnavailable
            )
        );
        assert_eq!(canonical_counts(&db, unhealthy_domain).await, [0, 0, 0, 0]);
    }

    #[tokio::test]
    #[ignore = "requires Postgres migrated through 0031"]
    async fn atomic_compatibility_paths_preserve_canonical_exact_once_state() {
        let db = test_db().await;
        exercise_invite_atomic_compatibility(&db).await;
        exercise_relay_member_atomic_compatibility(&db).await;
        exercise_private_channel_atomic_compatibility(&db).await;
    }
}
