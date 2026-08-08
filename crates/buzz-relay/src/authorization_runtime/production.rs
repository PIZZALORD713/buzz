//! Complete provider-free V1 production composition.
//!
//! The stock empty registry is strictly off. Enforced domains are installed
//! only from one complete typed configuration and share one ready live
//! invalidation observer. No provider registry, delegated grant synthesis, or
//! raw credential parsing exists at this boundary.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
    time::Duration,
};

use buzz_auth::{
    AssertionVerificationPolicy, AuthorizationEventCapacityPolicy, NipFiMode, NostrKeyClaimPolicy,
    StaticJwksAssertionVerifier, TrustedProxyAssertionVerifier,
};
use buzz_core::CommunityId;
use buzz_db::{
    authorization_policy::{
        AuthorizationEnrollmentMode, AuthorizationEnrollmentPolicy,
        AuthorizationEnrollmentPolicySemantics,
    },
    authorization_resolver::{PostgresLocalBindingResolver, ProviderFreeEnrollmentRuntime},
    Db, DbError,
};
use serde::Deserialize;
use sha2::Digest;
use thiserror::Error;

use super::{
    OperationRestoreRuntime, ProductionClientStatusRuntime,
    ProtectedPublicationAuthorizationHandle, ProtectedPublicationAuthorizationRuntime,
    ProtectedPublicationObserver,
};

/// Closed V1 enrollment posture for protected production composition.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaseV1EnrollmentMode {
    /// A verifier-attested event-author key may create a binding.
    AttestedKey,
    /// A separately provisioned key may create a binding.
    Provisioned,
    /// A locally risk-labelled trust-on-first-use decision may create a binding.
    RiskLabelledTofu,
}

impl BaseV1EnrollmentMode {
    #[allow(dead_code)] // Consumed by the separately reviewed root configuration child.
    const fn database_mode(self) -> AuthorizationEnrollmentMode {
        match self {
            Self::AttestedKey => AuthorizationEnrollmentMode::AttestedKey,
            Self::Provisioned => AuthorizationEnrollmentMode::Provisioned,
            Self::RiskLabelledTofu => AuthorizationEnrollmentMode::RiskLabelledTofu,
        }
    }

    const fn from_database(mode: AuthorizationEnrollmentMode) -> Self {
        match mode {
            AuthorizationEnrollmentMode::AttestedKey => Self::AttestedKey,
            AuthorizationEnrollmentMode::Provisioned => Self::Provisioned,
            AuthorizationEnrollmentMode::RiskLabelledTofu => Self::RiskLabelledTofu,
        }
    }
}

/// Complete per-domain Base V1 authorization configuration.
#[derive(Clone)]
pub struct BaseV1AuthorizationConfiguration {
    authorization_domain: CommunityId,
    mode: NipFiMode,
    event_capacity: Option<AuthorizationEventCapacityPolicy>,
    assertion_verifier: Option<Arc<TrustedProxyAssertionVerifier>>,
    enrollment_policy: Option<AuthorizationEnrollmentPolicy>,
    maximum_lease: Duration,
    restore_bootstrap_id: Option<uuid::Uuid>,
}

impl BaseV1AuthorizationConfiguration {
    /// Explicit emergency denial. No verifier, resolver, or observer is used.
    pub fn deny_protected(
        authorization_domain: CommunityId,
    ) -> Result<Self, ProviderFreeV1CompositionError> {
        validate_domain(authorization_domain)?;
        Ok(Self {
            authorization_domain,
            mode: NipFiMode::DenyProtected,
            event_capacity: None,
            assertion_verifier: None,
            enrollment_policy: None,
            maximum_lease: Duration::ZERO,
            restore_bootstrap_id: None,
        })
    }

    /// Complete direct-only Enforce configuration.
    #[allow(dead_code)] // Consumed by the separately reviewed root configuration child.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn enforce_direct(
        authorization_domain: CommunityId,
        event_capacity: AuthorizationEventCapacityPolicy,
        policy_revision: u64,
        enrollment_mode: BaseV1EnrollmentMode,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        subject_claim: impl Into<String>,
        jwks: jsonwebtoken::jwk::JwkSet,
        nostr_key_claim: Option<String>,
        assertion_header: impl Into<String>,
        provenance_header: impl Into<String>,
        provenance_key: impl AsRef<[u8]>,
        maximum_token_age: Duration,
        clock_skew: Duration,
        risk_acknowledgement: Option<String>,
        maximum_lease: Duration,
        restore_bootstrap_id: uuid::Uuid,
    ) -> Result<Self, ProviderFreeV1CompositionError> {
        validate_domain(authorization_domain)?;
        if maximum_lease.is_zero()
            || maximum_lease > Duration::from_secs(300)
            || restore_bootstrap_id.is_nil()
            || policy_revision == 0
            || policy_revision > i64::MAX as u64
        {
            return Err(ProviderFreeV1CompositionError::IncompleteConfiguration);
        }
        let exact_mode_configuration = match enrollment_mode {
            BaseV1EnrollmentMode::AttestedKey => {
                nostr_key_claim.is_some() && risk_acknowledgement.is_none()
            }
            BaseV1EnrollmentMode::Provisioned => risk_acknowledgement.is_none(),
            BaseV1EnrollmentMode::RiskLabelledTofu => {
                risk_acknowledgement.as_deref()
                    == Some(buzz_db::authorization_policy::RISK_LABELLED_TOFU_ACKNOWLEDGEMENT_V1)
            }
        };
        if !exact_mode_configuration {
            return Err(ProviderFreeV1CompositionError::IncompleteConfiguration);
        }
        let issuer = issuer.into();
        let audience = audience.into();
        let subject_claim = subject_claim.into();
        let assertion_header = assertion_header.into();
        let provenance_header = provenance_header.into();
        let provenance_key = provenance_key.as_ref();
        let assertion_key_set_digest = canonical_assertion_key_set_digest(&jwks)?;
        let provenance_key_digest: [u8; 32] = sha2::Sha256::digest(provenance_key).into();
        let mut verification_policy = AssertionVerificationPolicy::new(
            issuer.clone(),
            audience.clone(),
            subject_claim.clone(),
            maximum_token_age,
            clock_skew,
        )?;
        if let Some(claim) = nostr_key_claim.as_deref() {
            verification_policy =
                verification_policy.with_nostr_key_claim(NostrKeyClaimPolicy::lower_hex(claim)?)?;
        }
        let assertion_verifier = StaticJwksAssertionVerifier::new(verification_policy, jwks)?
            .trusted_proxy(
                assertion_header.clone(),
                provenance_header.clone(),
                provenance_key,
            )?;
        let semantics = AuthorizationEnrollmentPolicySemantics::new(
            issuer,
            audience,
            subject_claim,
            assertion_key_set_digest,
            nostr_key_claim,
            assertion_header,
            provenance_header,
            provenance_key_digest,
            maximum_token_age,
            clock_skew,
            maximum_lease,
            event_capacity,
            risk_acknowledgement,
            restore_bootstrap_id,
        )?;
        let enrollment_policy = AuthorizationEnrollmentPolicy::new(
            authorization_domain,
            policy_revision,
            enrollment_mode.database_mode(),
            semantics,
        )?;
        Ok(Self {
            authorization_domain,
            mode: NipFiMode::Enforce,
            event_capacity: Some(event_capacity),
            assertion_verifier: Some(Arc::new(assertion_verifier)),
            enrollment_policy: Some(enrollment_policy),
            maximum_lease,
            restore_bootstrap_id: Some(restore_bootstrap_id),
        })
    }

    /// Server-owned domain coordinate.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Explicit operating mode.
    pub const fn mode(&self) -> NipFiMode {
        self.mode
    }

    /// Typed enrollment posture retained by the installed domain runtime.
    pub const fn enrollment_mode(&self) -> Option<BaseV1EnrollmentMode> {
        match &self.enrollment_policy {
            Some(policy) => Some(BaseV1EnrollmentMode::from_database(
                policy.enrollment_mode(),
            )),
            None => None,
        }
    }

    /// Positive immutable policy revision for an Enforce domain.
    pub const fn policy_revision(&self) -> Option<u64> {
        match &self.enrollment_policy {
            Some(policy) => Some(policy.policy_revision()),
            None => None,
        }
    }

    /// Immutable external restore bootstrap identity for Enforce.
    pub const fn restore_bootstrap_id(&self) -> Option<uuid::Uuid> {
        self.restore_bootstrap_id
    }
}

impl fmt::Debug for BaseV1AuthorizationConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BaseV1AuthorizationConfiguration")
            .field("mode", &self.mode)
            .field("enrollment_mode", &self.enrollment_mode())
            .field("coordinates", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
enum InstalledDomain {
    DenyProtected,
    Enforce {
        publication: ProtectedPublicationAuthorizationHandle,
        enrollment: ProviderFreeEnrollmentRuntime,
        status: ProductionClientStatusRuntime,
        restore: OperationRestoreRuntime,
        enrollment_mode: BaseV1EnrollmentMode,
        policy_revision: u64,
    },
}

/// Immutable ready provider-free production registry.
#[derive(Clone, Default)]
pub struct ProviderFreeV1Composition {
    domains: Arc<HashMap<CommunityId, InstalledDomain>>,
}

impl ProviderFreeV1Composition {
    /// Validate the complete immutable domain set without database, listener,
    /// or object-store I/O. Root calls this before constructing dependencies.
    pub fn preflight(
        configurations: &[BaseV1AuthorizationConfiguration],
    ) -> Result<(), ProviderFreeV1CompositionError> {
        let mut configured_domains = HashSet::with_capacity(configurations.len());
        for configuration in configurations {
            if !configured_domains.insert(configuration.authorization_domain) {
                return Err(ProviderFreeV1CompositionError::DuplicateDomain);
            }
            validate_configuration(configuration)?;
        }
        Ok(())
    }

    /// Build a complete registry before it becomes observable by a router.
    /// An empty configuration performs zero protected database or listener I/O.
    pub async fn build(
        db: Db,
        relay_keys: nostr::Keys,
        configurations: Vec<BaseV1AuthorizationConfiguration>,
        restore: Option<OperationRestoreRuntime>,
    ) -> Result<Self, ProviderFreeV1CompositionError> {
        if configurations.is_empty() {
            return Ok(Self::default());
        }
        Self::preflight(&configurations)?;
        let mut domains = HashMap::with_capacity(configurations.len());
        let mut startup_policies = Vec::with_capacity(configurations.len());

        // Preflight above closes the complete set before the first I/O. Build
        // the already validated capacity set without mutating external state.
        for configuration in &configurations {
            if let (Some(policy), Some(capacity)) = (
                configuration.enrollment_policy.clone(),
                configuration.event_capacity,
            ) {
                startup_policies.push((policy, capacity));
            }
        }

        let restore = if startup_policies.is_empty() {
            None
        } else {
            let restore = restore.ok_or(ProviderFreeV1CompositionError::IncompleteConfiguration)?;
            if !restore.is_healthy() {
                return Err(ProviderFreeV1CompositionError::Unhealthy);
            }
            for (policy, _) in &startup_policies {
                let domain = policy.authorization_domain();
                restore.verify_domain(domain).await?;
            }
            Some(restore)
        };

        // The complete enabled-domain set is installed and reconciled in one
        // transaction only after the mandatory independent restore witness is
        // ready. A pre-latched unhealthy row or policy conflict rolls back any
        // new rows before listener startup or registry exposure.
        db.reconcile_authorization_enrollment_startup(&startup_policies)
            .await?;

        let observer = if startup_policies.is_empty() {
            None
        } else {
            Some(ProtectedPublicationObserver::start(db.clone()).await?)
        };
        for configuration in configurations {
            let installed = match configuration.mode {
                NipFiMode::Off => continue,
                NipFiMode::DenyProtected => InstalledDomain::DenyProtected,
                NipFiMode::Enforce => {
                    let verifier = configuration
                        .assertion_verifier
                        .ok_or(ProviderFreeV1CompositionError::IncompleteConfiguration)?;
                    let observer = observer
                        .clone()
                        .ok_or(ProviderFreeV1CompositionError::IncompleteConfiguration)?;
                    let restore = restore
                        .clone()
                        .ok_or(ProviderFreeV1CompositionError::IncompleteConfiguration)?;
                    let enrollment_policy = configuration
                        .enrollment_policy
                        .ok_or(ProviderFreeV1CompositionError::IncompleteConfiguration)?;
                    let enrollment_mode =
                        BaseV1EnrollmentMode::from_database(enrollment_policy.enrollment_mode());
                    let policy_revision = enrollment_policy.policy_revision();
                    let runtime = ProtectedPublicationAuthorizationRuntime::new_direct_only(
                        PostgresLocalBindingResolver::new(db.clone()),
                        observer,
                        verifier,
                        configuration.maximum_lease,
                    )?;
                    InstalledDomain::Enforce {
                        publication: ProtectedPublicationAuthorizationHandle::new(runtime),
                        enrollment: ProviderFreeEnrollmentRuntime::new(db.clone()),
                        status: ProductionClientStatusRuntime::new(
                            db.clone(),
                            relay_keys.clone(),
                            restore.clone(),
                        ),
                        restore,
                        enrollment_mode,
                        policy_revision,
                    }
                }
            };
            domains.insert(configuration.authorization_domain, installed);
        }
        Ok(Self {
            domains: Arc::new(domains),
        })
    }

    /// Read-only mode lookup. Unconfigured domains are strictly Off.
    pub fn mode(&self, authorization_domain: CommunityId) -> NipFiMode {
        match self.domains.get(&authorization_domain) {
            None => NipFiMode::Off,
            Some(InstalledDomain::DenyProtected) => NipFiMode::DenyProtected,
            Some(InstalledDomain::Enforce { .. }) => NipFiMode::Enforce,
        }
    }

    /// Exact healthy Enforce handle for one server-resolved domain.
    pub fn protected_publication_handle(
        &self,
        authorization_domain: CommunityId,
    ) -> Result<ProtectedPublicationAuthorizationHandle, ProviderFreeV1CompositionError> {
        match self.domains.get(&authorization_domain) {
            Some(InstalledDomain::Enforce {
                publication,
                restore,
                ..
            }) if publication.is_healthy() && restore.is_healthy() => Ok(publication.clone()),
            Some(InstalledDomain::Enforce { .. }) => Err(ProviderFreeV1CompositionError::Unhealthy),
            _ => Err(ProviderFreeV1CompositionError::NotEnforced),
        }
    }

    /// Exact healthy client-status producer for one Enforce domain.
    pub fn client_status_runtime(
        &self,
        authorization_domain: CommunityId,
    ) -> Result<ProductionClientStatusRuntime, ProviderFreeV1CompositionError> {
        match self.domains.get(&authorization_domain) {
            Some(InstalledDomain::Enforce {
                status, restore, ..
            }) if status.is_healthy() && restore.is_healthy() => Ok(status.clone()),
            Some(InstalledDomain::Enforce { .. }) => Err(ProviderFreeV1CompositionError::Unhealthy),
            _ => Err(ProviderFreeV1CompositionError::NotEnforced),
        }
    }

    /// Exact healthy operation-bound restore runtime for one Enforce domain.
    pub fn operation_restore_runtime(
        &self,
        authorization_domain: CommunityId,
    ) -> Result<OperationRestoreRuntime, ProviderFreeV1CompositionError> {
        match self.domains.get(&authorization_domain) {
            Some(InstalledDomain::Enforce { restore, .. }) if restore.is_healthy() => {
                Ok(restore.clone())
            }
            Some(InstalledDomain::Enforce { .. }) => Err(ProviderFreeV1CompositionError::Unhealthy),
            _ => Err(ProviderFreeV1CompositionError::NotEnforced),
        }
    }

    /// Exact healthy direct-enrollment and authority-loss preparer for one
    /// Enforce domain.
    pub fn enrollment_runtime(
        &self,
        authorization_domain: CommunityId,
    ) -> Result<ProviderFreeEnrollmentRuntime, ProviderFreeV1CompositionError> {
        match self.domains.get(&authorization_domain) {
            Some(InstalledDomain::Enforce {
                publication,
                enrollment,
                status,
                restore,
                ..
            }) if publication.is_healthy() && status.is_healthy() && restore.is_healthy() => {
                Ok(enrollment.clone())
            }
            Some(InstalledDomain::Enforce { .. }) => Err(ProviderFreeV1CompositionError::Unhealthy),
            _ => Err(ProviderFreeV1CompositionError::NotEnforced),
        }
    }

    /// Health-gated read-only enrollment metadata for one Enforce domain.
    ///
    /// Authorization uses the finalizer and database policy row, never this
    /// diagnostic value.
    pub fn enrollment_mode(
        &self,
        authorization_domain: CommunityId,
    ) -> Result<BaseV1EnrollmentMode, ProviderFreeV1CompositionError> {
        match self.domains.get(&authorization_domain) {
            Some(InstalledDomain::Enforce {
                publication,
                status,
                restore,
                enrollment_mode,
                ..
            }) if publication.is_healthy() && status.is_healthy() && restore.is_healthy() => {
                Ok(*enrollment_mode)
            }
            Some(InstalledDomain::Enforce { .. }) => Err(ProviderFreeV1CompositionError::Unhealthy),
            _ => Err(ProviderFreeV1CompositionError::NotEnforced),
        }
    }

    /// Health-gated read-only policy metadata for one Enforce domain.
    ///
    /// Authorization uses the finalizer and database policy row, never this
    /// diagnostic value.
    pub fn policy_revision(
        &self,
        authorization_domain: CommunityId,
    ) -> Result<u64, ProviderFreeV1CompositionError> {
        match self.domains.get(&authorization_domain) {
            Some(InstalledDomain::Enforce {
                publication,
                status,
                restore,
                policy_revision,
                ..
            }) if publication.is_healthy() && status.is_healthy() && restore.is_healthy() => {
                Ok(*policy_revision)
            }
            Some(InstalledDomain::Enforce { .. }) => Err(ProviderFreeV1CompositionError::Unhealthy),
            _ => Err(ProviderFreeV1CompositionError::NotEnforced),
        }
    }

    /// Whether every installed Enforce runtime remains healthy.
    pub fn is_healthy(&self) -> bool {
        self.domains.values().all(|domain| match domain {
            InstalledDomain::DenyProtected => true,
            InstalledDomain::Enforce {
                publication,
                status,
                restore,
                ..
            } => publication.is_healthy() && status.is_healthy() && restore.is_healthy(),
        })
    }
}

impl fmt::Debug for ProviderFreeV1Composition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFreeV1Composition")
            .field("configured_domains", &self.domains.len())
            .field("healthy", &self.is_healthy())
            .finish()
    }
}

fn validate_domain(domain: CommunityId) -> Result<(), ProviderFreeV1CompositionError> {
    if domain.as_uuid().is_nil() {
        Err(ProviderFreeV1CompositionError::IncompleteConfiguration)
    } else {
        Ok(())
    }
}

#[allow(dead_code)] // Consumed by the separately reviewed root configuration child.
fn canonical_assertion_key_set_digest(
    jwks: &jsonwebtoken::jwk::JwkSet,
) -> Result<[u8; 32], ProviderFreeV1CompositionError> {
    let mut keys = jwks
        .keys
        .iter()
        .map(|key| {
            let value = serde_json::to_value(key)
                .map_err(|_| ProviderFreeV1CompositionError::IncompleteConfiguration)?;
            let mut canonical = Vec::new();
            canonical_json(&value, &mut canonical)?;
            Ok(canonical)
        })
        .collect::<Result<Vec<_>, ProviderFreeV1CompositionError>>()?;
    if keys.is_empty() {
        return Err(ProviderFreeV1CompositionError::IncompleteConfiguration);
    }
    keys.sort();
    let mut digest = sha2::Sha256::new();
    digest.update(b"buzz:provider-free-jwks:v1");
    digest.update((keys.len() as u64).to_be_bytes());
    for key in keys {
        digest.update((key.len() as u64).to_be_bytes());
        digest.update(key);
    }
    Ok(digest.finalize().into())
}

#[allow(dead_code)] // Consumed by the separately reviewed root configuration child.
fn canonical_json(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), ProviderFreeV1CompositionError> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { &b"true"[..] } else { &b"false"[..] })
        }
        serde_json::Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        serde_json::Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|_| ProviderFreeV1CompositionError::IncompleteConfiguration)?
                .as_bytes(),
        ),
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                canonical_json(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|_| ProviderFreeV1CompositionError::IncompleteConfiguration)?
                        .as_bytes(),
                );
                output.push(b':');
                canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn validate_configuration(
    configuration: &BaseV1AuthorizationConfiguration,
) -> Result<(), ProviderFreeV1CompositionError> {
    validate_domain(configuration.authorization_domain)?;
    match configuration.mode {
        NipFiMode::Off => Err(ProviderFreeV1CompositionError::IncompleteConfiguration),
        NipFiMode::DenyProtected
            if configuration.event_capacity.is_none()
                && configuration.assertion_verifier.is_none()
                && configuration.enrollment_policy.is_none()
                && configuration.maximum_lease.is_zero()
                && configuration.restore_bootstrap_id.is_none() =>
        {
            Ok(())
        }
        NipFiMode::Enforce
            if configuration.event_capacity.is_some()
                && configuration.assertion_verifier.is_some()
                && configuration.enrollment_policy.is_some()
                && !configuration.maximum_lease.is_zero()
                && configuration.maximum_lease <= Duration::from_secs(300)
                && configuration
                    .restore_bootstrap_id
                    .is_some_and(|id| !id.is_nil()) =>
        {
            Ok(())
        }
        _ => Err(ProviderFreeV1CompositionError::IncompleteConfiguration),
    }
}

/// Closed production composition failures.
#[derive(Debug, Error)]
pub enum ProviderFreeV1CompositionError {
    /// A domain entry is incomplete or internally inconsistent.
    #[error("provider-free V1 configuration is incomplete")]
    IncompleteConfiguration,
    /// One domain appeared more than once.
    #[error("provider-free V1 domain configuration is duplicated")]
    DuplicateDomain,
    /// The requested domain is not in Enforce mode.
    #[error("provider-free V1 domain is not enforced")]
    NotEnforced,
    /// A required installed runtime is unhealthy.
    #[error("provider-free V1 runtime is unhealthy")]
    Unhealthy,
    /// Root attempted to replace an already installed immutable registry.
    #[error("provider-free V1 runtime is already installed")]
    AlreadyInstalled,
    /// PostgreSQL capacity installation or listener startup failed.
    #[error(transparent)]
    Database(#[from] DbError),
    /// Assertion, key-claim, or provenance policy was invalid.
    #[error(transparent)]
    Evidence(#[from] buzz_auth::EvidenceError),
    /// Protected finalization runtime construction failed.
    #[error(transparent)]
    Finalization(#[from] super::ProtectedPublicationAuthorizationError),
    /// Live invalidation observer startup failed.
    #[error(transparent)]
    Observer(#[from] super::ProtectedPublicationObserverError),
    /// Operation-bound external restore witnessing failed.
    #[error(transparent)]
    Restore(#[from] super::OperationRestoreError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_db::authorization_events::AuthorizationAuditFailureCode;
    use jsonwebtoken::jwk::{Jwk, JwkSet};
    use sqlx::postgres::PgPoolOptions;
    use sqlx::PgPool;
    use uuid::Uuid;

    fn unreachable_db() -> Db {
        let pool = PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(25))
            .connect_lazy("postgres://buzz:buzz@127.0.0.1:1/unreachable")
            .expect("lazy unreachable pool");
        Db::from_pool(pool)
    }

    fn direct_configuration(
        domain: CommunityId,
        capacity: AuthorizationEventCapacityPolicy,
    ) -> BaseV1AuthorizationConfiguration {
        direct_configuration_with_mode(domain, capacity, BaseV1EnrollmentMode::AttestedKey)
    }

    fn direct_configuration_with_mode(
        domain: CommunityId,
        capacity: AuthorizationEventCapacityPolicy,
        enrollment_mode: BaseV1EnrollmentMode,
    ) -> BaseV1AuthorizationConfiguration {
        direct_configuration_with_requirements(domain, capacity, enrollment_mode, None, None)
            .expect("complete direct configuration")
    }

    fn direct_configuration_with_requirements(
        domain: CommunityId,
        capacity: AuthorizationEventCapacityPolicy,
        enrollment_mode: BaseV1EnrollmentMode,
        claim_override: Option<Option<String>>,
        acknowledgement_override: Option<Option<String>>,
    ) -> Result<BaseV1AuthorizationConfiguration, ProviderFreeV1CompositionError> {
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "W5IdGgO6kT9y_Lknfulx05osPx0NTwHpGNJixSlFLmQ",
            "kid": "fixture-ed25519",
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "EdDSA"
        }))
        .expect("fixture JWK");
        let (default_claim, default_acknowledgement) = match enrollment_mode {
            BaseV1EnrollmentMode::AttestedKey => (Some("nostr_pubkey".to_owned()), None),
            BaseV1EnrollmentMode::Provisioned => (None, None),
            BaseV1EnrollmentMode::RiskLabelledTofu => (
                Some("nostr_pubkey".to_owned()),
                Some(
                    buzz_db::authorization_policy::RISK_LABELLED_TOFU_ACKNOWLEDGEMENT_V1.to_owned(),
                ),
            ),
        };
        let nostr_key_claim = claim_override.unwrap_or(default_claim);
        let risk_acknowledgement = acknowledgement_override.unwrap_or(default_acknowledgement);
        BaseV1AuthorizationConfiguration::enforce_direct(
            domain,
            capacity,
            1,
            enrollment_mode,
            "https://issuer.example",
            "buzz-relay",
            "employee_id",
            JwkSet { keys: vec![jwk] },
            nostr_key_claim,
            "x-buzz-identity",
            "x-buzz-identity-proof",
            [9_u8; 32],
            Duration::from_secs(300),
            Duration::from_secs(30),
            risk_acknowledgement,
            Duration::from_secs(60),
            Uuid::new_v4(),
        )
    }

    async fn scratch_database(label: &str) -> (PgPool, PgPool, String) {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_owned());
        let admin = PgPool::connect(&admin_url).await.expect("connect admin");
        let name = format!("s5_{label}_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("create scratch database");
        let split = admin_url.rfind('/').expect("database URL path");
        let scratch_url = format!("{}/{}", &admin_url[..split], name);
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&scratch_url)
            .await
            .expect("connect scratch database");
        buzz_db::migration::run_migrations(&pool)
            .await
            .expect("migrate scratch database");
        (admin, pool, name)
    }

    async fn drop_scratch_database(admin: PgPool, pool: PgPool, name: String) {
        pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("drop scratch database");
        admin.close().await;
    }

    async fn insert_community(pool: &PgPool, domain: CommunityId) {
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(domain.as_uuid())
            .bind(format!("capacity-{}.example", domain.as_uuid().simple()))
            .execute(pool)
            .await
            .expect("insert community");
    }

    #[test]
    fn empty_stock_composition_is_off_and_healthy() {
        let composition = ProviderFreeV1Composition::default();
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        assert_eq!(composition.mode(domain), NipFiMode::Off);
        assert!(composition.is_healthy());
        assert!(matches!(
            composition.protected_publication_handle(domain),
            Err(ProviderFreeV1CompositionError::NotEnforced)
        ));
    }

    #[test]
    fn deny_configuration_is_complete_without_a_verifier() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let configuration = BaseV1AuthorizationConfiguration::deny_protected(domain)
            .expect("valid deny configuration");
        assert_eq!(configuration.mode(), NipFiMode::DenyProtected);
        assert!(!format!("{configuration:?}").contains(&domain.as_uuid().to_string()));
    }

    #[test]
    fn every_stock_enrollment_mode_is_a_complete_typed_enforce_configuration() {
        let modes = [
            BaseV1EnrollmentMode::AttestedKey,
            BaseV1EnrollmentMode::Provisioned,
            BaseV1EnrollmentMode::RiskLabelledTofu,
        ];
        for mode in modes {
            let configuration = direct_configuration_with_mode(
                CommunityId::from_uuid(Uuid::new_v4()),
                AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10).expect("capacity"),
                mode,
            );
            ProviderFreeV1Composition::preflight(std::slice::from_ref(&configuration))
                .expect("closed stock enrollment mode");
            assert_eq!(configuration.enrollment_mode(), Some(mode));
            assert_eq!(configuration.policy_revision(), Some(1));
        }
        assert!(matches!(
            BaseV1AuthorizationConfiguration::enforce_direct(
                CommunityId::from_uuid(Uuid::new_v4()),
                AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10).expect("capacity"),
                0,
                BaseV1EnrollmentMode::AttestedKey,
                "https://issuer.example",
                "buzz-relay",
                "employee_id",
                JwkSet { keys: Vec::new() },
                Some("nostr_pubkey".to_owned()),
                "x-buzz-identity",
                "x-buzz-identity-proof",
                [9_u8; 32],
                Duration::from_secs(300),
                Duration::from_secs(30),
                None,
                Duration::from_secs(60),
                Uuid::new_v4(),
            ),
            Err(ProviderFreeV1CompositionError::IncompleteConfiguration)
        ));
        assert!(matches!(
            direct_configuration_with_requirements(
                CommunityId::from_uuid(Uuid::new_v4()),
                AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10).expect("capacity"),
                BaseV1EnrollmentMode::AttestedKey,
                Some(None),
                None,
            ),
            Err(ProviderFreeV1CompositionError::IncompleteConfiguration)
        ));
        assert!(matches!(
            direct_configuration_with_requirements(
                CommunityId::from_uuid(Uuid::new_v4()),
                AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10).expect("capacity"),
                BaseV1EnrollmentMode::RiskLabelledTofu,
                None,
                Some(Some("wrong".to_owned())),
            ),
            Err(ProviderFreeV1CompositionError::IncompleteConfiguration)
        ));
        assert!(matches!(
            direct_configuration_with_requirements(
                CommunityId::from_uuid(Uuid::new_v4()),
                AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10).expect("capacity"),
                BaseV1EnrollmentMode::Provisioned,
                None,
                Some(Some(
                    buzz_db::authorization_policy::RISK_LABELLED_TOFU_ACKNOWLEDGEMENT_V1.to_owned(),
                )),
            ),
            Err(ProviderFreeV1CompositionError::IncompleteConfiguration)
        ));
    }

    #[test]
    fn canonical_key_set_digest_is_independent_of_set_order() {
        let key = |kid: &str| {
            serde_json::from_value::<Jwk>(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "W5IdGgO6kT9y_Lknfulx05osPx0NTwHpGNJixSlFLmQ",
                "kid": kid,
                "use": "sig",
                "key_ops": ["verify"],
                "alg": "EdDSA"
            }))
            .expect("fixture JWK")
        };
        let first = JwkSet {
            keys: vec![key("a"), key("b")],
        };
        let reversed = JwkSet {
            keys: vec![key("b"), key("a")],
        };
        assert_eq!(
            canonical_assertion_key_set_digest(&first).expect("canonical first"),
            canonical_assertion_key_set_digest(&reversed).expect("canonical reversed")
        );
    }

    #[tokio::test]
    async fn stock_and_deny_build_without_protected_database_io() {
        let keys = nostr::Keys::generate();
        let stock =
            ProviderFreeV1Composition::build(unreachable_db(), keys.clone(), Vec::new(), None)
                .await
                .expect("stock composition performs no database I/O");
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        assert_eq!(stock.mode(domain), NipFiMode::Off);

        let deny = ProviderFreeV1Composition::build(
            unreachable_db(),
            keys,
            vec![BaseV1AuthorizationConfiguration::deny_protected(domain)
                .expect("valid deny configuration")],
            None,
        )
        .await
        .expect("deny composition performs no verifier or database I/O");
        assert_eq!(deny.mode(domain), NipFiMode::DenyProtected);
        assert!(matches!(
            deny.protected_publication_handle(domain),
            Err(ProviderFreeV1CompositionError::NotEnforced)
        ));
    }

    #[tokio::test]
    async fn duplicate_deny_domain_fails_before_database_io() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let configuration = BaseV1AuthorizationConfiguration::deny_protected(domain)
            .expect("valid deny configuration");
        let result = ProviderFreeV1Composition::build(
            unreachable_db(),
            nostr::Keys::generate(),
            vec![configuration.clone(), configuration],
            None,
        )
        .await;
        assert!(matches!(
            result,
            Err(ProviderFreeV1CompositionError::DuplicateDomain)
        ));
    }

    #[tokio::test]
    async fn enforce_requires_healthy_restore_before_database_io() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let capacity =
            AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10).expect("capacity");
        let configuration = direct_configuration(domain, capacity);
        let missing = ProviderFreeV1Composition::build(
            unreachable_db(),
            nostr::Keys::generate(),
            vec![configuration.clone()],
            None,
        )
        .await;
        assert!(matches!(
            missing,
            Err(ProviderFreeV1CompositionError::IncompleteConfiguration)
        ));

        let unhealthy = OperationRestoreRuntime::for_tests(
            unreachable_db(),
            [(
                domain,
                configuration.restore_bootstrap_id().expect("bootstrap"),
            )],
        );
        unhealthy.force_unhealthy_for_test();
        let result = ProviderFreeV1Composition::build(
            unreachable_db(),
            nostr::Keys::generate(),
            vec![configuration],
            Some(unhealthy),
        )
        .await;
        assert!(matches!(
            result,
            Err(ProviderFreeV1CompositionError::Unhealthy)
        ));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_duplicate_enforce_preflight_leaves_zero_capacity_residue() {
        let (admin, pool, name) = scratch_database("duplicate_capacity").await;
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        insert_community(&pool, domain).await;
        let first = AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10)
            .expect("valid first capacity");
        let second = AuthorizationEventCapacityPolicy::new(101, 2 << 20, 16 << 10)
            .expect("valid different capacity");

        let result = ProviderFreeV1Composition::build(
            Db::from_pool(pool.clone()),
            nostr::Keys::generate(),
            vec![
                direct_configuration(domain, first),
                direct_configuration(domain, second),
            ],
            None,
        )
        .await;
        assert!(matches!(
            result,
            Err(ProviderFreeV1CompositionError::DuplicateDomain)
        ));
        let capacity_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM authorization_event_capacity WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("count capacity residue");
        let policy_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM identity_enrollment_policies WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("count policy residue");
        assert_eq!(capacity_rows, 0);
        assert_eq!(policy_rows, 0);

        drop_scratch_database(admin, pool, name).await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_pre_latched_unhealthy_capacity_blocks_startup() {
        let (admin, pool, name) = scratch_database("unhealthy_capacity").await;
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        insert_community(&pool, domain).await;
        let capacity =
            AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10).expect("valid capacity");
        let db = Db::from_pool(pool.clone());
        db.install_authorization_event_capacity(domain, capacity)
            .await
            .expect("install initial capacity");
        db.latch_authorization_event_failure(
            domain,
            AuthorizationAuditFailureCode::StorageUnavailable,
        )
        .await
        .expect("latch capacity unhealthy");

        let configuration = direct_configuration(domain, capacity);
        let restore = OperationRestoreRuntime::for_tests(
            db.clone(),
            [(
                domain,
                configuration.restore_bootstrap_id().expect("bootstrap"),
            )],
        );
        restore
            .provision_domain(domain)
            .await
            .expect("explicitly provision restore baseline");
        let result = ProviderFreeV1Composition::build(
            db.clone(),
            nostr::Keys::generate(),
            vec![configuration],
            Some(restore),
        )
        .await;
        assert!(matches!(
            result,
            Err(ProviderFreeV1CompositionError::Database(DbError::InvalidData(ref message)))
                if message == "authorization event capacity is unhealthy"
        ));
        let health = db
            .authorization_event_capacity_health(domain)
            .await
            .expect("read sticky capacity health");
        assert!(!health.healthy);
        assert_eq!(
            health.failure_code,
            Some(AuthorizationAuditFailureCode::StorageUnavailable)
        );

        drop_scratch_database(admin, pool, name).await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_enforce_requires_and_provisions_operation_restore() {
        let (admin, pool, name) = scratch_database("operation_restore").await;
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        insert_community(&pool, domain).await;
        let capacity =
            AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10).expect("valid capacity");

        let witness_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .expect("connect independent witness pool");
        let configuration = direct_configuration(domain, capacity);
        let restore = OperationRestoreRuntime::for_tests(
            Db::from_pool(witness_pool.clone()),
            [(
                domain,
                configuration.restore_bootstrap_id().expect("bootstrap"),
            )],
        );
        restore
            .provision_domain(domain)
            .await
            .expect("explicitly provision restore baseline");
        let composition = ProviderFreeV1Composition::build(
            Db::from_pool(pool.clone()),
            nostr::Keys::generate(),
            vec![configuration],
            Some(restore),
        )
        .await
        .expect("Enforce starts with operation-bound restore witnessing");
        assert_eq!(composition.mode(domain), NipFiMode::Enforce);
        assert!(composition.is_healthy());
        assert!(composition.protected_publication_handle(domain).is_ok());
        assert!(composition.client_status_runtime(domain).is_ok());
        assert!(composition.operation_restore_runtime(domain).is_ok());

        let operation_manifest_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM authorization_operation_version_delta_manifests",
        )
        .fetch_one(&pool)
        .await
        .expect("count operation-bound manifests");
        assert_eq!(operation_manifest_rows, 0);

        let restore = composition
            .operation_restore_runtime(domain)
            .expect("healthy restore");
        restore.force_unhealthy_for_test();
        assert!(!composition.is_healthy());
        assert!(matches!(
            composition.protected_publication_handle(domain),
            Err(ProviderFreeV1CompositionError::Unhealthy)
        ));
        assert!(matches!(
            composition.client_status_runtime(domain),
            Err(ProviderFreeV1CompositionError::Unhealthy)
        ));

        drop(composition);
        tokio::task::yield_now().await;
        witness_pool.close().await;
        drop_scratch_database(admin, pool, name).await;
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn postgres_enforce_installs_every_typed_enrollment_mode() {
        let (admin, pool, name) = scratch_database("enrollment_modes").await;
        let modes = [
            BaseV1EnrollmentMode::AttestedKey,
            BaseV1EnrollmentMode::Provisioned,
            BaseV1EnrollmentMode::RiskLabelledTofu,
        ];
        let mut configurations = Vec::with_capacity(modes.len());
        let mut bootstraps = Vec::with_capacity(modes.len());
        let mut domains = Vec::with_capacity(modes.len());
        for mode in modes {
            let domain = CommunityId::from_uuid(Uuid::new_v4());
            insert_community(&pool, domain).await;
            let configuration = direct_configuration_with_mode(
                domain,
                AuthorizationEventCapacityPolicy::new(100, 1 << 20, 16 << 10).expect("capacity"),
                mode,
            );
            bootstraps.push((
                domain,
                configuration.restore_bootstrap_id().expect("bootstrap"),
            ));
            let policy_digest = configuration
                .enrollment_policy
                .as_ref()
                .expect("policy")
                .policy_digest();
            configurations.push(configuration);
            domains.push((domain, mode, policy_digest));
        }
        let witness_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .expect("connect independent witness pool");
        let restore = OperationRestoreRuntime::for_tests(
            Db::from_pool(witness_pool.clone()),
            bootstraps.iter().copied(),
        );
        for (domain, _, _) in &domains {
            restore
                .provision_domain(*domain)
                .await
                .expect("provision restore baseline");
        }
        let composition = ProviderFreeV1Composition::build(
            Db::from_pool(pool.clone()),
            nostr::Keys::generate(),
            configurations,
            Some(restore),
        )
        .await
        .expect("install every closed enrollment mode");
        for (domain, mode, policy_digest) in domains {
            assert_eq!(composition.mode(domain), NipFiMode::Enforce);
            assert_eq!(composition.enrollment_mode(domain).expect("mode"), mode);
            assert_eq!(composition.policy_revision(domain).expect("revision"), 1);
            assert!(composition.protected_publication_handle(domain).is_ok());
            let stored: (i16, Vec<u8>) = sqlx::query_as(
                "SELECT enrollment_mode,policy_digest FROM identity_enrollment_policies \
                 WHERE community_id=$1 AND policy_revision=1",
            )
            .bind(domain.as_uuid())
            .fetch_one(&pool)
            .await
            .expect("read reconciled policy");
            assert_eq!(stored.0, mode.database_mode() as i16);
            assert_eq!(stored.1, policy_digest);
        }
        assert!(composition.is_healthy());

        drop(composition);
        tokio::task::yield_now().await;
        witness_pool.close().await;
        drop_scratch_database(admin, pool, name).await;
    }
}
