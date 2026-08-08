//! Epoch-free kind-24244 production allocation and final delivery fence.

use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use buzz_auth::{CurrentBindingStatusEvidenceRequest, LocalBindingResolver};
use buzz_core::{
    client_binding_status::{
        ClientBindingStatusBuildError, ClientBindingStatusError, ClientBindingStatusInputV1,
    },
    CommunityId,
};
use buzz_db::{
    authorization_resolver::{AuthorizationResolverError, PostgresLocalBindingResolver},
    client_status::{
        ClientStatusAllocationRequest, ClientStatusOperationIdentity, ClientStatusRevisionError,
        ClientStatusWithdrawalRequest,
    },
    Db,
};
use nostr::{Event, PublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::{OperationRestoreError, OperationRestoreRuntime, RestoredClientStatusError};

struct StatusRuntimeInner {
    resolver: PostgresLocalBindingResolver,
    relay_keys: nostr::Keys,
    restore: OperationRestoreRuntime,
    healthy: AtomicBool,
}

/// Cloneable status producer installed only for complete Enforce domains.
#[derive(Clone)]
pub struct ProductionClientStatusRuntime(Arc<StatusRuntimeInner>);

impl ProductionClientStatusRuntime {
    /// Construct from the authoritative writer database and relay signing key.
    pub fn new(db: Db, relay_keys: nostr::Keys, restore: OperationRestoreRuntime) -> Self {
        Self(Arc::new(StatusRuntimeInner {
            resolver: PostgresLocalBindingResolver::new(db.clone()),
            relay_keys,
            restore,
            healthy: AtomicBool::new(true),
        }))
    }

    /// Allocate, sign, and finally recheck a current presentation event.
    /// A stale or failed final fence returns no event and never changes the
    /// authorization decision that authenticated the connection.
    pub async fn current(
        &self,
        authorization_domain: CommunityId,
        event_author_pubkey: PublicKey,
    ) -> Result<Event, ProductionClientStatusError> {
        if !self.is_healthy() {
            return Err(ProductionClientStatusError::Unhealthy);
        }
        let request =
            CurrentBindingStatusEvidenceRequest::new(authorization_domain, event_author_pubkey)?;
        let evidence = self
            .0
            .resolver
            .current_status_evidence(&request)
            .await
            .map_err(|error| self.map_resolver_error(error))?;
        let request_fingerprint = status_request_fingerprint(&evidence);
        let operation = status_operation(request_fingerprint);
        let request = ClientStatusAllocationRequest::new(evidence.clone(), operation);
        let allocated = self
            .0
            .restore
            .allocate_client_status_revision(request)
            .await
            .map_err(|error| self.map_restored_status_error(error))?;
        let event =
            ClientBindingStatusInputV1::current_from_evidence(&evidence, allocated.revision)?
                .sign_with_relay_keys(&self.0.relay_keys)?;
        let rechecked = self
            .0
            .resolver
            .recheck_current_status_evidence(&evidence)
            .await
            .map_err(|error| self.map_resolver_error(error))?;
        if rechecked != evidence {
            return Err(ProductionClientStatusError::Stale);
        }
        Ok(event)
    }

    /// Allocate and sign a withdrawal for the exact latest current revision.
    /// Withdrawal is presentation-only and does not mutate authorization.
    pub async fn withdraw(
        &self,
        authorization_domain: CommunityId,
        event_author_pubkey: PublicKey,
        supersedes_revision: u64,
    ) -> Result<Event, ProductionClientStatusError> {
        if !self.is_healthy() {
            return Err(ProductionClientStatusError::Unhealthy);
        }
        let request_fingerprint = withdrawal_request_fingerprint(
            authorization_domain,
            event_author_pubkey,
            supersedes_revision,
        );
        let operation = status_operation(request_fingerprint);
        let request = ClientStatusWithdrawalRequest::new(
            authorization_domain,
            event_author_pubkey,
            supersedes_revision,
            operation,
        )?;
        let allocated = self
            .0
            .restore
            .withdraw_client_status_revision(request)
            .await
            .map_err(|error| self.map_restored_status_error(error))?;
        let issued_at = u64::try_from(allocated.issued_at.timestamp())
            .map_err(|_| ProductionClientStatusError::InvalidTime)?;
        let fresh_until = u64::try_from(allocated.fresh_until.timestamp())
            .map_err(|_| ProductionClientStatusError::InvalidTime)?;
        Ok(ClientBindingStatusInputV1::withdrawn(
            authorization_domain,
            event_author_pubkey,
            allocated.revision,
            issued_at,
            fresh_until,
        )?
        .sign_with_relay_keys(&self.0.relay_keys)?)
    }

    /// Sticky runtime/audit health.
    pub fn is_healthy(&self) -> bool {
        self.0.healthy.load(Ordering::Acquire) && self.0.restore.is_healthy()
    }

    fn map_restore_terminal_result(
        &self,
        result: Result<(), OperationRestoreError>,
    ) -> Result<(), ProductionClientStatusError> {
        match result {
            Ok(()) => Ok(()),
            Err(error) if error.is_healthy_retryable() => {
                Err(ProductionClientStatusError::InProgress)
            }
            Err(_) => {
                self.0.healthy.store(false, Ordering::Release);
                Err(ProductionClientStatusError::Unhealthy)
            }
        }
    }

    fn map_restored_status_error(
        &self,
        error: RestoredClientStatusError,
    ) -> ProductionClientStatusError {
        match error {
            RestoredClientStatusError::Revision(error) => self.map_revision_error(error),
            RestoredClientStatusError::Restore(error) => self
                .map_restore_terminal_result(Err(error))
                .expect_err("restore failure always maps to presentation failure"),
        }
    }

    fn map_revision_error(&self, error: ClientStatusRevisionError) -> ProductionClientStatusError {
        match error {
            ClientStatusRevisionError::StaleEvidence
            | ClientStatusRevisionError::RevisionConflict => ProductionClientStatusError::Stale,
            ClientStatusRevisionError::AuditUnavailable => {
                self.0.healthy.store(false, Ordering::Release);
                ProductionClientStatusError::Unhealthy
            }
            ClientStatusRevisionError::Database(error) => {
                self.0.healthy.store(false, Ordering::Release);
                ProductionClientStatusError::Database(error)
            }
        }
    }

    fn map_resolver_error(&self, error: AuthorizationResolverError) -> ProductionClientStatusError {
        match error {
            AuthorizationResolverError::BindingUnavailable
            | AuthorizationResolverError::PolicyUnavailable
            | AuthorizationResolverError::StatusEvidenceStale => ProductionClientStatusError::Stale,
            AuthorizationResolverError::Database(error) => {
                self.0.healthy.store(false, Ordering::Release);
                ProductionClientStatusError::Database(error)
            }
            AuthorizationResolverError::ContractUnavailable
            | AuthorizationResolverError::DelegationAuthorityUnavailable => {
                self.0.healthy.store(false, Ordering::Release);
                ProductionClientStatusError::Unhealthy
            }
        }
    }
}

fn status_operation(request_fingerprint: [u8; 32]) -> ClientStatusOperationIdentity {
    ClientStatusOperationIdentity::new(
        Uuid::new_v4(),
        request_fingerprint,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    )
    .expect("server-generated status operation identity is valid")
}

fn status_request_fingerprint(evidence: &buzz_core::CanonicalCurrentBindingEvidence) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"buzz:client-status-presentation-request:v1");
    digest.update(evidence.authorization_domain().as_uuid().as_bytes());
    digest.update(evidence.event_author_pubkey().to_bytes());
    digest.update(evidence.binding_id().as_bytes());
    digest.update(evidence.binding_version().to_be_bytes());
    digest.update(evidence.policy_revision().to_be_bytes());
    digest.update(evidence.invalidation_generation().to_be_bytes());
    digest.update(evidence.authority_epoch().to_be_bytes());
    digest.update(evidence.fence().as_bytes());
    update_timestamp(&mut digest, evidence.observed_at());
    update_timestamp(&mut digest, evidence.fresh_until());
    digest.finalize().into()
}

fn withdrawal_request_fingerprint(
    authorization_domain: CommunityId,
    event_author_pubkey: PublicKey,
    supersedes_revision: u64,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"buzz:client-status-withdrawal-request:v1");
    digest.update(authorization_domain.as_uuid().as_bytes());
    digest.update(event_author_pubkey.to_bytes());
    digest.update(supersedes_revision.to_be_bytes());
    digest.finalize().into()
}

fn update_timestamp(digest: &mut Sha256, value: chrono::DateTime<chrono::Utc>) {
    digest.update(value.timestamp().to_be_bytes());
    digest.update(value.timestamp_subsec_nanos().to_be_bytes());
}

impl fmt::Debug for ProductionClientStatusRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionClientStatusRuntime")
            .field("healthy", &self.is_healthy())
            .finish()
    }
}

/// Presentation failures. None changes the underlying authorization result.
#[derive(Debug, Error)]
pub enum ProductionClientStatusError {
    /// Evidence changed before delivery.
    #[error("client binding status is stale")]
    Stale,
    /// Another request owns the same bounded restore intent.
    #[error("client binding status is already in progress")]
    InProgress,
    /// Durable audit/runtime health is unavailable.
    #[error("client binding status is unavailable")]
    Unhealthy,
    /// Local evidence request was invalid.
    #[error(transparent)]
    Authorization(#[from] buzz_auth::AuthorizationError),
    /// Status encoding failed.
    #[error(transparent)]
    Status(#[from] ClientBindingStatusError),
    /// Relay signing failed.
    #[error(transparent)]
    Build(#[from] ClientBindingStatusBuildError),
    /// PostgreSQL returned a time outside the public wire range.
    #[error("client binding status time is invalid")]
    InvalidTime,
    /// PostgreSQL failed.
    #[error(transparent)]
    Database(#[from] buzz_db::DbError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::{AuthorizationLeaseFence, CanonicalCurrentBindingEvidence};
    use chrono::{Duration, Utc};
    use sqlx::postgres::PgPoolOptions;

    #[test]
    fn request_fingerprint_binds_the_complete_privacy_safe_tuple() {
        let now = Utc::now();
        let evidence = CanonicalCurrentBindingEvidence::new(
            CommunityId::from_uuid(Uuid::new_v4()),
            nostr::Keys::generate().public_key(),
            Uuid::new_v4(),
            1,
            2,
            3,
            4,
            AuthorizationLeaseFence::from_bytes([5_u8; 32]).expect("valid fence"),
            now,
            now + Duration::seconds(30),
        )
        .expect("valid evidence");
        assert_ne!(status_request_fingerprint(&evidence), [0_u8; 32]);
        assert!(!format!("{:?}", status_request_fingerprint(&evidence))
            .contains(&evidence.binding_id().to_string()));
    }

    #[test]
    fn withdrawal_fingerprint_binds_the_exact_superseded_revision() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let author = nostr::Keys::generate().public_key();
        assert_ne!(
            withdrawal_request_fingerprint(domain, author, 1),
            withdrawal_request_fingerprint(domain, author, 2)
        );
    }

    #[tokio::test]
    async fn retryable_restore_contention_withholds_status_without_poisoning_health() {
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://127.0.0.1:1/unreachable")
            .expect("parse unreachable DB URL");
        let db = Db::from_pool(pool);
        let restore = OperationRestoreRuntime::for_tests(db.clone(), [(domain, Uuid::new_v4())]);
        let runtime =
            ProductionClientStatusRuntime::new(db, nostr::Keys::generate(), restore.clone());
        assert!(matches!(
            runtime.map_restore_terminal_result(Err(OperationRestoreError::CausalLag)),
            Err(ProductionClientStatusError::InProgress)
        ));
        assert!(matches!(
            runtime.map_restore_terminal_result(Err(OperationRestoreError::OperationContention)),
            Err(ProductionClientStatusError::InProgress)
        ));
        assert!(runtime.is_healthy());
        assert!(restore.is_healthy());
    }
}
