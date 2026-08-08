//! Read-only selection of an installed canonical enrollment policy.
//!
//! Policy creation and capacity adoption are explicit configuration work.
//! Identity evidence can select an already-installed attested-key policy but
//! can never mint policy bytes or silently adopt migration-bootstrap limits.

use buzz_auth::{
    AuthorizationEventCapacityPolicy, VerifiedIdentityBindingEvidence,
    HARD_MAX_AUTHORIZATION_EVENTS_PER_DOMAIN, HARD_MAX_AUTHORIZATION_EVENT_BYTES_PER_DOMAIN,
    HARD_MAX_AUTHORIZATION_EVENT_ENVELOPE_BYTES,
};
use buzz_core::CommunityId;
use sqlx::{Postgres, Row, Transaction};

#[cfg(test)]
use chrono::{DateTime, Utc};

use crate::{
    authorization_events::{
        event_capacity_is_configured_tx, install_authorization_event_capacity_tx,
    },
    Db, DbError, Result,
};

impl Db {
    /// Adopt or exactly replay the policy sealed by a trusted verifier.
    ///
    /// This is the production configuration path for corporate identity. The
    /// caller cannot supply a raw domain, digest, or capacity: identity is read
    /// from sealed evidence and the capacity uses the user-approved hard
    /// ceilings. Bootstrap adoption and monotonic policy rollover commit
    /// atomically. A conflicting installed capacity fails closed.
    pub async fn adopt_verified_identity_enrollment_policy(
        &self,
        evidence: &VerifiedIdentityBindingEvidence,
    ) -> Result<u64> {
        let community_id = evidence.assertion().authorization_domain();
        let policy_digest = evidence.enrollment_policy_digest();
        if community_id.as_uuid().is_nil() || policy_digest == [0; 32] {
            return Err(DbError::InvalidData(
                "verified identity enrollment policy is invalid".to_owned(),
            ));
        }
        let event_capacity = AuthorizationEventCapacityPolicy::new(
            HARD_MAX_AUTHORIZATION_EVENTS_PER_DOMAIN,
            HARD_MAX_AUTHORIZATION_EVENT_BYTES_PER_DOMAIN,
            HARD_MAX_AUTHORIZATION_EVENT_ENVELOPE_BYTES,
        )
        .map_err(|_| {
            DbError::InvalidData("corporate identity event capacity is invalid".to_owned())
        })?;
        let mut transaction = self.pool.begin().await?;
        install_authorization_event_capacity_tx(&mut transaction, community_id, event_capacity)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(\
             'buzz:identity-enrollment-policy:v1:' || $1::text,0))",
        )
        .bind(community_id.as_uuid())
        .execute(&mut *transaction)
        .await?;

        let existing: Option<i64> = sqlx::query_scalar(
            "SELECT policy_revision FROM identity_enrollment_policies \
             WHERE community_id=$1 AND enrollment_mode=1 AND policy_digest=$2 \
               AND effective_at<=clock_timestamp() \
               AND (expires_at IS NULL OR expires_at>clock_timestamp()) \
             ORDER BY policy_revision DESC LIMIT 1 FOR SHARE",
        )
        .bind(community_id.as_uuid())
        .bind(policy_digest.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = existing {
            let existing = u64::try_from(existing)
                .ok()
                .filter(|revision| *revision > 0)
                .ok_or_else(invalid_policy_revision)?;
            transaction.commit().await?;
            return Ok(existing);
        }

        let newest_revision: Option<i64> = sqlx::query_scalar(
            "SELECT max(policy_revision) FROM identity_enrollment_policies WHERE community_id=$1",
        )
        .bind(community_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        let next_revision = newest_revision
            .unwrap_or(0)
            .checked_add(1)
            .filter(|revision| *revision > 0)
            .ok_or_else(invalid_policy_revision)?;
        sqlx::query(
            "INSERT INTO identity_enrollment_policies \
             (community_id,policy_revision,enrollment_mode,policy_digest,effective_at,expires_at) \
             VALUES ($1,$2,1,$3,clock_timestamp(),NULL)",
        )
        .bind(community_id.as_uuid())
        .bind(next_revision)
        .bind(policy_digest.as_slice())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        u64::try_from(next_revision).map_err(|_| invalid_policy_revision())
    }

    /// Install or exactly replay one immutable attested-key enrollment policy.
    ///
    /// Audit bounds are mandatory and are installed in the same transaction.
    /// Revision reuse with different policy bytes or time bounds is rejected,
    /// as is insertion behind an already-installed higher revision.
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) async fn install_attested_identity_enrollment_policy(
        &self,
        community_id: CommunityId,
        policy_revision: u64,
        policy_digest: [u8; 32],
        effective_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        event_capacity: AuthorizationEventCapacityPolicy,
    ) -> Result<()> {
        if community_id.as_uuid().is_nil()
            || policy_revision == 0
            || policy_digest == [0; 32]
            || expires_at.is_some_and(|expires_at| effective_at >= expires_at)
        {
            return Err(DbError::InvalidData(
                "attested identity enrollment policy is invalid".to_owned(),
            ));
        }
        let policy_revision = i64::try_from(policy_revision).map_err(|_| {
            DbError::InvalidData(
                "attested identity enrollment policy revision exceeds PostgreSQL range".to_owned(),
            )
        })?;
        let mut transaction = self.pool.begin().await?;
        install_authorization_event_capacity_tx(&mut transaction, community_id, event_capacity)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(\
             'buzz:identity-enrollment-policy:v1:' || $1::text,0))",
        )
        .bind(community_id.as_uuid())
        .execute(&mut *transaction)
        .await?;

        let existing = sqlx::query(
            "SELECT enrollment_mode,policy_digest,effective_at,expires_at \
             FROM identity_enrollment_policies \
             WHERE community_id=$1 AND policy_revision=$2 FOR SHARE",
        )
        .bind(community_id.as_uuid())
        .bind(policy_revision)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = existing {
            let mode: i16 = existing.try_get("enrollment_mode")?;
            let digest: Vec<u8> = existing.try_get("policy_digest")?;
            let installed_effective_at: DateTime<Utc> = existing.try_get("effective_at")?;
            let installed_expires_at: Option<DateTime<Utc>> = existing.try_get("expires_at")?;
            if mode != 1
                || digest.as_slice() != policy_digest.as_slice()
                || installed_effective_at != effective_at
                || installed_expires_at != expires_at
            {
                return Err(DbError::InvalidData(
                    "attested identity enrollment policy revision conflicts with installed policy"
                        .to_owned(),
                ));
            }
            transaction.commit().await?;
            return Ok(());
        }

        let newest_revision: Option<i64> = sqlx::query_scalar(
            "SELECT max(policy_revision) FROM identity_enrollment_policies WHERE community_id=$1",
        )
        .bind(community_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        if newest_revision.is_some_and(|revision| revision >= policy_revision) {
            return Err(DbError::InvalidData(
                "attested identity enrollment policy revision is not monotonic".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO identity_enrollment_policies \
             (community_id,policy_revision,enrollment_mode,policy_digest,effective_at,expires_at) \
             VALUES ($1,$2,1,$3,$4,$5)",
        )
        .bind(community_id.as_uuid())
        .bind(policy_revision)
        .bind(policy_digest.as_slice())
        .bind(effective_at)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }
}

fn invalid_policy_revision() -> DbError {
    DbError::InvalidData("identity enrollment policy revision is invalid".to_owned())
}

#[derive(Clone, Copy)]
pub(crate) struct AttestedEnrollmentPolicy {
    pub(crate) revision: u64,
    pub(crate) digest: [u8; 32],
}

pub(crate) async fn load_attested_enrollment_policy_tx(
    transaction: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    expected_policy_digest: [u8; 32],
) -> Result<Option<AttestedEnrollmentPolicy>> {
    if expected_policy_digest == [0; 32] {
        return Err(DbError::InvalidData(
            "verified identity enrollment policy digest is invalid".to_owned(),
        ));
    }
    if !event_capacity_is_configured_tx(transaction, community_id).await? {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT policy_revision,policy_digest FROM identity_enrollment_policies \
         WHERE community_id=$1 AND enrollment_mode=1 AND policy_digest=$2 \
           AND effective_at<=clock_timestamp() \
           AND (expires_at IS NULL OR expires_at>clock_timestamp()) \
         ORDER BY policy_revision DESC LIMIT 1 FOR SHARE",
    )
    .bind(community_id.as_uuid())
    .bind(expected_policy_digest.as_slice())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let revision: i64 = row.try_get("policy_revision")?;
    let digest: Vec<u8> = row.try_get("policy_digest")?;
    let revision = u64::try_from(revision)
        .ok()
        .filter(|revision| *revision > 0)
        .ok_or_else(|| DbError::InvalidData("invalid enrollment policy revision".to_owned()))?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| DbError::InvalidData("invalid enrollment policy digest".to_owned()))?;
    if digest == [0; 32] {
        return Err(DbError::InvalidData(
            "invalid enrollment policy digest".to_owned(),
        ));
    }
    Ok(Some(AttestedEnrollmentPolicy { revision, digest }))
}
