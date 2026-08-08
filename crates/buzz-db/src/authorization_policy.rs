//! Explicit enrollment-policy installation and read-only request selection.
//!
//! Policy creation and capacity adoption are explicit configuration work.
//! Identity evidence can select an already-installed attested-key policy but
//! can never mint policy bytes or silently adopt migration-bootstrap limits.

use buzz_auth::AuthorizationEventCapacityPolicy;
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

/// Exact verifier policy and explicit immutable event capacity installed for a domain.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AttestedIdentityConfiguration {
    policy_digest: [u8; 32],
    event_capacity: AuthorizationEventCapacityPolicy,
}

impl AttestedIdentityConfiguration {
    /// Bind a nonzero verifier digest to operator-supplied validated capacity.
    pub fn new(
        policy_digest: [u8; 32],
        event_capacity: AuthorizationEventCapacityPolicy,
    ) -> Result<Self> {
        if policy_digest == [0; 32] {
            return Err(DbError::InvalidData(
                "attested identity enrollment policy digest is invalid".to_owned(),
            ));
        }
        Ok(Self {
            policy_digest,
            event_capacity,
        })
    }

    /// Verifier-owned digest installed by startup or provisioning.
    pub const fn policy_digest(self) -> [u8; 32] {
        self.policy_digest
    }

    /// Explicit immutable event capacity supplied by deployment configuration.
    pub const fn event_capacity(self) -> AuthorizationEventCapacityPolicy {
        self.event_capacity
    }
}

impl std::fmt::Debug for AttestedIdentityConfiguration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AttestedIdentityConfiguration([REDACTED])")
    }
}

impl Db {
    /// Install one explicit verifier policy and capacity for every active domain.
    ///
    /// Startup calls this before activating the verifier or serving traffic.
    /// All domains commit together, so a retained-counter conflict or policy
    /// failure cannot leave a partially configured deployment.
    pub async fn preflight_attested_identity_configuration(
        &self,
        policy_digest: [u8; 32],
        event_capacity: AuthorizationEventCapacityPolicy,
    ) -> Result<()> {
        let configuration = AttestedIdentityConfiguration::new(policy_digest, event_capacity)?;
        let mut transaction = self.pool.begin().await?;
        let communities: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM communities WHERE archived_at IS NULL ORDER BY id FOR SHARE",
        )
        .fetch_all(&mut *transaction)
        .await?;
        for community_id in communities {
            install_attested_identity_configuration_tx(
                &mut transaction,
                CommunityId::from_uuid(community_id),
                configuration.policy_digest(),
                configuration.event_capacity(),
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(())
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
        lock_identity_enrollment_policy_tx(&mut transaction, community_id).await?;

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

pub(crate) async fn install_attested_identity_configuration_tx(
    transaction: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    policy_digest: [u8; 32],
    event_capacity: AuthorizationEventCapacityPolicy,
) -> Result<u64> {
    if community_id.as_uuid().is_nil() || policy_digest == [0; 32] {
        return Err(DbError::InvalidData(
            "attested identity configuration is invalid".to_owned(),
        ));
    }
    install_authorization_event_capacity_tx(transaction, community_id, event_capacity).await?;
    lock_identity_enrollment_policy_tx(transaction, community_id).await?;

    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT policy_revision FROM identity_enrollment_policies \
         WHERE community_id=$1 AND enrollment_mode=1 AND policy_digest=$2 \
           AND effective_at<=clock_timestamp() \
           AND (expires_at IS NULL OR expires_at>clock_timestamp()) \
         ORDER BY policy_revision DESC LIMIT 1 FOR SHARE",
    )
    .bind(community_id.as_uuid())
    .bind(policy_digest.as_slice())
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(existing) = existing {
        return u64::try_from(existing)
            .ok()
            .filter(|revision| *revision > 0)
            .ok_or_else(invalid_policy_revision);
    }

    let newest_revision: Option<i64> = sqlx::query_scalar(
        "SELECT max(policy_revision) FROM identity_enrollment_policies WHERE community_id=$1",
    )
    .bind(community_id.as_uuid())
    .fetch_one(&mut **transaction)
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
    .execute(&mut **transaction)
    .await?;
    u64::try_from(next_revision).map_err(|_| invalid_policy_revision())
}

fn invalid_policy_revision() -> DbError {
    DbError::InvalidData("identity enrollment policy revision is invalid".to_owned())
}

async fn lock_identity_enrollment_policy_tx(
    transaction: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
) -> Result<()> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended(\
         'buzz:identity-enrollment-policy:v1:' || $1::text,0))",
    )
    .bind(community_id.as_uuid())
    .execute(&mut **transaction)
    .await?;
    Ok(())
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
         ORDER BY policy_revision DESC LIMIT 1",
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

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;
    use uuid::Uuid;

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1

    fn capacity(events: u64, bytes: u64, envelope: u32) -> AuthorizationEventCapacityPolicy {
        AuthorizationEventCapacityPolicy::new(events, bytes, envelope)
            .expect("valid explicit test capacity")
    }

    async fn isolated_database(prefix: &str) -> (Db, PgPool) {
        let admin_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("TEST_DATABASE_URL"))
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_owned());
        let admin = PgPool::connect(&admin_url)
            .await
            .expect("connect database server");
        let database_name = format!("{}_{}", prefix, Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE {database_name}"
        )))
        .execute(&admin)
        .await
        .expect("create isolated policy database");
        let separator = admin_url.rfind('/').expect("database URL path");
        let database_url = format!("{}/{database_name}", &admin_url[..separator]);
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect isolated policy database");
        crate::migration::run_migrations(&pool)
            .await
            .expect("migrate isolated policy database");
        (Db::from_pool(pool.clone()), pool)
    }

    async fn seed_migration_bootstrap_capacity(
        pool: &PgPool,
        community_id: Uuid,
        envelopes: &[Vec<u8>],
    ) {
        let mut transaction = pool.begin().await.expect("begin migration fixture");
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *transaction)
            .await
            .expect("suspend triggers for projected migration rows");
        for (index, envelope) in envelopes.iter().enumerate() {
            let operation_id = Uuid::new_v4();
            let request_fingerprint = [u8::try_from(index + 1).expect("bounded index"); 32];
            sqlx::query(
                "INSERT INTO authorization_operation_receipts \
                 (community_id,operation_id,request_fingerprint,operation_kind,actor_fingerprint,\
                  outcome_code,result_digest) VALUES ($1,$2,$3,1,$4,1,$5)",
            )
            .bind(community_id)
            .bind(operation_id)
            .bind(request_fingerprint.as_slice())
            .bind([91_u8; 32].as_slice())
            .bind([92_u8; 32].as_slice())
            .execute(&mut *transaction)
            .await
            .expect("insert projected migration receipt");
            sqlx::query(
                "INSERT INTO authorization_events \
                 (community_id,event_id,event_kind,outcome_code,reason_code,actor_kind,\
                  actor_fingerprint,subject_fingerprint,operation_id,request_fingerprint,\
                  correlation_id,attempt_id,occurred_at,canonical_envelope,envelope_digest) \
                 VALUES ($1,$2,1,1,1,1,$3,$4,$5,$6,$7,$8,clock_timestamp(),$9,$10)",
            )
            .bind(community_id)
            .bind(Uuid::new_v4())
            .bind([91_u8; 32].as_slice())
            .bind([93_u8; 32].as_slice())
            .bind(operation_id)
            .bind(request_fingerprint.as_slice())
            .bind(Uuid::new_v4())
            .bind(Uuid::new_v4())
            .bind(envelope)
            .bind([94_u8; 32].as_slice())
            .execute(&mut *transaction)
            .await
            .expect("insert projected migration event");
        }
        let retained_count = i64::try_from(envelopes.len()).expect("bounded fixture count");
        let retained_bytes = envelopes.iter().try_fold(0_i64, |sum, envelope| {
            i64::try_from(envelope.len())
                .ok()
                .and_then(|size| sum.checked_add(size))
        });
        let retained_bytes = retained_bytes.expect("bounded fixture bytes");
        let retained_largest = envelopes
            .iter()
            .map(Vec::len)
            .max()
            .and_then(|size| i32::try_from(size).ok())
            .unwrap_or(0);
        sqlx::query(
            "INSERT INTO authorization_event_capacity \
             (community_id,configuration_state,max_events_per_domain,max_bytes_per_domain,\
              max_envelope_bytes,retained_event_count,retained_envelope_bytes,\
              retained_largest_envelope_bytes,health_state,configured_at) \
             VALUES ($1,1,NULL,NULL,NULL,$2,$3,$4,1,NULL)",
        )
        .bind(community_id)
        .bind(retained_count)
        .bind(retained_bytes)
        .bind(retained_largest)
        .execute(&mut *transaction)
        .await
        .expect("insert migration bootstrap capacity");
        sqlx::query("SET LOCAL session_replication_role = origin")
            .execute(&mut *transaction)
            .await
            .expect("restore triggers after projected migration rows");
        transaction
            .commit()
            .await
            .expect("commit projected migration capacity");
    }

    #[tokio::test]
    #[ignore = "requires an isolated Postgres database migrated through 0031"]
    async fn postgres_startup_preflight_rolls_back_replays_and_rolls_over_exactly() {
        let (db, pool) = isolated_database("identity_policy_preflight").await;
        let first_id =
            Uuid::parse_str("10000000-0000-0000-0000-000000000001").expect("fixed first domain");
        let second_id =
            Uuid::parse_str("20000000-0000-0000-0000-000000000002").expect("fixed second domain");
        let archived_id =
            Uuid::parse_str("30000000-0000-0000-0000-000000000003").expect("fixed archived domain");
        let retained_count_id =
            Uuid::parse_str("40000000-0000-0000-0000-000000000004").expect("fixed count domain");
        let retained_bytes_id =
            Uuid::parse_str("50000000-0000-0000-0000-000000000005").expect("fixed bytes domain");
        let retained_envelope_id =
            Uuid::parse_str("60000000-0000-0000-0000-000000000006").expect("fixed envelope domain");
        for (id, host, archived) in [
            (first_id, "preflight-first.example", false),
            (second_id, "preflight-second.example", false),
            (archived_id, "preflight-archived.example", true),
            (retained_count_id, "preflight-count.example", false),
            (retained_bytes_id, "preflight-bytes.example", false),
            (retained_envelope_id, "preflight-envelope.example", false),
        ] {
            sqlx::query(
                "INSERT INTO communities (id,host,archived_at) \
                 VALUES ($1,$2,CASE WHEN $3 THEN clock_timestamp() ELSE NULL END)",
            )
            .bind(id)
            .bind(host)
            .bind(archived)
            .execute(&pool)
            .await
            .expect("insert preflight domain");
        }
        seed_migration_bootstrap_capacity(&pool, first_id, &[vec![1_u8; 700]]).await;
        seed_migration_bootstrap_capacity(
            &pool,
            retained_count_id,
            &[vec![2_u8; 50], vec![3_u8; 50]],
        )
        .await;
        seed_migration_bootstrap_capacity(
            &pool,
            retained_bytes_id,
            &[vec![4_u8; 60], vec![5_u8; 60]],
        )
        .await;
        seed_migration_bootstrap_capacity(&pool, retained_envelope_id, &[vec![6_u8; 101]]).await;

        for (community_id, configured, label) in [
            (
                retained_count_id,
                capacity(1, 1_000, 1_000),
                "retained event count",
            ),
            (
                retained_bytes_id,
                capacity(10, 100, 100),
                "retained envelope bytes",
            ),
            (
                retained_envelope_id,
                capacity(10, 1_000, 100),
                "retained largest envelope",
            ),
        ] {
            let mut rejected = pool.begin().await.expect("begin retained-limit check");
            let result = install_attested_identity_configuration_tx(
                &mut rejected,
                CommunityId::from_uuid(community_id),
                [10_u8; 32],
                configured,
            )
            .await;
            assert!(result.is_err(), "{label} above configured limit must fail");
            rejected
                .rollback()
                .await
                .expect("rollback retained-limit check");
        }
        let installed_capacity = capacity(20_000, 32 * 1024 * 1024, 32 * 1024);
        crate::authorization_events::install_authorization_event_capacity(
            &db,
            CommunityId::from_uuid(second_id),
            installed_capacity,
        )
        .await
        .expect("install conflicting second-domain capacity");

        let failed = db
            .preflight_attested_identity_configuration(
                [11_u8; 32],
                capacity(10_000, 16 * 1024 * 1024, 16 * 1024),
            )
            .await;
        assert!(
            failed.is_err(),
            "immutable capacity conflict must fail startup"
        );
        let first_after_rollback: (i16, Option<i64>) = sqlx::query_as(
            "SELECT configuration_state,max_events_per_domain \
             FROM authorization_event_capacity WHERE community_id=$1",
        )
        .bind(first_id)
        .fetch_one(&pool)
        .await
        .expect("read rolled-back bootstrap capacity");
        assert_eq!(first_after_rollback, (1, None));
        let policies_after_rollback: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM identity_enrollment_policies \
             WHERE community_id IN ($1,$2)",
        )
        .bind(first_id)
        .bind(second_id)
        .fetch_one(&pool)
        .await
        .expect("count rolled-back policies");
        assert_eq!(policies_after_rollback, 0);

        db.preflight_attested_identity_configuration([12_u8; 32], installed_capacity)
            .await
            .expect("adopt bootstrap and install exact policy");
        db.preflight_attested_identity_configuration([12_u8; 32], installed_capacity)
            .await
            .expect("exact startup replay");
        let first = db.preflight_attested_identity_configuration([13_u8; 32], installed_capacity);
        let second = db.preflight_attested_identity_configuration([13_u8; 32], installed_capacity);
        let (first, second) = tokio::join!(first, second);
        first.expect("first concurrent rollover");
        second.expect("second concurrent rollover replay");
        for conflicting_capacity in [
            capacity(20_001, 32 * 1024 * 1024, 32 * 1024),
            capacity(20_000, 32 * 1024 * 1024 + 1, 32 * 1024),
            capacity(20_000, 32 * 1024 * 1024, 32 * 1024 + 1),
        ] {
            assert!(
                db.preflight_attested_identity_configuration([13_u8; 32], conflicting_capacity,)
                    .await
                    .is_err(),
                "every immutable capacity coordinate must conflict independently",
            );
        }

        for community_id in [first_id, second_id] {
            let capacity_row: (i16, i64, i64, i32) = sqlx::query_as(
                "SELECT configuration_state,max_events_per_domain,max_bytes_per_domain,\
                        max_envelope_bytes FROM authorization_event_capacity WHERE community_id=$1",
            )
            .bind(community_id)
            .fetch_one(&pool)
            .await
            .expect("read installed capacity");
            assert_eq!(capacity_row, (2, 20_000, 32 * 1024 * 1024, 32 * 1024));
            let revisions: Vec<(i64, Vec<u8>)> = sqlx::query_as(
                "SELECT policy_revision,policy_digest FROM identity_enrollment_policies \
                 WHERE community_id=$1 ORDER BY policy_revision",
            )
            .bind(community_id)
            .fetch_all(&pool)
            .await
            .expect("read exact rollover revisions");
            assert_eq!(revisions.len(), 2);
            assert_eq!(revisions[0], (1, vec![12_u8; 32]));
            assert_eq!(revisions[1], (2, vec![13_u8; 32]));
        }
        let retained: (i64, i64, i32) = sqlx::query_as(
            "SELECT retained_event_count,retained_envelope_bytes,\
                    retained_largest_envelope_bytes \
             FROM authorization_event_capacity WHERE community_id=$1",
        )
        .bind(first_id)
        .fetch_one(&pool)
        .await
        .expect("read exactly adopted retained counters");
        assert_eq!(retained, (1, 700, 700));
        let archived_capacity: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM authorization_event_capacity WHERE community_id=$1",
        )
        .bind(archived_id)
        .fetch_one(&pool)
        .await
        .expect("count archived capacity");
        assert_eq!(archived_capacity, 0, "archived domains are not activated");
    }

    #[tokio::test]
    #[ignore = "requires an isolated Postgres database migrated through 0031"]
    async fn postgres_configured_community_owner_policy_is_one_atomic_outcome() {
        let (db, pool) = isolated_database("identity_policy_provision").await;
        let explicit_capacity = capacity(10_000, 16 * 1024 * 1024, 16 * 1024);
        let configuration = AttestedIdentityConfiguration::new([21_u8; 32], explicit_capacity)
            .expect("exact installation descriptor");
        let host = format!("configured-community-{}.example", Uuid::new_v4().simple());
        let owner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let created = db
            .create_community_with_owner_and_attested_identity(&host, owner, Some(configuration))
            .await
            .expect("create configured community");
        let crate::CreateCommunityWithOwnerResult::Created(created) = created else {
            panic!("configured community must be created")
        };
        let retry = db
            .create_community_with_owner_and_attested_identity(&host, owner, Some(configuration))
            .await
            .expect("exact configured create replay");
        assert_eq!(
            retry,
            crate::CreateCommunityWithOwnerResult::Created(created.clone())
        );
        let joined: (i64, i64, i64) = sqlx::query_as(
            "SELECT \
             (SELECT count(*) FROM relay_members WHERE community_id=$1 AND pubkey=$2 AND role='owner'),\
             (SELECT count(*) FROM authorization_event_capacity WHERE community_id=$1 \
              AND configuration_state=2),\
             (SELECT count(*) FROM identity_enrollment_policies WHERE community_id=$1 \
              AND policy_digest=$3)",
        )
        .bind(created.id.as_uuid())
        .bind(owner)
        .bind([21_u8; 32].as_slice())
        .fetch_one(&pool)
        .await
        .expect("read atomic configured community state");
        assert_eq!(joined, (1, 1, 1));

        let ensured_host = format!("configured-ensure-{}.example", Uuid::new_v4().simple());
        let ensured = db
            .ensure_configured_community_with_attested_identity(
                &ensured_host,
                Some(owner),
                Some(configuration),
            )
            .await
            .expect("ensure configured community");
        let ensured_retry = db
            .ensure_configured_community_with_attested_identity(
                &ensured_host,
                Some(owner),
                Some(configuration),
            )
            .await
            .expect("exact configured ensure replay");
        assert_eq!(ensured_retry.id, ensured.id);
        let ensured_joined: (i64, i64, i64) = sqlx::query_as(
            "SELECT \
             (SELECT count(*) FROM relay_members WHERE community_id=$1 AND pubkey=$2 AND role='owner'),\
             (SELECT count(*) FROM authorization_event_capacity WHERE community_id=$1),\
             (SELECT count(*) FROM identity_enrollment_policies WHERE community_id=$1)",
        )
        .bind(ensured.id.as_uuid())
        .bind(owner)
        .fetch_one(&pool)
        .await
        .expect("read atomically ensured configuration");
        assert_eq!(ensured_joined, (1, 1, 1));

        let off_host = format!("identity-off-{}.example", Uuid::new_v4().simple());
        let off = db
            .ensure_configured_community(&off_host)
            .await
            .expect("identity-off ensure preserves stock behavior");
        let off_configuration: (i64, i64) = sqlx::query_as(
            "SELECT \
             (SELECT count(*) FROM authorization_event_capacity WHERE community_id=$1),\
             (SELECT count(*) FROM identity_enrollment_policies WHERE community_id=$1)",
        )
        .bind(off.id.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("read identity-off configuration state");
        assert_eq!(off_configuration, (0, 0));

        let preflight = db.preflight_attested_identity_configuration(
            configuration.policy_digest(),
            configuration.event_capacity(),
        );
        let ensure = db.ensure_configured_community_with_attested_identity(
            &ensured_host,
            Some(owner),
            Some(configuration),
        );
        let (preflight, ensure) = tokio::join!(preflight, ensure);
        preflight.expect("concurrent startup preflight");
        ensure.expect("concurrent provisioning exact replay");

        let mut read_only = pool.begin().await.expect("begin read-only selector");
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *read_only)
            .await
            .expect("make selector transaction read-only");
        let selected = load_attested_enrollment_policy_tx(
            &mut read_only,
            ensured.id,
            configuration.policy_digest(),
        )
        .await
        .expect("read-only policy selection")
        .expect("installed exact policy");
        assert_eq!(selected.revision, 1);
        assert_eq!(selected.digest, configuration.policy_digest());
        read_only
            .rollback()
            .await
            .expect("finish read-only selector");

        let rollback_host = format!("configured-rollback-{}.example", Uuid::new_v4().simple());
        let mut transaction = pool.begin().await.expect("begin rollback fixture");
        let rollback_id: Uuid =
            sqlx::query_scalar("INSERT INTO communities (host) VALUES ($1) RETURNING id")
                .bind(&rollback_host)
                .fetch_one(&mut *transaction)
                .await
                .expect("stage community before policy failure");
        let failure = install_attested_identity_configuration_tx(
            &mut transaction,
            CommunityId::from_uuid(rollback_id),
            [0_u8; 32],
            explicit_capacity,
        )
        .await;
        assert!(failure.is_err());
        transaction
            .rollback()
            .await
            .expect("rollback failed provision");
        let residue: i64 =
            sqlx::query_scalar("SELECT count(*) FROM communities WHERE lower(host)=lower($1)")
                .bind(&rollback_host)
                .fetch_one(&pool)
                .await
                .expect("count rollback residue");
        assert_eq!(residue, 0);
    }
}
