use super::MIGRATOR;

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};
use std::time::Duration;
use uuid::Uuid;

const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1
const TEST_DEADLINE: Duration = Duration::from_secs(120);

async fn connect_pool() -> PgPool {
    let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| TEST_DB_URL.to_owned());
    PgPoolOptions::new()
        .max_connections(6)
        .after_connect(|connection, _| {
            Box::pin(async move {
                (&mut *connection)
                    .execute("SET statement_timeout = '30s'")
                    .await?;
                (&mut *connection)
                    .execute("SET lock_timeout = '5s'")
                    .await?;
                (&mut *connection)
                    .execute("SET idle_in_transaction_session_timeout = '30s'")
                    .await?;
                (&mut *connection).execute("SET TIME ZONE 'UTC'").await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await
        .expect("connect operator-preauth migration database")
}

async fn reset_public_schema(pool: &PgPool) {
    sqlx::raw_sql("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public")
        .execute(pool)
        .await
        .expect("reset public schema");
}

async fn insert_community(pool: &PgPool, community_id: Uuid, label: &str) {
    sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
        .bind(community_id)
        .bind(format!("{label}-{}.example", community_id.simple()))
        .execute(pool)
        .await
        .expect("insert preauth test community");
}

async fn assert_capacity_exact(pool: &PgPool, community_id: Uuid, expected: (i64, i64, i32)) {
    let actual: (i64, i64, i32) = sqlx::query_as(
        "SELECT retained_event_count,retained_envelope_bytes, \
                retained_largest_envelope_bytes \
         FROM authorization_operator_preauth_denial_capacity WHERE community_id=$1",
    )
    .bind(community_id)
    .fetch_one(pool)
    .await
    .expect("read exact preauth capacity");
    assert_eq!(actual, expected);
    let recomputed: (i64, i64, i32) = sqlx::query_as(
        "SELECT count(*),COALESCE(sum(octet_length(canonical_envelope)),0), \
                COALESCE(max(octet_length(canonical_envelope)),0) \
         FROM authorization_operator_preauth_denial_events WHERE community_id=$1",
    )
    .bind(community_id)
    .fetch_one(pool)
    .await
    .expect("recompute exact preauth capacity");
    assert_eq!(actual, recomputed);
}

#[tokio::test]
#[ignore = "requires a dedicated disposable Postgres database"]
async fn operator_preauth_0034_enforces_bounded_retention_and_trigger_ownership() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let pool = connect_pool().await;
        reset_public_schema(&pool).await;
        MIGRATOR
            .run(&pool)
            .await
            .expect("apply complete migration chain through 0034");

        let orphan: Option<String> = sqlx::query_scalar(
            "SELECT to_regclass('authorization_authentication_denial_attempts')::text",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect removed orphan table");
        assert_eq!(orphan, None);

        for function_name in [
            "authorization_operator_preauth_denial_capacity_before_insert_v1",
            "authorization_operator_preauth_denial_capacity_guard_v1",
            "authorization_operator_preauth_denial_events_retention_guard_v1",
        ] {
            let security: (bool, bool, bool, bool) = sqlx::query_as(
                "SELECT prosecdef, \
                        proconfig @> ARRAY['search_path=pg_catalog, public']::text[], \
                        pronargs=0, \
                        NOT EXISTS ( \
                            SELECT 1 \
                            FROM aclexplode(COALESCE(proacl,acldefault('f',proowner))) privilege \
                            WHERE privilege.grantee=0 AND privilege.privilege_type='EXECUTE' \
                        ) \
                 FROM pg_proc WHERE proname=$1",
            )
            .bind(function_name)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|error| panic!("inspect {function_name}: {error}"));
            assert_eq!(security, (true, true, true, true), "{function_name}");
        }

        let boundary_specs = [
            (
                "71000000-0000-0000-0000-000000000001",
                1_000_000_i64,
                4_294_967_296_i64,
                65_536_i32,
                true,
            ),
            (
                "71000000-0000-0000-0000-000000000002",
                1_000_001,
                4_294_967_296,
                65_536,
                false,
            ),
            (
                "71000000-0000-0000-0000-000000000003",
                1_000_000,
                4_294_967_297,
                65_536,
                false,
            ),
            (
                "71000000-0000-0000-0000-000000000004",
                1_000_000,
                4_294_967_296,
                65_537,
                false,
            ),
        ];
        for (raw_id, max_events, max_bytes, max_envelope, valid) in boundary_specs {
            let community_id = Uuid::parse_str(raw_id).unwrap();
            insert_community(&pool, community_id, "preauth-boundary").await;
            let result = sqlx::query(
                "INSERT INTO authorization_operator_preauth_denial_capacity \
                 (community_id,max_events_per_domain,max_bytes_per_domain,max_envelope_bytes) \
                 VALUES ($1,$2,$3,$4)",
            )
            .bind(community_id)
            .bind(max_events)
            .bind(max_bytes)
            .bind(max_envelope)
            .execute(&pool)
            .await;
            assert_eq!(
                result.is_ok(),
                valid,
                "unexpected policy bound result for {raw_id}"
            );
        }

        let replay_domain = Uuid::parse_str("72000000-0000-0000-0000-000000000001").unwrap();
        insert_community(&pool, replay_domain, "preauth-replay").await;
        sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_capacity \
             (community_id,max_events_per_domain,max_bytes_per_domain,max_envelope_bytes) \
             VALUES ($1,100,1048576,65536)",
        )
        .bind(replay_domain)
        .execute(&pool)
        .await
        .expect("install replay capacity");
        let canonical_before: (i64, i64, i64, i64, i32, i16) = sqlx::query_as(
            "SELECT \
                (SELECT count(*) FROM authorization_operation_receipts WHERE community_id=$1), \
                (SELECT count(*) FROM authorization_events WHERE community_id=$1), \
                retained_event_count,retained_envelope_bytes, \
                retained_largest_envelope_bytes,health_state \
             FROM authorization_event_capacity WHERE community_id=$1",
        )
        .bind(replay_domain)
        .fetch_optional(&pool)
        .await
        .expect("read canonical isolation baseline")
        .unwrap_or((0, 0, 0, 0, 0, 1));
        let event_id = Uuid::parse_str("72000000-0000-0000-0000-000000000011").unwrap();
        let operation_id = Uuid::parse_str("72000000-0000-0000-0000-000000000012").unwrap();
        let correlation_id = Uuid::parse_str("72000000-0000-0000-0000-000000000013").unwrap();
        let attempt_id = Uuid::parse_str("72000000-0000-0000-0000-000000000014").unwrap();
        sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_events \
             (community_id,event_id,operation_id,correlation_id,attempt_id, \
              semantic_fingerprint,denial_reason,expected_revision,action,reason_code, \
              occurred_at,canonical_envelope,envelope_digest,retain_until) \
             VALUES ($1,$2,$3,$4,$5,decode(repeat('11',32),'hex'),1,1,1,1, \
                     clock_timestamp(),decode('01020304','hex'), \
                     decode(repeat('22',32),'hex'),clock_timestamp()+interval '1 hour')",
        )
        .bind(replay_domain)
        .bind(event_id)
        .bind(operation_id)
        .bind(correlation_id)
        .bind(attempt_id)
        .execute(&pool)
        .await
        .expect("insert one retained preauth denial");
        assert_capacity_exact(&pool, replay_domain, (1, 4, 4)).await;

        let conflicting = sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_events \
             (community_id,event_id,operation_id,correlation_id,attempt_id, \
              semantic_fingerprint,denial_reason,expected_revision,action,reason_code, \
              occurred_at,canonical_envelope,envelope_digest,retain_until) \
             VALUES ($1,$2,$3,$4,$5,decode(repeat('11',32),'hex'),1,2,2,2, \
                     clock_timestamp(),decode('05','hex'), \
                     decode(repeat('33',32),'hex'),clock_timestamp()+interval '1 hour')",
        )
        .bind(replay_domain)
        .bind(Uuid::new_v4())
        .bind(operation_id)
        .bind(correlation_id)
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await;
        assert!(
            conflicting.is_err(),
            "changed five-coordinate replay must conflict"
        );
        assert_capacity_exact(&pool, replay_domain, (1, 4, 4)).await;

        let restart = sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_capacity \
             (community_id,max_events_per_domain,max_bytes_per_domain,max_envelope_bytes) \
             VALUES ($1,100,1048576,65536) ON CONFLICT (community_id) DO NOTHING",
        )
        .bind(replay_domain)
        .execute(&pool)
        .await
        .expect("restart policy replay with retained rows");
        assert_eq!(restart.rows_affected(), 0);
        assert_capacity_exact(&pool, replay_domain, (1, 4, 4)).await;

        let mut forged_transition = pool.begin().await.expect("begin forged transition");
        sqlx::query(
            "SELECT set_config('buzz.operator_preauth_capacity_transition', \
                    'insert:' || $1::text, true)",
        )
        .bind(replay_domain)
        .execute(&mut *forged_transition)
        .await
        .expect("forge caller-visible transition setting");
        let forged_update = sqlx::query(
            "UPDATE authorization_operator_preauth_denial_capacity \
             SET retained_event_count=retained_event_count+1 WHERE community_id=$1",
        )
        .bind(replay_domain)
        .execute(&mut *forged_transition)
        .await;
        assert!(forged_update.is_err());
        forged_transition
            .rollback()
            .await
            .expect("roll back forged transition");
        let direct_update = sqlx::query(
            "UPDATE authorization_operator_preauth_denial_events \
             SET reason_code=2 WHERE community_id=$1",
        )
        .bind(replay_domain)
        .execute(&pool)
        .await;
        assert!(direct_update.is_err());
        let direct_delete = sqlx::query(
            "DELETE FROM authorization_operator_preauth_denial_events WHERE community_id=$1",
        )
        .bind(replay_domain)
        .execute(&pool)
        .await;
        assert!(direct_delete.is_err());

        let reclaim_domain = Uuid::parse_str("73000000-0000-0000-0000-000000000001").unwrap();
        insert_community(&pool, reclaim_domain, "preauth-reclaim").await;
        sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_capacity \
             (community_id,max_events_per_domain,max_bytes_per_domain,max_envelope_bytes) \
             VALUES ($1,300,1048576,5)",
        )
        .bind(reclaim_domain)
        .execute(&pool)
        .await
        .expect("install reclaim capacity");
        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_events \
                 DISABLE TRIGGER authorization_operator_preauth_denial_capacity_insert; \
             ALTER TABLE authorization_operator_preauth_denial_capacity \
                 DISABLE TRIGGER authorization_operator_preauth_denial_capacity_monotonic",
        )
        .execute(&pool)
        .await
        .expect("open bounded reclaim fixture");
        sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_events \
             (community_id,event_id,operation_id,correlation_id,attempt_id, \
              semantic_fingerprint,denial_reason,expected_revision,action,reason_code, \
              occurred_at,accepted_at,canonical_envelope,envelope_digest,retain_until) \
             SELECT $1,md5('event-'||value)::uuid,md5('operation-'||value)::uuid, \
                    md5('correlation-'||value)::uuid,md5('attempt-'||value)::uuid, \
                    digest('semantic-'||value,'sha256'),1,1,1,1, \
                    clock_timestamp()-interval '25 hours', \
                    clock_timestamp()-interval '25 hours', \
                    decode(repeat('ab',CASE WHEN value=1 THEN 5 \
                                            WHEN value<=256 THEN 2 ELSE 1 END),'hex'), \
                    digest('envelope-'||value,'sha256'), \
                    CASE WHEN value<=256 THEN clock_timestamp()-interval '1 second' \
                         ELSE clock_timestamp()+interval '1 hour' END \
             FROM generate_series(1,257) value",
        )
        .bind(reclaim_domain)
        .execute(&pool)
        .await
        .expect("seed ordered expired denial rows");
        sqlx::query(
            "UPDATE authorization_operator_preauth_denial_capacity \
             SET retained_event_count=257,retained_envelope_bytes=516, \
                 retained_largest_envelope_bytes=5 WHERE community_id=$1",
        )
        .bind(reclaim_domain)
        .execute(&pool)
        .await
        .expect("seed exact reclaim aggregates");
        sqlx::raw_sql(
            "ALTER TABLE authorization_operator_preauth_denial_capacity \
                 ENABLE TRIGGER authorization_operator_preauth_denial_capacity_monotonic; \
             ALTER TABLE authorization_operator_preauth_denial_events \
                 ENABLE TRIGGER authorization_operator_preauth_denial_capacity_insert",
        )
        .execute(&pool)
        .await
        .expect("seal bounded reclaim fixture");

        let retained_expired_replay = sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_events \
             (community_id,event_id,operation_id,correlation_id,attempt_id, \
              semantic_fingerprint,denial_reason,expected_revision,action,reason_code, \
              occurred_at,accepted_at,canonical_envelope,envelope_digest,retain_until) \
             SELECT community_id,event_id,operation_id,correlation_id,attempt_id, \
                    semantic_fingerprint,denial_reason,expected_revision,action,reason_code, \
                    occurred_at,accepted_at,canonical_envelope,envelope_digest,retain_until \
             FROM authorization_operator_preauth_denial_events \
             WHERE community_id=$1 AND event_id=md5('event-1')::uuid",
        )
        .bind(reclaim_domain)
        .execute(&pool)
        .await
        .expect("expired retained exact replay is idempotent");
        assert_eq!(retained_expired_replay.rows_affected(), 0);
        assert_capacity_exact(&pool, reclaim_domain, (257, 516, 5)).await;

        let mut reclaim_transaction = pool.begin().await.expect("begin reclaim exhaustion");
        let exhausted = sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_events \
             (community_id,event_id,operation_id,correlation_id,attempt_id, \
              semantic_fingerprint,denial_reason,expected_revision,action,reason_code, \
              occurred_at,canonical_envelope,envelope_digest,retain_until) \
             VALUES ($1,$2,$3,$4,$5,decode(repeat('44',32),'hex'),2,1,2,2, \
                     clock_timestamp(),decode(repeat('cd',6),'hex'), \
                     decode(repeat('55',32),'hex'),clock_timestamp()+interval '1 hour')",
        )
        .bind(reclaim_domain)
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .execute(&mut *reclaim_transaction)
        .await
        .expect("capacity exhaustion is a committed zero-row outcome");
        assert_eq!(exhausted.rows_affected(), 0);
        let transaction_owns_signal: bool = sqlx::query_scalar(
            "SELECT last_signal_xid=pg_current_xact_id() \
             FROM authorization_operator_preauth_denial_capacity WHERE community_id=$1",
        )
        .bind(reclaim_domain)
        .fetch_one(&mut *reclaim_transaction)
        .await
        .expect("signal claim belongs to the saturating transaction");
        assert!(transaction_owns_signal);
        reclaim_transaction
            .commit()
            .await
            .expect("commit reclaim despite exhausted insertion");
        assert_capacity_exact(&pool, reclaim_domain, (1, 1, 1)).await;
        let saturation: (i64, i64, bool, bool) = sqlx::query_as(
            "SELECT saturation_generation,last_signaled_generation, \
                    last_signal_xid IS NOT NULL, \
                    next_signal_at=last_signal_at+interval '60 seconds' \
             FROM authorization_operator_preauth_denial_capacity WHERE community_id=$1",
        )
        .bind(reclaim_domain)
        .fetch_one(&pool)
        .await
        .expect("read committed saturation episode");
        assert_eq!(saturation, (1, 1, true, true));

        let rollback_domain = Uuid::parse_str("74000000-0000-0000-0000-000000000001").unwrap();
        insert_community(&pool, rollback_domain, "preauth-rollback").await;
        sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_capacity \
             (community_id,max_events_per_domain,max_bytes_per_domain,max_envelope_bytes) \
             VALUES ($1,100,1048576,1)",
        )
        .bind(rollback_domain)
        .execute(&pool)
        .await
        .expect("install rollback capacity");
        let insert_saturated = |event_id: Uuid, operation_id: Uuid, correlation_id: Uuid| {
            sqlx::query(
                "INSERT INTO authorization_operator_preauth_denial_events \
                 (community_id,event_id,operation_id,correlation_id,attempt_id, \
                  semantic_fingerprint,denial_reason,expected_revision,action,reason_code, \
                  occurred_at,canonical_envelope,envelope_digest,retain_until) \
                 VALUES ($1,$2,$3,$4,$5,digest($2::text,'sha256'),3,1,3,3, \
                         clock_timestamp(),decode('0102','hex'),digest($3::text,'sha256'), \
                         clock_timestamp()+interval '1 hour')",
            )
            .bind(rollback_domain)
            .bind(event_id)
            .bind(operation_id)
            .bind(correlation_id)
            .bind(Uuid::new_v4())
        };
        let first = insert_saturated(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let second = insert_saturated(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let (first, second) = tokio::join!(first.execute(&pool), second.execute(&pool));
        assert_eq!(
            first.expect("first concurrent saturation").rows_affected(),
            0
        );
        assert_eq!(
            second
                .expect("second concurrent saturation")
                .rows_affected(),
            0
        );
        let concurrent_state: (i64, i64) = sqlx::query_as(
            "SELECT saturation_generation,last_signaled_generation \
             FROM authorization_operator_preauth_denial_capacity WHERE community_id=$1",
        )
        .bind(rollback_domain)
        .fetch_one(&pool)
        .await
        .expect("read concurrent saturation state");
        assert_eq!(concurrent_state, (1, 1));

        let mut rolled_back = pool.begin().await.expect("begin rolled-back claim");
        sqlx::query(
            "INSERT INTO authorization_operator_preauth_denial_events \
             (community_id,event_id,operation_id,correlation_id,attempt_id, \
              semantic_fingerprint,denial_reason,expected_revision,action,reason_code, \
              occurred_at,canonical_envelope,envelope_digest,retain_until) \
             VALUES ($1,$2,$3,$4,$5,decode(repeat('66',32),'hex'),1,1,1,1, \
                     clock_timestamp(),decode('0102','hex'),decode(repeat('77',32),'hex'), \
                     clock_timestamp()+interval '1 hour')",
        )
        .bind(rollback_domain)
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .execute(&mut *rolled_back)
        .await
        .expect("run rolled-back saturated attempt");
        rolled_back
            .rollback()
            .await
            .expect("roll back saturated attempt");
        let after_rollback: (i64, i64) = sqlx::query_as(
            "SELECT saturation_generation,last_signaled_generation \
             FROM authorization_operator_preauth_denial_capacity WHERE community_id=$1",
        )
        .bind(rollback_domain)
        .fetch_one(&pool)
        .await
        .expect("read state after rollback");
        assert_eq!(after_rollback, concurrent_state);

        let canonical_after: (i64, i64, i64, i64, i32, i16) = sqlx::query_as(
            "SELECT \
                (SELECT count(*) FROM authorization_operation_receipts WHERE community_id=$1), \
                (SELECT count(*) FROM authorization_events WHERE community_id=$1), \
                retained_event_count,retained_envelope_bytes, \
                retained_largest_envelope_bytes,health_state \
             FROM authorization_event_capacity WHERE community_id=$1",
        )
        .bind(replay_domain)
        .fetch_optional(&pool)
        .await
        .expect("read canonical isolation result")
        .unwrap_or((0, 0, 0, 0, 0, 1));
        assert_eq!(canonical_after, canonical_before);

        assert!(
            sqlx::query("TRUNCATE authorization_operator_preauth_denial_events")
                .execute(&pool)
                .await
                .is_err()
        );
        assert!(
            sqlx::query("TRUNCATE authorization_operator_preauth_denial_capacity")
                .execute(&pool)
                .await
                .is_err()
        );
        pool.close().await;
    })
    .await
    .expect("0034 operator-preauth behavior exceeded 120 seconds");
}
