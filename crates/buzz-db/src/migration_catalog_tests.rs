use super::MIGRATOR;

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};
use std::time::Duration;

const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1
const TEST_DEADLINE: Duration = Duration::from_secs(120);

async fn connect_pool() -> PgPool {
    let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| TEST_DB_URL.to_owned());
    PgPoolOptions::new()
        .max_connections(4)
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
        .expect("connect catalog-parity database")
}

async fn reset_public_schema(pool: &PgPool) {
    sqlx::raw_sql("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public")
        .execute(pool)
        .await
        .expect("reset public schema");
}

async fn catalog_rows(pool: &PgPool, query: &'static str) -> Vec<String> {
    sqlx::query_scalar::<_, String>(query)
        .fetch_all(pool)
        .await
        .unwrap_or_else(|error| panic!("read PostgreSQL catalog component `{query}`: {error}"))
}

/// Canonical PostgreSQL catalog snapshot. SQLx bookkeeping and extension-owned
/// objects are excluded; all application relations, columns, constraints,
/// indexes, functions, triggers, types, partitioning, sequences, and policies
/// are compared exactly on the same server.
async fn catalog_snapshot(pool: &PgPool) -> Vec<String> {
    let mut snapshot = Vec::new();
    for query in [
        "SELECT jsonb_build_array('relation', class.relname, class.relkind, \
             class.relpersistence, class.relreplident, class.relrowsecurity, \
             class.relforcerowsecurity, COALESCE(pg_get_partkeydef(class.oid), ''), \
             COALESCE(pg_get_expr(class.relpartbound, class.oid), ''), \
             COALESCE(array_to_string(class.reloptions, ','), ''), \
             pg_get_userbyid(class.relowner), \
             COALESCE(array_to_string(class.relacl, ','), ''))::text \
         FROM pg_class class \
         JOIN pg_namespace namespace ON namespace.oid=class.relnamespace \
         WHERE namespace.nspname='public' \
           AND class.relkind IN ('r','p','S','v','m','f') \
           AND class.relname <> '_sqlx_migrations' \
           AND NOT EXISTS (SELECT 1 FROM pg_depend dependency \
                           WHERE dependency.classid='pg_class'::regclass \
                             AND dependency.objid=class.oid AND dependency.deptype='e')",
        "SELECT jsonb_build_array('column', class.relname, \
             row_number() OVER (PARTITION BY class.oid ORDER BY attribute.attnum), \
             attribute.attname, \
             format_type(attribute.atttypid, attribute.atttypmod), \
             attribute.attnotnull, COALESCE(pg_get_expr(default_value.adbin, default_value.adrelid), ''), \
             attribute.attidentity, attribute.attgenerated, \
             COALESCE(collation_row.collname, ''))::text \
         FROM pg_attribute attribute \
         JOIN pg_class class ON class.oid=attribute.attrelid \
         JOIN pg_namespace namespace ON namespace.oid=class.relnamespace \
         LEFT JOIN pg_attrdef default_value ON default_value.adrelid=attribute.attrelid \
                                            AND default_value.adnum=attribute.attnum \
         LEFT JOIN pg_collation collation_row ON collation_row.oid=attribute.attcollation \
         WHERE namespace.nspname='public' AND class.relname <> '_sqlx_migrations' \
           AND class.relkind IN ('r','p','v','m','f') \
           AND attribute.attnum>0 AND NOT attribute.attisdropped",
        "SELECT jsonb_build_array('constraint', relation.relname, constraint_row.conname, \
             constraint_row.contype, pg_get_constraintdef(constraint_row.oid, true), \
             constraint_row.condeferrable, constraint_row.condeferred, \
             constraint_row.convalidated, constraint_row.confupdtype, \
             constraint_row.confdeltype, constraint_row.confmatchtype, \
             CASE WHEN relation.relispartition THEN false \
                  ELSE constraint_row.connoinherit END)::text \
         FROM pg_constraint constraint_row \
         JOIN pg_class relation ON relation.oid=constraint_row.conrelid \
         JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace \
         WHERE namespace.nspname='public' AND relation.relname <> '_sqlx_migrations'",
        "SELECT jsonb_build_array('index', relation.relname, index_class.relname, \
             pg_get_indexdef(index_row.indexrelid), index_row.indisunique, \
             index_row.indisprimary, index_row.indisexclusion, index_row.indimmediate, \
             index_row.indisclustered, index_row.indisvalid, index_row.indcheckxmin, \
             index_row.indisready, index_row.indislive, index_row.indisreplident, \
             index_row.indnullsnotdistinct)::text \
         FROM pg_index index_row \
         JOIN pg_class relation ON relation.oid=index_row.indrelid \
         JOIN pg_class index_class ON index_class.oid=index_row.indexrelid \
         JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace \
         WHERE namespace.nspname='public' AND relation.relname <> '_sqlx_migrations'",
        "SELECT jsonb_build_array('function', procedure.proname, \
             pg_get_function_identity_arguments(procedure.oid), \
             pg_get_function_result(procedure.oid), procedure.prokind, \
             procedure.provolatile, procedure.proisstrict, procedure.prosecdef, \
             procedure.proleakproof, procedure.proparallel, language.lanname, \
             pg_get_functiondef(procedure.oid), pg_get_userbyid(procedure.proowner), \
             COALESCE(array_to_string(procedure.proacl, ','), ''))::text \
         FROM pg_proc procedure \
         JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace \
         JOIN pg_language language ON language.oid=procedure.prolang \
         WHERE namespace.nspname='public' \
           AND NOT EXISTS (SELECT 1 FROM pg_depend dependency \
                           WHERE dependency.classid='pg_proc'::regclass \
                             AND dependency.objid=procedure.oid AND dependency.deptype='e')",
        "SELECT jsonb_build_array('trigger', relation.relname, trigger_row.tgname, \
             trigger_row.tgenabled, pg_get_triggerdef(trigger_row.oid, true))::text \
         FROM pg_trigger trigger_row \
         JOIN pg_class relation ON relation.oid=trigger_row.tgrelid \
         JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace \
         WHERE namespace.nspname='public' AND NOT trigger_row.tgisinternal",
        "SELECT jsonb_build_array('type', type_row.typname, type_row.typtype, \
             format_type(type_row.typbasetype, type_row.typtypmod), type_row.typnotnull, \
             COALESCE(type_row.typdefault, ''), pg_get_userbyid(type_row.typowner), \
             COALESCE(array_to_string(type_row.typacl, ','), ''))::text \
         FROM pg_type type_row \
         JOIN pg_namespace namespace ON namespace.oid=type_row.typnamespace \
         LEFT JOIN pg_class composite_class ON composite_class.oid=type_row.typrelid \
         WHERE namespace.nspname='public' \
           AND (type_row.typtype IN ('e','d') \
                OR (type_row.typtype='c' AND composite_class.relkind='c')) \
           AND NOT EXISTS (SELECT 1 FROM pg_depend dependency \
                           WHERE dependency.classid='pg_type'::regclass \
                             AND dependency.objid=type_row.oid AND dependency.deptype='e')",
        "SELECT jsonb_build_array('composite-attribute', type_row.typname, \
             attribute.attnum, attribute.attname, \
             format_type(attribute.atttypid, attribute.atttypmod), \
             attribute.attnotnull, attribute.attidentity, attribute.attgenerated)::text \
         FROM pg_type type_row \
         JOIN pg_namespace namespace ON namespace.oid=type_row.typnamespace \
         JOIN pg_class composite_class ON composite_class.oid=type_row.typrelid \
                                      AND composite_class.relkind='c' \
         JOIN pg_attribute attribute ON attribute.attrelid=composite_class.oid \
         WHERE namespace.nspname='public' AND attribute.attnum>0 \
           AND NOT attribute.attisdropped",
        "SELECT jsonb_build_array('enum', type_row.typname, enum_row.enumsortorder, \
             enum_row.enumlabel)::text \
         FROM pg_enum enum_row \
         JOIN pg_type type_row ON type_row.oid=enum_row.enumtypid \
         JOIN pg_namespace namespace ON namespace.oid=type_row.typnamespace \
         WHERE namespace.nspname='public'",
        "SELECT jsonb_build_array('inheritance', child.relname, parent.relname, \
             inheritance.inhseqno)::text \
         FROM pg_inherits inheritance \
         JOIN pg_class child ON child.oid=inheritance.inhrelid \
         JOIN pg_class parent ON parent.oid=inheritance.inhparent \
         JOIN pg_namespace namespace ON namespace.oid=child.relnamespace \
         WHERE namespace.nspname='public'",
        "SELECT jsonb_build_array('sequence', class.relname, sequence.seqtypid::regtype::text, \
             sequence.seqstart, sequence.seqincrement, sequence.seqmax, sequence.seqmin, \
             sequence.seqcache, sequence.seqcycle)::text \
         FROM pg_sequence sequence \
         JOIN pg_class class ON class.oid=sequence.seqrelid \
         JOIN pg_namespace namespace ON namespace.oid=class.relnamespace \
         WHERE namespace.nspname='public'",
        "SELECT jsonb_build_array('policy', schemaname, tablename, policyname, \
             permissive, roles, cmd, COALESCE(qual, ''), COALESCE(with_check, ''))::text \
         FROM pg_policies WHERE schemaname='public'",
        "SELECT jsonb_build_array('extension', extension.extname, extension.extversion, \
             namespace.nspname)::text \
         FROM pg_extension extension \
         JOIN pg_namespace namespace ON namespace.oid=extension.extnamespace \
         WHERE extension.extname <> 'plpgsql'",
    ] {
        snapshot.extend(catalog_rows(pool, query).await);
    }
    snapshot.sort();
    snapshot
}

async fn seed_snapshot(pool: &PgPool) -> Vec<String> {
    let mut rows = sqlx::query_scalar::<_, String>(
        "SELECT jsonb_build_array('operator-global', table_name, reason)::text \
         FROM _operator_global_tables ORDER BY table_name",
    )
    .fetch_all(pool)
    .await
    .expect("read operator-global seed rows");
    rows.extend(
        sqlx::query_scalar::<_, String>(
            "SELECT jsonb_build_array('replica-heartbeat', id, token, epoch IS NOT NULL)::text \
             FROM replica_heartbeat ORDER BY id",
        )
        .fetch_all(pool)
        .await
        .expect("read replica-heartbeat seed row"),
    );
    rows.sort();
    rows
}

async fn parity_scenario() {
    let pool = connect_pool().await;
    reset_public_schema(&pool).await;
    MIGRATOR
        .run(&pool)
        .await
        .expect("apply complete embedded migration chain");
    let fresh_catalog = catalog_snapshot(&pool).await;
    let fresh_seeds = seed_snapshot(&pool).await;

    reset_public_schema(&pool).await;
    MIGRATOR
        .run_to(30, &pool)
        .await
        .expect("apply synthesized #1476 boundary");
    sqlx::raw_sql(
        r#"
        INSERT INTO communities (id,host)
        VALUES ('41000000-0000-0000-0000-000000000001','catalog-upgrade.example');
        INSERT INTO identity_bindings
            (community_id,issuer,uid,pubkey,source,created_at,updated_at,last_seen_at)
        VALUES
            ('41000000-0000-0000-0000-000000000001','catalog-issuer','catalog-subject',
             decode(repeat('41',32),'hex'),'jwt_npub',
             '2026-02-01 00:00:00+00','2026-02-01 00:00:00+00','2026-02-01 00:00:00+00');
        "#,
    )
    .execute(&pool)
    .await
    .expect("seed populated synthesized #1476 identity");
    MIGRATOR
        .run_to(31, &pool)
        .await
        .expect("project populated synthesized #1476 through 0031");
    let preserved: (String, String, Vec<u8>, i16, i64) = sqlx::query_as(
        "SELECT issuer,subject,event_author_pubkey,binding_state,binding_version \
         FROM identity_bindings WHERE community_id=$1",
    )
    .bind(uuid::Uuid::parse_str("41000000-0000-0000-0000-000000000001").unwrap())
    .fetch_one(&pool)
    .await
    .expect("read projected binding");
    assert_eq!(preserved.0, "catalog-issuer");
    assert_eq!(preserved.1, "catalog-subject");
    assert_eq!(preserved.2, vec![0x41; 32]);
    assert_eq!(preserved.3, 1);
    assert!(preserved.4 > 0);
    MIGRATOR
        .run_to(32, &pool)
        .await
        .expect("apply protected-authority prerequisite 0032");
    let protected_rows: (i64, i64, i64) = sqlx::query_as(
        "SELECT \
            (SELECT count(*) FROM authorization_invalidation_domains), \
            (SELECT count(*) FROM authorization_authority_epochs), \
            (SELECT count(*) FROM protected_object_authority)",
    )
    .fetch_one(&pool)
    .await
    .expect("read empty protected-authority prerequisite tables");
    assert_eq!(protected_rows, (0, 0, 0));
    let populated_catalog = catalog_snapshot(&pool).await;
    let populated_seeds = seed_snapshot(&pool).await;
    assert_eq!(
        populated_catalog, fresh_catalog,
        "populated synthesized-#1476 upgrade must produce the fresh 0032 catalog"
    );
    assert_eq!(populated_seeds, fresh_seeds);

    reset_public_schema(&pool).await;
    sqlx::raw_sql(include_str!("../../../schema/schema.sql"))
        .execute(&pool)
        .await
        .expect("apply regenerated desired-state schema");
    let desired_catalog = catalog_snapshot(&pool).await;
    let desired_seeds = seed_snapshot(&pool).await;

    if desired_catalog != fresh_catalog {
        let desired_only: Vec<_> = desired_catalog
            .iter()
            .filter(|row| !fresh_catalog.contains(row))
            .take(25)
            .collect();
        let migrated_only: Vec<_> = fresh_catalog
            .iter()
            .filter(|row| !desired_catalog.contains(row))
            .take(25)
            .collect();
        panic!(
            "desired schema must exactly match the installed PostgreSQL catalog; \
             desired-only={desired_only:#?}; migrated-only={migrated_only:#?}"
        );
    }
    assert_eq!(
        desired_seeds, fresh_seeds,
        "desired schema must install the same deterministic seed state"
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a dedicated disposable Postgres database"]
async fn protected_authority_0032_fresh_populated_and_desired_schema_have_full_postgresql_catalog_parity(
) {
    tokio::time::timeout(TEST_DEADLINE, parity_scenario())
        .await
        .expect("full catalog parity exceeded its 120-second wall-clock budget");
}
