//! SQLite FTS5 parity coverage for the single-node profile.

use buzz_core::CommunityId;
use buzz_db::Db;
use buzz_search::{ChannelScope, SearchMode, SearchQuery, SearchService};
use sqlx::SqlitePool;
use uuid::Uuid;

async fn setup() -> (Db, CommunityId) {
    let db = Db::new_sqlite("sqlite::memory:").await.expect("SQLite DB");
    let community = db
        .ensure_configured_community(&format!("{}.example", Uuid::new_v4()))
        .await
        .expect("community")
        .id;
    (db, community)
}

#[allow(clippy::too_many_arguments)]
async fn insert_event(
    pool: &SqlitePool,
    community: CommunityId,
    id: [u8; 32],
    pubkey: [u8; 32],
    kind: i32,
    content: &str,
    channel: Option<Uuid>,
    created_at: i64,
) {
    sqlx::query("INSERT INTO events (community_id,id,pubkey,created_at,kind,tags_json,content,sig,channel_id,received_at,event_json) VALUES (?1,?2,?3,?4,?5,'[]',?6,?7,?8,?4,'{}')")
        .bind(community.as_uuid().to_string())
        .bind(id.as_slice())
        .bind(pubkey.as_slice())
        .bind(created_at)
        .bind(kind)
        .bind(content)
        .bind([0_u8; 64].as_slice())
        .bind(channel.map(|id| id.to_string()))
        .execute(pool)
        .await
        .expect("insert event");
}

fn query(community: CommunityId, text: &str) -> SearchQuery {
    SearchQuery {
        community,
        q: text.into(),
        channel_scope: ChannelScope::Any,
        kinds: None,
        authors: None,
        since: None,
        until: None,
        page: 1,
        per_page: 10,
        mode: SearchMode::FullText,
    }
}

#[tokio::test]
async fn tenant_channel_kind_author_and_time_filters_match_sqlite_rows() {
    let (db, community) = setup().await;
    let foreign = db
        .ensure_configured_community(&format!("{}.example", Uuid::new_v4()))
        .await
        .unwrap()
        .id;
    let pool = db.sqlite_pool_clone().unwrap();
    let channel = Uuid::new_v4();
    let other_channel = Uuid::new_v4();
    let author = [7; 32];
    insert_event(
        &pool,
        community,
        [1; 32],
        author,
        9,
        "filter needle",
        Some(channel),
        100,
    )
    .await;
    insert_event(
        &pool,
        community,
        [2; 32],
        [8; 32],
        9,
        "filter needle",
        Some(other_channel),
        200,
    )
    .await;
    insert_event(
        &pool,
        community,
        [3; 32],
        author,
        0,
        "filter needle",
        None,
        300,
    )
    .await;
    insert_event(
        &pool,
        foreign,
        [4; 32],
        author,
        9,
        "filter needle",
        Some(channel),
        100,
    )
    .await;

    let service = SearchService::sqlite(pool);
    let mut q = query(community, "needle");
    q.channel_scope = ChannelScope::Channels(vec![channel]);
    q.kinds = Some(vec![9]);
    q.authors = Some(vec![author.to_vec()]);
    q.since = Some(90);
    q.until = Some(110);
    let result = service.search(&q).await.unwrap();
    assert_eq!(
        result
            .hits
            .iter()
            .map(|hit| hit.event_id)
            .collect::<Vec<_>>(),
        vec![[1; 32]]
    );

    q.channel_scope = ChannelScope::ChannelLessOnly;
    q.kinds = Some(vec![0]);
    q.since = None;
    q.until = None;
    let result = service.search(&q).await.unwrap();
    assert_eq!(
        result
            .hits
            .iter()
            .map(|hit| hit.event_id)
            .collect::<Vec<_>>(),
        vec![[3; 32]]
    );
}

#[tokio::test]
async fn prefix_full_text_pagination_and_query_bounds_work() {
    let (db, community) = setup().await;
    let pool = db.sqlite_pool_clone().unwrap();
    for (index, content) in ["project alpha", "project alpine", "project beta"]
        .into_iter()
        .enumerate()
    {
        insert_event(
            &pool,
            community,
            [index as u8 + 1; 32],
            [9; 32],
            9,
            content,
            None,
            100 + index as i64,
        )
        .await;
    }
    let service = SearchService::sqlite(pool);
    let mut q = query(community, "alp");
    assert!(service.search(&q).await.unwrap().hits.is_empty());
    q.mode = SearchMode::Prefix;
    assert_eq!(service.search(&q).await.unwrap().hits.len(), 2);
    q.q = "project al...".into();
    assert_eq!(service.search(&q).await.unwrap().hits.len(), 2);
    q.q = "project".into();
    q.per_page = 1;
    let first = service.search(&q).await.unwrap();
    q.page = 2;
    let second = service.search(&q).await.unwrap();
    assert_eq!(first.hits.len(), 1);
    assert_eq!(second.hits.len(), 1);
    assert_ne!(first.hits[0].event_id, second.hits[0].event_id);
    q.q = format!("project\0{}", "x".repeat(20_000));
    let _ = service.search(&q).await.unwrap();
    q.page = u32::MAX;
    assert_eq!(service.search(&q).await.unwrap().page, 1_000);
}

#[tokio::test]
async fn allowlist_and_delete_update_triggers_preserve_storage_privacy() {
    let (db, community) = setup().await;
    let pool = db.sqlite_pool_clone().unwrap();
    for (index, kind) in [9, 1059, 30300, 30350, 30622, 44100, 44101, 44200]
        .into_iter()
        .enumerate()
    {
        insert_event(
            &pool,
            community,
            [index as u8 + 1; 32],
            [4; 32],
            kind,
            "private marker",
            None,
            100,
        )
        .await;
    }
    let service = SearchService::sqlite(pool.clone());
    let q = query(community, "marker");
    let result = service.search(&q).await.unwrap();
    assert_eq!(
        result.hits.iter().map(|hit| hit.kind).collect::<Vec<_>>(),
        vec![9]
    );

    sqlx::query(
        "UPDATE events SET content = 'replacement token' WHERE community_id = ?1 AND id = ?2",
    )
    .bind(community.as_uuid().to_string())
    .bind([1_u8; 32].as_slice())
    .execute(&pool)
    .await
    .unwrap();
    assert!(service.search(&q).await.unwrap().hits.is_empty());
    assert_eq!(
        service
            .search(&query(community, "replacement"))
            .await
            .unwrap()
            .hits
            .len(),
        1
    );
    sqlx::query("DELETE FROM events WHERE community_id = ?1 AND id = ?2")
        .bind(community.as_uuid().to_string())
        .bind([1_u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(service
        .search(&query(community, "replacement"))
        .await
        .unwrap()
        .hits
        .is_empty());
}

#[tokio::test]
async fn migration_backfills_existing_rows_and_survives_reopen() {
    let path = std::env::temp_dir().join(format!("buzz-search-{}.sqlite", Uuid::new_v4()));
    let url = path.to_string_lossy().to_string();
    let db = Db::new_sqlite(&url).await.unwrap();
    let community = db
        .ensure_configured_community("reopen.example")
        .await
        .unwrap()
        .id;
    let pool = db.sqlite_pool_clone().unwrap();
    insert_event(
        &pool,
        community,
        [5; 32],
        [6; 32],
        9,
        "durable orchard",
        None,
        100,
    )
    .await;
    pool.close().await;
    drop(db);

    let reopened = Db::new_sqlite(&url).await.unwrap();
    let service = SearchService::sqlite(reopened.sqlite_pool_clone().unwrap());
    assert_eq!(
        service
            .search(&query(community, "orchard"))
            .await
            .unwrap()
            .hits
            .len(),
        1
    );
    drop(reopened);
    let _ = std::fs::remove_file(path);
}
