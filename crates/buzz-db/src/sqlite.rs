//! SQLite storage for the single-node relay profile.
//!
//! This module deliberately contains a separate, minimal schema rather than
//! attempting to translate the production PostgreSQL migrations.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;
use uuid::Uuid;

use buzz_core::CommunityId;

use crate::{CommunityRecord, EnsuredCommunityRecord, Result};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS communities (
    id TEXT PRIMARY KEY NOT NULL,
    host TEXT NOT NULL COLLATE NOCASE UNIQUE,
    icon TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    archived_at INTEGER
);

CREATE TABLE IF NOT EXISTS relay_members (
    community_id TEXT NOT NULL,
    pubkey TEXT NOT NULL COLLATE NOCASE,
    role TEXT NOT NULL,
    added_by TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (community_id, pubkey),
    FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users (
    community_id TEXT NOT NULL,
    pubkey BLOB NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    about TEXT,
    nip05_handle TEXT,
    channel_add_policy TEXT NOT NULL DEFAULT 'anyone',
    is_agent INTEGER NOT NULL DEFAULT 0,
    agent_owner_pubkey BLOB,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (community_id, pubkey),
    FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY NOT NULL,
    community_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    canvas TEXT,
    channel_type TEXT NOT NULL,
    visibility TEXT NOT NULL,
    participant_hash BLOB,
    created_by BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    archived_at INTEGER,
    deleted_at INTEGER,
    nip29_group_id TEXT,
    topic_required INTEGER NOT NULL DEFAULT 0,
    max_members INTEGER,
    topic TEXT,
    topic_set_by BLOB,
    topic_set_at INTEGER,
    purpose TEXT,
    purpose_set_by BLOB,
    purpose_set_at INTEGER,
    ttl_seconds INTEGER,
    ttl_deadline INTEGER,
    FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS channel_members (
    channel_id TEXT NOT NULL,
    pubkey BLOB NOT NULL,
    role TEXT NOT NULL,
    joined_at INTEGER NOT NULL DEFAULT (unixepoch()),
    invited_by BLOB,
    hidden_at INTEGER,
    removed_at INTEGER,
    PRIMARY KEY (channel_id, pubkey),
    FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS moderation_restrictions (
    community_id TEXT NOT NULL,
    pubkey TEXT NOT NULL COLLATE NOCASE,
    restriction_type TEXT NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (community_id, pubkey, restriction_type),
    FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    community_id TEXT NOT NULL,
    id BLOB NOT NULL,
    pubkey BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    kind INTEGER NOT NULL,
    tags_json TEXT NOT NULL,
    content TEXT NOT NULL,
    sig BLOB NOT NULL,
    channel_id TEXT,
    received_at INTEGER NOT NULL,
    event_json TEXT NOT NULL,
    PRIMARY KEY (community_id, id),
    FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_community_created
    ON events (community_id, created_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_events_community_kind
    ON events (community_id, kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_channel_created
    ON events (community_id, channel_id, created_at DESC);

CREATE TABLE IF NOT EXISTS reactions (
    community_id TEXT NOT NULL,
    event_created_at INTEGER NOT NULL,
    event_id BLOB NOT NULL,
    pubkey BLOB NOT NULL,
    emoji TEXT NOT NULL,
    reaction_event_id BLOB,
    removed_at INTEGER,
    PRIMARY KEY (community_id, event_created_at, event_id, pubkey, emoji),
    FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reactions_source_event
    ON reactions (community_id, reaction_event_id)
    WHERE reaction_event_id IS NOT NULL;
"#;

pub(crate) async fn connect(path_or_url: &str) -> Result<SqlitePool> {
    let database_url = if path_or_url.starts_with("sqlite:") {
        path_or_url.to_owned()
    } else {
        format!("sqlite://{path_or_url}")
    };
    let options = SqliteConnectOptions::from_str(&database_url)?
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    migrate(&pool).await?;
    Ok(pool)
}

pub(crate) async fn migrate(pool: &SqlitePool) -> Result<()> {
    let had_application_schema = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'channels'",
    )
    .fetch_one(pool)
    .await?
        != 0;

    for statement in SCHEMA.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        sqlx::query(statement).execute(pool).await?;
    }
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_version (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL)",
    )
    .execute(pool)
    .await?;
    let initial_version = if had_application_schema { 1_i64 } else { 2_i64 };
    sqlx::query(
        "INSERT INTO schema_version (singleton, version) VALUES (1, ?1) ON CONFLICT(singleton) DO NOTHING",
    )
    .bind(initial_version)
    .execute(pool)
    .await?;

    let mut version =
        sqlx::query_scalar::<_, i64>("SELECT version FROM schema_version WHERE singleton = 1")
            .fetch_one(pool)
            .await?;
    if version < 2 {
        let mut tx = pool.begin().await?;
        ensure_column_on(
            &mut tx,
            "channels",
            "participant_hash",
            "ALTER TABLE channels ADD COLUMN participant_hash BLOB",
        )
        .await?;
        ensure_column_on(
            &mut tx,
            "channel_members",
            "hidden_at",
            "ALTER TABLE channel_members ADD COLUMN hidden_at INTEGER",
        )
        .await?;
        sqlx::query("UPDATE schema_version SET version = 2 WHERE singleton = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 2;
    }
    if version < 3 {
        let mut tx = pool.begin().await?;
        for statement in [
            "CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(content, content='events', content_rowid='rowid', tokenize='unicode61')",
            "CREATE TRIGGER IF NOT EXISTS events_fts_insert AFTER INSERT ON events WHEN new.kind IN (0, 9, 40002, 45001, 45003) BEGIN INSERT INTO events_fts(rowid, content) VALUES (new.rowid, new.content); END",
            "CREATE TRIGGER IF NOT EXISTS events_fts_delete AFTER DELETE ON events WHEN old.kind IN (0, 9, 40002, 45001, 45003) BEGIN INSERT INTO events_fts(events_fts, rowid, content) VALUES ('delete', old.rowid, old.content); END",
            "CREATE TRIGGER IF NOT EXISTS events_fts_update AFTER UPDATE OF content, kind ON events BEGIN INSERT INTO events_fts(events_fts, rowid, content) SELECT 'delete', old.rowid, old.content WHERE old.kind IN (0, 9, 40002, 45001, 45003); INSERT INTO events_fts(rowid, content) SELECT new.rowid, new.content WHERE new.kind IN (0, 9, 40002, 45001, 45003); END",
            "INSERT INTO events_fts(rowid, content) SELECT rowid, content FROM events WHERE kind IN (0, 9, 40002, 45001, 45003)",
        ] {
            sqlx::query(statement).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE schema_version SET version = 3 WHERE singleton = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 3;
    }
    if version != 3 {
        return Err(crate::DbError::InvalidData(format!(
            "unsupported SQLite schema version {version}"
        )));
    }
    Ok(())
}

async fn ensure_column_on(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    table: &str,
    column: &str,
    alter_sql: &'static str,
) -> Result<()> {
    let pragma = format!("PRAGMA table_info({table})");
    let exists = sqlx::query(sqlx::AssertSqlSafe(pragma))
        .fetch_all(&mut **tx)
        .await?
        .iter()
        .any(|row| row.get::<String, _>("name") == column);
    if !exists {
        sqlx::query(alter_sql).execute(&mut **tx).await?;
    }
    Ok(())
}

pub(crate) async fn lookup_community_by_host(
    pool: &SqlitePool,
    normalized_host: &str,
) -> Result<Option<CommunityRecord>> {
    let row = sqlx::query(
        "SELECT id, host FROM communities WHERE host = ?1 COLLATE NOCASE AND archived_at IS NULL",
    )
    .bind(normalized_host)
    .fetch_optional(pool)
    .await?;
    row.map(community_record).transpose()
}

pub(crate) async fn lookup_community_host(
    pool: &SqlitePool,
    community_id: CommunityId,
) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT host FROM communities WHERE id = ?1 AND archived_at IS NULL")
            .bind(community_id.as_uuid().to_string())
            .fetch_optional(pool)
            .await?,
    )
}

pub(crate) async fn is_community_active(
    pool: &SqlitePool,
    community_id: CommunityId,
) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM communities WHERE id = ?1 AND archived_at IS NULL",
    )
    .bind(community_id.as_uuid().to_string())
    .fetch_one(pool)
    .await?;
    Ok(count != 0)
}

pub(crate) async fn ensure_configured_community(
    pool: &SqlitePool,
    normalized_host: &str,
) -> Result<EnsuredCommunityRecord> {
    let id = Uuid::new_v4();
    let inserted =
        sqlx::query("INSERT INTO communities (id, host) VALUES (?1, ?2) ON CONFLICT DO NOTHING")
            .bind(id.to_string())
            .bind(normalized_host)
            .execute(pool)
            .await?
            .rows_affected()
            == 1;

    let row = sqlx::query("SELECT id, host FROM communities WHERE host = ?1 COLLATE NOCASE")
        .bind(normalized_host)
        .fetch_one(pool)
        .await?;
    let record = community_record(row)?;
    Ok(EnsuredCommunityRecord {
        id: record.id,
        host: record.host,
        created: inserted,
    })
}

pub(crate) async fn insert_event(
    pool: &SqlitePool,
    community: CommunityId,
    event: &nostr::Event,
    channel_id: Option<Uuid>,
) -> Result<(buzz_core::StoredEvent, bool)> {
    let kind = u32::from(event.kind.as_u16());
    if kind == buzz_core::kind::KIND_AUTH {
        return Err(crate::DbError::AuthEventRejected);
    }
    if buzz_core::kind::is_ephemeral(kind) {
        return Err(crate::DbError::EphemeralEventRejected(event.kind.as_u16()));
    }
    let received_at = chrono::Utc::now();
    let inserted = sqlx::query("INSERT INTO events (community_id, id, pubkey, created_at, kind, tags_json, content, sig, channel_id, received_at, event_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) ON CONFLICT DO NOTHING")
        .bind(community.as_uuid().to_string()).bind(event.id.as_bytes().as_slice()).bind(event.pubkey.to_bytes().as_slice())
        .bind(event.created_at.as_secs() as i64).bind(event.kind.as_u16() as i32).bind(serde_json::to_string(&event.tags)?)
        .bind(&event.content).bind(event.sig.serialize().as_slice()).bind(channel_id.map(|id| id.to_string()))
        .bind(received_at.timestamp()).bind(serde_json::to_string(event)?).execute(pool).await?.rows_affected() == 1;
    Ok((
        buzz_core::StoredEvent::with_received_at(event.clone(), received_at, channel_id, true),
        inserted,
    ))
}

pub(crate) async fn replace_event(
    pool: &SqlitePool,
    community: CommunityId,
    event: &nostr::Event,
    channel_id: Option<Uuid>,
    d_tag: Option<&str>,
) -> Result<(buzz_core::StoredEvent, bool)> {
    let mut tx = pool.begin().await?;
    let rows = sqlx::query("SELECT id, event_json FROM events WHERE community_id = ?1 AND kind = ?2 AND pubkey = ?3 AND channel_id IS ?4")
        .bind(community.as_uuid().to_string())
        .bind(event.kind.as_u16() as i32)
        .bind(event.pubkey.to_bytes().as_slice())
        .bind(channel_id.map(|id| id.to_string()))
        .fetch_all(&mut *tx)
        .await?;
    let mut replaced_ids = Vec::new();
    for row in rows {
        let existing: nostr::Event = serde_json::from_str(row.try_get("event_json")?)?;
        let existing_d = crate::event::extract_d_tag(&existing).unwrap_or_default();
        if d_tag.is_some_and(|expected| existing_d != expected) {
            continue;
        }
        if event.created_at < existing.created_at
            || (event.created_at == existing.created_at && event.id <= existing.id)
        {
            return Ok((
                buzz_core::StoredEvent::with_received_at(
                    existing,
                    chrono::Utc::now(),
                    channel_id,
                    true,
                ),
                false,
            ));
        }
        replaced_ids.push(row.try_get::<Vec<u8>, _>("id")?);
    }
    for id in replaced_ids {
        sqlx::query("DELETE FROM events WHERE community_id = ?1 AND id = ?2")
            .bind(community.as_uuid().to_string())
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    let received_at = chrono::Utc::now();
    sqlx::query("INSERT INTO events (community_id, id, pubkey, created_at, kind, tags_json, content, sig, channel_id, received_at, event_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)")
        .bind(community.as_uuid().to_string()).bind(event.id.as_bytes().as_slice()).bind(event.pubkey.to_bytes().as_slice())
        .bind(event.created_at.as_secs() as i64).bind(event.kind.as_u16() as i32).bind(serde_json::to_string(&event.tags)?)
        .bind(&event.content).bind(event.sig.serialize().as_slice()).bind(channel_id.map(|id| id.to_string()))
        .bind(received_at.timestamp()).bind(serde_json::to_string(event)?).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((
        buzz_core::StoredEvent::with_received_at(event.clone(), received_at, channel_id, true),
        true,
    ))
}

pub(crate) async fn soft_delete_event(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
) -> Result<bool> {
    Ok(
        sqlx::query("DELETE FROM events WHERE community_id = ?1 AND id = ?2")
            .bind(community.as_uuid().to_string())
            .bind(event_id)
            .execute(pool)
            .await?
            .rows_affected()
            != 0,
    )
}

pub(crate) async fn get_event_by_id(
    pool: &SqlitePool,
    community: CommunityId,
    id: &[u8],
) -> Result<Option<buzz_core::StoredEvent>> {
    let row = sqlx::query("SELECT event_json, received_at, channel_id FROM events WHERE community_id = ?1 AND id = ?2")
        .bind(community.as_uuid().to_string()).bind(id).fetch_optional(pool).await?;
    row.map(stored_event).transpose()
}

pub(crate) async fn query_events(
    pool: &SqlitePool,
    q: &crate::EventQuery,
) -> Result<Vec<buzz_core::StoredEvent>> {
    if q.before_id.is_some() && q.until.is_none() {
        return Err(crate::DbError::InvalidData(
            "before_id requires until to be set".into(),
        ));
    }
    if q.global_only && q.channel_id.is_some() {
        return Err(crate::DbError::InvalidData(
            "global_only and channel_id are mutually exclusive".into(),
        ));
    }
    if q.kinds.as_ref().is_some_and(Vec::is_empty)
        || q.authors.as_ref().is_some_and(Vec::is_empty)
        || q.ids.as_ref().is_some_and(Vec::is_empty)
        || q.e_tags.as_ref().is_some_and(Vec::is_empty)
    {
        return Ok(vec![]);
    }
    let rows = sqlx::query("SELECT event_json, received_at, channel_id FROM events WHERE community_id = ?1 ORDER BY created_at DESC, id ASC")
        .bind(q.community_id.as_uuid().to_string()).fetch_all(pool).await?;
    let mut events = Vec::new();
    for row in rows {
        let stored = stored_event(row)?;
        let event = &stored.event;
        let created = event.created_at.as_secs() as i64;
        let id = event.id.as_bytes().as_slice();
        let tags: Vec<Vec<String>> = event
            .tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect();
        let has_tag = |name: &str, value: &str| {
            tags.iter().any(|tag| {
                tag.first().is_some_and(|v| v == name) && tag.get(1).is_some_and(|v| v == value)
            })
        };
        if q.channel_id.is_some_and(|ch| stored.channel_id != Some(ch))
            || (q.global_only && stored.channel_id.is_some())
        {
            continue;
        }
        if q.channel_ids
            .as_ref()
            .is_some_and(|ids| stored.channel_id.is_some_and(|id| !ids.contains(&id)))
        {
            continue;
        }
        if q.kinds
            .as_ref()
            .is_some_and(|ks| !ks.contains(&(event.kind.as_u16() as i32)))
        {
            continue;
        }
        if q.pubkey
            .as_ref()
            .is_some_and(|pk| pk.as_slice() != event.pubkey.to_bytes().as_slice())
        {
            continue;
        }
        if q.authors.as_ref().is_some_and(|authors| {
            !authors
                .iter()
                .any(|pk| pk.as_slice() == event.pubkey.to_bytes().as_slice())
        }) {
            continue;
        }
        if q.ids
            .as_ref()
            .is_some_and(|ids| !ids.iter().any(|candidate| candidate.as_slice() == id))
        {
            continue;
        }
        if q.since.is_some_and(|since| created < since.timestamp())
            || q.until.is_some_and(|until| created > until.timestamp())
        {
            continue;
        }
        if q.before_id.as_ref().is_some_and(|before| {
            q.until.is_some_and(|until| created == until.timestamp()) && id <= before.as_slice()
        }) {
            continue;
        }
        if q.p_tag_hex
            .as_ref()
            .is_some_and(|p| !has_tag("p", &p.to_ascii_lowercase()))
        {
            continue;
        }
        if q.e_tags
            .as_ref()
            .is_some_and(|values| !values.iter().any(|value| has_tag("e", value)))
        {
            continue;
        }
        let d_tag = tags
            .iter()
            .find(|tag| tag.first().is_some_and(|v| v == "d"))
            .and_then(|tag| tag.get(1));
        if q.d_tag.as_ref().is_some_and(|d| d_tag != Some(d)) {
            continue;
        }
        if q.d_tags
            .as_ref()
            .is_some_and(|ds| !d_tag.is_some_and(|d| ds.contains(d)))
        {
            continue;
        }
        if q.shared_gated_reader.as_ref().is_some_and(|reader| {
            buzz_core::kind::SHARED_GATED_KINDS.contains(&(event.kind.as_u16() as u32))
                && reader.as_slice() != event.pubkey.to_bytes().as_slice()
                && !has_tag("shared", "true")
        }) {
            continue;
        }
        events.push(stored);
    }
    let offset = q.offset.unwrap_or(0).max(0) as usize;
    let limit = q
        .limit
        .unwrap_or(100)
        .min(q.max_limit.unwrap_or(crate::DEFAULT_MAX_PAGE_LIMIT))
        .max(0) as usize;
    Ok(events.into_iter().skip(offset).take(limit).collect())
}

pub(crate) async fn query_feed_mentions(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey_bytes: &[u8],
    accessible_channel_ids: &[Uuid],
    since: Option<chrono::DateTime<chrono::Utc>>,
    limit: i64,
) -> Result<Vec<buzz_core::StoredEvent>> {
    let mut query = crate::EventQuery::for_community(community);
    query.kinds = Some(vec![
        buzz_core::kind::KIND_STREAM_MESSAGE as i32,
        buzz_core::kind::KIND_STREAM_MESSAGE_V2 as i32,
        buzz_core::kind::KIND_TEXT_NOTE as i32,
        buzz_core::kind::KIND_FORUM_POST as i32,
        buzz_core::kind::KIND_FORUM_COMMENT as i32,
        buzz_core::kind::KIND_GIT_PULL_REQUEST as i32,
        buzz_core::kind::KIND_GIT_PR_UPDATE as i32,
        buzz_core::kind::KIND_GIT_ISSUE as i32,
        buzz_core::kind::KIND_GIT_STATUS_OPEN as i32,
        buzz_core::kind::KIND_GIT_STATUS_MERGED as i32,
        buzz_core::kind::KIND_GIT_STATUS_CLOSED as i32,
        buzz_core::kind::KIND_GIT_STATUS_DRAFT as i32,
    ]);
    query.p_tag_hex = Some(hex::encode(pubkey_bytes));
    query.channel_ids = Some(accessible_channel_ids.to_vec());
    query.since = since;
    query.limit = Some(limit.min(crate::feed::FEED_MAX_LIMIT));
    query_events(pool, &query).await
}

pub(crate) async fn query_feed_needs_action(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey_bytes: &[u8],
    accessible_channel_ids: &[Uuid],
    since: Option<chrono::DateTime<chrono::Utc>>,
    limit: i64,
) -> Result<Vec<buzz_core::StoredEvent>> {
    let mut query = crate::EventQuery::for_community(community);
    query.kinds = Some(vec![
        buzz_core::kind::KIND_WORKFLOW_APPROVAL_REQUESTED as i32,
        buzz_core::kind::KIND_STREAM_REMINDER as i32,
    ]);
    query.p_tag_hex = Some(hex::encode(pubkey_bytes));
    query.channel_ids = Some(accessible_channel_ids.to_vec());
    query.since = since;
    query.limit = Some(limit.min(crate::feed::FEED_MAX_LIMIT));
    query_events(pool, &query).await
}

pub(crate) async fn query_feed_activity(
    pool: &SqlitePool,
    community: CommunityId,
    accessible_channel_ids: &[Uuid],
    since: Option<chrono::DateTime<chrono::Utc>>,
    limit: i64,
) -> Result<Vec<buzz_core::StoredEvent>> {
    let mut query = crate::EventQuery::for_community(community);
    query.kinds = Some(vec![
        buzz_core::kind::KIND_STREAM_MESSAGE as i32,
        buzz_core::kind::KIND_STREAM_MESSAGE_V2 as i32,
        buzz_core::kind::KIND_FORUM_POST as i32,
        buzz_core::kind::KIND_JOB_REQUEST as i32,
        buzz_core::kind::KIND_JOB_PROGRESS as i32,
        buzz_core::kind::KIND_JOB_RESULT as i32,
    ]);
    query.channel_ids = Some(accessible_channel_ids.to_vec());
    query.since = since;
    query.limit = Some(limit.min(crate::feed::FEED_MAX_LIMIT));
    query_events(pool, &query).await
}

pub(crate) async fn insert_reaction_event(
    pool: &SqlitePool,
    community: CommunityId,
    reaction_event: &nostr::Event,
    channel_id: Option<Uuid>,
    target_event_id: &[u8],
    actor_pubkey: &[u8],
    emoji: &str,
) -> Result<crate::event::ReactionEventInsertOutcome> {
    let mut tx = pool.begin().await?;
    let target_created_at: Option<i64> = sqlx::query_scalar(
        "SELECT created_at FROM events WHERE community_id = ?1 AND id = ?2 LIMIT 1",
    )
    .bind(community.as_uuid().to_string())
    .bind(target_event_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(target_created_at) = target_created_at else {
        return Ok(crate::event::ReactionEventInsertOutcome::TargetMissing);
    };
    let changed = sqlx::query("INSERT INTO reactions (community_id, event_created_at, event_id, pubkey, emoji, reaction_event_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT (community_id, event_created_at, event_id, pubkey, emoji) DO UPDATE SET removed_at = NULL, reaction_event_id = excluded.reaction_event_id WHERE reactions.removed_at IS NOT NULL")
        .bind(community.as_uuid().to_string()).bind(target_created_at).bind(target_event_id)
        .bind(actor_pubkey).bind(emoji).bind(reaction_event.id.as_bytes().as_slice())
        .execute(&mut *tx).await?.rows_affected() != 0;
    if !changed {
        return Ok(crate::event::ReactionEventInsertOutcome::Duplicate);
    }
    let received_at = chrono::Utc::now();
    let inserted = sqlx::query("INSERT INTO events (community_id, id, pubkey, created_at, kind, tags_json, content, sig, channel_id, received_at, event_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) ON CONFLICT DO NOTHING")
        .bind(community.as_uuid().to_string()).bind(reaction_event.id.as_bytes().as_slice()).bind(reaction_event.pubkey.to_bytes().as_slice())
        .bind(reaction_event.created_at.as_secs() as i64).bind(reaction_event.kind.as_u16() as i32).bind(serde_json::to_string(&reaction_event.tags)?)
        .bind(&reaction_event.content).bind(reaction_event.sig.serialize().as_slice()).bind(channel_id.map(|id| id.to_string()))
        .bind(received_at.timestamp()).bind(serde_json::to_string(reaction_event)?).execute(&mut *tx).await?.rows_affected() == 1;
    tx.commit().await?;
    Ok(crate::event::ReactionEventInsertOutcome::Inserted {
        stored_event: Box::new(buzz_core::StoredEvent::with_received_at(
            reaction_event.clone(),
            received_at,
            channel_id,
            true,
        )),
        was_inserted: inserted,
    })
}

pub(crate) async fn add_reaction(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
    event_created_at: chrono::DateTime<chrono::Utc>,
    pubkey: &[u8],
    emoji: &str,
    reaction_event_id: Option<&[u8]>,
) -> Result<bool> {
    let result = sqlx::query("INSERT INTO reactions (community_id,event_created_at,event_id,pubkey,emoji,reaction_event_id) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT (community_id,event_created_at,event_id,pubkey,emoji) DO UPDATE SET removed_at=NULL, reaction_event_id=COALESCE(excluded.reaction_event_id,reactions.reaction_event_id) WHERE reactions.removed_at IS NOT NULL")
        .bind(community.as_uuid().to_string()).bind(event_created_at.timestamp()).bind(event_id).bind(pubkey).bind(emoji).bind(reaction_event_id).execute(pool).await?;
    Ok(result.rows_affected() != 0)
}

pub(crate) async fn get_active_reaction_record(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
    event_created_at: chrono::DateTime<chrono::Utc>,
    pubkey: &[u8],
    emoji: &str,
) -> Result<Option<crate::reaction::ActiveReactionRecord>> {
    let row = sqlx::query("SELECT reaction_event_id FROM reactions WHERE community_id=?1 AND event_id=?2 AND event_created_at=?3 AND pubkey=?4 AND emoji=?5 AND removed_at IS NULL LIMIT 1")
        .bind(community.as_uuid().to_string()).bind(event_id).bind(event_created_at.timestamp()).bind(pubkey).bind(emoji).fetch_optional(pool).await?;
    row.map(|r| {
        Ok(crate::reaction::ActiveReactionRecord {
            reaction_event_id: r.try_get("reaction_event_id")?,
        })
    })
    .transpose()
}

pub(crate) async fn set_reaction_event_id(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
    event_created_at: chrono::DateTime<chrono::Utc>,
    pubkey: &[u8],
    emoji: &str,
    reaction_event_id: &[u8],
) -> Result<bool> {
    Ok(sqlx::query("UPDATE reactions SET reaction_event_id=?1 WHERE community_id=?2 AND event_created_at=?3 AND event_id=?4 AND pubkey=?5 AND emoji=?6 AND removed_at IS NULL")
        .bind(reaction_event_id).bind(community.as_uuid().to_string()).bind(event_created_at.timestamp()).bind(event_id).bind(pubkey).bind(emoji).execute(pool).await?.rows_affected() > 0)
}

pub(crate) async fn get_reactions(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
    event_created_at: chrono::DateTime<chrono::Utc>,
    limit: u32,
    _cursor: Option<&str>,
) -> Result<Vec<crate::reaction::ReactionGroup>> {
    let rows = sqlx::query("SELECT r.emoji,r.pubkey,r.reaction_event_id FROM reactions r WHERE r.community_id=?1 AND r.event_id=?2 AND r.event_created_at=?3 AND r.removed_at IS NULL AND r.emoji IN (SELECT emoji FROM reactions WHERE community_id=?1 AND event_id=?2 AND event_created_at=?3 AND removed_at IS NULL GROUP BY emoji ORDER BY emoji LIMIT ?4) ORDER BY r.emoji,r.rowid")
        .bind(community.as_uuid().to_string()).bind(event_id).bind(event_created_at.timestamp()).bind(limit as i64).fetch_all(pool).await?;
    let mut groups = Vec::new();
    let mut current: Option<String> = None;
    let mut users = Vec::new();
    for row in rows {
        let emoji: String = row.try_get("emoji")?;
        if current.as_ref() != Some(&emoji) {
            if let Some(e) = current.take() {
                groups.push(crate::reaction::ReactionGroup {
                    emoji: e,
                    count: users.len() as i64,
                    users: std::mem::take(&mut users),
                });
            }
            current = Some(emoji);
        }
        users.push(crate::reaction::ReactionUser {
            pubkey: row.try_get("pubkey")?,
            display_name: None,
            reaction_event_id: row.try_get("reaction_event_id")?,
        });
    }
    if let Some(e) = current {
        groups.push(crate::reaction::ReactionGroup {
            emoji: e,
            count: users.len() as i64,
            users,
        });
    }
    Ok(groups)
}

pub(crate) async fn get_reactions_bulk(
    pool: &SqlitePool,
    community: CommunityId,
    event_ids: &[(&[u8], chrono::DateTime<chrono::Utc>)],
) -> Result<Vec<crate::reaction::BulkReactionEntry>> {
    let mut out = Vec::new();
    for (event_id, ts) in event_ids {
        let rows=sqlx::query("SELECT emoji,COUNT(*) AS count FROM reactions WHERE community_id=?1 AND event_id=?2 AND event_created_at=?3 AND removed_at IS NULL GROUP BY emoji ORDER BY emoji").bind(community.as_uuid().to_string()).bind(*event_id).bind(ts.timestamp()).fetch_all(pool).await?;
        if rows.is_empty() {
            continue;
        }
        let reactions = rows
            .into_iter()
            .map(|r| {
                Ok(crate::reaction::ReactionSummary {
                    emoji: r.try_get("emoji")?,
                    count: r.try_get("count")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        out.push(crate::reaction::BulkReactionEntry {
            event_id: event_id.to_vec(),
            event_created_at: *ts,
            reactions,
        });
    }
    Ok(out)
}

pub(crate) async fn remove_reaction(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
    event_created_at: chrono::DateTime<chrono::Utc>,
    pubkey: &[u8],
    emoji: &str,
) -> Result<bool> {
    Ok(sqlx::query("UPDATE reactions SET removed_at = unixepoch() WHERE community_id = ?1 AND event_created_at = ?2 AND event_id = ?3 AND pubkey = ?4 AND emoji = ?5 AND removed_at IS NULL")
        .bind(community.as_uuid().to_string()).bind(event_created_at.timestamp()).bind(event_id).bind(pubkey).bind(emoji)
        .execute(pool).await?.rows_affected() != 0)
}

pub(crate) async fn remove_reaction_by_source_event_id(
    pool: &SqlitePool,
    community: CommunityId,
    reaction_event_id: &[u8],
) -> Result<bool> {
    Ok(sqlx::query("UPDATE reactions SET removed_at = unixepoch() WHERE community_id = ?1 AND reaction_event_id = ?2 AND removed_at IS NULL")
        .bind(community.as_uuid().to_string()).bind(reaction_event_id)
        .execute(pool).await?.rows_affected() != 0)
}

pub(crate) async fn set_channel_add_policy(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
    policy: &str,
) -> Result<()> {
    if !matches!(policy, "anyone" | "owner_only" | "nobody") {
        return Err(crate::DbError::InvalidData(format!(
            "invalid channel_add_policy: {policy}"
        )));
    }
    let result = sqlx::query(
        "UPDATE users SET channel_add_policy = ?1 WHERE community_id = ?2 AND pubkey = ?3",
    )
    .bind(policy)
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(crate::DbError::NotFound(
            "pubkey not found in users table".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn find_dm_by_participants(
    pool: &SqlitePool,
    community: CommunityId,
    participant_hash: &[u8],
) -> Result<Option<crate::channel::ChannelRecord>> {
    let row = sqlx::query("SELECT id, name, channel_type, visibility, description, canvas, created_by, created_at, updated_at, archived_at, deleted_at, nip29_group_id, topic_required, max_members, topic, topic_set_by, topic_set_at, purpose, purpose_set_by, purpose_set_at, ttl_seconds, ttl_deadline FROM channels WHERE community_id = ?1 AND participant_hash = ?2 AND channel_type = 'dm' AND deleted_at IS NULL LIMIT 1")
        .bind(community.as_uuid().to_string()).bind(participant_hash).fetch_optional(pool).await?;
    row.map(channel_record).transpose()
}

pub(crate) async fn create_dm(
    pool: &SqlitePool,
    community: CommunityId,
    participants: &[&[u8]],
    created_by: &[u8],
) -> Result<crate::channel::ChannelRecord> {
    if !(2..=9).contains(&participants.len()) {
        return Err(crate::DbError::InvalidData(
            "DM requires 2-9 participants".into(),
        ));
    }
    if participants.iter().any(|p| p.len() != 32) {
        return Err(crate::DbError::InvalidData(
            "DM participant pubkeys must be 32 bytes".into(),
        ));
    }
    if !participants.contains(&created_by) {
        return Err(crate::DbError::InvalidData(
            "DM creator must be a participant".into(),
        ));
    }
    let mut unique = participants.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != participants.len() {
        return Err(crate::DbError::InvalidData(
            "DM participants must be unique".into(),
        ));
    }
    let hash = crate::dm::compute_participant_hash(participants);
    let mut tx = pool.begin().await?;
    let query = "SELECT id, name, channel_type, visibility, description, canvas, created_by, created_at, updated_at, archived_at, deleted_at, nip29_group_id, topic_required, max_members, topic, topic_set_by, topic_set_at, purpose, purpose_set_by, purpose_set_at, ttl_seconds, ttl_deadline FROM channels WHERE community_id = ?1 AND participant_hash = ?2 AND channel_type = 'dm' AND deleted_at IS NULL LIMIT 1";
    if let Some(row) = sqlx::query(query)
        .bind(community.as_uuid().to_string())
        .bind(hash.as_slice())
        .fetch_optional(&mut *tx)
        .await?
    {
        tx.commit().await?;
        return channel_record(row);
    }
    let id = Uuid::new_v4();
    let name = if participants.len() == 2 {
        "DM".to_owned()
    } else {
        format!("Group DM ({})", participants.len())
    };
    sqlx::query("INSERT INTO channels (id, community_id, name, channel_type, visibility, participant_hash, created_by) VALUES (?1, ?2, ?3, 'dm', 'private', ?4, ?5)")
        .bind(id.to_string()).bind(community.as_uuid().to_string()).bind(name).bind(hash.as_slice()).bind(created_by).execute(&mut *tx).await?;
    for participant in participants {
        sqlx::query("INSERT INTO channel_members (channel_id, pubkey, role, invited_by) VALUES (?1, ?2, 'member', ?3)")
            .bind(id.to_string()).bind(*participant).bind(created_by).execute(&mut *tx).await?;
    }
    let row = sqlx::query("SELECT id, name, channel_type, visibility, description, canvas, created_by, created_at, updated_at, archived_at, deleted_at, nip29_group_id, topic_required, max_members, topic, topic_set_by, topic_set_at, purpose, purpose_set_by, purpose_set_at, ttl_seconds, ttl_deadline FROM channels WHERE community_id = ?1 AND participant_hash = ?2 AND channel_type = 'dm' AND deleted_at IS NULL LIMIT 1")
        .bind(community.as_uuid().to_string())
        .bind(hash.as_slice())
        .fetch_one(&mut *tx)
        .await?;
    let record = channel_record(row)?;
    tx.commit().await?;
    Ok(record)
}

pub(crate) async fn list_dms_for_user(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
    limit: u32,
    cursor: Option<Uuid>,
) -> Result<Vec<crate::dm::DmRecord>> {
    let limit = limit.min(200) as i64;
    let cursor_ts = if let Some(id) = cursor {
        sqlx::query_scalar::<_, i64>(
            "SELECT updated_at FROM channels WHERE id = ?1 AND community_id = ?2",
        )
        .bind(id.to_string())
        .bind(community.as_uuid().to_string())
        .fetch_optional(pool)
        .await?
    } else {
        None
    };
    let rows = if let Some(ts) = cursor_ts {
        sqlx::query("SELECT c.id, c.created_at, c.updated_at FROM channels c JOIN channel_members cm ON c.id = cm.channel_id AND cm.pubkey = ?2 AND cm.removed_at IS NULL AND cm.hidden_at IS NULL WHERE c.community_id = ?1 AND c.channel_type = 'dm' AND c.deleted_at IS NULL AND c.updated_at < ?3 ORDER BY c.updated_at DESC LIMIT ?4")
            .bind(community.as_uuid().to_string()).bind(pubkey).bind(ts).bind(limit).fetch_all(pool).await?
    } else {
        sqlx::query("SELECT c.id, c.created_at, c.updated_at FROM channels c JOIN channel_members cm ON c.id = cm.channel_id AND cm.pubkey = ?2 AND cm.removed_at IS NULL AND cm.hidden_at IS NULL WHERE c.community_id = ?1 AND c.channel_type = 'dm' AND c.deleted_at IS NULL ORDER BY c.updated_at DESC LIMIT ?3")
            .bind(community.as_uuid().to_string()).bind(pubkey).bind(limit).fetch_all(pool).await?
    };
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id")?;
        let channel_id = Uuid::parse_str(&id)
            .map_err(|e| crate::DbError::InvalidData(format!("invalid SQLite channel id: {e}")))?;
        let created_at = timestamp(row.try_get("created_at")?)?;
        let updated_at = timestamp(row.try_get("updated_at")?)?;
        let members = sqlx::query("SELECT cm.pubkey, cm.role, u.display_name FROM channel_members cm LEFT JOIN users u ON u.community_id = ?1 AND u.pubkey = cm.pubkey JOIN channels c ON c.id = cm.channel_id AND c.community_id = ?1 WHERE cm.channel_id = ?2 AND cm.removed_at IS NULL ORDER BY cm.joined_at ASC")
            .bind(community.as_uuid().to_string()).bind(id).fetch_all(pool).await?;
        let participants = members
            .into_iter()
            .map(|r| {
                Ok(crate::dm::DmParticipant {
                    pubkey: r.try_get("pubkey")?,
                    display_name: r.try_get("display_name")?,
                    role: r.try_get("role")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        out.push(crate::dm::DmRecord {
            channel_id,
            participants,
            last_message_at: Some(updated_at),
            created_at,
        });
    }
    Ok(out)
}

pub(crate) async fn hide_dm(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
) -> Result<()> {
    let result = sqlx::query("UPDATE channel_members SET hidden_at = unixepoch() WHERE channel_id = ?1 AND pubkey = ?2 AND removed_at IS NULL AND EXISTS (SELECT 1 FROM channels c WHERE c.id = channel_members.channel_id AND c.community_id = ?3)").bind(channel_id.to_string()).bind(pubkey).bind(community.as_uuid().to_string()).execute(pool).await?;
    if result.rows_affected() == 0 {
        return Err(crate::DbError::NotFound(format!(
            "no active membership for channel {channel_id}"
        )));
    }
    Ok(())
}

pub(crate) async fn unhide_dm(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
) -> Result<()> {
    sqlx::query("UPDATE channel_members SET hidden_at = NULL WHERE channel_id = ?1 AND pubkey = ?2 AND removed_at IS NULL AND EXISTS (SELECT 1 FROM channels c WHERE c.id = channel_members.channel_id AND c.community_id = ?3)").bind(channel_id.to_string()).bind(pubkey).bind(community.as_uuid().to_string()).execute(pool).await?;
    Ok(())
}

pub(crate) async fn list_hidden_dms(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
) -> Result<Vec<Uuid>> {
    let rows = sqlx::query("SELECT cm.channel_id FROM channel_members cm JOIN channels c ON c.id = cm.channel_id AND c.community_id = ?1 WHERE cm.pubkey = ?2 AND cm.removed_at IS NULL AND cm.hidden_at IS NOT NULL AND c.channel_type = 'dm' AND c.deleted_at IS NULL ORDER BY cm.channel_id")
        .bind(community.as_uuid().to_string()).bind(pubkey).fetch_all(pool).await?;
    rows.into_iter()
        .map(|r| {
            let id: String = r.try_get("channel_id")?;
            Uuid::parse_str(&id)
                .map_err(|e| crate::DbError::InvalidData(format!("invalid SQLite channel id: {e}")))
        })
        .collect()
}

pub(crate) async fn open_dm(
    pool: &SqlitePool,
    community: CommunityId,
    pubkeys: &[&[u8]],
    created_by: &[u8],
    command_event: Option<&nostr::Event>,
) -> Result<Option<(crate::channel::ChannelRecord, bool)>> {
    let mut participants = pubkeys.to_vec();
    if !participants.contains(&created_by) {
        participants.push(created_by);
    }
    participants.sort_unstable();
    participants.dedup();
    if !(2..=9).contains(&participants.len()) {
        return Err(crate::DbError::InvalidData(
            "DM requires 2-9 unique participants".into(),
        ));
    }
    if participants.iter().any(|pubkey| pubkey.len() != 32) {
        return Err(crate::DbError::InvalidData(
            "DM participant pubkeys must be 32 bytes".into(),
        ));
    }
    let hash = crate::dm::compute_participant_hash(&participants);
    let mut tx = pool.begin().await?;
    if let Some(event) = command_event {
        let received_at = chrono::Utc::now();
        let inserted = sqlx::query("INSERT INTO events (community_id, id, pubkey, created_at, kind, tags_json, content, sig, channel_id, received_at, event_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10) ON CONFLICT DO NOTHING")
            .bind(community.as_uuid().to_string()).bind(event.id.as_bytes().as_slice()).bind(event.pubkey.to_bytes().as_slice())
            .bind(event.created_at.as_secs() as i64).bind(event.kind.as_u16() as i32).bind(serde_json::to_string(&event.tags)?)
            .bind(&event.content).bind(event.sig.serialize().as_slice()).bind(received_at.timestamp()).bind(serde_json::to_string(event)?)
            .execute(&mut *tx).await?.rows_affected() != 0;
        if !inserted {
            return Ok(None);
        }
    }
    let select = "SELECT id, name, channel_type, visibility, description, canvas, created_by, created_at, updated_at, archived_at, deleted_at, nip29_group_id, topic_required, max_members, topic, topic_set_by, topic_set_at, purpose, purpose_set_by, purpose_set_at, ttl_seconds, ttl_deadline FROM channels WHERE community_id = ?1 AND participant_hash = ?2 AND channel_type = 'dm' AND deleted_at IS NULL LIMIT 1";
    if let Some(row) = sqlx::query(select)
        .bind(community.as_uuid().to_string())
        .bind(hash.as_slice())
        .fetch_optional(&mut *tx)
        .await?
    {
        sqlx::query("UPDATE channel_members SET hidden_at = NULL WHERE channel_id = ?1 AND pubkey = ?2 AND removed_at IS NULL")
            .bind(row.try_get::<String, _>("id")?)
            .bind(created_by)
            .execute(&mut *tx)
            .await?;
        let record = channel_record(row)?;
        tx.commit().await?;
        return Ok(Some((record, false)));
    }

    let id = Uuid::new_v4();
    let name = if participants.len() == 2 {
        "DM".to_owned()
    } else {
        format!("Group DM ({})", participants.len())
    };
    sqlx::query("INSERT INTO channels (id, community_id, name, channel_type, visibility, participant_hash, created_by) VALUES (?1, ?2, ?3, 'dm', 'private', ?4, ?5)")
        .bind(id.to_string())
        .bind(community.as_uuid().to_string())
        .bind(name)
        .bind(hash.as_slice())
        .bind(created_by)
        .execute(&mut *tx)
        .await?;
    for participant in participants {
        sqlx::query("INSERT INTO channel_members (channel_id, pubkey, role, invited_by) VALUES (?1, ?2, 'member', ?3)")
            .bind(id.to_string())
            .bind(participant)
            .bind(created_by)
            .execute(&mut *tx)
            .await?;
    }
    let row = sqlx::query(select)
        .bind(community.as_uuid().to_string())
        .bind(hash.as_slice())
        .fetch_one(&mut *tx)
        .await?;
    let record = channel_record(row)?;
    tx.commit().await?;
    Ok(Some((record, true)))
}

fn stored_event(row: sqlx::sqlite::SqliteRow) -> Result<buzz_core::StoredEvent> {
    let json: String = row.try_get("event_json")?;
    let event: nostr::Event = serde_json::from_str(&json)?;
    let received: i64 = row.try_get("received_at")?;
    let channel: Option<String> = row.try_get("channel_id")?;
    let channel_id = channel
        .map(|id| {
            Uuid::parse_str(&id)
                .map_err(|e| crate::DbError::InvalidData(format!("invalid SQLite channel id: {e}")))
        })
        .transpose()?;
    Ok(buzz_core::StoredEvent::with_received_at(
        event,
        timestamp(received)?,
        channel_id,
        true,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_channel_with_id(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
    name: &str,
    channel_type: crate::channel::ChannelType,
    visibility: crate::channel::ChannelVisibility,
    description: Option<&str>,
    created_by: &[u8],
    ttl_seconds: Option<i32>,
) -> Result<(crate::channel::ChannelRecord, bool)> {
    if created_by.len() != 32 {
        return Err(crate::DbError::InvalidData(format!(
            "pubkey must be 32 bytes, got {}",
            created_by.len()
        )));
    }
    if channel_id.is_nil() {
        return Err(crate::DbError::InvalidData(
            "channel_id must not be nil (reserved for global fan-out)".into(),
        ));
    }
    let name = buzz_core::channel::canonical_channel_name(name);
    if name.trim().is_empty() {
        return Err(crate::DbError::InvalidData(
            "channel name is required".into(),
        ));
    }
    let mut tx = pool.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO channels (id, community_id, name, channel_type, visibility, description, created_by, ttl_seconds, ttl_deadline) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, CASE WHEN ?8 IS NULL THEN NULL ELSE unixepoch() + ?8 END) ON CONFLICT DO NOTHING",
    )
    .bind(channel_id.to_string()).bind(community.as_uuid().to_string()).bind(&name)
    .bind(channel_type.as_str()).bind(visibility.as_str()).bind(description).bind(created_by)
    .bind(ttl_seconds).execute(&mut *tx).await?.rows_affected() == 1;
    if inserted {
        sqlx::query("INSERT INTO channel_members (channel_id, pubkey, role, invited_by) VALUES (?1, ?2, 'owner', ?2)")
            .bind(channel_id.to_string()).bind(created_by).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok((get_channel(pool, community, channel_id).await?, inserted))
}

pub(crate) async fn get_channel(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
) -> Result<crate::channel::ChannelRecord> {
    let row = sqlx::query(
        "SELECT * FROM channels WHERE community_id = ?1 AND id = ?2 AND deleted_at IS NULL",
    )
    .bind(community.as_uuid().to_string())
    .bind(channel_id.to_string())
    .fetch_optional(pool)
    .await?
    .ok_or(crate::DbError::ChannelNotFound(channel_id))?;
    channel_record(row)
}

pub(crate) async fn add_member(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
    role: crate::channel::MemberRole,
    invited_by: Option<&[u8]>,
) -> Result<crate::channel::MemberRecord> {
    get_channel(pool, community, channel_id).await?;
    sqlx::query("INSERT INTO channel_members (channel_id, pubkey, role, invited_by) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(channel_id, pubkey) DO UPDATE SET role = excluded.role, invited_by = excluded.invited_by, removed_at = NULL")
        .bind(channel_id.to_string()).bind(pubkey).bind(role.as_str()).bind(invited_by).execute(pool).await?;
    member_record(sqlx::query("SELECT channel_id, pubkey, role, joined_at, invited_by, removed_at FROM channel_members WHERE channel_id = ?1 AND pubkey = ?2")
        .bind(channel_id.to_string()).bind(pubkey).fetch_one(pool).await?)
}

pub(crate) async fn is_member(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM channel_members cm JOIN channels c ON c.id = cm.channel_id WHERE c.community_id = ?1 AND c.id = ?2 AND cm.pubkey = ?3 AND cm.removed_at IS NULL AND c.deleted_at IS NULL")
        .bind(community.as_uuid().to_string()).bind(channel_id.to_string()).bind(pubkey).fetch_one(pool).await? != 0)
}

pub(crate) async fn get_members(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
) -> Result<Vec<crate::channel::MemberRecord>> {
    get_channel(pool, community, channel_id).await?;
    sqlx::query("SELECT channel_id, pubkey, role, joined_at, invited_by, removed_at FROM channel_members WHERE channel_id = ?1 AND removed_at IS NULL ORDER BY joined_at, pubkey")
        .bind(channel_id.to_string()).fetch_all(pool).await?.into_iter().map(member_record).collect()
}

pub(crate) async fn get_accessible_channel_ids(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
) -> Result<Vec<Uuid>> {
    let rows = sqlx::query_scalar::<_, String>("SELECT c.id FROM channels c JOIN channel_members cm ON cm.channel_id = c.id WHERE c.community_id = ?1 AND cm.pubkey = ?2 AND cm.removed_at IS NULL AND c.deleted_at IS NULL ORDER BY c.created_at, c.id")
        .bind(community.as_uuid().to_string()).bind(pubkey).fetch_all(pool).await?;
    rows.into_iter()
        .map(|id| {
            Uuid::parse_str(&id)
                .map_err(|e| crate::DbError::InvalidData(format!("invalid SQLite channel id: {e}")))
        })
        .collect()
}

pub(crate) async fn communities_of_channels(
    pool: &SqlitePool,
    channel_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, CommunityId>> {
    let mut out = std::collections::HashMap::with_capacity(channel_ids.len());
    for channel_id in channel_ids {
        let row = sqlx::query_scalar::<_, String>(
            "SELECT community_id FROM channels WHERE id = ?1 AND deleted_at IS NULL",
        )
        .bind(channel_id.to_string())
        .fetch_optional(pool)
        .await?;
        if let Some(community_id) = row {
            let community_id = Uuid::parse_str(&community_id).map_err(|e| {
                crate::DbError::InvalidData(format!("invalid SQLite community id: {e}"))
            })?;
            out.insert(*channel_id, CommunityId::from_uuid(community_id));
        }
    }
    Ok(out)
}

pub(crate) async fn get_member_role(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar("SELECT cm.role FROM channel_members cm JOIN channels c ON c.id = cm.channel_id WHERE c.community_id = ?1 AND c.id = ?2 AND cm.pubkey = ?3 AND cm.removed_at IS NULL AND c.deleted_at IS NULL")
        .bind(community.as_uuid().to_string()).bind(channel_id.to_string()).bind(pubkey).fetch_optional(pool).await?)
}

fn timestamp(value: i64) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(value, 0).ok_or(crate::DbError::InvalidTimestamp(value))
}
fn optional_timestamp(value: Option<i64>) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    value.map(timestamp).transpose()
}
fn channel_record(row: sqlx::sqlite::SqliteRow) -> Result<crate::channel::ChannelRecord> {
    let id: String = row.try_get("id")?;
    Ok(crate::channel::ChannelRecord {
        id: Uuid::parse_str(&id)
            .map_err(|e| crate::DbError::InvalidData(format!("invalid SQLite channel id: {e}")))?,
        name: row.try_get("name")?,
        channel_type: row.try_get("channel_type")?,
        visibility: row.try_get("visibility")?,
        description: row.try_get("description")?,
        canvas: row.try_get("canvas")?,
        created_by: row.try_get("created_by")?,
        created_at: timestamp(row.try_get("created_at")?)?,
        updated_at: timestamp(row.try_get("updated_at")?)?,
        archived_at: optional_timestamp(row.try_get("archived_at")?)?,
        deleted_at: optional_timestamp(row.try_get("deleted_at")?)?,
        nip29_group_id: row.try_get("nip29_group_id")?,
        topic_required: row.try_get::<i64, _>("topic_required")? != 0,
        max_members: row.try_get("max_members")?,
        topic: row.try_get("topic")?,
        topic_set_by: row.try_get("topic_set_by")?,
        topic_set_at: optional_timestamp(row.try_get("topic_set_at")?)?,
        purpose: row.try_get("purpose")?,
        purpose_set_by: row.try_get("purpose_set_by")?,
        purpose_set_at: optional_timestamp(row.try_get("purpose_set_at")?)?,
        ttl_seconds: row.try_get("ttl_seconds")?,
        ttl_deadline: optional_timestamp(row.try_get("ttl_deadline")?)?,
    })
}
fn member_record(row: sqlx::sqlite::SqliteRow) -> Result<crate::channel::MemberRecord> {
    let id: String = row.try_get("channel_id")?;
    Ok(crate::channel::MemberRecord {
        channel_id: Uuid::parse_str(&id)
            .map_err(|e| crate::DbError::InvalidData(format!("invalid SQLite channel id: {e}")))?,
        pubkey: row.try_get("pubkey")?,
        role: row.try_get("role")?,
        joined_at: timestamp(row.try_get("joined_at")?)?,
        invited_by: row.try_get("invited_by")?,
        removed_at: optional_timestamp(row.try_get("removed_at")?)?,
    })
}

pub(crate) async fn ensure_user(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
) -> Result<bool> {
    Ok(sqlx::query(
        "INSERT INTO users (community_id, pubkey) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub(crate) async fn update_user_profile(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
    display_name: Option<&str>,
    avatar_url: Option<&str>,
    about: Option<&str>,
    nip05_handle: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE users SET display_name = COALESCE(?3, display_name), avatar_url = COALESCE(?4, avatar_url), about = COALESCE(?5, about), nip05_handle = COALESCE(?6, nip05_handle) WHERE community_id = ?1 AND pubkey = ?2",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .bind(display_name)
    .bind(avatar_url)
    .bind(about)
    .bind(nip05_handle)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn get_user(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
) -> Result<Option<crate::user::UserProfile>> {
    let row = sqlx::query(
        "SELECT pubkey, display_name, avatar_url, about, nip05_handle FROM users WHERE community_id = ?1 AND pubkey = ?2",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .fetch_optional(pool)
    .await?;
    row.map(|row| {
        Ok(crate::user::UserProfile {
            pubkey: row.try_get("pubkey")?,
            display_name: row.try_get("display_name")?,
            avatar_url: row.try_get("avatar_url")?,
            about: row.try_get("about")?,
            nip05_handle: row.try_get("nip05_handle")?,
        })
    })
    .transpose()
}

pub(crate) async fn set_agent_owner(
    pool: &SqlitePool,
    community: CommunityId,
    agent_pubkey: &[u8],
    owner_pubkey: &[u8],
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE users SET agent_owner_pubkey = ?3, is_agent = 1 WHERE community_id = ?1 AND pubkey = ?2 AND agent_owner_pubkey IS NULL",
    )
    .bind(community.as_uuid().to_string())
    .bind(agent_pubkey)
    .bind(owner_pubkey)
    .execute(pool)
    .await?
    .rows_affected() == 1)
}

pub(crate) async fn get_agent_channel_policy(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
) -> Result<Option<(String, Option<Vec<u8>>)>> {
    Ok(sqlx::query_as(
        "SELECT channel_add_policy, agent_owner_pubkey FROM users WHERE community_id = ?1 AND pubkey = ?2",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .fetch_optional(pool)
    .await?)
}

pub(crate) async fn is_agent_owner(
    pool: &SqlitePool,
    community: CommunityId,
    target_pubkey: &[u8],
    actor_pubkey: &[u8],
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM users WHERE community_id = ?1 AND pubkey = ?2 AND agent_owner_pubkey = ?3",
    )
    .bind(community.as_uuid().to_string())
    .bind(target_pubkey)
    .bind(actor_pubkey)
    .fetch_one(pool)
    .await? != 0)
}

pub(crate) async fn is_relay_member(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM relay_members WHERE community_id = ?1 AND pubkey = ?2 COLLATE NOCASE",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .fetch_one(pool)
    .await?
        != 0)
}

pub(crate) async fn get_relay_member(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &str,
) -> Result<Option<crate::relay_members::RelayMember>> {
    let row = sqlx::query(
        "SELECT pubkey, role, added_by, created_at, updated_at FROM relay_members WHERE community_id = ?1 AND pubkey = ?2 COLLATE NOCASE",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .fetch_optional(pool)
    .await?;
    row.map(relay_member).transpose()
}

pub(crate) async fn list_relay_members(
    pool: &SqlitePool,
    community: CommunityId,
) -> Result<Vec<crate::relay_members::RelayMember>> {
    sqlx::query(
        "SELECT pubkey, role, added_by, created_at, updated_at FROM relay_members WHERE community_id = ?1 ORDER BY created_at ASC, pubkey ASC",
    )
    .bind(community.as_uuid().to_string())
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(relay_member)
    .collect()
}

pub(crate) async fn add_relay_member(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &str,
    role: &str,
    added_by: Option<&str>,
) -> Result<bool> {
    Ok(sqlx::query(
        "INSERT INTO relay_members (community_id, pubkey, role, added_by) VALUES (?1, lower(?2), ?3, ?4) ON CONFLICT DO NOTHING",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .bind(role)
    .bind(added_by)
    .execute(pool)
    .await?
    .rows_affected() == 1)
}

pub(crate) async fn bootstrap_owner(
    pool: &SqlitePool,
    community: CommunityId,
    owner_pubkey: &str,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE relay_members SET role = 'admin', updated_at = unixepoch() WHERE community_id = ?1 AND role = 'owner' AND pubkey <> ?2 COLLATE NOCASE",
    )
    .bind(community.as_uuid().to_string())
    .bind(owner_pubkey)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO relay_members (community_id, pubkey, role) VALUES (?1, lower(?2), 'owner') ON CONFLICT(community_id, pubkey) DO UPDATE SET role = 'owner', updated_at = unixepoch()",
    )
    .bind(community.as_uuid().to_string())
    .bind(owner_pubkey)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

fn relay_member(row: sqlx::sqlite::SqliteRow) -> Result<crate::relay_members::RelayMember> {
    let created_at: i64 = row.try_get("created_at")?;
    let updated_at: i64 = row.try_get("updated_at")?;
    Ok(crate::relay_members::RelayMember {
        pubkey: row.try_get("pubkey")?,
        role: row.try_get("role")?,
        added_by: row.try_get("added_by")?,
        created_at: chrono::DateTime::from_timestamp(created_at, 0)
            .ok_or(crate::DbError::InvalidTimestamp(created_at))?,
        updated_at: chrono::DateTime::from_timestamp(updated_at, 0)
            .ok_or(crate::DbError::InvalidTimestamp(updated_at))?,
    })
}

fn community_record(row: sqlx::sqlite::SqliteRow) -> Result<CommunityRecord> {
    let id: String = row.try_get("id")?;
    let id = Uuid::parse_str(&id)
        .map_err(|e| crate::DbError::InvalidData(format!("invalid SQLite community id: {e}")))?;
    Ok(CommunityRecord {
        id: CommunityId::from_uuid(id),
        host: row.try_get("host")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind};

    #[tokio::test]
    async fn upgrades_phase_1_core_schema_before_dm_use() {
        let path = std::env::temp_dir().join(format!("buzz-db-upgrade-{}.sqlite", Uuid::new_v4()));
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .unwrap()
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE communities (id TEXT PRIMARY KEY NOT NULL, host TEXT NOT NULL COLLATE NOCASE UNIQUE, icon TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch()), archived_at INTEGER)")
            .execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE channels (id TEXT PRIMARY KEY NOT NULL, community_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT, canvas TEXT, channel_type TEXT NOT NULL, visibility TEXT NOT NULL, created_by BLOB NOT NULL, created_at INTEGER NOT NULL DEFAULT (unixepoch()), updated_at INTEGER NOT NULL DEFAULT (unixepoch()), archived_at INTEGER, deleted_at INTEGER, nip29_group_id TEXT, topic_required INTEGER NOT NULL DEFAULT 0, max_members INTEGER, topic TEXT, topic_set_by BLOB, topic_set_at INTEGER, purpose TEXT, purpose_set_by BLOB, purpose_set_at INTEGER, ttl_seconds INTEGER, ttl_deadline INTEGER)")
            .execute(&pool).await.unwrap();
        sqlx::query("CREATE TABLE channel_members (channel_id TEXT NOT NULL, pubkey BLOB NOT NULL, role TEXT NOT NULL, joined_at INTEGER NOT NULL DEFAULT (unixepoch()), invited_by BLOB, removed_at INTEGER, PRIMARY KEY (channel_id, pubkey))")
            .execute(&pool).await.unwrap();
        pool.close().await;

        let upgraded = connect(path.to_str().unwrap()).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT version FROM schema_version WHERE singleton = 1")
                .fetch_one(&upgraded)
                .await
                .unwrap(),
            3
        );
        for (table, column) in [
            ("channels", "participant_hash"),
            ("channel_members", "hidden_at"),
        ] {
            let pragma = format!("PRAGMA table_info({table})");
            assert!(sqlx::query(sqlx::AssertSqlSafe(pragma))
                .fetch_all(&upgraded)
                .await
                .unwrap()
                .iter()
                .any(|row| row.get::<String, _>("name") == column));
        }
        upgraded.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn core_slice_survives_temporary_file_reopen() {
        let path = std::env::temp_dir().join(format!("buzz-db-{}.sqlite", Uuid::new_v4()));
        let path_string = path.to_string_lossy().into_owned();
        let owner = Keys::generate();
        let owner_bytes = owner.public_key().to_bytes();
        let owner_hex = owner.public_key().to_hex();
        let channel_id = Uuid::new_v4();
        let event = EventBuilder::new(Kind::Custom(9), "durable message")
            .sign_with_keys(&owner)
            .unwrap();

        let pool = connect(&path_string).await.unwrap();
        let ensured = ensure_configured_community(&pool, "Local.Buzz")
            .await
            .unwrap();
        bootstrap_owner(&pool, ensured.id, &owner_hex)
            .await
            .unwrap();
        assert!(ensure_user(&pool, ensured.id, &owner_bytes).await.unwrap());
        let (channel, created) = create_channel_with_id(
            &pool,
            ensured.id,
            channel_id,
            "general",
            crate::channel::ChannelType::Stream,
            crate::channel::ChannelVisibility::Private,
            None,
            &owner_bytes,
            None,
        )
        .await
        .unwrap();
        assert!(created);
        assert_eq!(channel.id, channel_id);
        assert!(is_member(&pool, ensured.id, channel_id, &owner_bytes)
            .await
            .unwrap());
        assert!(
            insert_event(&pool, ensured.id, &event, Some(channel_id))
                .await
                .unwrap()
                .1
        );
        pool.close().await;

        let reopened = connect(&path_string).await.unwrap();
        let found = lookup_community_by_host(&reopened, "local.buzz")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, ensured.id);
        assert!(is_community_active(&reopened, ensured.id).await.unwrap());
        assert!(is_relay_member(&reopened, ensured.id, &owner_hex)
            .await
            .unwrap());
        assert_eq!(
            get_accessible_channel_ids(&reopened, ensured.id, &owner_bytes)
                .await
                .unwrap(),
            vec![channel_id]
        );
        let stored = get_event_by_id(&reopened, ensured.id, event.id.as_bytes())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.event.content, "durable message");
        let mut query = crate::EventQuery::for_community(ensured.id);
        query.channel_id = Some(channel_id);
        query.kinds = Some(vec![9]);
        assert_eq!(query_events(&reopened, &query).await.unwrap().len(), 1);
        reopened.close().await;
        std::fs::remove_file(path).unwrap();
    }
}
