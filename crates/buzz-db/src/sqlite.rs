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
    for statement in SCHEMA.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        sqlx::query(statement).execute(pool).await?;
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
