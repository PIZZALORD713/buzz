//! SQLite storage for the single-node relay profile.
//!
//! This module deliberately contains a separate, minimal schema rather than
//! attempting to translate the production PostgreSQL migrations.

use sha2::{Digest, Sha256};
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
    not_before INTEGER,
    delivered_at INTEGER,
    PRIMARY KEY (community_id, id),
    FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_community_created
    ON events (community_id, created_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_events_community_kind
    ON events (community_id, kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_channel_created
    ON events (community_id, channel_id, created_at DESC);

CREATE TABLE IF NOT EXISTS pubkey_allowlist (
    community_id TEXT NOT NULL,
    pubkey BLOB NOT NULL,
    added_by BLOB NOT NULL,
    added_at INTEGER NOT NULL DEFAULT (unixepoch()),
    note TEXT,
    PRIMARY KEY (community_id, pubkey),
    FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);

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
            "CREATE VIEW IF NOT EXISTS searchable_events AS SELECT rowid, content FROM events WHERE kind IN (0, 9, 40002, 45001, 45003)",
            "CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(content, content='searchable_events', content_rowid='rowid', tokenize='unicode61')",
            "INSERT INTO events_fts(events_fts) VALUES ('rebuild')",
            "CREATE TRIGGER IF NOT EXISTS events_fts_insert AFTER INSERT ON events WHEN new.kind IN (0, 9, 40002, 45001, 45003) BEGIN INSERT INTO events_fts(rowid, content) VALUES (new.rowid, new.content); END",
            "CREATE TRIGGER IF NOT EXISTS events_fts_delete AFTER DELETE ON events WHEN old.kind IN (0, 9, 40002, 45001, 45003) BEGIN INSERT INTO events_fts(events_fts, rowid, content) VALUES ('delete', old.rowid, old.content); END",
            "CREATE TRIGGER IF NOT EXISTS events_fts_update AFTER UPDATE OF content, kind ON events BEGIN INSERT INTO events_fts(events_fts, rowid, content) SELECT 'delete', old.rowid, old.content WHERE old.kind IN (0, 9, 40002, 45001, 45003); INSERT INTO events_fts(rowid, content) SELECT new.rowid, new.content WHERE new.kind IN (0, 9, 40002, 45001, 45003); END",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_dm_hash ON channels (community_id, participant_hash) WHERE channel_type = 'dm' AND deleted_at IS NULL",
        ] {
            sqlx::query(statement).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE schema_version SET version = 3 WHERE singleton = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 3;
    }
    if version < 4 {
        let mut tx = pool.begin().await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS archived_identities (community_id TEXT NOT NULL, pubkey TEXT NOT NULL, consent_path TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT, replaced_by TEXT, request_event_id TEXT NOT NULL, archived_at INTEGER NOT NULL DEFAULT (unixepoch()), PRIMARY KEY (community_id, pubkey), FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE)")
            .execute(&mut *tx).await?;
        sqlx::query("UPDATE schema_version SET version = 4 WHERE singleton = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 4;
    }
    if version < 5 {
        let mut tx = pool.begin().await?;
        for statement in [
            "DROP TRIGGER IF EXISTS events_fts_insert",
            "DROP TRIGGER IF EXISTS events_fts_delete",
            "DROP TRIGGER IF EXISTS events_fts_update",
            "DROP TABLE IF EXISTS events_fts",
            "DROP VIEW IF EXISTS searchable_events",
            "CREATE VIEW searchable_events AS SELECT rowid, content FROM events WHERE kind IN (0, 9, 40002, 45001, 45003)",
            "CREATE VIRTUAL TABLE events_fts USING fts5(content, content='searchable_events', content_rowid='rowid', tokenize='unicode61')",
            "INSERT INTO events_fts(events_fts) VALUES ('rebuild')",
            "CREATE TRIGGER events_fts_insert AFTER INSERT ON events WHEN new.kind IN (0, 9, 40002, 45001, 45003) BEGIN INSERT INTO events_fts(rowid, content) VALUES (new.rowid, new.content); END",
            "CREATE TRIGGER events_fts_delete AFTER DELETE ON events WHEN old.kind IN (0, 9, 40002, 45001, 45003) BEGIN INSERT INTO events_fts(events_fts, rowid, content) VALUES ('delete', old.rowid, old.content); END",
            "CREATE TRIGGER events_fts_update AFTER UPDATE OF content, kind ON events BEGIN INSERT INTO events_fts(events_fts, rowid, content) SELECT 'delete', old.rowid, old.content WHERE old.kind IN (0, 9, 40002, 45001, 45003); INSERT INTO events_fts(rowid, content) SELECT new.rowid, new.content WHERE new.kind IN (0, 9, 40002, 45001, 45003); END",
            "CREATE TEMP TABLE dm_channel_merges (loser_id TEXT PRIMARY KEY, winner_id TEXT NOT NULL)",
            "INSERT INTO dm_channel_merges (loser_id, winner_id) SELECT id, winner_id FROM (SELECT id, FIRST_VALUE(id) OVER (PARTITION BY community_id, participant_hash ORDER BY created_at ASC, id ASC) AS winner_id, ROW_NUMBER() OVER (PARTITION BY community_id, participant_hash ORDER BY created_at ASC, id ASC) AS ordinal FROM channels WHERE channel_type = 'dm' AND deleted_at IS NULL AND participant_hash IS NOT NULL) ranked WHERE ordinal > 1",
            "UPDATE events SET channel_id = (SELECT winner_id FROM dm_channel_merges WHERE loser_id = events.channel_id) WHERE channel_id IN (SELECT loser_id FROM dm_channel_merges)",
            "INSERT INTO channel_members (channel_id, pubkey, role, joined_at, invited_by, hidden_at, removed_at) SELECT merges.winner_id, members.pubkey, members.role, members.joined_at, members.invited_by, members.hidden_at, members.removed_at FROM channel_members members JOIN dm_channel_merges merges ON merges.loser_id = members.channel_id WHERE true ON CONFLICT(channel_id, pubkey) DO UPDATE SET joined_at = MIN(channel_members.joined_at, excluded.joined_at), invited_by = COALESCE(channel_members.invited_by, excluded.invited_by), hidden_at = CASE WHEN channel_members.hidden_at IS NULL OR excluded.hidden_at IS NULL THEN NULL ELSE MIN(channel_members.hidden_at, excluded.hidden_at) END, removed_at = CASE WHEN channel_members.removed_at IS NULL OR excluded.removed_at IS NULL THEN NULL ELSE MIN(channel_members.removed_at, excluded.removed_at) END",
            "DELETE FROM channels WHERE id IN (SELECT loser_id FROM dm_channel_merges)",
            "DROP TABLE dm_channel_merges",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_dm_hash ON channels (community_id, participant_hash) WHERE channel_type = 'dm' AND deleted_at IS NULL",
            "CREATE TABLE IF NOT EXISTS git_repo_names (community_id TEXT NOT NULL, repo_id TEXT NOT NULL, owner_pubkey TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (unixepoch()), PRIMARY KEY (community_id, repo_id), FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE)",
        ] {
            sqlx::query(statement).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE schema_version SET version = 5 WHERE singleton = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 5;
    }
    if version < 6 {
        let mut tx = pool.begin().await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS api_tokens (community_id TEXT NOT NULL, id TEXT NOT NULL, token_hash BLOB NOT NULL, owner_pubkey BLOB NOT NULL, name TEXT NOT NULL, scopes TEXT NOT NULL, channel_ids TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch()), expires_at INTEGER, last_used_at INTEGER, revoked_at INTEGER, revoked_by BLOB, created_by_self_mint INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (community_id, id), UNIQUE (community_id, token_hash), FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE)")
            .execute(&mut *tx).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_tokens_owner ON api_tokens (community_id, owner_pubkey, created_at DESC)")
            .execute(&mut *tx).await?;
        sqlx::query("UPDATE schema_version SET version = 6 WHERE singleton = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 6;
    }
    if version < 7 {
        let mut tx = pool.begin().await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS thread_metadata (community_id TEXT NOT NULL, event_created_at INTEGER NOT NULL, event_id BLOB NOT NULL, channel_id TEXT NOT NULL, parent_event_id BLOB, parent_event_created_at INTEGER, root_event_id BLOB, root_event_created_at INTEGER, depth INTEGER NOT NULL DEFAULT 0, reply_count INTEGER NOT NULL DEFAULT 0, descendant_count INTEGER NOT NULL DEFAULT 0, last_reply_at INTEGER, broadcast INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (community_id, event_id), FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE, FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE)")
            .execute(&mut *tx).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_thread_metadata_root ON thread_metadata (community_id, root_event_id, event_created_at, event_id)")
            .execute(&mut *tx).await?;
        sqlx::query("UPDATE schema_version SET version = 7 WHERE singleton = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 7;
    }
    if version < 8 {
        let mut tx = pool.begin().await?;
        for statement in [
            "CREATE TABLE IF NOT EXISTS relay_invites (community_id TEXT NOT NULL, id TEXT NOT NULL, token_hash BLOB NOT NULL, max_uses INTEGER, use_count INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL, created_by TEXT NOT NULL, PRIMARY KEY (community_id, id), UNIQUE (community_id, token_hash), FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE)",
            "CREATE INDEX IF NOT EXISTS idx_relay_invites_expires ON relay_invites (expires_at)",
            "CREATE TABLE IF NOT EXISTS join_policy_acceptances (community_id TEXT NOT NULL, pubkey TEXT NOT NULL, policy_version TEXT NOT NULL, accepted_at INTEGER NOT NULL DEFAULT (unixepoch()), PRIMARY KEY (community_id, pubkey, policy_version), FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE)",
        ] {
            sqlx::query(statement).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE schema_version SET version = 8 WHERE singleton = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 8;
    }
    if version < 9 {
        let mut tx = pool.begin().await?;
        for statement in [
            "CREATE TABLE IF NOT EXISTS product_feedback (id TEXT PRIMARY KEY NOT NULL, community_id TEXT NOT NULL, event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 32), submitter_pubkey BLOB NOT NULL CHECK (length(submitter_pubkey) = 32), category TEXT CHECK (category IN ('bug', 'praise', 'needs-work')), body TEXT NOT NULL CHECK (length(trim(body)) > 0), tags TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags) AND json_type(tags) = 'array'), event_created_at INTEGER NOT NULL, received_at INTEGER NOT NULL DEFAULT (unixepoch()), FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS moderation_reports (id TEXT PRIMARY KEY NOT NULL, community_id TEXT NOT NULL, report_event_id BLOB NOT NULL CHECK (length(report_event_id) = 32), reporter_pubkey BLOB NOT NULL CHECK (length(reporter_pubkey) = 32), target_kind TEXT NOT NULL CHECK (target_kind IN ('event', 'pubkey', 'blob')), target_event_id BLOB CHECK (target_event_id IS NULL OR length(target_event_id) = 32), target_pubkey BLOB CHECK (target_pubkey IS NULL OR length(target_pubkey) = 32), target_blob_sha256 BLOB CHECK (target_blob_sha256 IS NULL OR length(target_blob_sha256) = 32), channel_id TEXT, report_type TEXT NOT NULL, note TEXT, status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'dismissed', 'escalated')), resolved_by BLOB, resolved_at INTEGER, action_id TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch()), CHECK ((target_kind = 'event' AND target_event_id IS NOT NULL AND target_pubkey IS NULL AND target_blob_sha256 IS NULL) OR (target_kind = 'pubkey' AND target_event_id IS NULL AND target_pubkey IS NOT NULL AND target_blob_sha256 IS NULL) OR (target_kind = 'blob' AND target_event_id IS NULL AND target_pubkey IS NULL AND target_blob_sha256 IS NOT NULL)), FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE, FOREIGN KEY (channel_id) REFERENCES channels(id))",
            "CREATE INDEX IF NOT EXISTS idx_product_feedback_received ON product_feedback (received_at DESC, id)",
            "CREATE INDEX IF NOT EXISTS idx_product_feedback_community_received ON product_feedback (community_id, received_at DESC, id)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_moderation_reports_event ON moderation_reports (community_id, report_event_id)",
            "CREATE INDEX IF NOT EXISTS idx_moderation_reports_created ON moderation_reports (created_at DESC, id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_moderation_reports_status ON moderation_reports (community_id, status, created_at DESC)",
        ] { sqlx::query(statement).execute(&mut *tx).await?; }
        sqlx::query("UPDATE schema_version SET version = 9 WHERE singleton = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 9;
    }
    if version < 10 {
        let mut tx = pool.begin().await?;
        for statement in [
            "CREATE TABLE IF NOT EXISTS community_bans (community_id TEXT NOT NULL, pubkey BLOB NOT NULL CHECK (length(pubkey) = 32), banned INTEGER NOT NULL DEFAULT 0 CHECK (banned IN (0, 1)), ban_expires_at INTEGER, ban_reason TEXT, muted_until INTEGER, mute_reason TEXT, actor_pubkey BLOB NOT NULL CHECK (length(actor_pubkey) = 32), created_at INTEGER NOT NULL DEFAULT (unixepoch()), updated_at INTEGER NOT NULL DEFAULT (unixepoch()), PRIMARY KEY (community_id, pubkey), FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE)",
            "CREATE TABLE IF NOT EXISTS moderation_actions (community_id TEXT NOT NULL, id TEXT NOT NULL, actor_pubkey BLOB NOT NULL CHECK (length(actor_pubkey) = 32), action TEXT NOT NULL CHECK (action IN ('delete_message', 'kick', 'ban', 'unban', 'timeout', 'untimeout', 'dismiss_report', 'escalate', 'resolve:delete', 'resolve:kick', 'resolve:ban', 'resolve:timeout')), target_pubkey BLOB CHECK (target_pubkey IS NULL OR length(target_pubkey) = 32), target_event_id BLOB CHECK (target_event_id IS NULL OR length(target_event_id) = 32), channel_id TEXT, reason_code TEXT, public_reason TEXT, private_reason TEXT, matched_principal TEXT CHECK (matched_principal IS NULL OR matched_principal IN ('self', 'owner')), created_at INTEGER NOT NULL DEFAULT (unixepoch()), PRIMARY KEY (community_id, id), FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE, FOREIGN KEY (channel_id) REFERENCES channels(id))",
            "CREATE INDEX IF NOT EXISTS idx_moderation_actions_created ON moderation_actions (community_id, created_at DESC, id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_moderation_actions_target_pubkey ON moderation_actions (community_id, target_pubkey) WHERE target_pubkey IS NOT NULL",
            "CREATE INDEX IF NOT EXISTS idx_community_bans_active ON community_bans (community_id, updated_at DESC)",
            "CREATE TRIGGER IF NOT EXISTS moderation_reports_action_tenant_insert BEFORE INSERT ON moderation_reports WHEN NEW.action_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM moderation_actions WHERE community_id=NEW.community_id AND id=NEW.action_id) BEGIN SELECT RAISE(ABORT, 'moderation report action must belong to community'); END",
            "CREATE TRIGGER IF NOT EXISTS moderation_reports_action_tenant_update BEFORE UPDATE OF action_id, community_id ON moderation_reports WHEN NEW.action_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM moderation_actions WHERE community_id=NEW.community_id AND id=NEW.action_id) BEGIN SELECT RAISE(ABORT, 'moderation report action must belong to community'); END",
            "CREATE TRIGGER IF NOT EXISTS moderation_actions_channel_tenant_insert BEFORE INSERT ON moderation_actions WHEN NEW.channel_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM channels WHERE community_id=NEW.community_id AND id=NEW.channel_id) BEGIN SELECT RAISE(ABORT, 'moderation action channel must belong to community'); END",
            "CREATE TRIGGER IF NOT EXISTS moderation_actions_channel_tenant_update BEFORE UPDATE OF channel_id, community_id ON moderation_actions WHEN NEW.channel_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM channels WHERE community_id=NEW.community_id AND id=NEW.channel_id) BEGIN SELECT RAISE(ABORT, 'moderation action channel must belong to community'); END",
        ] { sqlx::query(statement).execute(&mut *tx).await?; }
        sqlx::query("UPDATE schema_version SET version = 10 WHERE singleton = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 10;
    }
    if version < 11 {
        let mut tx = pool.begin().await?;
        for statement in [
            "CREATE TABLE IF NOT EXISTS workflows (community_id TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, owner_pubkey BLOB NOT NULL, channel_id TEXT, definition TEXT NOT NULL CHECK (json_valid(definition)), definition_hash BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','archived')), enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)), created_at INTEGER NOT NULL DEFAULT (unixepoch()), updated_at INTEGER NOT NULL DEFAULT (unixepoch()), PRIMARY KEY (community_id,id), FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE, FOREIGN KEY (channel_id) REFERENCES channels(id))",
            "CREATE INDEX IF NOT EXISTS idx_workflows_channel_active ON workflows (community_id,channel_id,status,enabled)",
            "CREATE TRIGGER IF NOT EXISTS workflows_owner_tenant_insert BEFORE INSERT ON workflows WHEN NOT EXISTS (SELECT 1 FROM users WHERE community_id=NEW.community_id AND pubkey=NEW.owner_pubkey) BEGIN SELECT RAISE(ABORT, 'workflow owner must belong to community'); END",
            "CREATE TRIGGER IF NOT EXISTS workflows_owner_tenant_update BEFORE UPDATE OF owner_pubkey, community_id ON workflows WHEN NOT EXISTS (SELECT 1 FROM users WHERE community_id=NEW.community_id AND pubkey=NEW.owner_pubkey) BEGIN SELECT RAISE(ABORT, 'workflow owner must belong to community'); END",
            "CREATE TRIGGER IF NOT EXISTS workflows_channel_tenant_insert BEFORE INSERT ON workflows WHEN NEW.channel_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM channels WHERE community_id=NEW.community_id AND id=NEW.channel_id) BEGIN SELECT RAISE(ABORT, 'workflow channel must belong to community'); END",
            "CREATE TRIGGER IF NOT EXISTS workflows_channel_tenant_update BEFORE UPDATE OF channel_id, community_id ON workflows WHEN NEW.channel_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM channels WHERE community_id=NEW.community_id AND id=NEW.channel_id) BEGIN SELECT RAISE(ABORT, 'workflow channel must belong to community'); END",
            "CREATE TABLE IF NOT EXISTS workflow_runs (community_id TEXT NOT NULL, id TEXT NOT NULL, workflow_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','waiting_approval','completed','failed','cancelled')), trigger_event_id BLOB, current_step INTEGER NOT NULL DEFAULT 0, execution_trace TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(execution_trace)), trigger_context TEXT CHECK (trigger_context IS NULL OR json_valid(trigger_context)), started_at INTEGER, completed_at INTEGER, error_message TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch()), PRIMARY KEY (community_id,id), FOREIGN KEY (community_id,workflow_id) REFERENCES workflows(community_id,id) ON DELETE CASCADE)",
            "CREATE INDEX IF NOT EXISTS idx_workflow_runs_workflow ON workflow_runs (community_id,workflow_id,created_at DESC)",
            "CREATE TABLE IF NOT EXISTS workflow_approvals (community_id TEXT NOT NULL, token BLOB NOT NULL, workflow_id TEXT NOT NULL, run_id TEXT NOT NULL, step_id TEXT NOT NULL, step_index INTEGER NOT NULL, approver_spec TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','granted','denied','expired')), approver_pubkey BLOB, note TEXT, granted_at INTEGER, denied_at INTEGER, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL DEFAULT (unixepoch()), PRIMARY KEY (community_id,token), FOREIGN KEY (community_id,workflow_id) REFERENCES workflows(community_id,id) ON DELETE CASCADE, FOREIGN KEY (community_id,run_id) REFERENCES workflow_runs(community_id,id) ON DELETE CASCADE)",
            "CREATE INDEX IF NOT EXISTS idx_workflow_approvals_run ON workflow_approvals (community_id,run_id,step_index,created_at)",
            "CREATE TABLE IF NOT EXISTS scheduled_workflow_fires (community_id TEXT NOT NULL, workflow_id TEXT NOT NULL, scheduled_for INTEGER NOT NULL, claimed_at INTEGER NOT NULL DEFAULT (unixepoch()), workflow_run_id TEXT, PRIMARY KEY (community_id,workflow_id,scheduled_for), FOREIGN KEY (community_id,workflow_id) REFERENCES workflows(community_id,id) ON DELETE CASCADE, FOREIGN KEY (community_id,workflow_run_id) REFERENCES workflow_runs(community_id,id))",
            "CREATE INDEX IF NOT EXISTS idx_scheduled_fires_claimed_at ON scheduled_workflow_fires (claimed_at)",
        ] { sqlx::query(statement).execute(&mut *tx).await?; }
        sqlx::query("UPDATE schema_version SET version=11 WHERE singleton=1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 11;
    }
    if version < 12 {
        let mut tx = pool.begin().await?;
        ensure_column_on(
            &mut tx,
            "events",
            "not_before",
            "ALTER TABLE events ADD COLUMN not_before INTEGER",
        )
        .await?;
        ensure_column_on(
            &mut tx,
            "events",
            "delivered_at",
            "ALTER TABLE events ADD COLUMN delivered_at INTEGER",
        )
        .await?;
        let reminder_rows = sqlx::query(
            "SELECT community_id, id, event_json FROM events WHERE kind = ?1 AND not_before IS NULL",
        )
        .bind(buzz_core::kind::KIND_EVENT_REMINDER as i32)
        .fetch_all(&mut *tx)
        .await?;
        for row in reminder_rows {
            let event: nostr::Event = serde_json::from_str(row.try_get("event_json")?)?;
            if let Some(not_before) = crate::event::extract_not_before(&event) {
                sqlx::query(
                    "UPDATE events SET not_before = ?1 WHERE community_id = ?2 AND id = ?3",
                )
                .bind(not_before)
                .bind(row.try_get::<String, _>("community_id")?)
                .bind(row.try_get::<Vec<u8>, _>("id")?)
                .execute(&mut *tx)
                .await?;
            }
        }
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_due_reminders ON events (not_before, community_id, pubkey, created_at DESC, id) WHERE kind = 30300 AND delivered_at IS NULL")
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE schema_version SET version = 12 WHERE singleton = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        version = 12;
    }
    if version != 12 {
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

pub(crate) async fn lookup_community_icon(
    pool: &SqlitePool,
    community: CommunityId,
) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar::<_, Option<String>>("SELECT icon FROM communities WHERE id = ?1")
            .bind(community.as_uuid().to_string())
            .fetch_optional(pool)
            .await?
            .flatten()
            .filter(|icon| !icon.is_empty()),
    )
}

pub(crate) async fn set_community_icon(
    pool: &SqlitePool,
    community: CommunityId,
    icon: Option<&str>,
) -> Result<()> {
    sqlx::query("UPDATE communities SET icon = ?2 WHERE id = ?1")
        .bind(community.as_uuid().to_string())
        .bind(icon)
        .execute(pool)
        .await?;
    Ok(())
}

pub(crate) async fn community_of_channel(
    pool: &SqlitePool,
    channel_id: Uuid,
) -> Result<Option<CommunityId>> {
    let community: Option<String> = sqlx::query_scalar(
        "SELECT community_id FROM channels WHERE id = ?1 AND deleted_at IS NULL",
    )
    .bind(channel_id.to_string())
    .fetch_optional(pool)
    .await?;
    community
        .map(|id| {
            Uuid::parse_str(&id)
                .map(CommunityId::from_uuid)
                .map_err(|e| crate::DbError::InvalidData(e.to_string()))
        })
        .transpose()
}

pub(crate) async fn rebind_single_node_community_host(
    pool: &SqlitePool,
    normalized_host: &str,
    owner_pubkey: &str,
) -> Result<Option<CommunityRecord>> {
    let mut tx = pool.begin().await?;

    // Defect-era databases may contain several loopback communities, one per
    // ephemeral port. Prefer a community owned by this desktop identity, then
    // the one carrying the most events. This preserves the most useful UUID and
    // its channels/messages while making the current Host header resolvable.
    let row = sqlx::query(
        r#"SELECT c.id, c.host
           FROM communities c
           LEFT JOIN relay_members rm
             ON rm.community_id = c.id
            AND lower(rm.pubkey) = lower(?1)
            AND rm.role = 'owner'
           LEFT JOIN events e ON e.community_id = c.id
           WHERE c.archived_at IS NULL
             AND c.host LIKE '127.0.0.1:%'
           GROUP BY c.id, c.host, c.created_at
           ORDER BY (rm.pubkey IS NOT NULL) DESC, count(e.id) DESC, c.created_at ASC, c.id ASC
           LIMIT 1"#,
    )
    .bind(owner_pubkey)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let record = community_record(row)?;
    if record.host.eq_ignore_ascii_case(normalized_host) {
        tx.commit().await?;
        return Ok(Some(record));
    }

    // The OS may reuse a port that belongs to another stale defect-era row.
    // Swap that collision to the selected row's old authority transactionally,
    // using a temporary unique host to satisfy the case-insensitive constraint.
    if let Some(collision_id) = sqlx::query_scalar::<_, String>(
        "SELECT id FROM communities WHERE host = ?1 COLLATE NOCASE AND id <> ?2",
    )
    .bind(normalized_host)
    .bind(record.id.as_uuid().to_string())
    .fetch_optional(&mut *tx)
    .await?
    {
        let temporary_host = format!("rebind-{}.invalid", Uuid::new_v4());
        sqlx::query("UPDATE communities SET host = ?2 WHERE id = ?1")
            .bind(&collision_id)
            .bind(&temporary_host)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE communities SET host = ?2 WHERE id = ?1")
            .bind(record.id.as_uuid().to_string())
            .bind(normalized_host)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE communities SET host = ?2 WHERE id = ?1")
            .bind(collision_id)
            .bind(&record.host)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query("UPDATE communities SET host = ?2 WHERE id = ?1")
            .bind(record.id.as_uuid().to_string())
            .bind(normalized_host)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Some(CommunityRecord {
        id: record.id,
        host: normalized_host.to_string(),
    }))
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

pub(crate) async fn soft_delete_discovery_events(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
    relay_pubkey: &[u8],
) -> Result<u64> {
    Ok(sqlx::query("DELETE FROM events WHERE community_id = ?1 AND channel_id = ?2 AND pubkey = ?3 AND kind IN (39000,39001,39002)")
        .bind(community.as_uuid().to_string())
        .bind(channel_id.to_string())
        .bind(relay_pubkey)
        .execute(pool)
        .await?
        .rows_affected())
}

async fn insert_command_event_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    community: CommunityId,
    event: &nostr::Event,
    channel_id: Option<Uuid>,
) -> Result<bool> {
    let received_at = chrono::Utc::now();
    let not_before = crate::event::extract_not_before(event);
    Ok(sqlx::query("INSERT INTO events (community_id, id, pubkey, created_at, kind, tags_json, content, sig, channel_id, received_at, event_json, not_before) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) ON CONFLICT DO NOTHING")
        .bind(community.as_uuid().to_string())
        .bind(event.id.as_bytes().as_slice())
        .bind(event.pubkey.to_bytes().as_slice())
        .bind(event.created_at.as_secs() as i64)
        .bind(event.kind.as_u16() as i32)
        .bind(serde_json::to_string(&event.tags)?)
        .bind(&event.content)
        .bind(event.sig.serialize().as_slice())
        .bind(channel_id.map(|id| id.to_string()))
        .bind(received_at.timestamp())
        .bind(serde_json::to_string(event)?)
        .bind(not_before)
        .execute(&mut **tx)
        .await?
        .rows_affected() == 1)
}

async fn replace_command_event_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    community: CommunityId,
    event: &nostr::Event,
    channel_id: Option<Uuid>,
    d_tag: &str,
) -> Result<bool> {
    let rows = sqlx::query(
        "SELECT id, event_json FROM events WHERE community_id = ?1 AND kind = ?2 AND pubkey = ?3",
    )
    .bind(community.as_uuid().to_string())
    .bind(event.kind.as_u16() as i32)
    .bind(event.pubkey.to_bytes().as_slice())
    .fetch_all(&mut **tx)
    .await?;
    let mut replaced_ids = Vec::new();
    for row in rows {
        let existing: nostr::Event = serde_json::from_str(row.try_get("event_json")?)?;
        if crate::event::extract_d_tag(&existing).as_deref() != Some(d_tag) {
            continue;
        }
        if event.created_at < existing.created_at
            || (event.created_at == existing.created_at && event.id >= existing.id)
        {
            return Ok(false);
        }
        replaced_ids.push(row.try_get::<Vec<u8>, _>("id")?);
    }
    for id in replaced_ids {
        sqlx::query("DELETE FROM events WHERE community_id = ?1 AND id = ?2")
            .bind(community.as_uuid().to_string())
            .bind(id)
            .execute(&mut **tx)
            .await?;
    }
    insert_command_event_tx(tx, community, event, channel_id).await
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
    let not_before = crate::event::extract_not_before(event);
    let inserted = sqlx::query("INSERT INTO events (community_id, id, pubkey, created_at, kind, tags_json, content, sig, channel_id, received_at, event_json, not_before) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) ON CONFLICT DO NOTHING")
        .bind(community.as_uuid().to_string()).bind(event.id.as_bytes().as_slice()).bind(event.pubkey.to_bytes().as_slice())
        .bind(event.created_at.as_secs() as i64).bind(event.kind.as_u16() as i32).bind(serde_json::to_string(&event.tags)?)
        .bind(&event.content).bind(event.sig.serialize().as_slice()).bind(channel_id.map(|id| id.to_string()))
        .bind(received_at.timestamp()).bind(serde_json::to_string(event)?).bind(not_before).execute(pool).await?.rows_affected() == 1;
    Ok((
        buzz_core::StoredEvent::with_received_at(event.clone(), received_at, channel_id, true),
        inserted,
    ))
}

async fn insert_thread_metadata_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    community: CommunityId,
    meta: &crate::event::ThreadMetadataParams<'_>,
) -> Result<()> {
    let inserted = sqlx::query("INSERT INTO thread_metadata (community_id,event_created_at,event_id,channel_id,parent_event_id,parent_event_created_at,root_event_id,root_event_created_at,depth,broadcast) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT DO NOTHING")
        .bind(community.as_uuid().to_string()).bind(meta.event_created_at.timestamp()).bind(meta.event_id)
        .bind(meta.channel_id.to_string()).bind(meta.parent_event_id).bind(meta.parent_event_created_at.map(|t| t.timestamp()))
        .bind(meta.root_event_id).bind(meta.root_event_created_at.map(|t| t.timestamp())).bind(meta.depth).bind(meta.broadcast)
        .execute(&mut **tx).await?.rows_affected() != 0;
    if !inserted {
        return Ok(());
    }
    if let Some(parent) = meta.parent_event_id {
        let parent_at = meta
            .parent_event_created_at
            .unwrap_or(meta.event_created_at)
            .timestamp();
        sqlx::query("INSERT INTO thread_metadata (community_id,event_created_at,event_id,channel_id,depth,broadcast) VALUES (?1,?2,?3,?4,0,0) ON CONFLICT DO NOTHING")
            .bind(community.as_uuid().to_string()).bind(parent_at).bind(parent).bind(meta.channel_id.to_string()).execute(&mut **tx).await?;
        if let Some(root) = meta.root_event_id.filter(|root| *root != parent) {
            let root_at = meta
                .root_event_created_at
                .unwrap_or(meta.event_created_at)
                .timestamp();
            sqlx::query("INSERT INTO thread_metadata (community_id,event_created_at,event_id,channel_id,depth,broadcast) VALUES (?1,?2,?3,?4,0,0) ON CONFLICT DO NOTHING")
                .bind(community.as_uuid().to_string()).bind(root_at).bind(root).bind(meta.channel_id.to_string()).execute(&mut **tx).await?;
        }
        sqlx::query("UPDATE thread_metadata SET reply_count=reply_count+1,last_reply_at=unixepoch() WHERE community_id=?1 AND event_id=?2")
            .bind(community.as_uuid().to_string()).bind(parent).execute(&mut **tx).await?;
        if let Some(root) = meta.root_event_id {
            sqlx::query("UPDATE thread_metadata SET descendant_count=descendant_count+1 WHERE community_id=?1 AND event_id=?2")
                .bind(community.as_uuid().to_string()).bind(root).execute(&mut **tx).await?;
        }
    }
    Ok(())
}

pub(crate) async fn get_thread_replies(
    pool: &SqlitePool,
    community: CommunityId,
    root_event_id: &[u8],
    depth_limit: Option<u32>,
    limit: u32,
    cursor: Option<&[u8]>,
) -> Result<Vec<crate::thread::ThreadReply>> {
    let cursor = cursor.filter(|value| value.len() >= 8).map(|value| {
        (
            i64::from_be_bytes(value[..8].try_into().expect("length checked")),
            (value.len() > 8).then(|| value[8..].to_vec()),
        )
    });
    let rows = sqlx::query("SELECT tm.event_id,tm.parent_event_id,tm.root_event_id,tm.channel_id,tm.depth,tm.event_created_at,tm.broadcast,e.pubkey,e.tags_json,e.content,e.event_json,e.received_at,e.channel_id AS event_channel_id FROM thread_metadata tm JOIN events e ON e.community_id=tm.community_id AND e.id=tm.event_id WHERE tm.community_id=?1 AND tm.root_event_id=?2 ORDER BY tm.event_created_at ASC,tm.event_id ASC")
        .bind(community.as_uuid().to_string()).bind(root_event_id).fetch_all(pool).await?;
    let mut replies = Vec::new();
    for row in rows {
        let created: i64 = row.try_get("event_created_at")?;
        let id: Vec<u8> = row.try_get("event_id")?;
        if depth_limit.is_some_and(|max| row.get::<i32, _>("depth") > max as i32)
            || cursor.as_ref().is_some_and(|(at, cursor_id)| {
                created < *at
                    || (created == *at
                        && cursor_id.as_ref().is_none_or(|cursor_id| id <= *cursor_id))
            })
        {
            continue;
        }
        let channel: String = row.try_get("channel_id")?;
        let parent_event_id = row.try_get("parent_event_id")?;
        let root_event_id = row.try_get("root_event_id")?;
        let depth = row.try_get("depth")?;
        let broadcast = row.get::<i64, _>("broadcast") != 0;
        let stored = stored_event(row)?;
        replies.push(crate::thread::ThreadReply {
            event_id: id,
            parent_event_id,
            root_event_id,
            channel_id: Uuid::parse_str(&channel).map_err(|e| {
                crate::DbError::InvalidData(format!("invalid SQLite channel id: {e}"))
            })?,
            pubkey: stored.event.pubkey.to_bytes().to_vec(),
            tags: serde_json::to_value(&stored.event.tags)?,
            content: stored.event.content.clone(),
            stored_event: stored,
            depth,
            created_at: chrono::DateTime::from_timestamp(created, 0)
                .ok_or(crate::DbError::InvalidTimestamp(created))?,
            broadcast,
        });
        if replies.len() >= limit as usize {
            break;
        }
    }
    Ok(replies)
}

pub(crate) async fn get_channel_window(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
    limit: u32,
    cursor: Option<(chrono::DateTime<chrono::Utc>, Vec<u8>)>,
    kind_filter: Option<&[u32]>,
) -> Result<crate::thread::ChannelWindow> {
    let rows = sqlx::query("SELECT e.id,e.created_at,e.kind,e.event_json,e.received_at,e.channel_id,tm.reply_count,tm.descendant_count,tm.last_reply_at FROM events e LEFT JOIN thread_metadata tm ON tm.community_id=e.community_id AND tm.event_id=e.id WHERE e.community_id=?1 AND e.channel_id=?2 AND (tm.depth IS NULL OR tm.depth=0 OR (tm.depth=1 AND tm.broadcast=1)) ORDER BY e.created_at DESC,e.id ASC")
        .bind(community.as_uuid().to_string()).bind(channel_id.to_string()).fetch_all(pool).await?;
    let mut retained = Vec::new();
    for row in rows {
        let created: i64 = row.try_get("created_at")?;
        let id: Vec<u8> = row.try_get("id")?;
        let kind: i32 = row.try_get("kind")?;
        if cursor.as_ref().is_some_and(|(at, cursor_id)| {
            created > at.timestamp() || (created == at.timestamp() && id <= *cursor_id)
        }) || kind_filter
            .is_some_and(|kinds| !kinds.is_empty() && !kinds.contains(&(kind as u32)))
        {
            continue;
        }
        retained.push(row);
        if retained.len() > limit as usize {
            break;
        }
    }
    let has_more = retained.len() > limit as usize;
    retained.truncate(limit as usize);
    let next_cursor = if has_more {
        retained.last().map(|row| {
            let created: i64 = row.get("created_at");
            let id: Vec<u8> = row.get("id");
            (
                chrono::DateTime::from_timestamp(created, 0).expect("stored timestamps are valid"),
                id,
            )
        })
    } else {
        None
    };
    let mut result = Vec::with_capacity(retained.len());
    for row in retained {
        let reply_count: Option<i32> = row.try_get("reply_count")?;
        let root_id: Vec<u8> = row.try_get("id")?;
        let summary = if reply_count.is_some_and(|count| count > 0) {
            get_thread_summary(pool, community, &root_id).await?
        } else {
            None
        };
        result.push(crate::thread::ChannelWindowRow {
            stored_event: stored_event(row)?,
            thread_summary: summary,
        });
    }
    Ok(crate::thread::ChannelWindow {
        rows: result,
        has_more,
        next_cursor,
    })
}

pub(crate) async fn get_thread_metadata_by_event(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
) -> Result<Option<crate::thread::ThreadMetadataRecord>> {
    let row = sqlx::query("SELECT event_id,event_created_at,channel_id,parent_event_id,root_event_id,depth,reply_count,descendant_count,broadcast FROM thread_metadata WHERE community_id=?1 AND event_id=?2")
        .bind(community.as_uuid().to_string()).bind(event_id).fetch_optional(pool).await?;
    row.map(|row| {
        let event_created_at: i64 = row.try_get("event_created_at")?;
        let channel_id: String = row.try_get("channel_id")?;
        Ok(crate::thread::ThreadMetadataRecord {
            event_id: row.try_get("event_id")?,
            event_created_at: chrono::DateTime::from_timestamp(event_created_at, 0)
                .ok_or(crate::DbError::InvalidTimestamp(event_created_at))?,
            channel_id: Uuid::parse_str(&channel_id).map_err(|e| {
                crate::DbError::InvalidData(format!("invalid SQLite channel id: {e}"))
            })?,
            parent_event_id: row.try_get("parent_event_id")?,
            root_event_id: row.try_get("root_event_id")?,
            depth: row.try_get("depth")?,
            reply_count: row.try_get("reply_count")?,
            descendant_count: row.try_get("descendant_count")?,
            broadcast: row.try_get::<i64, _>("broadcast")? != 0,
        })
    })
    .transpose()
}

pub(crate) async fn decrement_reply_count(
    pool: &SqlitePool,
    community: CommunityId,
    parent: &[u8],
    root: Option<&[u8]>,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE thread_metadata SET reply_count=MAX(reply_count-1,0) WHERE community_id=?1 AND event_id=?2")
        .bind(community.as_uuid().to_string()).bind(parent).execute(&mut *tx).await?;
    if let Some(root) = root {
        sqlx::query("UPDATE thread_metadata SET descendant_count=MAX(descendant_count-1,0) WHERE community_id=?1 AND event_id=?2")
            .bind(community.as_uuid().to_string()).bind(root).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn get_thread_summary(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
) -> Result<Option<crate::thread::ThreadSummary>> {
    let row = sqlx::query("SELECT reply_count,descendant_count,last_reply_at FROM thread_metadata WHERE community_id=?1 AND event_id=?2")
        .bind(community.as_uuid().to_string()).bind(event_id).fetch_optional(pool).await?;
    let Some(row) = row else { return Ok(None) };
    let last: Option<i64> = row.try_get("last_reply_at")?;
    let participants = sqlx::query_scalar::<_, Vec<u8>>("SELECT e.pubkey FROM thread_metadata tm JOIN events e ON e.community_id=tm.community_id AND e.id=tm.event_id WHERE tm.community_id=?1 AND tm.root_event_id=?2 GROUP BY e.pubkey ORDER BY MAX(e.created_at) DESC LIMIT 10")
        .bind(community.as_uuid().to_string()).bind(event_id).fetch_all(pool).await?;
    Ok(Some(crate::thread::ThreadSummary {
        reply_count: row.try_get("reply_count")?,
        descendant_count: row.try_get("descendant_count")?,
        last_reply_at: last
            .map(|v| {
                chrono::DateTime::from_timestamp(v, 0).ok_or(crate::DbError::InvalidTimestamp(v))
            })
            .transpose()?,
        participants,
    }))
}

pub(crate) async fn insert_event_with_thread_metadata(
    pool: &SqlitePool,
    community: CommunityId,
    event: &nostr::Event,
    channel_id: Option<Uuid>,
    thread_meta: Option<crate::event::ThreadMetadataParams<'_>>,
) -> Result<(buzz_core::StoredEvent, bool)> {
    let kind = u32::from(event.kind.as_u16());
    if kind == buzz_core::kind::KIND_AUTH {
        return Err(crate::DbError::AuthEventRejected);
    }
    if buzz_core::kind::is_ephemeral(kind) {
        return Err(crate::DbError::EphemeralEventRejected(event.kind.as_u16()));
    }
    let received_at = chrono::Utc::now();
    let mut tx = pool.begin().await?;
    let not_before = crate::event::extract_not_before(event);
    let inserted = sqlx::query("INSERT INTO events (community_id,id,pubkey,created_at,kind,tags_json,content,sig,channel_id,received_at,event_json,not_before) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT DO NOTHING")
        .bind(community.as_uuid().to_string()).bind(event.id.as_bytes().as_slice()).bind(event.pubkey.to_bytes().as_slice())
        .bind(event.created_at.as_secs() as i64).bind(event.kind.as_u16() as i32).bind(serde_json::to_string(&event.tags)?)
        .bind(&event.content).bind(event.sig.serialize().as_slice()).bind(channel_id.map(|id| id.to_string()))
        .bind(received_at.timestamp()).bind(serde_json::to_string(event)?).bind(not_before).execute(&mut *tx).await?.rows_affected() != 0;
    if inserted {
        if let Some(meta) = &thread_meta {
            insert_thread_metadata_tx(&mut tx, community, meta).await?;
        }
    }
    tx.commit().await?;
    Ok((
        buzz_core::StoredEvent::with_received_at(event.clone(), received_at, channel_id, true),
        inserted,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_thread_metadata(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
    event_created_at: chrono::DateTime<chrono::Utc>,
    channel_id: Uuid,
    parent_event_id: Option<&[u8]>,
    parent_event_created_at: Option<chrono::DateTime<chrono::Utc>>,
    root_event_id: Option<&[u8]>,
    root_event_created_at: Option<chrono::DateTime<chrono::Utc>>,
    depth: i32,
    broadcast: bool,
) -> Result<()> {
    let meta = crate::event::ThreadMetadataParams {
        event_id,
        event_created_at,
        channel_id,
        parent_event_id,
        parent_event_created_at,
        root_event_id,
        root_event_created_at,
        depth,
        broadcast,
    };
    let mut tx = pool.begin().await?;
    insert_thread_metadata_tx(&mut tx, community, &meta).await?;
    tx.commit().await?;
    Ok(())
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
    let not_before = crate::event::extract_not_before(event);
    sqlx::query("INSERT INTO events (community_id, id, pubkey, created_at, kind, tags_json, content, sig, channel_id, received_at, event_json, not_before) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)")
        .bind(community.as_uuid().to_string()).bind(event.id.as_bytes().as_slice()).bind(event.pubkey.to_bytes().as_slice())
        .bind(event.created_at.as_secs() as i64).bind(event.kind.as_u16() as i32).bind(serde_json::to_string(&event.tags)?)
        .bind(&event.content).bind(event.sig.serialize().as_slice()).bind(channel_id.map(|id| id.to_string()))
        .bind(received_at.timestamp()).bind(serde_json::to_string(event)?).bind(not_before).execute(&mut *tx).await?;
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

pub(crate) async fn soft_delete_event_and_update_thread(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
    parent: Option<&[u8]>,
    root: Option<&[u8]>,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let deleted = sqlx::query("DELETE FROM events WHERE community_id = ?1 AND id = ?2")
        .bind(community.as_uuid().to_string())
        .bind(event_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        != 0;
    if deleted {
        if let Some(parent) = parent {
            sqlx::query("UPDATE thread_metadata SET reply_count=MAX(reply_count-1,0) WHERE community_id=?1 AND event_id=?2")
                .bind(community.as_uuid().to_string()).bind(parent).execute(&mut *tx).await?;
        }
        if let Some(root) = root {
            sqlx::query("UPDATE thread_metadata SET descendant_count=MAX(descendant_count-1,0) WHERE community_id=?1 AND event_id=?2")
                .bind(community.as_uuid().to_string()).bind(root).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(deleted)
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

pub(crate) async fn get_events_by_ids(
    pool: &SqlitePool,
    community: CommunityId,
    ids: &[&[u8]],
) -> Result<Vec<buzz_core::StoredEvent>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT event_json, received_at, channel_id FROM events WHERE community_id = ",
    );
    qb.push_bind(community.as_uuid().to_string());
    qb.push(" AND id IN (");
    let mut separated = qb.separated(", ");
    for id in ids {
        separated.push_bind(*id);
    }
    separated.push_unseparated(")");
    qb.build()
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(stored_event)
        .collect()
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
        if q.p_tag_hex.as_ref().is_some_and(|p| {
            !tags.iter().any(|tag| {
                tag.first().is_some_and(|name| name == "p")
                    && tag
                        .get(1)
                        .is_some_and(|value| value.eq_ignore_ascii_case(p))
            })
        }) {
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

pub(crate) async fn count_events(pool: &SqlitePool, q: &crate::EventQuery) -> Result<i64> {
    let mut unpaged = q.clone();
    unpaged.offset = None;
    unpaged.limit = Some(i64::MAX);
    unpaged.max_limit = Some(i64::MAX);
    Ok(query_events(pool, &unpaged).await?.len() as i64)
}

pub(crate) async fn huddle_started_link_exists(
    pool: &SqlitePool,
    community: CommunityId,
    parent_channel_id: Uuid,
    ephemeral_channel_id: Uuid,
    creator_pubkey: &[u8],
) -> Result<bool> {
    let rows = sqlx::query(
        "SELECT content FROM events WHERE community_id = ?1 AND channel_id = ?2 AND kind = ?3 AND pubkey = ?4 AND length(CAST(content AS BLOB)) <= 512 AND instr(LOWER(content), LOWER(?5)) > 0 ORDER BY created_at DESC, id ASC LIMIT 32",
    )
    .bind(community.as_uuid().to_string())
    .bind(parent_channel_id.to_string())
    .bind(buzz_core::kind::KIND_HUDDLE_STARTED as i32)
    .bind(creator_pubkey)
    .bind(ephemeral_channel_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().any(|row| {
        row.try_get::<String, _>("content")
            .ok()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
            .and_then(|value| {
                value
                    .get("ephemeral_channel_id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|id| Uuid::parse_str(id).ok())
            })
            .is_some_and(|id| id == ephemeral_channel_id)
    }))
}

pub(crate) async fn get_latest_global_replaceable(
    pool: &SqlitePool,
    community: CommunityId,
    kind: i32,
    pubkey: &[u8],
) -> Result<Option<buzz_core::StoredEvent>> {
    sqlx::query("SELECT event_json, received_at, channel_id FROM events WHERE community_id = ?1 AND kind = ?2 AND pubkey = ?3 AND channel_id IS NULL ORDER BY created_at DESC, id ASC LIMIT 1")
        .bind(community.as_uuid().to_string()).bind(kind).bind(pubkey)
        .fetch_optional(pool).await?.map(stored_event).transpose()
}

pub(crate) async fn soft_delete_by_coordinate(
    pool: &SqlitePool,
    community: CommunityId,
    kind: i32,
    pubkey: &[u8],
    d_tag: &str,
) -> Result<bool> {
    let rows = sqlx::query(
        "SELECT id, event_json FROM events WHERE community_id = ?1 AND kind = ?2 AND pubkey = ?3",
    )
    .bind(community.as_uuid().to_string())
    .bind(kind)
    .bind(pubkey)
    .fetch_all(pool)
    .await?;
    let mut ids = Vec::new();
    for row in rows {
        let event: nostr::Event = serde_json::from_str(&row.try_get::<String, _>("event_json")?)?;
        let matches = crate::event::extract_d_tag(&event).as_deref() == Some(d_tag);
        if matches {
            ids.push(row.try_get::<Vec<u8>, _>("id")?);
        }
    }
    let mut deleted = false;
    for id in ids {
        deleted |= sqlx::query("DELETE FROM events WHERE community_id = ?1 AND id = ?2")
            .bind(community.as_uuid().to_string())
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected()
            != 0;
    }
    Ok(deleted)
}

pub(crate) async fn get_last_message_at(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    sqlx::query_scalar::<_, Option<i64>>(
        "SELECT MAX(created_at) FROM events WHERE community_id = ?1 AND channel_id = ?2",
    )
    .bind(community.as_uuid().to_string())
    .bind(channel_id.to_string())
    .fetch_one(pool)
    .await?
    .map(timestamp)
    .transpose()
}

pub(crate) async fn get_last_message_at_bulk(
    pool: &SqlitePool,
    community: CommunityId,
    channel_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, chrono::DateTime<chrono::Utc>>> {
    if channel_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT channel_id, MAX(created_at) AS last_at FROM events WHERE community_id = ",
    );
    qb.push_bind(community.as_uuid().to_string())
        .push(" AND channel_id IN (");
    let mut separated = qb.separated(", ");
    for id in channel_ids {
        separated.push_bind(id.to_string());
    }
    separated.push_unseparated(") GROUP BY channel_id");
    let mut result = std::collections::HashMap::new();
    for row in qb.build().fetch_all(pool).await? {
        let id = Uuid::parse_str(&row.try_get::<String, _>("channel_id")?)
            .map_err(|e| crate::DbError::InvalidData(format!("invalid SQLite channel id: {e}")))?;
        result.insert(id, timestamp(row.try_get("last_at")?)?);
    }
    Ok(result)
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

pub(crate) async fn query_due_reminders(
    pool: &SqlitePool,
    now_secs: i64,
    batch_limit: i64,
) -> Result<Vec<crate::event::DueReminder>> {
    if batch_limit <= 0 {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        r#"
        SELECT e.community_id, c.host, e.id, e.pubkey, e.created_at, e.kind,
               e.tags_json, e.content, e.sig, e.channel_id, e.event_json
        FROM events e
        JOIN communities c ON c.id = e.community_id
        WHERE e.kind = ?1
          AND e.not_before IS NOT NULL
          AND e.not_before <= ?2
          AND e.delivered_at IS NULL
          AND c.archived_at IS NULL
        ORDER BY e.community_id, e.pubkey, e.created_at DESC, e.id ASC
        "#,
    )
    .bind(buzz_core::kind::KIND_EVENT_REMINDER as i32)
    .bind(now_secs)
    .fetch_all(pool)
    .await?;
    let mut candidates = Vec::with_capacity(rows.len());
    for row in rows {
        let community: String = row.try_get("community_id")?;
        let pubkey: Vec<u8> = row.try_get("pubkey")?;
        let created_at: i64 = row.try_get("created_at")?;
        let id: Vec<u8> = row.try_get("id")?;
        let event: nostr::Event = serde_json::from_str(row.try_get("event_json")?)?;
        candidates.push((
            community,
            pubkey,
            crate::event::extract_d_tag(&event)
                .unwrap_or_default()
                .to_owned(),
            created_at,
            id,
            row,
        ));
    }
    candidates.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| b.3.cmp(&a.3))
            .then_with(|| a.4.cmp(&b.4))
    });
    let mut seen_addresses = std::collections::HashSet::new();
    let mut results = Vec::new();
    for (community, pubkey, d_tag, created_at, id, row) in candidates {
        if !seen_addresses.insert((community.clone(), pubkey.clone(), d_tag)) {
            continue;
        }
        let channel_id: Option<String> = row.try_get("channel_id")?;
        results.push(crate::event::DueReminder {
            community_id: CommunityId::from_uuid(
                Uuid::parse_str(&community)
                    .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
            ),
            host: row.try_get("host")?,
            id,
            pubkey,
            created_at: chrono::DateTime::from_timestamp(created_at, 0)
                .ok_or(crate::DbError::InvalidTimestamp(created_at))?,
            kind: row.try_get("kind")?,
            tags: serde_json::from_str(row.try_get("tags_json")?)?,
            content: row.try_get("content")?,
            sig: row.try_get("sig")?,
            channel_id: channel_id
                .map(|id| {
                    Uuid::parse_str(&id).map_err(|e| crate::DbError::InvalidData(e.to_string()))
                })
                .transpose()?,
        });
        if results.len() >= batch_limit as usize {
            break;
        }
    }
    Ok(results)
}

pub(crate) async fn claim_due_reminder_with_stamp(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
    event_created_at: chrono::DateTime<chrono::Utc>,
    delivery_stamp: i64,
) -> Result<bool> {
    Ok(sqlx::query("UPDATE events SET delivered_at = ?1 WHERE community_id = ?2 AND created_at = ?3 AND id = ?4 AND delivered_at IS NULL")
        .bind(delivery_stamp)
        .bind(community.as_uuid().to_string())
        .bind(event_created_at.timestamp())
        .bind(event_id)
        .execute(pool)
        .await?
        .rows_affected() == 1)
}

pub(crate) async fn release_due_reminder(
    pool: &SqlitePool,
    community: CommunityId,
    event_id: &[u8],
    event_created_at: chrono::DateTime<chrono::Utc>,
    delivery_stamp: i64,
) -> Result<bool> {
    Ok(sqlx::query("UPDATE events SET delivered_at = NULL WHERE community_id = ?1 AND created_at = ?2 AND id = ?3 AND delivered_at = ?4")
        .bind(community.as_uuid().to_string())
        .bind(event_created_at.timestamp())
        .bind(event_id)
        .bind(delivery_stamp)
        .execute(pool)
        .await?
        .rows_affected() == 1)
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
    let inserted = sqlx::query("INSERT INTO channels (id, community_id, name, channel_type, visibility, participant_hash, created_by) VALUES (?1, ?2, ?3, 'dm', 'private', ?4, ?5) ON CONFLICT DO NOTHING")
        .bind(id.to_string()).bind(community.as_uuid().to_string()).bind(name).bind(hash.as_slice()).bind(created_by).execute(&mut *tx).await?.rows_affected() == 1;
    if !inserted {
        let row = sqlx::query(query)
            .bind(community.as_uuid().to_string())
            .bind(hash.as_slice())
            .fetch_one(&mut *tx)
            .await?;
        let record = channel_record(row)?;
        tx.commit().await?;
        return Ok(record);
    }
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

pub(crate) async fn hide_dm_command(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
    event: &nostr::Event,
) -> Result<Option<()>> {
    let mut tx = pool.begin().await?;
    if !insert_command_event_tx(&mut tx, community, event, None).await? {
        return Ok(None);
    }
    let result = sqlx::query("UPDATE channel_members SET hidden_at = unixepoch() WHERE channel_id = ?1 AND pubkey = ?2 AND removed_at IS NULL AND EXISTS (SELECT 1 FROM channels c WHERE c.id = channel_members.channel_id AND c.community_id = ?3)")
        .bind(channel_id.to_string())
        .bind(pubkey)
        .bind(community.as_uuid().to_string())
        .execute(&mut *tx)
        .await?;
    if result.rows_affected() == 0 {
        return Err(crate::DbError::NotFound(format!(
            "no active membership for channel {channel_id}"
        )));
    }
    tx.commit().await?;
    Ok(Some(()))
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

pub(crate) async fn create_api_token(
    pool: &SqlitePool,
    community_id: CommunityId,
    token_hash: &[u8],
    owner_pubkey: &[u8],
    name: &str,
    scopes: &[String],
    channel_ids: Option<&[Uuid]>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let scopes =
        serde_json::to_string(scopes).map_err(|e| crate::DbError::InvalidData(e.to_string()))?;
    let channel_ids = channel_ids
        .map(|ids| {
            serde_json::to_string(&ids.iter().map(Uuid::to_string).collect::<Vec<_>>())
                .map_err(|e| crate::DbError::InvalidData(format!("channel_ids serialization: {e}")))
        })
        .transpose()?;
    sqlx::query("INSERT INTO api_tokens (community_id, id, token_hash, owner_pubkey, name, scopes, channel_ids, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")
        .bind(community_id.as_uuid().to_string()).bind(id.to_string()).bind(token_hash).bind(owner_pubkey)
        .bind(name).bind(scopes).bind(channel_ids).bind(expires_at.map(|v| v.timestamp())).execute(pool).await?;
    Ok(id)
}

pub(crate) async fn create_api_token_if_under_limit(
    pool: &SqlitePool,
    community_id: CommunityId,
    token_hash: &[u8],
    owner_pubkey: &[u8],
    name: &str,
    scopes: &[String],
    channel_ids: Option<&[Uuid]>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Option<Uuid>> {
    let id = Uuid::new_v4();
    let scopes =
        serde_json::to_string(scopes).map_err(|e| crate::DbError::InvalidData(e.to_string()))?;
    let channel_ids = channel_ids
        .map(|ids| {
            serde_json::to_string(&ids.iter().map(Uuid::to_string).collect::<Vec<_>>())
                .map_err(|e| crate::DbError::InvalidData(format!("channel_ids serialization: {e}")))
        })
        .transpose()?;
    let result = sqlx::query("INSERT INTO api_tokens (community_id, id, token_hash, owner_pubkey, name, scopes, channel_ids, expires_at, created_by_self_mint) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1 WHERE (SELECT COUNT(*) FROM api_tokens WHERE community_id = ?1 AND owner_pubkey = ?9 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > unixepoch())) < 10")
        .bind(community_id.as_uuid().to_string()).bind(id.to_string()).bind(token_hash).bind(owner_pubkey).bind(name).bind(scopes).bind(channel_ids).bind(expires_at.map(|v| v.timestamp())).bind(owner_pubkey).execute(pool).await?;
    Ok((result.rows_affected() == 1).then_some(id))
}

pub(crate) async fn get_api_token_by_hash(
    pool: &SqlitePool,
    community_id: CommunityId,
    hash: &[u8],
    include_revoked: bool,
) -> Result<Option<crate::ApiTokenRecord>> {
    let query = if include_revoked {
        "SELECT id, token_hash, owner_pubkey, name, scopes, channel_ids, created_at, expires_at, last_used_at, revoked_at FROM api_tokens WHERE community_id = ?1 AND token_hash = ?2"
    } else {
        "SELECT id, token_hash, owner_pubkey, name, scopes, channel_ids, created_at, expires_at, last_used_at, revoked_at FROM api_tokens WHERE community_id = ?1 AND token_hash = ?2 AND revoked_at IS NULL"
    };
    let row = sqlx::query(query)
        .bind(community_id.as_uuid().to_string())
        .bind(hash)
        .fetch_optional(pool)
        .await?;
    row.map(api_token_record).transpose()
}

pub(crate) async fn touch_api_token(
    pool: &SqlitePool,
    community_id: CommunityId,
    hash: &[u8],
) -> Result<()> {
    sqlx::query("UPDATE api_tokens SET last_used_at = unixepoch() WHERE community_id = ?1 AND token_hash = ?2").bind(community_id.as_uuid().to_string()).bind(hash).execute(pool).await?;
    Ok(())
}

pub(crate) async fn list_active_tokens(
    pool: &SqlitePool,
    community_id: CommunityId,
) -> Result<Vec<crate::TokenSummary>> {
    let rows = sqlx::query("SELECT id, name, owner_pubkey, scopes, created_at, expires_at FROM api_tokens WHERE community_id = ?1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1000").bind(community_id.as_uuid().to_string()).fetch_all(pool).await?;
    rows.into_iter()
        .map(|row| {
            Ok(crate::TokenSummary {
                id: Uuid::parse_str(row.get::<String, _>("id").as_str())
                    .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
                name: row.get("name"),
                owner_pubkey: row.get("owner_pubkey"),
                scopes: serde_json::from_str(&row.get::<String, _>("scopes"))
                    .map_err(|e| crate::DbError::InvalidData(format!("scopes JSON: {e}")))?,
                created_at: timestamp(row.get("created_at"))?,
                expires_at: optional_timestamp(row.try_get("expires_at")?)?,
            })
        })
        .collect()
}

pub(crate) async fn list_tokens_by_owner(
    pool: &SqlitePool,
    community_id: CommunityId,
    owner: &[u8],
) -> Result<Vec<crate::ApiTokenRecord>> {
    let rows = sqlx::query("SELECT id, token_hash, owner_pubkey, name, scopes, channel_ids, created_at, expires_at, last_used_at, revoked_at FROM api_tokens WHERE community_id = ?1 AND owner_pubkey = ?2 ORDER BY created_at DESC").bind(community_id.as_uuid().to_string()).bind(owner).fetch_all(pool).await?;
    rows.into_iter().map(api_token_record).collect()
}

pub(crate) async fn revoke_token(
    pool: &SqlitePool,
    community_id: CommunityId,
    id: Uuid,
    owner: &[u8],
    revoked_by: &[u8],
) -> Result<bool> {
    Ok(sqlx::query("UPDATE api_tokens SET revoked_at = unixepoch(), revoked_by = ?1 WHERE community_id = ?2 AND id = ?3 AND owner_pubkey = ?4 AND revoked_at IS NULL").bind(revoked_by).bind(community_id.as_uuid().to_string()).bind(id.to_string()).bind(owner).execute(pool).await?.rows_affected() > 0)
}

pub(crate) async fn revoke_all_tokens(
    pool: &SqlitePool,
    community_id: CommunityId,
    owner: &[u8],
    revoked_by: &[u8],
) -> Result<u64> {
    Ok(sqlx::query("UPDATE api_tokens SET revoked_at = unixepoch(), revoked_by = ?1 WHERE community_id = ?2 AND owner_pubkey = ?3 AND revoked_at IS NULL").bind(revoked_by).bind(community_id.as_uuid().to_string()).bind(owner).execute(pool).await?.rows_affected())
}

fn api_token_record(row: sqlx::sqlite::SqliteRow) -> Result<crate::ApiTokenRecord> {
    let id = Uuid::parse_str(row.get::<String, _>("id").as_str())
        .map_err(|e| crate::DbError::InvalidData(e.to_string()))?;
    let channel_ids = row
        .try_get::<Option<String>, _>("channel_ids")?
        .map(|v| {
            let ids: Vec<String> = serde_json::from_str(&v)
                .map_err(|e| crate::DbError::InvalidData(format!("channel_ids JSON: {e}")))?;
            ids.into_iter()
                .map(|s| {
                    Uuid::parse_str(&s)
                        .map_err(|e| crate::DbError::InvalidData(format!("channel_ids UUID: {e}")))
                })
                .collect()
        })
        .transpose()?;
    Ok(crate::ApiTokenRecord {
        id,
        token_hash: row.get("token_hash"),
        owner_pubkey: row.get("owner_pubkey"),
        name: row.get("name"),
        scopes: serde_json::from_str(&row.get::<String, _>("scopes"))
            .map_err(|e| crate::DbError::InvalidData(format!("scopes JSON: {e}")))?,
        channel_ids,
        created_at: timestamp(row.get("created_at"))?,
        expires_at: optional_timestamp(row.try_get("expires_at")?)?,
        last_used_at: optional_timestamp(row.try_get("last_used_at")?)?,
        revoked_at: optional_timestamp(row.try_get("revoked_at")?)?,
    })
}
pub(crate) async fn mint_relay_invite(
    pool: &SqlitePool,
    community: CommunityId,
    created_by: &str,
    ttl_secs: u64,
    max_uses: Option<i32>,
) -> Result<crate::relay_invite::MintedInvite> {
    if !(buzz_core::invite::MIN_INVITE_TTL_SECS..=buzz_core::invite::MAX_INVITE_TTL_SECS)
        .contains(&ttl_secs)
        || max_uses.is_some_and(|n| !(1..=buzz_core::invite::MAX_INVITE_USES).contains(&n))
    {
        return Err(crate::DbError::InvalidData(
            "invalid relay invite parameters".into(),
        ));
    }
    let secret: [u8; buzz_core::invite::V2_SECRET_LEN] = rand::random();
    let code = buzz_core::invite::encode_v2_code(&secret);
    let hash = buzz_core::invite::hash_v2_code(&code);
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO relay_invites (community_id, id, token_hash, max_uses, expires_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
        .bind(community.as_uuid().to_string()).bind(id.to_string()).bind(hash.as_slice()).bind(max_uses).bind(expires_at.timestamp()).bind(created_by).execute(pool).await?;
    Ok(crate::relay_invite::MintedInvite {
        code,
        expires_at,
        max_uses,
        uses_remaining: max_uses,
        invite_id: id,
    })
}

pub(crate) async fn reap_expired_relay_invites(
    pool: &SqlitePool,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> Result<u64> {
    Ok(sqlx::query("DELETE FROM relay_invites WHERE rowid IN (SELECT rowid FROM relay_invites WHERE expires_at < ?1 ORDER BY expires_at LIMIT 1000)").bind(cutoff.timestamp()).execute(pool).await?.rows_affected())
}

pub(crate) async fn claim_relay_invite(
    pool: &SqlitePool,
    community: CommunityId,
    token_hash: &[u8; 32],
    claimer: &str,
    policy_version: Option<&str>,
) -> Result<crate::relay_invite::ClaimOutcome> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query("SELECT id, max_uses, use_count, expires_at FROM relay_invites WHERE community_id = ?1 AND token_hash = ?2")
        .bind(community.as_uuid().to_string()).bind(token_hash.as_slice()).fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(crate::relay_invite::ClaimOutcome::Invalid);
    };
    let id: String = row.get("id");
    let max_uses: Option<i32> = row.try_get("max_uses")?;
    let use_count: i32 = row.get("use_count");
    let expires_at: i64 = row.get("expires_at");
    if expires_at <= chrono::Utc::now().timestamp() {
        tx.rollback().await?;
        return Ok(crate::relay_invite::ClaimOutcome::Expired);
    }
    let remaining = || max_uses.map(|n| n - use_count);
    let existing =
        sqlx::query("SELECT 1 FROM relay_members WHERE community_id = ?1 AND pubkey = ?2")
            .bind(community.as_uuid().to_string())
            .bind(claimer)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
    if existing {
        if let Some(version) = policy_version {
            sqlx::query("INSERT INTO join_policy_acceptances (community_id, pubkey, policy_version) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING").bind(community.as_uuid().to_string()).bind(claimer).bind(version).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        return Ok(crate::relay_invite::ClaimOutcome::AlreadyMember {
            use_count,
            uses_remaining: remaining(),
        });
    }
    if max_uses.is_some_and(|n| use_count >= n) {
        tx.rollback().await?;
        return Ok(crate::relay_invite::ClaimOutcome::Exhausted);
    }
    let inserted = sqlx::query("INSERT INTO relay_members (community_id, pubkey, role, added_by) VALUES (?1, lower(?2), 'member', 'invite') ON CONFLICT DO NOTHING").bind(community.as_uuid().to_string()).bind(claimer).execute(&mut *tx).await?.rows_affected() > 0;
    if let Some(version) = policy_version {
        sqlx::query("INSERT INTO join_policy_acceptances (community_id, pubkey, policy_version) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING").bind(community.as_uuid().to_string()).bind(claimer).bind(version).execute(&mut *tx).await?;
    }
    if !inserted {
        tx.commit().await?;
        return Ok(crate::relay_invite::ClaimOutcome::AlreadyMember {
            use_count,
            uses_remaining: remaining(),
        });
    }
    let new_count = use_count + 1;
    sqlx::query("UPDATE relay_invites SET use_count = ?1 WHERE community_id = ?2 AND id = ?3")
        .bind(new_count)
        .bind(community.as_uuid().to_string())
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(crate::relay_invite::ClaimOutcome::Joined {
        use_count: new_count,
        uses_remaining: max_uses.map(|n| n - new_count),
    })
}
fn workflow_row(r: sqlx::sqlite::SqliteRow) -> Result<crate::workflow::WorkflowRecord> {
    Ok(crate::workflow::WorkflowRecord {
        id: parse_uuid(r.get("id"))?,
        community_id: CommunityId::from_uuid(parse_uuid(r.get("community_id"))?),
        name: r.get("name"),
        owner_pubkey: r.get("owner_pubkey"),
        channel_id: optional_uuid(r.try_get("channel_id")?)?,
        definition: serde_json::from_str(&r.get::<String, _>("definition"))
            .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
        definition_hash: r.get("definition_hash"),
        status: r.get::<String, _>("status").parse()?,
        enabled: r.get::<i64, _>("enabled") != 0,
        created_at: timestamp(r.get("created_at"))?,
        updated_at: timestamp(r.get("updated_at"))?,
    })
}
const WF_COLS:&str="id,community_id,name,owner_pubkey,channel_id,definition,definition_hash,status,enabled,created_at,updated_at";
pub(crate) async fn create_workflow(
    pool: &SqlitePool,
    c: CommunityId,
    ch: Option<Uuid>,
    owner: &[u8],
    name: &str,
    def: &str,
    hash: &[u8],
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO workflows(community_id,id,name,owner_pubkey,channel_id,definition,definition_hash) VALUES(?1,?2,?3,?4,?5,?6,?7)").bind(c.as_uuid().to_string()).bind(id.to_string()).bind(name).bind(owner).bind(ch.map(|v|v.to_string())).bind(def).bind(hash).execute(pool).await?;
    Ok(id)
}
pub(crate) async fn upsert_workflow(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
    ch: Option<Uuid>,
    owner: &[u8],
    name: &str,
    def: &str,
    hash: &[u8],
) -> Result<()> {
    let n=sqlx::query("INSERT INTO workflows(community_id,id,name,owner_pubkey,channel_id,definition,definition_hash) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(community_id,id) DO UPDATE SET name=excluded.name,definition=excluded.definition,definition_hash=excluded.definition_hash,updated_at=unixepoch() WHERE workflows.owner_pubkey=excluded.owner_pubkey AND workflows.channel_id IS excluded.channel_id").bind(c.as_uuid().to_string()).bind(id.to_string()).bind(name).bind(owner).bind(ch.map(|v|v.to_string())).bind(def).bind(hash).execute(pool).await?.rows_affected();
    if n == 0 {
        return Err(crate::DbError::AccessDenied(format!(
            "workflow {id} belongs to a different owner or channel"
        )));
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn upsert_workflow_command(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
    ch: Option<Uuid>,
    owner: &[u8],
    name: &str,
    def: &str,
    hash: &[u8],
    event: &nostr::Event,
    d_tag: &str,
) -> Result<Option<()>> {
    let mut tx = pool.begin().await?;
    if !replace_command_event_tx(&mut tx, c, event, ch, d_tag).await? {
        return Ok(None);
    }
    let n = sqlx::query("INSERT INTO workflows(community_id,id,name,owner_pubkey,channel_id,definition,definition_hash) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(community_id,id) DO UPDATE SET name=excluded.name,definition=excluded.definition,definition_hash=excluded.definition_hash,updated_at=unixepoch() WHERE workflows.owner_pubkey=excluded.owner_pubkey AND workflows.channel_id IS excluded.channel_id")
        .bind(c.as_uuid().to_string()).bind(id.to_string()).bind(name).bind(owner)
        .bind(ch.map(|v| v.to_string())).bind(def).bind(hash).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(crate::DbError::AccessDenied(format!(
            "workflow {id} belongs to a different owner or channel"
        )));
    }
    tx.commit().await?;
    Ok(Some(()))
}

pub(crate) async fn get_workflow(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
) -> Result<crate::workflow::WorkflowRecord> {
    let q = format!("SELECT {WF_COLS} FROM workflows WHERE community_id=?1 AND id=?2");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(c.as_uuid().to_string())
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| crate::DbError::NotFound(format!("workflow {id}")))
        .and_then(workflow_row)
}
pub(crate) async fn list_channel_workflows(
    pool: &SqlitePool,
    c: CommunityId,
    ch: Uuid,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<crate::workflow::WorkflowRecord>> {
    let q=format!("SELECT {WF_COLS} FROM workflows WHERE community_id=?1 AND channel_id=?2 ORDER BY created_at DESC,id DESC LIMIT ?3 OFFSET ?4");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(c.as_uuid().to_string())
        .bind(ch.to_string())
        .bind(
            limit
                .unwrap_or(crate::workflow::LIST_DEFAULT_LIMIT)
                .clamp(1, crate::workflow::LIST_MAX_LIMIT),
        )
        .bind(offset.unwrap_or(0).max(0))
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(workflow_row)
        .collect()
}
pub(crate) async fn list_enabled_channel_workflows(
    pool: &SqlitePool,
    c: CommunityId,
    ch: Uuid,
) -> Result<Vec<crate::workflow::WorkflowRecord>> {
    let q=format!("SELECT {WF_COLS} FROM workflows WHERE community_id=?1 AND channel_id=?2 AND status='active' AND enabled=1 ORDER BY created_at DESC,id DESC LIMIT ?3");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(c.as_uuid().to_string())
        .bind(ch.to_string())
        .bind(crate::workflow::LIST_MAX_LIMIT)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(workflow_row)
        .collect()
}
pub(crate) async fn list_all_enabled_workflows(
    pool: &SqlitePool,
) -> Result<Vec<crate::workflow::WorkflowRecord>> {
    let q="SELECT w.id,w.community_id,w.name,w.owner_pubkey,w.channel_id,w.definition,w.definition_hash,w.status,w.enabled,w.created_at,w.updated_at FROM workflows w JOIN communities c ON c.id=w.community_id WHERE w.status='active' AND w.enabled=1 AND json_extract(w.definition,'$.trigger.on')='schedule' AND c.archived_at IS NULL ORDER BY w.created_at,w.id LIMIT ?1";
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(crate::workflow::LIST_MAX_LIMIT)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(workflow_row)
        .collect()
}
pub(crate) async fn claim_scheduled_workflow_fire(
    pool: &SqlitePool,
    c: CommunityId,
    w: Uuid,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<crate::workflow::ScheduledWorkflowFireClaim>> {
    let n=sqlx::query("INSERT INTO scheduled_workflow_fires(community_id,workflow_id,scheduled_for) SELECT community_id,id,?3 FROM workflows WHERE community_id=?1 AND id=?2 ON CONFLICT DO NOTHING").bind(c.as_uuid().to_string()).bind(w.to_string()).bind(at.timestamp()).execute(pool).await?.rows_affected();
    if n == 0 {
        return Ok(None);
    };
    let claimed:i64=sqlx::query_scalar("SELECT claimed_at FROM scheduled_workflow_fires WHERE community_id=?1 AND workflow_id=?2 AND scheduled_for=?3").bind(c.as_uuid().to_string()).bind(w.to_string()).bind(at.timestamp()).fetch_one(pool).await?;
    Ok(Some(crate::workflow::ScheduledWorkflowFireClaim {
        community_id: c,
        workflow_id: w,
        scheduled_for: at,
        claimed_at: timestamp(claimed)?,
    }))
}
pub(crate) async fn latest_scheduled_workflow_fire(
    pool: &SqlitePool,
    c: CommunityId,
    w: Uuid,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    optional_timestamp(sqlx::query_scalar("SELECT MAX(scheduled_for) FROM scheduled_workflow_fires WHERE community_id=?1 AND workflow_id=?2").bind(c.as_uuid().to_string()).bind(w.to_string()).fetch_one(pool).await?)
}
pub(crate) async fn attach_scheduled_workflow_run(
    pool: &SqlitePool,
    c: CommunityId,
    w: Uuid,
    at: chrono::DateTime<chrono::Utc>,
    run: Uuid,
) -> Result<bool> {
    Ok(sqlx::query("UPDATE scheduled_workflow_fires SET workflow_run_id=?4 WHERE community_id=?1 AND workflow_id=?2 AND scheduled_for=?3 AND workflow_run_id IS NULL").bind(c.as_uuid().to_string()).bind(w.to_string()).bind(at.timestamp()).bind(run.to_string()).execute(pool).await?.rows_affected()==1)
}
pub(crate) async fn prune_scheduled_workflow_fires_before(
    pool: &SqlitePool,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<u64> {
    Ok(
        sqlx::query("DELETE FROM scheduled_workflow_fires WHERE claimed_at<?1")
            .bind(at.timestamp())
            .execute(pool)
            .await?
            .rows_affected(),
    )
}
async fn require_workflow_change(result: sqlx::sqlite::SqliteQueryResult, id: Uuid) -> Result<()> {
    if result.rows_affected() == 0 {
        Err(crate::DbError::NotFound(format!("workflow {id}")))
    } else {
        Ok(())
    }
}
pub(crate) async fn update_workflow(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
    name: &str,
    def: &str,
    hash: &[u8],
) -> Result<()> {
    require_workflow_change(sqlx::query("UPDATE workflows SET name=?1,definition=?2,definition_hash=?3,updated_at=unixepoch() WHERE community_id=?4 AND id=?5").bind(name).bind(def).bind(hash).bind(c.as_uuid().to_string()).bind(id.to_string()).execute(pool).await?,id).await
}
pub(crate) async fn update_workflow_status(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
    status: crate::workflow::WorkflowStatus,
) -> Result<()> {
    require_workflow_change(
        sqlx::query(
            "UPDATE workflows SET status=?1,updated_at=unixepoch() WHERE community_id=?2 AND id=?3",
        )
        .bind(status.to_string())
        .bind(c.as_uuid().to_string())
        .bind(id.to_string())
        .execute(pool)
        .await?,
        id,
    )
    .await
}
pub(crate) async fn set_workflow_enabled(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
    on: bool,
) -> Result<()> {
    require_workflow_change(sqlx::query("UPDATE workflows SET enabled=?1,updated_at=unixepoch() WHERE community_id=?2 AND id=?3").bind(on).bind(c.as_uuid().to_string()).bind(id.to_string()).execute(pool).await?,id).await
}
pub(crate) async fn disable_workflows_for_owner_in_channel(
    pool: &SqlitePool,
    c: CommunityId,
    ch: Uuid,
    owner: &[u8],
) -> Result<u64> {
    Ok(sqlx::query("UPDATE workflows SET enabled=0,updated_at=unixepoch() WHERE community_id=?1 AND channel_id=?2 AND owner_pubkey=?3 AND enabled=1").bind(c.as_uuid().to_string()).bind(ch.to_string()).bind(owner).execute(pool).await?.rows_affected())
}
pub(crate) async fn delete_workflow(pool: &SqlitePool, c: CommunityId, id: Uuid) -> Result<()> {
    require_workflow_change(
        sqlx::query("DELETE FROM workflows WHERE community_id=?1 AND id=?2")
            .bind(c.as_uuid().to_string())
            .bind(id.to_string())
            .execute(pool)
            .await?,
        id,
    )
    .await
}
pub(crate) async fn delete_workflow_for_owner(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
    owner: &[u8],
) -> Result<Option<Uuid>> {
    let row=sqlx::query("DELETE FROM workflows WHERE community_id=?1 AND id=?2 AND owner_pubkey=?3 RETURNING channel_id").bind(c.as_uuid().to_string()).bind(id.to_string()).bind(owner).fetch_optional(pool).await?.ok_or_else(||crate::DbError::NotFound(format!("workflow {id}")))?;
    optional_uuid(row.try_get("channel_id")?)
}
pub(crate) async fn find_workflow_by_owner_and_name(
    pool: &SqlitePool,
    c: CommunityId,
    owner: &[u8],
    name: &str,
) -> Result<Option<crate::workflow::WorkflowRecord>> {
    let q=format!("SELECT {WF_COLS} FROM workflows WHERE community_id=?1 AND owner_pubkey=?2 AND name=?3 LIMIT 1");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(c.as_uuid().to_string())
        .bind(owner)
        .bind(name)
        .fetch_optional(pool)
        .await?
        .map(workflow_row)
        .transpose()
}
fn run_row(r: sqlx::sqlite::SqliteRow) -> Result<crate::workflow::WorkflowRunRecord> {
    Ok(crate::workflow::WorkflowRunRecord {
        id: parse_uuid(r.get("id"))?,
        community_id: CommunityId::from_uuid(parse_uuid(r.get("community_id"))?),
        workflow_id: parse_uuid(r.get("workflow_id"))?,
        status: r.get::<String, _>("status").parse()?,
        trigger_event_id: r.get("trigger_event_id"),
        current_step: r.get::<i64, _>("current_step") as i32,
        execution_trace: serde_json::from_str(&r.get::<String, _>("execution_trace"))
            .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
        trigger_context: r
            .try_get::<Option<String>, _>("trigger_context")?
            .map(|v| {
                serde_json::from_str(&v).map_err(|e| crate::DbError::InvalidData(e.to_string()))
            })
            .transpose()?,
        started_at: optional_timestamp(r.try_get("started_at")?)?,
        completed_at: optional_timestamp(r.try_get("completed_at")?)?,
        error_message: r.get("error_message"),
        created_at: timestamp(r.get("created_at"))?,
    })
}
const RUN_COLS:&str="community_id,id,workflow_id,status,trigger_event_id,current_step,execution_trace,trigger_context,started_at,completed_at,error_message,created_at";
pub(crate) async fn create_workflow_run(
    pool: &SqlitePool,
    c: CommunityId,
    w: Uuid,
    event: Option<&[u8]>,
    ctx: Option<&serde_json::Value>,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO workflow_runs(community_id,id,workflow_id,trigger_event_id,trigger_context) VALUES(?1,?2,?3,?4,?5)").bind(c.as_uuid().to_string()).bind(id.to_string()).bind(w.to_string()).bind(event).bind(ctx.map(|v|v.to_string())).execute(pool).await?;
    Ok(id)
}
pub(crate) async fn create_workflow_run_command(
    pool: &SqlitePool,
    c: CommunityId,
    w: Uuid,
    trigger_event_id: &[u8],
    ctx: Option<&serde_json::Value>,
    channel_id: Option<Uuid>,
    event: &nostr::Event,
) -> Result<Option<Uuid>> {
    let mut tx = pool.begin().await?;
    if !insert_command_event_tx(&mut tx, c, event, channel_id).await? {
        return Ok(None);
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO workflow_runs(community_id,id,workflow_id,trigger_event_id,trigger_context) VALUES(?1,?2,?3,?4,?5)")
        .bind(c.as_uuid().to_string()).bind(id.to_string()).bind(w.to_string())
        .bind(trigger_event_id).bind(ctx.map(|v| v.to_string())).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Some(id))
}

pub(crate) async fn get_workflow_run(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
) -> Result<crate::workflow::WorkflowRunRecord> {
    let q = format!("SELECT {RUN_COLS} FROM workflow_runs WHERE community_id=?1 AND id=?2");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(c.as_uuid().to_string())
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| crate::DbError::NotFound(format!("workflow_run {id}")))
        .and_then(run_row)
}
pub(crate) async fn list_workflow_runs(
    pool: &SqlitePool,
    c: CommunityId,
    w: Uuid,
    limit: i64,
) -> Result<Vec<crate::workflow::WorkflowRunRecord>> {
    let q=format!("SELECT {RUN_COLS} FROM workflow_runs WHERE community_id=?1 AND workflow_id=?2 ORDER BY created_at DESC,id DESC LIMIT ?3");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(c.as_uuid().to_string())
        .bind(w.to_string())
        .bind(limit.min(1000))
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(run_row)
        .collect()
}
pub(crate) async fn update_workflow_run(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
    status: crate::workflow::RunStatus,
    step: i32,
    trace: &serde_json::Value,
    error: Option<&str>,
) -> Result<()> {
    let st = status.to_string();
    let n=sqlx::query("UPDATE workflow_runs SET status=?1,current_step=?2,execution_trace=?3,error_message=?4,started_at=CASE WHEN ?1='running' AND started_at IS NULL THEN unixepoch() ELSE started_at END,completed_at=CASE WHEN ?1 IN ('completed','failed','cancelled') THEN unixepoch() ELSE completed_at END WHERE community_id=?5 AND id=?6").bind(st).bind(step).bind(trace.to_string()).bind(error).bind(c.as_uuid().to_string()).bind(id.to_string()).execute(pool).await?.rows_affected();
    if n == 0 {
        Err(crate::DbError::NotFound(format!("workflow_run {id}")))
    } else {
        Ok(())
    }
}
fn approval_row(r: sqlx::sqlite::SqliteRow) -> Result<crate::workflow::ApprovalRecord> {
    Ok(crate::workflow::ApprovalRecord {
        token: r.get("token"),
        workflow_id: parse_uuid(r.get("workflow_id"))?,
        run_id: parse_uuid(r.get("run_id"))?,
        step_id: r.get("step_id"),
        step_index: r.get::<i64, _>("step_index") as i32,
        approver_spec: r.get("approver_spec"),
        status: r.get::<String, _>("status").parse()?,
        approver_pubkey: r.get("approver_pubkey"),
        note: r.get("note"),
        expires_at: timestamp(r.get("expires_at"))?,
        created_at: timestamp(r.get("created_at"))?,
    })
}
const APPROVAL_COLS:&str="token,workflow_id,run_id,step_id,step_index,approver_spec,status,approver_pubkey,note,expires_at,created_at";
pub(crate) async fn create_approval(
    pool: &SqlitePool,
    p: crate::workflow::CreateApprovalParams<'_>,
) -> Result<()> {
    let token = Sha256::digest(p.token.as_bytes()).to_vec();
    sqlx::query("INSERT INTO workflow_approvals(community_id,token,workflow_id,run_id,step_id,step_index,approver_spec,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)").bind(p.community_id.as_uuid().to_string()).bind(token).bind(p.workflow_id.to_string()).bind(p.run_id.to_string()).bind(p.step_id).bind(p.step_index).bind(p.approver_spec).bind(p.expires_at.timestamp()).execute(pool).await?;
    Ok(())
}
pub(crate) async fn get_approval(
    pool: &SqlitePool,
    c: CommunityId,
    token: &str,
) -> Result<crate::workflow::ApprovalRecord> {
    get_approval_by_hash(pool, c, &Sha256::digest(token.as_bytes())).await
}
pub(crate) async fn get_approval_by_hash(
    pool: &SqlitePool,
    c: CommunityId,
    hash: &[u8],
) -> Result<crate::workflow::ApprovalRecord> {
    let q = format!(
        "SELECT {APPROVAL_COLS} FROM workflow_approvals WHERE community_id=?1 AND token=?2"
    );
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(c.as_uuid().to_string())
        .bind(hash)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| crate::DbError::NotFound("approval token (hashed)".into()))
        .and_then(approval_row)
}
pub(crate) async fn get_run_approvals(
    pool: &SqlitePool,
    c: CommunityId,
    w: Uuid,
    run: Uuid,
) -> Result<Vec<crate::workflow::ApprovalRecord>> {
    let q=format!("SELECT {APPROVAL_COLS} FROM workflow_approvals WHERE community_id=?1 AND run_id=?2 AND workflow_id=?3 ORDER BY step_index,created_at");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(c.as_uuid().to_string())
        .bind(run.to_string())
        .bind(w.to_string())
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(approval_row)
        .collect()
}
pub(crate) async fn update_approval(
    pool: &SqlitePool,
    c: CommunityId,
    token: &str,
    status: crate::workflow::ApprovalStatus,
    pk: Option<&[u8]>,
    note: Option<&str>,
) -> Result<bool> {
    update_approval_by_hash(pool, c, &Sha256::digest(token.as_bytes()), status, pk, note).await
}
pub(crate) async fn update_approval_by_hash(
    pool: &SqlitePool,
    c: CommunityId,
    hash: &[u8],
    status: crate::workflow::ApprovalStatus,
    pk: Option<&[u8]>,
    note: Option<&str>,
) -> Result<bool> {
    let st = status.to_string();
    Ok(sqlx::query("UPDATE workflow_approvals SET status=?1,approver_pubkey=?2,note=?3,granted_at=CASE WHEN ?1='granted' THEN unixepoch() ELSE granted_at END,denied_at=CASE WHEN ?1='denied' THEN unixepoch() ELSE denied_at END WHERE community_id=?4 AND token=?5 AND status='pending'").bind(st).bind(pk).bind(note).bind(c.as_uuid().to_string()).bind(hash).execute(pool).await?.rows_affected()>0)
}

pub(crate) async fn update_approval_command(
    pool: &SqlitePool,
    c: CommunityId,
    hash: &[u8],
    status: crate::workflow::ApprovalStatus,
    pk: Option<&[u8]>,
    note: Option<&str>,
    event: &nostr::Event,
) -> Result<Option<bool>> {
    let mut tx = pool.begin().await?;
    if !insert_command_event_tx(&mut tx, c, event, None).await? {
        return Ok(None);
    }
    let st = status.to_string();
    let updated = sqlx::query("UPDATE workflow_approvals SET status=?1,approver_pubkey=?2,note=?3,granted_at=CASE WHEN ?1='granted' THEN unixepoch() ELSE granted_at END,denied_at=CASE WHEN ?1='denied' THEN unixepoch() ELSE denied_at END WHERE community_id=?4 AND token=?5 AND status='pending'")
        .bind(st).bind(pk).bind(note).bind(c.as_uuid().to_string()).bind(hash)
        .execute(&mut *tx).await?.rows_affected() > 0;
    if updated {
        tx.commit().await?;
    }
    Ok(Some(updated))
}

pub(crate) async fn insert_product_feedback(
    pool: &SqlitePool,
    community: CommunityId,
    feedback: crate::product_feedback::NewProductFeedback<'_>,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO product_feedback (id, community_id, event_id, submitter_pubkey, category, body, tags, event_created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(event_id) DO UPDATE SET event_id = excluded.event_id")
        .bind(id.to_string()).bind(community.as_uuid().to_string()).bind(feedback.event_id).bind(feedback.submitter_pubkey).bind(feedback.category).bind(feedback.body).bind(feedback.tags.to_string()).bind(feedback.event_created_at.timestamp()).execute(pool).await?;
    Ok(
        sqlx::query_scalar::<_, String>("SELECT id FROM product_feedback WHERE event_id = ?1")
            .bind(feedback.event_id)
            .fetch_one(pool)
            .await?
            .parse::<Uuid>()
            .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
    )
}

pub(crate) async fn list_product_feedback(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<crate::product_feedback::ProductFeedbackRecord>> {
    let rows = sqlx::query("SELECT id, community_id, event_id, submitter_pubkey, category, body, tags, event_created_at, received_at FROM product_feedback ORDER BY received_at DESC, id LIMIT ?1").bind(limit).fetch_all(pool).await?;
    rows.into_iter()
        .map(|r| {
            Ok(crate::product_feedback::ProductFeedbackRecord {
                id: r
                    .get::<String, _>("id")
                    .parse::<Uuid>()
                    .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
                community_id: r
                    .get::<String, _>("community_id")
                    .parse::<Uuid>()
                    .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
                event_id: hex::encode(r.get::<Vec<u8>, _>("event_id")),
                submitter_pubkey: hex::encode(r.get::<Vec<u8>, _>("submitter_pubkey")),
                category: r.get("category"),
                body: r.get("body"),
                tags: serde_json::from_str(&r.get::<String, _>("tags"))
                    .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
                event_created_at: timestamp(r.get("event_created_at"))?,
                received_at: timestamp(r.get("received_at"))?,
            })
        })
        .collect()
}

fn moderation_report_row(r: sqlx::sqlite::SqliteRow) -> Result<crate::moderation::ReportRecord> {
    let target = match r.get::<String, _>("target_kind").as_str() {
        "event" => crate::moderation::ReportTarget::Event(r.get("target_event_id")),
        "pubkey" => crate::moderation::ReportTarget::Pubkey(r.get("target_pubkey")),
        "blob" => crate::moderation::ReportTarget::Blob(r.get("target_blob_sha256")),
        other => {
            return Err(crate::DbError::InvalidData(format!(
                "invalid report target_kind: {other}"
            )))
        }
    };
    Ok(crate::moderation::ReportRecord {
        id: parse_uuid(r.get("id"))?,
        report_event_id: r.get("report_event_id"),
        reporter_pubkey: r.get("reporter_pubkey"),
        target,
        channel_id: optional_uuid(r.try_get("channel_id")?)?,
        report_type: r.get("report_type"),
        note: r.get("note"),
        status: r.get("status"),
        resolved_by: r.get("resolved_by"),
        resolved_at: optional_timestamp(r.try_get("resolved_at")?)?,
        action_id: optional_uuid(r.try_get("action_id")?)?,
        created_at: timestamp(r.get("created_at"))?,
    })
}

fn parse_uuid(value: String) -> Result<Uuid> {
    Uuid::parse_str(&value).map_err(|e| crate::DbError::InvalidData(e.to_string()))
}
fn optional_uuid(value: Option<String>) -> Result<Option<Uuid>> {
    value.map(parse_uuid).transpose()
}

pub(crate) async fn insert_moderation_report(
    pool: &SqlitePool,
    community: CommunityId,
    report: crate::moderation::NewReport<'_>,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let (kind, event, pubkey, blob) = match &report.target {
        crate::moderation::ReportTarget::Event(v) => ("event", Some(v.as_slice()), None, None),
        crate::moderation::ReportTarget::Pubkey(v) => ("pubkey", None, Some(v.as_slice()), None),
        crate::moderation::ReportTarget::Blob(v) => ("blob", None, None, Some(v.as_slice())),
    };
    sqlx::query("INSERT INTO moderation_reports (id, community_id, report_event_id, reporter_pubkey, target_kind, target_event_id, target_pubkey, target_blob_sha256, channel_id, report_type, note) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) ON CONFLICT(community_id, report_event_id) DO NOTHING")
        .bind(id.to_string()).bind(community.as_uuid().to_string()).bind(report.report_event_id).bind(report.reporter_pubkey).bind(kind).bind(event).bind(pubkey).bind(blob).bind(report.channel_id.map(|v| v.to_string())).bind(report.report_type).bind(report.note).execute(pool).await?;
    parse_uuid(
        sqlx::query_scalar(
            "SELECT id FROM moderation_reports WHERE community_id=?1 AND report_event_id=?2",
        )
        .bind(community.as_uuid().to_string())
        .bind(report.report_event_id)
        .fetch_one(pool)
        .await?,
    )
}

const REPORT_COLUMNS: &str = "id, report_event_id, reporter_pubkey, target_kind, target_event_id, target_pubkey, target_blob_sha256, channel_id, report_type, note, status, resolved_by, resolved_at, action_id, created_at";
pub(crate) async fn list_moderation_reports(
    pool: &SqlitePool,
    community: CommunityId,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<crate::moderation::ReportRecord>> {
    let q = format!("SELECT {REPORT_COLUMNS} FROM moderation_reports WHERE community_id=?1 AND (?2 IS NULL OR status=?2) ORDER BY created_at DESC, id DESC LIMIT ?3");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(community.as_uuid().to_string())
        .bind(status)
        .bind(limit)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(moderation_report_row)
        .collect()
}
pub(crate) async fn get_moderation_report(
    pool: &SqlitePool,
    community: CommunityId,
    id: Uuid,
) -> Result<Option<crate::moderation::ReportRecord>> {
    let q =
        format!("SELECT {REPORT_COLUMNS} FROM moderation_reports WHERE community_id=?1 AND id=?2");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(community.as_uuid().to_string())
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?
        .map(moderation_report_row)
        .transpose()
}
pub(crate) async fn get_moderation_report_by_event(
    pool: &SqlitePool,
    community: CommunityId,
    event: &[u8],
) -> Result<Option<crate::moderation::ReportRecord>> {
    let q=format!("SELECT {REPORT_COLUMNS} FROM moderation_reports WHERE community_id=?1 AND report_event_id=?2");
    sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(community.as_uuid().to_string())
        .bind(event)
        .fetch_optional(pool)
        .await?
        .map(moderation_report_row)
        .transpose()
}
pub(crate) async fn resolve_moderation_report(
    pool: &SqlitePool,
    community: CommunityId,
    id: Uuid,
    status: &str,
    actor: &[u8],
    action_id: Option<Uuid>,
) -> Result<bool> {
    Ok(sqlx::query("UPDATE moderation_reports SET status=?3,resolved_by=?4,resolved_at=unixepoch(),action_id=?5 WHERE community_id=?1 AND id=?2 AND status='open'").bind(community.as_uuid().to_string()).bind(id.to_string()).bind(status).bind(actor).bind(action_id.map(|v|v.to_string())).execute(pool).await?.rows_affected()>0)
}
pub(crate) async fn ban_member(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
    actor: &[u8],
    reason: Option<&str>,
    expires: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<()> {
    sqlx::query("INSERT INTO community_bans (community_id,pubkey,banned,ban_expires_at,ban_reason,actor_pubkey) VALUES (?1,?2,1,?3,?4,?5) ON CONFLICT(community_id,pubkey) DO UPDATE SET banned=1,ban_expires_at=excluded.ban_expires_at,ban_reason=excluded.ban_reason,actor_pubkey=excluded.actor_pubkey,updated_at=unixepoch()").bind(community.as_uuid().to_string()).bind(pubkey).bind(expires.map(|v|v.timestamp())).bind(reason).bind(actor).execute(pool).await?;
    Ok(())
}
pub(crate) async fn unban_member(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
    actor: &[u8],
) -> Result<bool> {
    Ok(sqlx::query("UPDATE community_bans SET banned=0,ban_expires_at=NULL,ban_reason=NULL,actor_pubkey=?3,updated_at=unixepoch() WHERE community_id=?1 AND pubkey=?2 AND banned=1").bind(community.as_uuid().to_string()).bind(pubkey).bind(actor).execute(pool).await?.rows_affected()>0)
}
pub(crate) async fn timeout_member(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
    actor: &[u8],
    until: chrono::DateTime<chrono::Utc>,
    reason: Option<&str>,
) -> Result<()> {
    sqlx::query("INSERT INTO community_bans (community_id,pubkey,muted_until,mute_reason,actor_pubkey) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(community_id,pubkey) DO UPDATE SET muted_until=excluded.muted_until,mute_reason=excluded.mute_reason,actor_pubkey=excluded.actor_pubkey,updated_at=unixepoch()").bind(community.as_uuid().to_string()).bind(pubkey).bind(until.timestamp()).bind(reason).bind(actor).execute(pool).await?;
    Ok(())
}
pub(crate) async fn untimeout_member(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
    actor: &[u8],
) -> Result<bool> {
    Ok(sqlx::query("UPDATE community_bans SET muted_until=NULL,mute_reason=NULL,actor_pubkey=?3,updated_at=unixepoch() WHERE community_id=?1 AND pubkey=?2 AND muted_until>unixepoch()").bind(community.as_uuid().to_string()).bind(pubkey).bind(actor).execute(pool).await?.rows_affected()>0)
}
pub(crate) async fn restriction_state(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
) -> Result<crate::moderation::RestrictionState> {
    let row=sqlx::query("SELECT banned AND (ban_expires_at IS NULL OR ban_expires_at>unixepoch()) AS banned, CASE WHEN muted_until>unixepoch() THEN muted_until END AS muted_until FROM community_bans WHERE community_id=?1 AND pubkey=?2").bind(community.as_uuid().to_string()).bind(pubkey).fetch_optional(pool).await?;
    Ok(match row {
        Some(r) => crate::moderation::RestrictionState {
            banned: r.get::<i64, _>("banned") != 0,
            muted_until: optional_timestamp(r.try_get("muted_until")?)?,
        },
        None => Default::default(),
    })
}
fn ban_row(r: sqlx::sqlite::SqliteRow) -> Result<crate::moderation::BanRecord> {
    Ok(crate::moderation::BanRecord {
        pubkey: r.get("pubkey"),
        banned: r.get::<i64, _>("banned") != 0,
        ban_expires_at: optional_timestamp(r.try_get("ban_expires_at")?)?,
        ban_reason: r.get("ban_reason"),
        muted_until: optional_timestamp(r.try_get("muted_until")?)?,
        mute_reason: r.get("mute_reason"),
        actor_pubkey: r.get("actor_pubkey"),
        updated_at: timestamp(r.get("updated_at"))?,
    })
}
pub(crate) async fn get_ban(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
) -> Result<Option<crate::moderation::BanRecord>> {
    sqlx::query("SELECT pubkey,banned AND (ban_expires_at IS NULL OR ban_expires_at>unixepoch()) AS banned,ban_expires_at,ban_reason,muted_until,mute_reason,actor_pubkey,updated_at FROM community_bans WHERE community_id=?1 AND pubkey=?2").bind(community.as_uuid().to_string()).bind(pubkey).fetch_optional(pool).await?.map(ban_row).transpose()
}
pub(crate) async fn list_restricted(
    pool: &SqlitePool,
    community: CommunityId,
) -> Result<Vec<crate::moderation::BanRecord>> {
    sqlx::query("SELECT pubkey,banned AND (ban_expires_at IS NULL OR ban_expires_at>unixepoch()) AS banned,ban_expires_at,ban_reason,muted_until,mute_reason,actor_pubkey,updated_at FROM community_bans WHERE community_id=?1 AND ((banned=1 AND (ban_expires_at IS NULL OR ban_expires_at>unixepoch())) OR muted_until>unixepoch()) ORDER BY updated_at DESC,pubkey").bind(community.as_uuid().to_string()).fetch_all(pool).await?.into_iter().map(ban_row).collect()
}
pub(crate) async fn insert_moderation_action(
    pool: &SqlitePool,
    community: CommunityId,
    a: crate::moderation::NewAction<'_>,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO moderation_actions (community_id,id,actor_pubkey,action,target_pubkey,target_event_id,channel_id,reason_code,public_reason,private_reason,matched_principal) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)").bind(community.as_uuid().to_string()).bind(id.to_string()).bind(a.actor_pubkey).bind(a.action).bind(a.target_pubkey).bind(a.target_event_id).bind(a.channel_id.map(|v|v.to_string())).bind(a.reason_code).bind(a.public_reason).bind(a.private_reason).bind(a.matched_principal).execute(pool).await?;
    Ok(id)
}
fn action_row(r: sqlx::sqlite::SqliteRow) -> Result<crate::moderation::ActionRecord> {
    Ok(crate::moderation::ActionRecord {
        id: parse_uuid(r.get("id"))?,
        actor_pubkey: r.get("actor_pubkey"),
        action: r.get("action"),
        target_pubkey: r.get("target_pubkey"),
        target_event_id: r.get("target_event_id"),
        channel_id: optional_uuid(r.try_get("channel_id")?)?,
        reason_code: r.get("reason_code"),
        public_reason: r.get("public_reason"),
        private_reason: r.get("private_reason"),
        matched_principal: r.get("matched_principal"),
        created_at: timestamp(r.get("created_at"))?,
    })
}
pub(crate) async fn list_moderation_actions(
    pool: &SqlitePool,
    community: CommunityId,
    limit: i64,
) -> Result<Vec<crate::moderation::ActionRecord>> {
    sqlx::query("SELECT id,actor_pubkey,action,target_pubkey,target_event_id,channel_id,reason_code,public_reason,private_reason,matched_principal,created_at FROM moderation_actions WHERE community_id=?1 ORDER BY created_at DESC,id DESC LIMIT ?2").bind(community.as_uuid().to_string()).bind(limit).fetch_all(pool).await?.into_iter().map(action_row).collect()
}

pub(crate) async fn admin_list_feedback(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<crate::admin_moderation::AdminFeedback>> {
    let rows = sqlx::query("SELECT f.id, f.community_id, c.host AS community_host, f.event_id, f.submitter_pubkey, f.category, f.body, f.tags, f.event_created_at, f.received_at FROM product_feedback f JOIN communities c ON c.id=f.community_id ORDER BY f.received_at DESC, f.id DESC LIMIT ?1").bind(limit.clamp(1, 200)).fetch_all(pool).await?;
    rows.into_iter().map(admin_feedback_row).collect()
}

fn admin_feedback_row(
    r: sqlx::sqlite::SqliteRow,
) -> Result<crate::admin_moderation::AdminFeedback> {
    Ok(crate::admin_moderation::AdminFeedback {
        id: r
            .get::<String, _>("id")
            .parse::<Uuid>()
            .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
        community_id: r
            .get::<String, _>("community_id")
            .parse::<Uuid>()
            .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
        community_host: r.get("community_host"),
        event_id: hex::encode(r.get::<Vec<u8>, _>("event_id")),
        submitter_pubkey: hex::encode(r.get::<Vec<u8>, _>("submitter_pubkey")),
        category: r.get("category"),
        body: r.get("body"),
        tags: serde_json::from_str(&r.get::<String, _>("tags"))
            .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
        event_created_at: timestamp(r.get("event_created_at"))?,
        received_at: timestamp(r.get("received_at"))?,
    })
}

pub(crate) async fn admin_get_feedback(
    pool: &SqlitePool,
    id: Uuid,
) -> Result<Option<crate::admin_moderation::AdminFeedback>> {
    sqlx::query("SELECT f.id, f.community_id, c.host AS community_host, f.event_id, f.submitter_pubkey, f.category, f.body, f.tags, f.event_created_at, f.received_at FROM product_feedback f JOIN communities c ON c.id=f.community_id WHERE f.id=?1").bind(id.to_string()).fetch_optional(pool).await?.map(admin_feedback_row).transpose()
}
pub(crate) async fn admin_list_reports(
    pool: &SqlitePool,
    community_id: Option<Uuid>,
    status: Option<&str>,
    report_type: Option<&str>,
    target_kind: Option<&str>,
    after: Option<chrono::DateTime<chrono::Utc>>,
    before: Option<chrono::DateTime<chrono::Utc>>,
    cursor: Option<(chrono::DateTime<chrono::Utc>, Uuid)>,
    limit: i64,
) -> Result<Vec<crate::admin_moderation::AdminReport>> {
    let (cursor_time, cursor_id) = cursor.map_or((None, None), |(t, id)| {
        (Some(t.timestamp()), Some(id.to_string()))
    });
    let rows = sqlx::query("SELECT r.id, r.community_id, c.host AS community_host, r.report_event_id, r.reporter_pubkey, r.target_kind, r.target_event_id, r.target_pubkey, r.target_blob_sha256, r.channel_id, r.report_type, r.note, r.status, r.resolved_by, r.resolved_at, r.action_id, r.created_at FROM moderation_reports r JOIN communities c ON c.id=r.community_id WHERE (?1 IS NULL OR r.community_id=?1) AND (?2 IS NULL OR r.status=?2) AND (?3 IS NULL OR r.report_type=?3) AND (?4 IS NULL OR r.target_kind=?4) AND (?5 IS NULL OR r.created_at>=?5) AND (?6 IS NULL OR r.created_at<?6) AND (?7 IS NULL OR r.created_at<?7 OR (r.created_at=?7 AND r.id<?8)) ORDER BY r.created_at DESC, r.id DESC LIMIT ?9").bind(community_id.map(|v| v.to_string())).bind(status).bind(report_type).bind(target_kind).bind(after.map(|v| v.timestamp())).bind(before.map(|v| v.timestamp())).bind(cursor_time).bind(cursor_id).bind(limit.clamp(1, 200)).fetch_all(pool).await?;
    rows.into_iter().map(|r| admin_report_row(&r)).collect()
}

fn admin_report_row(r: &sqlx::sqlite::SqliteRow) -> Result<crate::admin_moderation::AdminReport> {
    let kind: String = r.get("target_kind");
    let target = match kind.as_str() {
        "event" => r
            .try_get::<Option<Vec<u8>>, _>("target_event_id")?
            .unwrap_or_default(),
        "pubkey" => r
            .try_get::<Option<Vec<u8>>, _>("target_pubkey")?
            .unwrap_or_default(),
        "blob" => r
            .try_get::<Option<Vec<u8>>, _>("target_blob_sha256")?
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    Ok(crate::admin_moderation::AdminReport {
        id: r
            .get::<String, _>("id")
            .parse::<Uuid>()
            .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
        community_id: r
            .get::<String, _>("community_id")
            .parse::<Uuid>()
            .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
        community_host: r.get("community_host"),
        report_event_id: hex::encode(r.get::<Vec<u8>, _>("report_event_id")),
        reporter_pubkey: hex::encode(r.get::<Vec<u8>, _>("reporter_pubkey")),
        target_kind: kind,
        target: hex::encode(target),
        channel_id: r
            .try_get::<Option<String>, _>("channel_id")?
            .map(|value| {
                Uuid::parse_str(&value)
                    .map_err(|error| crate::DbError::InvalidData(error.to_string()))
            })
            .transpose()?,
        report_type: r.get("report_type"),
        note: r.get("note"),
        status: r.get("status"),
        resolved_by: r
            .try_get::<Option<Vec<u8>>, _>("resolved_by")?
            .map(hex::encode),
        resolved_at: optional_timestamp(r.try_get("resolved_at")?)?,
        action_id: r
            .try_get::<Option<String>, _>("action_id")?
            .map(|value| {
                Uuid::parse_str(&value)
                    .map_err(|error| crate::DbError::InvalidData(error.to_string()))
            })
            .transpose()?,
        created_at: timestamp(r.get("created_at"))?,
    })
}

pub(crate) async fn admin_get_report(
    pool: &SqlitePool,
    id: Uuid,
) -> Result<Option<crate::admin_moderation::AdminReportDetail>> {
    let row = sqlx::query("SELECT r.id, r.community_id, c.host AS community_host, r.report_event_id, r.reporter_pubkey, r.target_kind, r.target_event_id, r.target_pubkey, r.target_blob_sha256, r.channel_id, r.report_type, r.note, r.status, r.resolved_by, r.resolved_at, r.action_id, r.created_at, e.pubkey AS message_author_pubkey, e.content AS message_content, e.created_at AS message_created_at FROM moderation_reports r JOIN communities c ON c.id=r.community_id LEFT JOIN events e ON r.target_kind='event' AND e.community_id=r.community_id AND e.id=r.target_event_id WHERE r.id=?1").bind(id.to_string()).fetch_optional(pool).await?;
    row.map(|r| {
        let report = admin_report_row(&r)?;
        let message = r
            .try_get::<Option<Vec<u8>>, _>("message_author_pubkey")?
            .map(
                |author| -> Result<crate::admin_moderation::AdminReportedMessage> {
                    Ok(crate::admin_moderation::AdminReportedMessage {
                        author_pubkey: hex::encode(author),
                        content: r.get("message_content"),
                        created_at: timestamp(r.get("message_created_at"))?,
                        deleted_at: None,
                    })
                },
            )
            .transpose()?;
        Ok(crate::admin_moderation::AdminReportDetail { report, message })
    })
    .transpose()
}
pub(crate) async fn repo_name_owner(
    pool: &SqlitePool,
    community: CommunityId,
    repo_id: &str,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT owner_pubkey FROM git_repo_names WHERE community_id = ?1 AND repo_id = ?2",
    )
    .bind(community.as_uuid().to_string())
    .bind(repo_id)
    .fetch_optional(pool)
    .await?)
}

pub(crate) async fn reserve_repo_name(
    pool: &SqlitePool,
    community: CommunityId,
    repo_id: &str,
    owner_pubkey: &str,
) -> Result<crate::git_repo::ReserveOutcome> {
    let inserted = sqlx::query("INSERT INTO git_repo_names (community_id,repo_id,owner_pubkey) VALUES (?1,?2,?3) ON CONFLICT (community_id,repo_id) DO NOTHING")
        .bind(community.as_uuid().to_string()).bind(repo_id).bind(owner_pubkey).execute(pool).await?.rows_affected();
    if inserted != 0 {
        return Ok(crate::git_repo::ReserveOutcome::Reserved);
    }
    match repo_name_owner(pool, community, repo_id).await? {
        Some(holder) if holder == owner_pubkey => Ok(crate::git_repo::ReserveOutcome::AlreadyOwned),
        _ => Ok(crate::git_repo::ReserveOutcome::TakenByOther),
    }
}

pub(crate) async fn count_repos_for_owner(
    pool: &SqlitePool,
    community: CommunityId,
    owner_pubkey: &str,
) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM git_repo_names WHERE community_id = ?1 AND owner_pubkey = ?2",
    )
    .bind(community.as_uuid().to_string())
    .bind(owner_pubkey)
    .fetch_one(pool)
    .await?)
}

pub(crate) async fn release_repo_name(
    pool: &SqlitePool,
    community: CommunityId,
    repo_id: &str,
    owner_pubkey: &str,
) -> Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM git_repo_names WHERE community_id = ?1 AND repo_id = ?2 AND owner_pubkey = ?3",
    )
    .bind(community.as_uuid().to_string())
    .bind(repo_id)
    .bind(owner_pubkey)
    .execute(pool)
    .await?
    .rows_affected())
}

pub(crate) async fn is_archived(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM archived_identities WHERE community_id = ?1 AND pubkey = ?2)",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .fetch_one(pool)
    .await?
        != 0)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn archive(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &str,
    consent_path: &str,
    actor: &str,
    reason: Option<&str>,
    replaced_by: Option<&str>,
    request_event_id: &str,
) -> Result<bool> {
    Ok(sqlx::query("INSERT INTO archived_identities (community_id,pubkey,consent_path,actor,reason,replaced_by,request_event_id) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT (community_id,pubkey) DO NOTHING")
        .bind(community.as_uuid().to_string()).bind(pubkey).bind(consent_path).bind(actor).bind(reason).bind(replaced_by).bind(request_event_id)
        .execute(pool).await?.rows_affected() > 0)
}

pub(crate) async fn unarchive(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &str,
) -> Result<bool> {
    Ok(
        sqlx::query("DELETE FROM archived_identities WHERE community_id = ?1 AND pubkey = ?2")
            .bind(community.as_uuid().to_string())
            .bind(pubkey)
            .execute(pool)
            .await?
            .rows_affected()
            > 0,
    )
}

pub(crate) async fn list_archived(
    pool: &SqlitePool,
    community: CommunityId,
) -> Result<Vec<crate::archived_identities::ArchivedIdentity>> {
    let rows = sqlx::query("SELECT pubkey,consent_path,actor,reason,replaced_by,request_event_id,archived_at FROM archived_identities WHERE community_id = ?1 ORDER BY archived_at ASC")
        .bind(community.as_uuid().to_string()).fetch_all(pool).await?;
    rows.into_iter()
        .map(|row| {
            let archived_at: i64 = row.try_get("archived_at")?;
            Ok(crate::archived_identities::ArchivedIdentity {
                pubkey: row.try_get("pubkey")?,
                consent_path: row.try_get("consent_path")?,
                actor: row.try_get("actor")?,
                reason: row.try_get("reason")?,
                replaced_by: row.try_get("replaced_by")?,
                request_event_id: row.try_get("request_event_id")?,
                archived_at: timestamp(archived_at)?,
            })
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
        if !insert_command_event_tx(&mut tx, community, event, None).await? {
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

pub(crate) async fn create_channel(
    pool: &SqlitePool,
    community: CommunityId,
    name: &str,
    channel_type: crate::channel::ChannelType,
    visibility: crate::channel::ChannelVisibility,
    description: Option<&str>,
    created_by: &[u8],
    ttl_seconds: Option<i32>,
) -> Result<crate::channel::ChannelRecord> {
    let id = Uuid::new_v4();
    create_channel_with_id(
        pool,
        community,
        id,
        name,
        channel_type,
        visibility,
        description,
        created_by,
        ttl_seconds,
    )
    .await
    .map(|(r, _)| r)
}

pub(crate) async fn get_canvas(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT canvas FROM channels WHERE community_id = ?1 AND id = ?2 AND deleted_at IS NULL",
    )
    .bind(community.as_uuid().to_string())
    .bind(channel_id.to_string())
    .fetch_optional(pool)
    .await?
    .flatten())
}

pub(crate) async fn set_canvas(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
    canvas: Option<&str>,
) -> Result<()> {
    let n = sqlx::query("UPDATE channels SET canvas = ?1, updated_at = unixepoch() WHERE community_id = ?2 AND id = ?3 AND deleted_at IS NULL")
        .bind(canvas).bind(community.as_uuid().to_string()).bind(channel_id.to_string()).execute(pool).await?.rows_affected();
    if n == 0 {
        return Err(crate::DbError::ChannelNotFound(channel_id));
    }
    Ok(())
}

pub(crate) async fn remove_member(
    pool: &SqlitePool,
    community: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
    actor: &[u8],
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let cid = community.as_uuid().to_string();
    let chid = channel_id.to_string();
    let is_self = pubkey == actor;
    if !is_self {
        let actor_role: Option<String> = sqlx::query_scalar("SELECT cm.role FROM channel_members cm JOIN channels c ON c.id=cm.channel_id AND c.community_id=?1 WHERE cm.channel_id=?2 AND cm.pubkey=?3 AND cm.removed_at IS NULL AND c.deleted_at IS NULL")
            .bind(&cid).bind(&chid).bind(actor).fetch_optional(&mut *tx).await?;
        let agent_owner: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE community_id=?1 AND pubkey=?2 AND agent_owner_pubkey=?3")
            .bind(&cid).bind(pubkey).bind(actor).fetch_one(&mut *tx).await?;
        let elevated = matches!(actor_role.as_deref(), Some("owner" | "admin"));
        if !elevated && agent_owner == 0 {
            return Err(crate::DbError::AccessDenied(
                "only owners/admins or the agent's owner may remove other members".into(),
            ));
        }
    }
    let target_role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM channel_members WHERE channel_id=?1 AND pubkey=?2 AND removed_at IS NULL",
    )
    .bind(&chid)
    .bind(pubkey)
    .fetch_optional(&mut *tx)
    .await?;
    if target_role.is_none() {
        return Err(crate::DbError::MemberNotFound(channel_id));
    }
    if target_role.as_deref() == Some("owner") {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM channel_members WHERE channel_id=?1 AND role='owner' AND removed_at IS NULL").bind(&chid).fetch_one(&mut *tx).await?;
        if count <= 1 {
            return Err(crate::DbError::AccessDenied(
                "cannot remove the last owner — transfer ownership first".into(),
            ));
        }
    }
    let n = sqlx::query("UPDATE channel_members SET removed_at=unixepoch() WHERE channel_id=?1 AND pubkey=?2 AND removed_at IS NULL").bind(&chid).bind(pubkey).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(crate::DbError::MemberNotFound(channel_id));
    }
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn membership_pairs(
    pool: &SqlitePool,
    community: CommunityId,
    channel_ids: &[Uuid],
    pubkeys: &[Vec<u8>],
) -> Result<Vec<(Uuid, Vec<u8>)>> {
    if channel_ids.is_empty() || pubkeys.is_empty() {
        return Ok(Vec::new());
    }
    let ids = channel_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");
    let keys = pubkeys.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!("SELECT cm.channel_id,cm.pubkey FROM channel_members cm JOIN channels c ON c.id=cm.channel_id AND c.community_id=? AND c.deleted_at IS NULL WHERE cm.channel_id IN ({ids}) AND cm.pubkey IN ({keys}) AND cm.removed_at IS NULL");
    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(community.as_uuid().to_string());
    for id in channel_ids {
        q = q.bind(id.to_string());
    }
    for pk in pubkeys {
        q = q.bind(pk);
    }
    let mut out = Vec::new();
    for r in q.fetch_all(pool).await? {
        let id: String = r.try_get("channel_id")?;
        out.push((
            Uuid::parse_str(&id).map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
            r.try_get("pubkey")?,
        ));
    }
    Ok(out)
}

pub(crate) async fn get_members_bulk(
    pool: &SqlitePool,
    community: CommunityId,
    channel_ids: &[Uuid],
) -> Result<Vec<crate::channel::MemberRecord>> {
    if channel_ids.is_empty() {
        return Ok(Vec::new());
    }
    let ids = channel_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");
    let sql=format!("SELECT cm.channel_id,cm.pubkey,cm.role,cm.joined_at,cm.invited_by,cm.removed_at FROM channel_members cm JOIN channels c ON c.id=cm.channel_id AND c.community_id=? AND c.deleted_at IS NULL WHERE cm.channel_id IN ({ids}) AND cm.removed_at IS NULL ORDER BY cm.joined_at ASC");
    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(community.as_uuid().to_string());
    for id in channel_ids {
        q = q.bind(id.to_string());
    }
    q.fetch_all(pool)
        .await?
        .into_iter()
        .map(member_record)
        .collect()
}

pub(crate) async fn list_channels(
    pool: &SqlitePool,
    community: CommunityId,
    visibility: Option<&str>,
) -> Result<Vec<crate::channel::ChannelRecord>> {
    let mut sql = "SELECT * FROM channels WHERE community_id=? AND deleted_at IS NULL".to_string();
    if visibility.is_some() {
        sql.push_str(" AND visibility=?");
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT 1000");
    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(community.as_uuid().to_string());
    if let Some(v) = visibility {
        q = q.bind(v);
    }
    q.fetch_all(pool)
        .await?
        .into_iter()
        .map(channel_record)
        .collect()
}

pub(crate) async fn get_accessible_channels(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
    visibility: Option<&str>,
    member_only: Option<bool>,
) -> Result<Vec<crate::channel::AccessibleChannel>> {
    let mut sql="SELECT c.*, (cm.channel_id IS NOT NULL) AS is_member FROM channels c LEFT JOIN channel_members cm ON cm.channel_id=c.id AND cm.pubkey=? AND cm.removed_at IS NULL WHERE c.community_id=? AND c.deleted_at IS NULL AND (c.channel_type != 'dm' OR cm.hidden_at IS NULL)".to_string();
    if member_only == Some(true) {
        sql.push_str(" AND cm.channel_id IS NOT NULL");
    } else {
        sql.push_str(" AND (c.visibility='open' OR cm.channel_id IS NOT NULL)");
    }
    if visibility.is_some() {
        sql.push_str(" AND c.visibility=?");
    }
    sql.push_str(" ORDER BY CASE c.channel_type WHEN 'stream' THEN 0 WHEN 'forum' THEN 1 WHEN 'dm' THEN 2 ELSE 3 END,c.name LIMIT 1000");
    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(pubkey)
        .bind(community.as_uuid().to_string());
    if let Some(v) = visibility {
        q = q.bind(v);
    }
    let mut out = Vec::new();
    for r in q.fetch_all(pool).await? {
        let m = r.try_get::<i64, _>("is_member")? != 0;
        out.push(crate::channel::AccessibleChannel {
            channel: channel_record(r)?,
            is_member: m,
        });
    }
    Ok(out)
}

pub(crate) async fn get_bot_members(
    pool: &SqlitePool,
    community: CommunityId,
) -> Result<Vec<crate::channel::BotMemberRecord>> {
    let rows=sqlx::query("SELECT cm.pubkey,u.display_name FROM channel_members cm LEFT JOIN users u ON u.community_id=? AND u.pubkey=cm.pubkey JOIN channels c ON c.id=cm.channel_id AND c.deleted_at IS NULL WHERE c.community_id=? AND cm.role='bot' AND cm.removed_at IS NULL GROUP BY cm.pubkey,u.display_name LIMIT 1000").bind(community.as_uuid().to_string()).bind(community.as_uuid().to_string()).fetch_all(pool).await?;
    let mut out = Vec::new();
    for r in rows {
        let pk = r.try_get("pubkey")?;
        let chans=sqlx::query("SELECT c.name,c.id FROM channel_members cm JOIN channels c ON c.id=cm.channel_id WHERE c.community_id=? AND cm.pubkey=? AND cm.role='bot' AND cm.removed_at IS NULL AND c.deleted_at IS NULL ORDER BY c.name").bind(community.as_uuid().to_string()).bind(&pk).fetch_all(pool).await?;
        let channels = chans
            .into_iter()
            .map(|x| {
                Ok(crate::channel::BotChannelEntry {
                    name: x.try_get("name")?,
                    id: x.try_get("id")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        out.push(crate::channel::BotMemberRecord {
            pubkey: pk,
            display_name: r.try_get("display_name")?,
            agent_type: None,
            capabilities: None,
            channels,
        });
    }
    Ok(out)
}

pub(crate) async fn get_users_bulk(
    pool: &SqlitePool,
    community: CommunityId,
    pubkeys: &[Vec<u8>],
) -> Result<Vec<crate::channel::UserRecord>> {
    if pubkeys.is_empty() {
        return Ok(Vec::new());
    }
    let keys = pubkeys.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let mut q=sqlx::query(sqlx::AssertSqlSafe(format!("SELECT pubkey,display_name,avatar_url,nip05_handle FROM users WHERE community_id=? AND pubkey IN ({keys})"))).bind(community.as_uuid().to_string());
    for pk in pubkeys {
        q = q.bind(pk);
    }
    q.fetch_all(pool)
        .await?
        .into_iter()
        .map(|r| {
            Ok(crate::channel::UserRecord {
                pubkey: r.try_get("pubkey")?,
                display_name: r.try_get("display_name")?,
                avatar_url: r.try_get("avatar_url")?,
                nip05_handle: r.try_get("nip05_handle")?,
            })
        })
        .collect()
}

fn channel_not_found_if_zero(n: u64, id: Uuid) -> Result<()> {
    if n == 0 {
        Err(crate::DbError::ChannelNotFound(id))
    } else {
        Ok(())
    }
}

pub(crate) async fn update_channel(
    pool: &SqlitePool,
    community: CommunityId,
    id: Uuid,
    mut u: crate::channel::ChannelUpdate,
) -> Result<crate::channel::ChannelRecord> {
    if u.name.is_none()
        && u.description.is_none()
        && u.visibility.is_none()
        && u.ttl_seconds.is_none()
    {
        return Err(crate::DbError::InvalidData(
            "at least one field must be provided for update".into(),
        ));
    }
    if let Some(n) = u.name.as_mut() {
        *n = buzz_core::channel::canonical_channel_name(n).to_owned();
        if n.trim().is_empty() {
            return Err(crate::DbError::InvalidData(
                "channel name is required".into(),
            ));
        }
    }
    let mut sets = Vec::new();
    if u.name.is_some() {
        sets.push("name=?");
    }
    if u.description.is_some() {
        sets.push("description=?");
    }
    if u.visibility.is_some() {
        sets.push("visibility=?");
    }
    if u.ttl_seconds.is_some() {
        sets.push("ttl_seconds=?");
        sets.push("ttl_deadline=CASE WHEN ? IS NULL THEN NULL ELSE unixepoch()+? END");
    }
    sets.push("updated_at=unixepoch()");
    let mut q = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE channels SET {} WHERE community_id=? AND id=? AND deleted_at IS NULL",
        sets.join(",")
    )));
    if let Some(v) = &u.name {
        q = q.bind(v);
    }
    if let Some(v) = &u.description {
        q = q.bind(v);
    }
    if let Some(v) = &u.visibility {
        q = q.bind(v);
    }
    if let Some(v) = u.ttl_seconds {
        q = q.bind(v).bind(v).bind(v);
    }
    q = q.bind(community.as_uuid().to_string()).bind(id.to_string());
    channel_not_found_if_zero(q.execute(pool).await?.rows_affected(), id)?;
    get_channel(pool, community, id).await
}

pub(crate) async fn set_topic(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
    v: &str,
    by: &[u8],
) -> Result<()> {
    let n=sqlx::query("UPDATE channels SET topic=?,topic_set_by=?,topic_set_at=unixepoch(),updated_at=unixepoch() WHERE community_id=? AND id=? AND deleted_at IS NULL").bind(v).bind(by).bind(c.as_uuid().to_string()).bind(id.to_string()).execute(pool).await?.rows_affected();
    channel_not_found_if_zero(n, id)
}
pub(crate) async fn set_purpose(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
    v: &str,
    by: &[u8],
) -> Result<()> {
    let n=sqlx::query("UPDATE channels SET purpose=?,purpose_set_by=?,purpose_set_at=unixepoch(),updated_at=unixepoch() WHERE community_id=? AND id=? AND deleted_at IS NULL").bind(v).bind(by).bind(c.as_uuid().to_string()).bind(id.to_string()).execute(pool).await?.rows_affected();
    channel_not_found_if_zero(n, id)
}
pub(crate) async fn archive_channel(pool: &SqlitePool, c: CommunityId, id: Uuid) -> Result<()> {
    let row = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT archived_at FROM channels WHERE community_id=? AND id=? AND deleted_at IS NULL",
    )
    .bind(c.as_uuid().to_string())
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    match row {
        None => Err(crate::DbError::ChannelNotFound(id)),
        Some(Some(_)) => Err(crate::DbError::AccessDenied(
            "channel is already archived".into(),
        )),
        Some(None) => {
            sqlx::query("UPDATE channels SET archived_at=unixepoch() WHERE community_id=? AND id=? AND archived_at IS NULL AND deleted_at IS NULL").bind(c.as_uuid().to_string()).bind(id.to_string()).execute(pool).await?;
            Ok(())
        }
    }
}
pub(crate) async fn unarchive_channel(pool: &SqlitePool, c: CommunityId, id: Uuid) -> Result<()> {
    let row = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT archived_at FROM channels WHERE community_id=? AND id=? AND deleted_at IS NULL",
    )
    .bind(c.as_uuid().to_string())
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    match row {
        None => Err(crate::DbError::ChannelNotFound(id)),
        Some(None) => Err(crate::DbError::AccessDenied(
            "channel is not archived".into(),
        )),
        Some(Some(_)) => {
            sqlx::query("UPDATE channels SET archived_at=NULL,ttl_deadline=CASE WHEN ttl_seconds IS NULL THEN ttl_deadline ELSE unixepoch()+ttl_seconds END WHERE community_id=? AND id=? AND deleted_at IS NULL").bind(c.as_uuid().to_string()).bind(id.to_string()).execute(pool).await?;
            Ok(())
        }
    }
}
pub(crate) async fn soft_delete_channel(
    pool: &SqlitePool,
    c: CommunityId,
    id: Uuid,
) -> Result<bool> {
    Ok(sqlx::query("UPDATE channels SET deleted_at=unixepoch() WHERE community_id=? AND id=? AND deleted_at IS NULL").bind(c.as_uuid().to_string()).bind(id.to_string()).execute(pool).await?.rows_affected()>0)
}
pub(crate) async fn get_member_count(pool: &SqlitePool, c: CommunityId, id: Uuid) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM channel_members cm JOIN channels ch ON ch.id=cm.channel_id AND ch.community_id=? WHERE cm.channel_id=? AND cm.removed_at IS NULL").bind(c.as_uuid().to_string()).bind(id.to_string()).fetch_one(pool).await?)
}
pub(crate) async fn get_member_counts_bulk(
    pool: &SqlitePool,
    c: CommunityId,
    ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, i64>> {
    if ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let ph = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let mut q=sqlx::query(sqlx::AssertSqlSafe(format!("SELECT cm.channel_id,count(*) cnt FROM channel_members cm JOIN channels ch ON ch.id=cm.channel_id AND ch.community_id=? WHERE cm.channel_id IN ({ph}) AND cm.removed_at IS NULL GROUP BY cm.channel_id"))).bind(c.as_uuid().to_string());
    for id in ids {
        q = q.bind(id.to_string());
    }
    let mut out = std::collections::HashMap::new();
    for r in q.fetch_all(pool).await? {
        let id: String = r.try_get("channel_id")?;
        out.insert(
            Uuid::parse_str(&id).map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
            r.try_get("cnt")?,
        );
    }
    Ok(out)
}
pub(crate) async fn reap_expired_ephemeral_channels(
    pool: &SqlitePool,
) -> Result<Vec<crate::channel::ReapedEphemeralChannel>> {
    let rows = sqlx::query(
        "UPDATE channels SET archived_at=unixepoch() WHERE ttl_seconds IS NOT NULL AND ttl_deadline<unixepoch() AND archived_at IS NULL AND deleted_at IS NULL AND EXISTS (SELECT 1 FROM communities c WHERE c.id=channels.community_id AND c.archived_at IS NULL) RETURNING community_id,id,(SELECT host FROM communities c WHERE c.id=channels.community_id) AS host",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let community_id: String = row.try_get("community_id")?;
            let channel_id: String = row.try_get("id")?;
            Ok(crate::channel::ReapedEphemeralChannel {
                community_id: CommunityId::from_uuid(
                    Uuid::parse_str(&community_id)
                        .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
                ),
                host: row.try_get("host")?,
                channel_id: Uuid::parse_str(&channel_id)
                    .map_err(|e| crate::DbError::InvalidData(e.to_string()))?,
            })
        })
        .collect()
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

fn user_profile(row: sqlx::sqlite::SqliteRow) -> Result<crate::user::UserProfile> {
    Ok(crate::user::UserProfile {
        pubkey: row.try_get("pubkey")?,
        display_name: row.try_get("display_name")?,
        avatar_url: row.try_get("avatar_url")?,
        about: row.try_get("about")?,
        nip05_handle: row.try_get("nip05_handle")?,
    })
}

pub(crate) async fn get_user(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
) -> Result<Option<crate::user::UserProfile>> {
    sqlx::query(
        "SELECT pubkey, display_name, avatar_url, about, nip05_handle FROM users WHERE community_id = ?1 AND pubkey = ?2",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .fetch_optional(pool)
    .await?
    .map(user_profile)
    .transpose()
}

pub(crate) async fn get_user_by_nip05(
    pool: &SqlitePool,
    community: CommunityId,
    local_part: &str,
    domain: &str,
) -> Result<Option<crate::user::UserProfile>> {
    let handle = format!("{local_part}@{domain}").to_lowercase();
    let rows = sqlx::query(
        "SELECT pubkey, display_name, avatar_url, about, nip05_handle FROM users WHERE community_id = ?1 AND nip05_handle IS NOT NULL",
    )
    .bind(community.as_uuid().to_string())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .find(|row| {
            row.try_get::<String, _>("nip05_handle")
                .is_ok_and(|stored| stored.to_lowercase() == handle)
        })
        .map(user_profile)
        .transpose()
}

pub(crate) async fn search_users(
    pool: &SqlitePool,
    community: CommunityId,
    query: &str,
    limit: u32,
) -> Result<Vec<crate::user::UserSearchProfile>> {
    let normalized = query.trim().to_lowercase();
    if normalized.is_empty() {
        return Ok(Vec::new());
    }

    let rows = sqlx::query(
        "SELECT pubkey, display_name, avatar_url, nip05_handle FROM users WHERE community_id = ?1",
    )
    .bind(community.as_uuid().to_string())
    .fetch_all(pool)
    .await?;

    let mut matches = rows
        .into_iter()
        .map(|row| {
            let profile = crate::user::UserSearchProfile {
                pubkey: row.try_get("pubkey")?,
                display_name: row.try_get("display_name")?,
                avatar_url: row.try_get("avatar_url")?,
                nip05_handle: row.try_get("nip05_handle")?,
            };
            let display_name = profile
                .display_name
                .as_deref()
                .unwrap_or_default()
                .to_lowercase();
            let nip05_handle = profile
                .nip05_handle
                .as_deref()
                .unwrap_or_default()
                .to_lowercase();
            let pubkey = hex::encode(&profile.pubkey);
            let rank = if display_name == normalized {
                0
            } else if nip05_handle == normalized {
                1
            } else if pubkey == normalized {
                2
            } else if display_name.starts_with(&normalized) {
                3
            } else if nip05_handle.starts_with(&normalized) {
                4
            } else if pubkey.starts_with(&normalized) {
                5
            } else {
                6
            };
            let sort_name = profile
                .display_name
                .as_deref()
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    profile
                        .nip05_handle
                        .as_deref()
                        .filter(|value| !value.is_empty())
                })
                .map(str::to_owned)
                .unwrap_or_else(|| pubkey.clone());
            Ok((
                display_name.contains(&normalized)
                    || nip05_handle.contains(&normalized)
                    || pubkey.contains(&normalized),
                rank,
                sort_name,
                profile,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    matches.retain(|(is_match, _, _, _)| *is_match);
    matches.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.2.cmp(&right.2)));
    Ok(matches
        .into_iter()
        .take(limit.clamp(1, 500) as usize)
        .map(|(_, _, _, profile)| profile)
        .collect())
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

pub(crate) async fn is_pubkey_allowed(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM pubkey_allowlist WHERE community_id = ?1 AND pubkey = ?2",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .fetch_one(pool)
    .await?
        != 0)
}

pub(crate) async fn has_allowlist_entries(
    pool: &SqlitePool,
    community: CommunityId,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM pubkey_allowlist WHERE community_id = ?1",
    )
    .bind(community.as_uuid().to_string())
    .fetch_one(pool)
    .await?
        != 0)
}

pub(crate) async fn add_to_allowlist(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
    added_by: &[u8],
    note: Option<&str>,
) -> Result<bool> {
    Ok(sqlx::query("INSERT INTO pubkey_allowlist (community_id,pubkey,added_by,note) VALUES (?1,?2,?3,?4) ON CONFLICT DO NOTHING")
        .bind(community.as_uuid().to_string())
        .bind(pubkey)
        .bind(added_by)
        .bind(note)
        .execute(pool)
        .await?
        .rows_affected() == 1)
}

pub(crate) async fn remove_from_allowlist(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &[u8],
) -> Result<bool> {
    Ok(
        sqlx::query("DELETE FROM pubkey_allowlist WHERE community_id = ?1 AND pubkey = ?2")
            .bind(community.as_uuid().to_string())
            .bind(pubkey)
            .execute(pool)
            .await?
            .rows_affected()
            == 1,
    )
}

pub(crate) async fn list_allowlist(
    pool: &SqlitePool,
    community: CommunityId,
) -> Result<Vec<crate::AllowlistEntry>> {
    sqlx::query("SELECT pubkey,added_by,added_at,note FROM pubkey_allowlist WHERE community_id = ?1 ORDER BY added_at DESC")
        .bind(community.as_uuid().to_string())
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| {
            let added_at: i64 = row.try_get("added_at")?;
            Ok(crate::AllowlistEntry {
                pubkey: row.try_get("pubkey")?,
                added_by: row.try_get("added_by")?,
                added_at: chrono::DateTime::from_timestamp(added_at, 0)
                    .ok_or(crate::DbError::InvalidTimestamp(added_at))?,
                note: row.try_get("note")?,
            })
        })
        .collect()
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

pub(crate) async fn claim_relay_membership(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &str,
    role: &str,
    policy_version: Option<&str>,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO relay_members (community_id, pubkey, role, added_by) VALUES (?1, lower(?2), ?3, 'invite') ON CONFLICT DO NOTHING",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .bind(role)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if let Some(version) = policy_version {
        sqlx::query("INSERT INTO join_policy_acceptances (community_id, pubkey, policy_version) VALUES (?1, lower(?2), ?3) ON CONFLICT DO NOTHING")
            .bind(community.as_uuid().to_string())
            .bind(pubkey)
            .bind(version)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(inserted)
}

pub(crate) async fn has_join_policy_acceptance(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &str,
    policy_version: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM join_policy_acceptances WHERE community_id = ?1 AND pubkey = lower(?2) AND policy_version = ?3",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .bind(policy_version)
    .fetch_one(pool)
    .await?
        != 0)
}

pub(crate) async fn remove_relay_member(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &str,
    expected_role: Option<&str>,
) -> Result<crate::relay_members::RemoveResult> {
    use crate::relay_members::RemoveResult;
    let result = if let Some(role) = expected_role {
        sqlx::query("DELETE FROM relay_members WHERE community_id = ?1 AND pubkey = lower(?2) AND role = ?3")
            .bind(community.as_uuid().to_string())
            .bind(pubkey)
            .bind(role)
            .execute(pool)
            .await?
    } else {
        sqlx::query("DELETE FROM relay_members WHERE community_id = ?1 AND pubkey = lower(?2) AND role <> 'owner'")
            .bind(community.as_uuid().to_string())
            .bind(pubkey)
            .execute(pool)
            .await?
    };
    if result.rows_affected() == 1 {
        return Ok(RemoveResult::Removed);
    }
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM relay_members WHERE community_id = ?1 AND pubkey = lower(?2)",
    )
    .bind(community.as_uuid().to_string())
    .bind(pubkey)
    .fetch_optional(pool)
    .await?;
    Ok(match role.as_deref() {
        None => RemoveResult::NotFound,
        Some("owner") => RemoveResult::IsOwner,
        Some(_) if expected_role.is_some() => RemoveResult::RoleMismatch,
        Some(_) => RemoveResult::NotFound,
    })
}

pub(crate) async fn update_relay_member_role(
    pool: &SqlitePool,
    community: CommunityId,
    pubkey: &str,
    new_role: &str,
) -> Result<bool> {
    Ok(sqlx::query("UPDATE relay_members SET role = ?3, updated_at = unixepoch() WHERE community_id = ?1 AND pubkey = lower(?2) AND role <> 'owner'")
        .bind(community.as_uuid().to_string())
        .bind(pubkey)
        .bind(new_role)
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
    use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

    #[tokio::test]
    async fn event_query_parity_vectors_hold_for_sqlite() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "parity.example")
            .await
            .unwrap()
            .id;
        let other = ensure_configured_community(&pool, "other-parity.example")
            .await
            .unwrap()
            .id;
        let first_keys = Keys::generate();
        let second_keys = Keys::generate();
        let p_tag_hex = hex::encode(second_keys.public_key().to_bytes());
        let first = EventBuilder::new(Kind::Custom(1), "first")
            .tags([
                Tag::parse(["d", "alpha"]).unwrap(),
                Tag::parse(["p", &p_tag_hex.to_ascii_uppercase()]).unwrap(),
            ])
            .custom_created_at(Timestamp::from(100_u64))
            .sign_with_keys(&first_keys)
            .unwrap();
        let second = EventBuilder::new(Kind::Custom(2), "second")
            .custom_created_at(Timestamp::from(101_u64))
            .sign_with_keys(&second_keys)
            .unwrap();
        let third = EventBuilder::new(Kind::Custom(1), "third")
            .custom_created_at(Timestamp::from(102_u64))
            .sign_with_keys(&first_keys)
            .unwrap();
        let channel_id = Uuid::new_v4();
        insert_event(&pool, community, &first, None).await.unwrap();
        insert_event(&pool, community, &second, Some(channel_id))
            .await
            .unwrap();
        insert_event(&pool, community, &third, None).await.unwrap();
        insert_event(&pool, other, &third, None).await.unwrap();

        let fixture = crate::event::EventQueryParityFixture {
            first_id: first.id.as_bytes().to_vec(),
            second_id: second.id.as_bytes().to_vec(),
            third_id: third.id.as_bytes().to_vec(),
            first_author: first.pubkey.to_bytes().to_vec(),
            p_tag_hex,
            channel_id,
        };
        for (name, query, expected_ids, expected_count) in
            crate::event::event_query_parity_vectors(community, &fixture)
        {
            let events = query_events(&pool, &query).await.unwrap();
            let ids: Vec<_> = events
                .into_iter()
                .map(|event| event.event.id.as_bytes().to_vec())
                .collect();
            assert_eq!(ids, expected_ids, "{name}");
            assert_eq!(
                count_events(&pool, &query).await.unwrap(),
                expected_count,
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn rebind_single_node_community_preserves_best_owner_uuid() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let owner = "ab".repeat(32);
        let older = ensure_configured_community(&pool, "127.0.0.1:41001")
            .await
            .unwrap();
        let best = ensure_configured_community(&pool, "127.0.0.1:41002")
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO relay_members (community_id, pubkey, role) VALUES (?1, ?2, 'owner')",
        )
        .bind(best.id.as_uuid().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        for id in [vec![1_u8; 32], vec![2_u8; 32]] {
            sqlx::query("INSERT INTO events (community_id,id,pubkey,created_at,kind,tags_json,content,sig,received_at,event_json) VALUES (?1,?2,?3,1,9,'[]','marker',?4,1,'{}')")
                .bind(best.id.as_uuid().to_string())
                .bind(id)
                .bind(vec![3_u8; 32])
                .bind(vec![4_u8; 64])
                .execute(&pool)
                .await
                .unwrap();
        }

        let rebound = rebind_single_node_community_host(&pool, "127.0.0.1:41999", &owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rebound.id, best.id);
        assert_eq!(rebound.host, "127.0.0.1:41999");
        assert!(lookup_community_by_host(&pool, "127.0.0.1:41002")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            lookup_community_by_host(&pool, "127.0.0.1:41001")
                .await
                .unwrap()
                .unwrap()
                .id,
            older.id
        );
    }

    #[tokio::test]
    async fn rebind_single_node_community_is_idempotent_for_current_host() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let current = ensure_configured_community(&pool, "127.0.0.1:42000")
            .await
            .unwrap();
        let rebound = rebind_single_node_community_host(&pool, "127.0.0.1:42000", &"cd".repeat(32))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rebound.id, current.id);
    }

    #[tokio::test]
    async fn rebind_single_node_community_swaps_stale_port_collision() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let owner = "ef".repeat(32);
        let selected = ensure_configured_community(&pool, "127.0.0.1:43001")
            .await
            .unwrap();
        let stale = ensure_configured_community(&pool, "127.0.0.1:43002")
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO relay_members (community_id, pubkey, role) VALUES (?1, ?2, 'owner')",
        )
        .bind(selected.id.as_uuid().to_string())
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();

        let rebound = rebind_single_node_community_host(&pool, "127.0.0.1:43002", &owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rebound.id, selected.id);
        assert_eq!(
            lookup_community_by_host(&pool, "127.0.0.1:43002")
                .await
                .unwrap()
                .unwrap()
                .id,
            selected.id
        );
        assert_eq!(
            lookup_community_by_host(&pool, "127.0.0.1:43001")
                .await
                .unwrap()
                .unwrap()
                .id,
            stale.id
        );
    }

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
        sqlx::query("CREATE TABLE events (community_id TEXT NOT NULL, id BLOB NOT NULL, pubkey BLOB NOT NULL, created_at INTEGER NOT NULL, kind INTEGER NOT NULL, tags_json TEXT NOT NULL, content TEXT NOT NULL, sig BLOB NOT NULL, channel_id TEXT, received_at INTEGER NOT NULL, event_json TEXT NOT NULL, PRIMARY KEY (community_id, id))")
            .execute(&pool).await.unwrap();
        let legacy_community = Uuid::new_v4();
        sqlx::query("INSERT INTO communities (id, host) VALUES (?1, 'legacy.example')")
            .bind(legacy_community.to_string())
            .execute(&pool)
            .await
            .unwrap();
        let legacy_reminder = EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_EVENT_REMINDER as u16),
            "legacy reminder",
        )
        .tags([
            Tag::parse(["d", "legacy"]).unwrap(),
            Tag::parse(["not_before", "1234"]).unwrap(),
        ])
        .custom_created_at(Timestamp::from(99_u64))
        .sign_with_keys(&Keys::generate())
        .unwrap();
        sqlx::query("INSERT INTO events (community_id,id,pubkey,created_at,kind,tags_json,content,sig,received_at,event_json) VALUES (?1,?2,?3,99,?4,?5,?6,?7,99,?8)")
            .bind(legacy_community.to_string())
            .bind(legacy_reminder.id.as_bytes().as_slice())
            .bind(legacy_reminder.pubkey.to_bytes().as_slice())
            .bind(legacy_reminder.kind.as_u16() as i32)
            .bind(serde_json::to_string(&legacy_reminder.tags).unwrap())
            .bind(&legacy_reminder.content)
            .bind(legacy_reminder.sig.serialize().as_slice())
            .bind(serde_json::to_string(&legacy_reminder).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO events (community_id,id,pubkey,created_at,kind,tags_json,content,sig,received_at,event_json) VALUES (?1,?2,?3,100,9,'[]','legacy searchable orchard',?4,100,'{}')")
            .bind(legacy_community.to_string()).bind(vec![1_u8; 32]).bind(vec![2_u8; 32]).bind(vec![3_u8; 64]).execute(&pool).await.unwrap();
        pool.close().await;

        let upgraded = connect(path.to_str().unwrap()).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT version FROM schema_version WHERE singleton = 1")
                .fetch_one(&upgraded)
                .await
                .unwrap(),
            12
        );
        for (table, column) in [
            ("channels", "participant_hash"),
            ("channel_members", "hidden_at"),
            ("events", "not_before"),
            ("events", "delivered_at"),
        ] {
            let pragma = format!("PRAGMA table_info({table})");
            assert!(sqlx::query(sqlx::AssertSqlSafe(pragma))
                .fetch_all(&upgraded)
                .await
                .unwrap()
                .iter()
                .any(|row| row.get::<String, _>("name") == column));
        }
        assert_eq!(
            sqlx::query_scalar::<_, Option<i64>>("SELECT not_before FROM events WHERE id = ?1")
                .bind(legacy_reminder.id.as_bytes().as_slice())
                .fetch_one(&upgraded)
                .await
                .unwrap(),
            Some(1234)
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM events_fts WHERE events_fts MATCH 'orchard'"
            )
            .fetch_one(&upgraded)
            .await
            .unwrap(),
            1
        );
        upgraded.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn repairs_old_v3_fts_privacy_and_dm_uniqueness_on_upgrade() {
        let path =
            std::env::temp_dir().join(format!("buzz-db-v3-upgrade-{}.sqlite", Uuid::new_v4()));
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .unwrap()
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        for statement in SCHEMA.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        sqlx::query("CREATE TABLE schema_version (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO schema_version (singleton, version) VALUES (1, 3)")
            .execute(&pool)
            .await
            .unwrap();
        let community = ensure_configured_community(&pool, "v3-upgrade.example")
            .await
            .unwrap()
            .id;

        for (id, kind, content) in [
            (vec![1_u8; 32], 9_i64, "public orchard"),
            (vec![2_u8; 32], 1_i64, "private orchard"),
        ] {
            sqlx::query("INSERT INTO events (community_id,id,pubkey,created_at,kind,tags_json,content,sig,received_at,event_json) VALUES (?1,?2,?3,100,?4,'[]',?5,?6,100,'{}')")
                .bind(community.as_uuid().to_string())
                .bind(id)
                .bind(vec![3_u8; 32])
                .bind(kind)
                .bind(content)
                .bind(vec![4_u8; 64])
                .execute(&pool)
                .await
                .unwrap();
        }

        let winner = "00000000-0000-0000-0000-000000000001";
        let loser = "00000000-0000-0000-0000-000000000002";
        let participant_hash = vec![9_u8; 32];
        for (id, created_at) in [(winner, 100_i64), (loser, 101_i64)] {
            sqlx::query("INSERT INTO channels (id, community_id, name, channel_type, visibility, participant_hash, created_by, created_at, updated_at) VALUES (?1, ?2, 'dm', 'dm', 'private', ?3, ?4, ?5, ?5)")
                .bind(id)
                .bind(community.as_uuid().to_string())
                .bind(&participant_hash)
                .bind(vec![10_u8; 32])
                .bind(created_at)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO channel_members (channel_id, pubkey, role, joined_at) VALUES (?1, ?2, 'member', 100), (?3, ?4, 'member', 101)")
            .bind(winner)
            .bind(vec![11_u8; 32])
            .bind(loser)
            .bind(vec![12_u8; 32])
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE events SET channel_id = ?1 WHERE content = 'private orchard'")
            .bind(loser)
            .execute(&pool)
            .await
            .unwrap();

        for statement in [
            "CREATE VIRTUAL TABLE events_fts USING fts5(content, content='events', content_rowid='rowid', tokenize='unicode61')",
            "INSERT INTO events_fts(events_fts) VALUES ('rebuild')",
            "CREATE TRIGGER events_fts_insert AFTER INSERT ON events WHEN new.kind NOT IN (1059, 30300, 30350, 30622, 44100, 44101, 44200) BEGIN INSERT INTO events_fts(rowid, content) VALUES (new.rowid, new.content); END",
            "CREATE TRIGGER events_fts_delete AFTER DELETE ON events WHEN old.kind NOT IN (1059, 30300, 30350, 30622, 44100, 44101, 44200) BEGIN INSERT INTO events_fts(events_fts, rowid, content) VALUES ('delete', old.rowid, old.content); END",
            "CREATE TRIGGER events_fts_update AFTER UPDATE OF content, kind ON events BEGIN INSERT INTO events_fts(events_fts, rowid, content) SELECT 'delete', old.rowid, old.content WHERE old.kind NOT IN (1059, 30300, 30350, 30622, 44100, 44101, 44200); INSERT INTO events_fts(rowid, content) SELECT new.rowid, new.content WHERE new.kind NOT IN (1059, 30300, 30350, 30622, 44100, 44101, 44200); END",
            "UPDATE schema_version SET version = 3 WHERE singleton = 1",
        ] {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM events_fts WHERE events_fts MATCH 'private'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        pool.close().await;

        let upgraded = connect(path.to_str().unwrap()).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT version FROM schema_version WHERE singleton = 1")
                .fetch_one(&upgraded)
                .await
                .unwrap(),
            12
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM events_fts WHERE events_fts MATCH 'public'"
            )
            .fetch_one(&upgraded)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM events_fts WHERE events_fts MATCH 'private'"
            )
            .fetch_one(&upgraded)
            .await
            .unwrap(),
            0
        );

        let content_table_sql: String = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'events_fts'",
        )
        .fetch_one(&upgraded)
        .await
        .unwrap();
        assert!(content_table_sql.contains("content='searchable_events'"));
        for trigger in [
            "events_fts_insert",
            "events_fts_delete",
            "events_fts_update",
        ] {
            let sql: String = sqlx::query_scalar(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
            )
            .bind(trigger)
            .fetch_one(&upgraded)
            .await
            .unwrap();
            assert!(sql.contains("kind IN (0, 9, 40002, 45001, 45003)"));
            assert!(!sql.contains("kind NOT IN"));
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_channels_dm_hash'")
                .fetch_one(&upgraded)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM channels WHERE community_id = ?1 AND participant_hash = ?2 AND channel_type = 'dm' AND deleted_at IS NULL")
                .bind(community.as_uuid().to_string())
                .bind(&participant_hash)
                .fetch_one(&upgraded)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM channel_members WHERE channel_id = ?1"
            )
            .bind(winner)
            .fetch_one(&upgraded)
            .await
            .unwrap(),
            2
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT channel_id FROM events WHERE content = 'private orchard'"
            )
            .fetch_one(&upgraded)
            .await
            .unwrap(),
            winner
        );

        for (id, kind, content) in [
            (vec![5_u8; 32], 45001_i64, "allowed trigger token"),
            (vec![6_u8; 32], 1_i64, "excluded trigger token"),
        ] {
            sqlx::query("INSERT INTO events (community_id,id,pubkey,created_at,kind,tags_json,content,sig,received_at,event_json) VALUES (?1,?2,?3,101,?4,'[]',?5,?6,101,'{}')")
                .bind(community.as_uuid().to_string())
                .bind(id)
                .bind(vec![7_u8; 32])
                .bind(kind)
                .bind(content)
                .bind(vec![8_u8; 64])
                .execute(&upgraded)
                .await
                .unwrap();
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM events_fts WHERE events_fts MATCH 'trigger'"
            )
            .fetch_one(&upgraded)
            .await
            .unwrap(),
            1
        );
        upgraded.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn community_icon_and_channel_owner_helpers_match_lifecycle_contracts() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "community-helpers.example")
            .await
            .unwrap()
            .id;
        assert_eq!(lookup_community_icon(&pool, community).await.unwrap(), None);
        set_community_icon(&pool, community, Some("https://example.test/icon.png"))
            .await
            .unwrap();
        assert_eq!(
            lookup_community_icon(&pool, community)
                .await
                .unwrap()
                .as_deref(),
            Some("https://example.test/icon.png")
        );
        set_community_icon(&pool, community, Some(""))
            .await
            .unwrap();
        assert_eq!(lookup_community_icon(&pool, community).await.unwrap(), None);
        set_community_icon(&pool, community, None).await.unwrap();

        let channel = Uuid::new_v4();
        sqlx::query("INSERT INTO channels (id,community_id,name,channel_type,visibility,created_by) VALUES (?1,?2,'helper','public','public',?3)")
            .bind(channel.to_string())
            .bind(community.as_uuid().to_string())
            .bind(vec![1_u8; 32])
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            community_of_channel(&pool, channel).await.unwrap(),
            Some(community)
        );
        sqlx::query("UPDATE channels SET deleted_at = unixepoch() WHERE id = ?1")
            .bind(channel.to_string())
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(community_of_channel(&pool, channel).await.unwrap(), None);
        assert_eq!(
            community_of_channel(&pool, Uuid::new_v4()).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn allowlist_is_idempotent_and_community_scoped() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let a = ensure_configured_community(&pool, "allowlist-a.example")
            .await
            .unwrap()
            .id;
        let b = ensure_configured_community(&pool, "allowlist-b.example")
            .await
            .unwrap()
            .id;
        let pubkey = vec![1_u8; 32];
        let actor = vec![2_u8; 32];
        assert!(!has_allowlist_entries(&pool, a).await.unwrap());
        assert!(add_to_allowlist(&pool, a, &pubkey, &actor, Some("a-only"))
            .await
            .unwrap());
        assert!(
            !add_to_allowlist(&pool, a, &pubkey, &actor, Some("duplicate"))
                .await
                .unwrap()
        );
        assert!(is_pubkey_allowed(&pool, a, &pubkey).await.unwrap());
        assert!(!is_pubkey_allowed(&pool, b, &pubkey).await.unwrap());
        assert!(has_allowlist_entries(&pool, a).await.unwrap());
        assert!(!has_allowlist_entries(&pool, b).await.unwrap());
        let entries = list_allowlist(&pool, a).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].note.as_deref(), Some("a-only"));
        assert!(!remove_from_allowlist(&pool, b, &pubkey).await.unwrap());
        assert!(remove_from_allowlist(&pool, a, &pubkey).await.unwrap());
        assert!(!has_allowlist_entries(&pool, a).await.unwrap());
    }

    #[tokio::test]
    async fn due_reminders_are_latest_per_tenant_address_and_claims_compare_and_clear() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let a = ensure_configured_community(&pool, "reminders-a.example")
            .await
            .unwrap()
            .id;
        let b = ensure_configured_community(&pool, "reminders-b.example")
            .await
            .unwrap()
            .id;
        let keys = Keys::generate();
        let reminder = |created_at: u64, d_tag: &str, not_before: i64, content: &str| {
            EventBuilder::new(
                Kind::Custom(buzz_core::kind::KIND_EVENT_REMINDER as u16),
                content,
            )
            .tags([
                Tag::parse(["d", d_tag]).unwrap(),
                Tag::parse(["not_before", &not_before.to_string()]).unwrap(),
            ])
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(&keys)
            .unwrap()
        };
        let old = reminder(100, "same", 50, "old");
        let latest = reminder(101, "same", 50, "latest");
        let future = reminder(102, "future", 500, "future");
        for (community, event) in [(a, &old), (a, &latest), (a, &future), (b, &latest)] {
            insert_event(&pool, community, event, None).await.unwrap();
        }

        let due = query_due_reminders(&pool, 100, 100).await.unwrap();
        assert_eq!(due.len(), 2);
        assert!(due.iter().all(|row| row.id == latest.id.as_bytes()));
        assert_eq!(due.iter().filter(|row| row.community_id == a).count(), 1);
        assert_eq!(due.iter().filter(|row| row.community_id == b).count(), 1);
        assert!(due.iter().all(|row| row.content == "latest"));

        let created_at = chrono::DateTime::from_timestamp(101, 0).unwrap();
        assert!(
            claim_due_reminder_with_stamp(&pool, a, latest.id.as_bytes(), created_at, 7)
                .await
                .unwrap()
        );
        assert!(
            !claim_due_reminder_with_stamp(&pool, a, latest.id.as_bytes(), created_at, 8)
                .await
                .unwrap()
        );
        assert!(
            claim_due_reminder_with_stamp(&pool, b, latest.id.as_bytes(), created_at, 8)
                .await
                .unwrap()
        );
        assert!(
            !release_due_reminder(&pool, a, latest.id.as_bytes(), created_at, 8)
                .await
                .unwrap()
        );
        assert!(
            release_due_reminder(&pool, a, latest.id.as_bytes(), created_at, 7)
                .await
                .unwrap()
        );
        assert!(
            claim_due_reminder_with_stamp(&pool, a, latest.id.as_bytes(), created_at, 9)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn discovery_delete_is_channel_relay_kind_and_tenant_scoped() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let a = ensure_configured_community(&pool, "discovery-a.example")
            .await
            .unwrap()
            .id;
        let b = ensure_configured_community(&pool, "discovery-b.example")
            .await
            .unwrap()
            .id;
        let relay = Keys::generate();
        let other = Keys::generate();
        let channel = Uuid::new_v4();
        let other_channel = Uuid::new_v4();
        let mut events = Vec::new();
        for (index, kind, keys, channel_id, community) in [
            (0, 39000, &relay, channel, a),
            (1, 39001, &relay, channel, a),
            (2, 39002, &relay, channel, a),
            (3, 9, &relay, channel, a),
            (4, 39000, &relay, other_channel, a),
            (5, 39000, &other, channel, a),
            (6, 39000, &relay, channel, b),
        ] {
            let event = EventBuilder::new(Kind::Custom(kind), format!("discovery-{index}"))
                .custom_created_at(Timestamp::from(100 + index as u64))
                .sign_with_keys(keys)
                .unwrap();
            insert_event(&pool, community, &event, Some(channel_id))
                .await
                .unwrap();
            events.push((community, event));
        }
        assert_eq!(
            soft_delete_discovery_events(&pool, a, channel, &relay.public_key().to_bytes())
                .await
                .unwrap(),
            3
        );
        for (index, (community, event)) in events.iter().enumerate() {
            assert_eq!(
                get_event_by_id(&pool, *community, event.id.as_bytes())
                    .await
                    .unwrap()
                    .is_some(),
                index >= 3
            );
        }
    }

    #[tokio::test]
    async fn direct_event_helpers_match_count_order_scope_and_delete_contracts() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let a = ensure_configured_community(&pool, "events-a.example")
            .await
            .unwrap()
            .id;
        let b = ensure_configured_community(&pool, "events-b.example")
            .await
            .unwrap()
            .id;
        let keys = Keys::generate();
        let other = Keys::generate();
        let channel = Uuid::new_v4();
        let ephemeral = Uuid::new_v4();
        let d_tag = "coordinate";
        let global_old = EventBuilder::new(Kind::Custom(30023), "old")
            .tags([Tag::parse(["d", d_tag]).unwrap()])
            .custom_created_at(Timestamp::from(100_u64))
            .sign_with_keys(&keys)
            .unwrap();
        let global_new = EventBuilder::new(Kind::Custom(30023), "new")
            .tags([Tag::parse(["d", d_tag]).unwrap()])
            .custom_created_at(Timestamp::from(101_u64))
            .sign_with_keys(&keys)
            .unwrap();
        let channel_event = EventBuilder::new(Kind::Custom(9), "channel")
            .custom_created_at(Timestamp::from(102_u64))
            .sign_with_keys(&keys)
            .unwrap();
        let huddle = EventBuilder::new(
            Kind::Custom(buzz_core::kind::KIND_HUDDLE_STARTED as u16),
            serde_json::json!({"ephemeral_channel_id": ephemeral}).to_string(),
        )
        .custom_created_at(Timestamp::from(103_u64))
        .sign_with_keys(&keys)
        .unwrap();
        let second_d_only = EventBuilder::new(Kind::Custom(30024), "second d")
            .tags([
                Tag::parse(["d", "first-coordinate"]).unwrap(),
                Tag::parse(["d", d_tag]).unwrap(),
            ])
            .custom_created_at(Timestamp::from(104_u64))
            .sign_with_keys(&keys)
            .unwrap();
        let non_parameterized_d = EventBuilder::new(Kind::Custom(9), "not nip33")
            .tags([Tag::parse(["d", d_tag]).unwrap()])
            .custom_created_at(Timestamp::from(105_u64))
            .sign_with_keys(&keys)
            .unwrap();
        for (community, event, channel_id) in [
            (a, &global_old, None),
            (a, &global_new, None),
            (a, &channel_event, Some(channel)),
            (a, &huddle, Some(channel)),
            (a, &second_d_only, None),
            (a, &non_parameterized_d, None),
            (b, &global_new, None),
        ] {
            insert_event(&pool, community, event, channel_id)
                .await
                .unwrap();
        }

        let mut query = crate::EventQuery::for_community(a);
        query.limit = Some(1);
        query.offset = Some(1);
        assert_eq!(count_events(&pool, &query).await.unwrap(), 6);
        query.global_only = true;
        query.offset = None;
        assert_eq!(count_events(&pool, &query).await.unwrap(), 4);
        assert_eq!(
            get_latest_global_replaceable(&pool, a, 30023, &keys.public_key().to_bytes())
                .await
                .unwrap()
                .unwrap()
                .event
                .id,
            global_new.id
        );
        assert!(
            get_latest_global_replaceable(&pool, a, 30023, &other.public_key().to_bytes())
                .await
                .unwrap()
                .is_none()
        );
        assert!(huddle_started_link_exists(
            &pool,
            a,
            channel,
            ephemeral,
            &keys.public_key().to_bytes()
        )
        .await
        .unwrap());
        for created_at in 104_u64..137 {
            let noise = EventBuilder::new(
                Kind::Custom(buzz_core::kind::KIND_HUDDLE_STARTED as u16),
                serde_json::json!({"ephemeral_channel_id": Uuid::new_v4()}).to_string(),
            )
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(&keys)
            .unwrap();
            insert_event(&pool, a, &noise, Some(channel)).await.unwrap();
        }
        assert!(huddle_started_link_exists(
            &pool,
            a,
            channel,
            ephemeral,
            &keys.public_key().to_bytes()
        )
        .await
        .unwrap());
        assert!(!huddle_started_link_exists(
            &pool,
            b,
            channel,
            ephemeral,
            &keys.public_key().to_bytes()
        )
        .await
        .unwrap());
        assert_eq!(
            get_last_message_at(&pool, a, channel)
                .await
                .unwrap()
                .unwrap()
                .timestamp(),
            136
        );
        let bulk = get_last_message_at_bulk(&pool, a, &[channel, Uuid::new_v4()])
            .await
            .unwrap();
        assert_eq!(bulk.len(), 1);
        assert_eq!(bulk[&channel].timestamp(), 136);
        assert!(
            soft_delete_by_coordinate(&pool, a, 30023, &keys.public_key().to_bytes(), d_tag)
                .await
                .unwrap()
        );
        assert!(
            !soft_delete_by_coordinate(&pool, a, 30023, &keys.public_key().to_bytes(), d_tag)
                .await
                .unwrap()
        );
        assert!(get_event_by_id(&pool, a, global_new.id.as_bytes())
            .await
            .unwrap()
            .is_none());
        assert!(get_event_by_id(&pool, a, second_d_only.id.as_bytes())
            .await
            .unwrap()
            .is_some());
        assert!(get_event_by_id(&pool, a, non_parameterized_d.id.as_bytes())
            .await
            .unwrap()
            .is_some());
        assert!(get_event_by_id(&pool, b, global_new.id.as_bytes())
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn user_nip05_and_search_match_scope_ranking_and_literal_like_contracts() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let a = ensure_configured_community(&pool, "users-a.example")
            .await
            .unwrap()
            .id;
        let b = ensure_configured_community(&pool, "users-b.example")
            .await
            .unwrap()
            .id;
        let exact_name = vec![0x10_u8; 32];
        let exact_nip05 = vec![0x20_u8; 32];
        let prefix_name = vec![0x30_u8; 32];
        let wildcard_name = vec![0x40_u8; 32];
        let other_tenant = vec![0x50_u8; 32];
        let unicode_name = vec![0x60_u8; 32];
        let backslash_name = vec![0x70_u8; 32];

        for pubkey in [
            &exact_name,
            &exact_nip05,
            &prefix_name,
            &wildcard_name,
            &unicode_name,
            &backslash_name,
        ] {
            ensure_user(&pool, a, pubkey).await.unwrap();
        }
        ensure_user(&pool, b, &other_tenant).await.unwrap();
        update_user_profile(
            &pool,
            a,
            &exact_name,
            Some("Alice"),
            Some("alice.png"),
            Some("first"),
            Some("name@example.com"),
        )
        .await
        .unwrap();
        update_user_profile(
            &pool,
            a,
            &exact_nip05,
            Some("Elsewhere"),
            None,
            None,
            Some("alice"),
        )
        .await
        .unwrap();
        update_user_profile(
            &pool,
            a,
            &prefix_name,
            Some("Alice Cooper"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        update_user_profile(
            &pool,
            a,
            &wildcard_name,
            Some("100%_literal"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        update_user_profile(
            &pool,
            a,
            &unicode_name,
            Some("Älice"),
            None,
            None,
            Some("Üser@example.com"),
        )
        .await
        .unwrap();
        update_user_profile(
            &pool,
            a,
            &backslash_name,
            Some(r"path\user"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        update_user_profile(
            &pool,
            b,
            &other_tenant,
            Some("Other Tenant"),
            None,
            None,
            Some("only-other@example.com"),
        )
        .await
        .unwrap();

        let nip05 = get_user_by_nip05(&pool, a, "NAME", "EXAMPLE.COM")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(nip05.pubkey, exact_name);
        assert_eq!(nip05.about.as_deref(), Some("first"));
        assert_eq!(
            get_user_by_nip05(&pool, a, "ÜSER", "EXAMPLE.COM")
                .await
                .unwrap()
                .unwrap()
                .pubkey,
            unicode_name
        );
        assert!(get_user_by_nip05(&pool, a, "only-other", "example.com")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            get_user_by_nip05(&pool, b, "only-other", "example.com")
                .await
                .unwrap()
                .unwrap()
                .pubkey,
            other_tenant
        );

        let ranked = search_users(&pool, a, "  ALICE  ", 20).await.unwrap();
        assert_eq!(
            ranked
                .iter()
                .map(|profile| profile.pubkey.clone())
                .collect::<Vec<_>>(),
            vec![exact_name.clone(), exact_nip05.clone(), prefix_name]
        );
        assert!(search_users(&pool, a, " ", 20).await.unwrap().is_empty());
        assert_eq!(
            search_users(&pool, a, "%_", 20)
                .await
                .unwrap()
                .into_iter()
                .map(|profile| profile.pubkey)
                .collect::<Vec<_>>(),
            vec![wildcard_name]
        );
        assert_eq!(
            search_users(&pool, a, "ÄLICE", 20)
                .await
                .unwrap()
                .into_iter()
                .map(|profile| profile.pubkey)
                .collect::<Vec<_>>(),
            vec![unicode_name]
        );
        assert_eq!(
            search_users(&pool, a, r"path\user", 20)
                .await
                .unwrap()
                .into_iter()
                .map(|profile| profile.pubkey)
                .collect::<Vec<_>>(),
            vec![backslash_name]
        );
        assert!(search_users(&pool, a, "other tenant", 20)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            search_users(&pool, a, "1010", 20)
                .await
                .unwrap()
                .into_iter()
                .map(|profile| profile.pubkey)
                .collect::<Vec<_>>(),
            vec![exact_name]
        );
        assert_eq!(search_users(&pool, a, "alice", 0).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dm_create_list_hide_and_scope_match_contract() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let a = ensure_configured_community(&pool, "dm-a.example")
            .await
            .unwrap()
            .id;
        let b = ensure_configured_community(&pool, "dm-b.example")
            .await
            .unwrap()
            .id;
        let owner = vec![1_u8; 32];
        let peer = vec![2_u8; 32];
        let participants = [owner.as_slice(), peer.as_slice()];
        ensure_user(&pool, a, &owner).await.unwrap();
        ensure_user(&pool, a, &peer).await.unwrap();
        update_user_profile(&pool, a, &peer, Some("Peer"), None, None, None)
            .await
            .unwrap();
        let first = create_dm(&pool, a, &participants, &owner).await.unwrap();
        let second = create_dm(&pool, a, &participants, &owner).await.unwrap();
        assert_eq!(first.id, second.id);
        let hash = crate::dm::compute_participant_hash(&participants);
        assert_eq!(
            find_dm_by_participants(&pool, a, &hash)
                .await
                .unwrap()
                .unwrap()
                .id,
            first.id
        );
        assert!(find_dm_by_participants(&pool, b, &hash)
            .await
            .unwrap()
            .is_none());
        let listed = list_dms_for_user(&pool, a, &owner, 20, None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0]
            .participants
            .iter()
            .any(|p| p.display_name.as_deref() == Some("Peer")));
        hide_dm(&pool, a, first.id, &owner).await.unwrap();
        assert!(list_dms_for_user(&pool, a, &owner, 20, None)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            list_hidden_dms(&pool, a, &owner).await.unwrap(),
            vec![first.id]
        );
        unhide_dm(&pool, a, first.id, &owner).await.unwrap();
        assert_eq!(
            list_dms_for_user(&pool, a, &owner, 20, None)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(create_dm(&pool, a, &[owner.as_slice()], &owner)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn git_repo_names_are_scoped_idempotent_and_owner_released() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let a = ensure_configured_community(&pool, "git-a.example")
            .await
            .unwrap()
            .id;
        let b = ensure_configured_community(&pool, "git-b.example")
            .await
            .unwrap()
            .id;
        assert_eq!(
            reserve_repo_name(&pool, a, "project", "alice")
                .await
                .unwrap(),
            crate::git_repo::ReserveOutcome::Reserved
        );
        assert_eq!(
            reserve_repo_name(&pool, a, "project", "alice")
                .await
                .unwrap(),
            crate::git_repo::ReserveOutcome::AlreadyOwned
        );
        assert_eq!(
            reserve_repo_name(&pool, a, "project", "bob").await.unwrap(),
            crate::git_repo::ReserveOutcome::TakenByOther
        );
        assert_eq!(
            reserve_repo_name(&pool, b, "project", "bob").await.unwrap(),
            crate::git_repo::ReserveOutcome::Reserved
        );
        assert_eq!(
            repo_name_owner(&pool, a, "project")
                .await
                .unwrap()
                .as_deref(),
            Some("alice")
        );
        assert_eq!(count_repos_for_owner(&pool, a, "alice").await.unwrap(), 1);
        assert_eq!(
            release_repo_name(&pool, a, "project", "bob").await.unwrap(),
            0
        );
        assert_eq!(
            release_repo_name(&pool, a, "project", "alice")
                .await
                .unwrap(),
            1
        );
        assert!(repo_name_owner(&pool, a, "project")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            repo_name_owner(&pool, b, "project")
                .await
                .unwrap()
                .as_deref(),
            Some("bob")
        );
    }

    #[tokio::test]
    async fn archived_identities_are_idempotent_and_community_scoped() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let a = ensure_configured_community(&pool, "archive-a.example")
            .await
            .unwrap()
            .id;
        let b = ensure_configured_community(&pool, "archive-b.example")
            .await
            .unwrap()
            .id;
        let pubkey = "aa".repeat(32);
        let actor = "bb".repeat(32);
        let event = "cc".repeat(32);
        assert!(archive(
            &pool,
            a,
            &pubkey,
            "self",
            &actor,
            Some("reason"),
            None,
            &event
        )
        .await
        .unwrap());
        assert!(
            !archive(&pool, a, &pubkey, "self", &actor, None, None, &event)
                .await
                .unwrap()
        );
        assert!(is_archived(&pool, a, &pubkey).await.unwrap());
        assert!(!is_archived(&pool, b, &pubkey).await.unwrap());
        assert_eq!(list_archived(&pool, a).await.unwrap().len(), 1);
        assert!(list_archived(&pool, b).await.unwrap().is_empty());
        assert!(!unarchive(&pool, b, &pubkey).await.unwrap());
        assert!(unarchive(&pool, a, &pubkey).await.unwrap());
        assert!(!unarchive(&pool, a, &pubkey).await.unwrap());
    }

    #[tokio::test]
    async fn dm_helpers_are_idempotent_hidden_and_community_scoped() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "dm.example")
            .await
            .unwrap()
            .id;
        let foreign = ensure_configured_community(&pool, "dm-foreign.example")
            .await
            .unwrap()
            .id;
        let alice = vec![1_u8; 32];
        let bob = vec![2_u8; 32];
        let participants = [alice.as_slice(), bob.as_slice()];
        let first = create_dm(&pool, community, &participants, &alice)
            .await
            .unwrap();
        let second = create_dm(&pool, community, &participants, &alice)
            .await
            .unwrap();
        assert_eq!(first.id, second.id);
        let hash = crate::dm::compute_participant_hash(&participants);
        assert_eq!(
            find_dm_by_participants(&pool, community, &hash)
                .await
                .unwrap()
                .unwrap()
                .id,
            first.id
        );
        assert!(find_dm_by_participants(&pool, foreign, &hash)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            list_dms_for_user(&pool, community, &alice, 10, None)
                .await
                .unwrap()
                .len(),
            1
        );
        hide_dm(&pool, community, first.id, &alice).await.unwrap();
        assert!(list_dms_for_user(&pool, community, &alice, 10, None)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            list_hidden_dms(&pool, community, &alice).await.unwrap(),
            vec![first.id]
        );
        unhide_dm(&pool, community, first.id, &alice).await.unwrap();
        assert_eq!(
            list_dms_for_user(&pool, community, &alice, 10, None)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn reaction_helpers_preserve_dedupe_aggregation_and_tenant_scope() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "reactions.example")
            .await
            .unwrap()
            .id;
        let foreign = ensure_configured_community(&pool, "foreign.example")
            .await
            .unwrap()
            .id;
        let target = vec![1_u8; 32];
        let actor = vec![2_u8; 32];
        let source = vec![3_u8; 32];
        let at = chrono::DateTime::from_timestamp(100, 0).unwrap();
        assert!(
            add_reaction(&pool, community, &target, at, &actor, "👍", None)
                .await
                .unwrap()
        );
        assert!(
            !add_reaction(&pool, community, &target, at, &actor, "👍", None)
                .await
                .unwrap()
        );
        assert!(
            set_reaction_event_id(&pool, community, &target, at, &actor, "👍", &source)
                .await
                .unwrap()
        );
        assert_eq!(
            get_active_reaction_record(&pool, community, &target, at, &actor, "👍")
                .await
                .unwrap()
                .unwrap()
                .reaction_event_id,
            Some(source)
        );
        let groups = get_reactions(&pool, community, &target, at, 10, None)
            .await
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count, 1);
        assert!(get_reactions(&pool, foreign, &target, at, 10, None)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            get_reactions_bulk(&pool, community, &[(&target, at)])
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(remove_reaction(&pool, community, &target, at, &actor, "👍")
            .await
            .unwrap());
        assert!(get_reactions(&pool, community, &target, at, 10, None)
            .await
            .unwrap()
            .is_empty());
        assert!(
            add_reaction(&pool, community, &target, at, &actor, "👍", None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn product_feedback_is_deployment_idempotent_with_first_provenance() {
        let pool = connect(":memory:").await.unwrap();
        let first = ensure_configured_community(&pool, "feedback-first.local")
            .await
            .unwrap()
            .id;
        let second = ensure_configured_community(&pool, "feedback-second.local")
            .await
            .unwrap()
            .id;
        let event_id = vec![21_u8; 32];
        let submitter = vec![22_u8; 32];
        let tags = serde_json::json!([["category", "bug"]]);
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let feedback = || crate::product_feedback::NewProductFeedback {
            event_id: &event_id,
            submitter_pubkey: &submitter,
            category: Some("bug"),
            body: "same signed feedback",
            tags: &tags,
            event_created_at: created_at,
        };

        let first_id = insert_product_feedback(&pool, first, feedback())
            .await
            .unwrap();
        let replay_id = insert_product_feedback(&pool, second, feedback())
            .await
            .unwrap();
        assert_eq!(replay_id, first_id);

        let rows = list_product_feedback(&pool, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].community_id, *first.as_uuid());
        assert_eq!(rows[0].event_id, hex::encode(&event_id));
        assert_eq!(rows[0].tags, tags);

        let admin = admin_get_feedback(&pool, first_id).await.unwrap().unwrap();
        assert_eq!(admin.community_id, *first.as_uuid());
        assert_eq!(admin.community_host, "feedback-first.local");
        assert_eq!(admin_list_feedback(&pool, 0).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn admin_report_reads_filter_and_preserve_tenant_event_join() {
        let pool = connect(":memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "reports.local")
            .await
            .unwrap()
            .id;
        let foreign = ensure_configured_community(&pool, "reports-foreign.local")
            .await
            .unwrap()
            .id;
        let report_id = Uuid::new_v4();
        let target = vec![31_u8; 32];
        let author = vec![32_u8; 32];
        sqlx::query("INSERT INTO events (community_id,id,pubkey,created_at,kind,tags_json,content,sig,received_at,event_json) VALUES (?1,?2,?3,100,9,'[]','reported message',?4,100,'{}')")
            .bind(community.as_uuid().to_string())
            .bind(&target)
            .bind(&author)
            .bind(vec![33_u8; 64])
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO moderation_reports (id,community_id,report_event_id,reporter_pubkey,target_kind,target_event_id,report_type) VALUES (?1,?2,?3,?4,'event',?5,'spam')")
            .bind(report_id.to_string())
            .bind(community.as_uuid().to_string())
            .bind(vec![34_u8; 32])
            .bind(vec![35_u8; 32])
            .bind(&target)
            .execute(&pool)
            .await
            .unwrap();

        assert!(admin_list_reports(
            &pool,
            Some(*foreign.as_uuid()),
            None,
            None,
            None,
            None,
            None,
            None,
            10,
        )
        .await
        .unwrap()
        .is_empty());
        let reports = admin_list_reports(
            &pool,
            Some(*community.as_uuid()),
            Some("open"),
            Some("spam"),
            Some("event"),
            None,
            None,
            None,
            10,
        )
        .await
        .unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].target, hex::encode(&target));

        let detail = admin_get_report(&pool, report_id).await.unwrap().unwrap();
        let message = detail.message.unwrap();
        assert_eq!(message.author_pubkey, hex::encode(author));
        assert_eq!(message.content, "reported message");
        assert_eq!(message.deleted_at, None);
    }

    #[tokio::test]
    async fn moderation_mutations_restrictions_and_audit_are_scoped() {
        let pool = connect(":memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "moderation.local")
            .await
            .unwrap()
            .id;
        let foreign = ensure_configured_community(&pool, "moderation-foreign.local")
            .await
            .unwrap()
            .id;
        let report_event = vec![41_u8; 32];
        let reporter = vec![42_u8; 32];
        let target = vec![43_u8; 32];
        let actor = vec![44_u8; 32];
        let report = || crate::moderation::NewReport {
            report_event_id: &report_event,
            reporter_pubkey: &reporter,
            target: crate::moderation::ReportTarget::Event(target.clone()),
            channel_id: None,
            report_type: "spam",
            note: Some("first note"),
        };
        let id = insert_moderation_report(&pool, community, report())
            .await
            .unwrap();
        assert_eq!(
            insert_moderation_report(&pool, community, report())
                .await
                .unwrap(),
            id
        );
        assert_eq!(
            list_moderation_reports(&pool, community, Some("open"), 10)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            get_moderation_report_by_event(&pool, foreign, &report_event)
                .await
                .unwrap()
                .is_none()
        );

        let action_id = insert_moderation_action(
            &pool,
            community,
            crate::moderation::NewAction {
                actor_pubkey: &actor,
                action: "resolve:ban",
                target_pubkey: Some(&target),
                target_event_id: None,
                channel_id: None,
                reason_code: Some("spam"),
                public_reason: None,
                private_reason: Some("audit context"),
                matched_principal: Some("self"),
            },
        )
        .await
        .unwrap();
        assert!(resolve_moderation_report(
            &pool,
            community,
            id,
            "resolved",
            &actor,
            Some(action_id)
        )
        .await
        .unwrap());
        assert!(
            !resolve_moderation_report(&pool, community, id, "dismissed", &actor, None)
                .await
                .unwrap()
        );
        assert_eq!(
            get_moderation_report(&pool, community, id)
                .await
                .unwrap()
                .unwrap()
                .status,
            "resolved"
        );

        let expired = chrono::Utc::now() - chrono::Duration::seconds(10);
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        ban_member(
            &pool,
            community,
            &target,
            &actor,
            Some("expired"),
            Some(expired),
        )
        .await
        .unwrap();
        timeout_member(&pool, community, &target, &actor, future, Some("active"))
            .await
            .unwrap();
        let state = restriction_state(&pool, community, &target).await.unwrap();
        assert!(!state.banned);
        assert_eq!(
            state.muted_until.map(|v| v.timestamp()),
            Some(future.timestamp())
        );
        assert_eq!(list_restricted(&pool, community).await.unwrap().len(), 1);
        assert!(list_restricted(&pool, foreign).await.unwrap().is_empty());
        assert!(untimeout_member(&pool, community, &target, &actor)
            .await
            .unwrap());
        assert!(!untimeout_member(&pool, community, &target, &actor)
            .await
            .unwrap());
        ban_member(&pool, community, &target, &actor, None, None)
            .await
            .unwrap();
        assert!(
            restriction_state(&pool, community, &target)
                .await
                .unwrap()
                .banned
        );
        assert!(unban_member(&pool, community, &target, &actor)
            .await
            .unwrap());
        assert!(!unban_member(&pool, community, &target, &actor)
            .await
            .unwrap());
        assert_eq!(
            list_moderation_actions(&pool, community, 10).await.unwrap()[0].id,
            action_id
        );
        assert!(list_moderation_actions(&pool, foreign, 10)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn thread_metadata_counters_are_idempotent_scoped_and_clamped() {
        let pool = connect(":memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "threads.local")
            .await
            .unwrap()
            .id;
        let foreign = ensure_configured_community(&pool, "foreign.local")
            .await
            .unwrap()
            .id;
        let channel = Uuid::new_v4();
        sqlx::query("INSERT INTO channels (id,community_id,name,channel_type,visibility,created_by) VALUES (?1,?2,'threads','stream','private',?3)")
            .bind(channel.to_string()).bind(community.as_uuid().to_string()).bind(vec![1_u8; 32]).execute(&pool).await.unwrap();
        let root = vec![2_u8; 32];
        let reply = vec![3_u8; 32];
        let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();

        insert_thread_metadata(
            &pool,
            community,
            &reply,
            at,
            channel,
            Some(&root),
            Some(at),
            Some(&root),
            Some(at),
            1,
            false,
        )
        .await
        .unwrap();
        // Duplicate ingestion must not double-count.
        insert_thread_metadata(
            &pool,
            community,
            &reply,
            at,
            channel,
            Some(&root),
            Some(at),
            Some(&root),
            Some(at),
            1,
            false,
        )
        .await
        .unwrap();

        let root_meta = get_thread_metadata_by_event(&pool, community, &root)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((root_meta.reply_count, root_meta.descendant_count), (1, 1));
        assert!(get_thread_metadata_by_event(&pool, foreign, &root)
            .await
            .unwrap()
            .is_none());
        let summary = get_thread_summary(&pool, community, &root)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((summary.reply_count, summary.descendant_count), (1, 1));

        decrement_reply_count(&pool, community, &root, Some(&root))
            .await
            .unwrap();
        decrement_reply_count(&pool, community, &root, Some(&root))
            .await
            .unwrap();
        let summary = get_thread_summary(&pool, community, &root)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((summary.reply_count, summary.descendant_count), (0, 0));
    }

    #[tokio::test]
    async fn relay_invites_preserve_claim_scope_limits_policy_and_retention() {
        let pool = connect(":memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "invites.local")
            .await
            .unwrap()
            .id;
        let foreign = ensure_configured_community(&pool, "foreign-invites.local")
            .await
            .unwrap()
            .id;
        let now = chrono::Utc::now().timestamp();
        let bounded = [7_u8; 32];
        sqlx::query("INSERT INTO relay_invites (community_id,id,token_hash,max_uses,expires_at,created_by) VALUES (?1,?2,?3,1,?4,'owner')")
            .bind(community.as_uuid().to_string()).bind(Uuid::new_v4().to_string()).bind(bounded.as_slice()).bind(now + 3600).execute(&pool).await.unwrap();

        assert_eq!(
            claim_relay_invite(&pool, foreign, &bounded, "alice", None)
                .await
                .unwrap(),
            crate::relay_invite::ClaimOutcome::Invalid
        );
        assert_eq!(
            claim_relay_invite(&pool, community, &bounded, "alice", Some("v1"))
                .await
                .unwrap(),
            crate::relay_invite::ClaimOutcome::Joined {
                use_count: 1,
                uses_remaining: Some(0)
            }
        );
        assert_eq!(
            claim_relay_invite(&pool, community, &bounded, "alice", Some("v1"))
                .await
                .unwrap(),
            crate::relay_invite::ClaimOutcome::AlreadyMember {
                use_count: 1,
                uses_remaining: Some(0)
            }
        );
        assert_eq!(
            claim_relay_invite(&pool, community, &bounded, "bob", None)
                .await
                .unwrap(),
            crate::relay_invite::ClaimOutcome::Exhausted
        );
        assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM join_policy_acceptances WHERE community_id=?1 AND pubkey='alice' AND policy_version='v1'").bind(community.as_uuid().to_string()).fetch_one(&pool).await.unwrap(), 1);

        let unlimited = [8_u8; 32];
        sqlx::query("INSERT INTO relay_invites (community_id,id,token_hash,max_uses,expires_at,created_by) VALUES (?1,?2,?3,NULL,?4,'owner')")
            .bind(community.as_uuid().to_string()).bind(Uuid::new_v4().to_string()).bind(unlimited.as_slice()).bind(now + 3600).execute(&pool).await.unwrap();
        assert_eq!(
            claim_relay_invite(&pool, community, &unlimited, "carol", None)
                .await
                .unwrap(),
            crate::relay_invite::ClaimOutcome::Joined {
                use_count: 1,
                uses_remaining: None
            }
        );
        assert_eq!(
            claim_relay_invite(&pool, community, &unlimited, "dave", None)
                .await
                .unwrap(),
            crate::relay_invite::ClaimOutcome::Joined {
                use_count: 2,
                uses_remaining: None
            }
        );

        let expired = [9_u8; 32];
        sqlx::query("INSERT INTO relay_invites (community_id,id,token_hash,max_uses,expires_at,created_by) VALUES (?1,?2,?3,1,?4,'owner')")
            .bind(community.as_uuid().to_string()).bind(Uuid::new_v4().to_string()).bind(expired.as_slice()).bind(now - 10).execute(&pool).await.unwrap();
        assert_eq!(
            claim_relay_invite(&pool, community, &expired, "erin", None)
                .await
                .unwrap(),
            crate::relay_invite::ClaimOutcome::Expired
        );
        assert_eq!(
            reap_expired_relay_invites(&pool, chrono::Utc::now())
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn workflow_crud_runs_approvals_and_schedule_are_scoped() {
        let pool = connect(":memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "workflow.local")
            .await
            .unwrap()
            .id;
        let foreign = ensure_configured_community(&pool, "workflow-foreign.local")
            .await
            .unwrap()
            .id;
        let owner = vec![51_u8; 32];
        ensure_user(&pool, community, &owner).await.unwrap();
        ensure_user(&pool, foreign, &owner).await.unwrap();
        let hash = vec![52_u8; 32];
        let definition = r#"{"trigger":{"on":"schedule"},"steps":[]}"#;
        let workflow_id =
            create_workflow(&pool, community, None, &owner, "daily", definition, &hash)
                .await
                .unwrap();
        assert!(get_workflow(&pool, foreign, workflow_id).await.is_err());
        assert_eq!(list_all_enabled_workflows(&pool).await.unwrap().len(), 1);

        let scheduled = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        assert!(
            claim_scheduled_workflow_fire(&pool, community, workflow_id, scheduled)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            claim_scheduled_workflow_fire(&pool, community, workflow_id, scheduled)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            latest_scheduled_workflow_fire(&pool, community, workflow_id)
                .await
                .unwrap(),
            Some(scheduled)
        );

        let context = serde_json::json!({"channel":"local"});
        let run_id = create_workflow_run(
            &pool,
            community,
            workflow_id,
            Some(&[53_u8; 32]),
            Some(&context),
        )
        .await
        .unwrap();
        assert!(
            attach_scheduled_workflow_run(&pool, community, workflow_id, scheduled, run_id)
                .await
                .unwrap()
        );
        assert!(
            !attach_scheduled_workflow_run(&pool, community, workflow_id, scheduled, run_id)
                .await
                .unwrap()
        );
        update_workflow_run(
            &pool,
            community,
            run_id,
            crate::workflow::RunStatus::Running,
            1,
            &serde_json::json!([{"step":0}]),
            None,
        )
        .await
        .unwrap();
        let run = get_workflow_run(&pool, community, run_id).await.unwrap();
        assert_eq!(run.trigger_context, Some(context));
        assert!(run.started_at.is_some());

        let expires = chrono::Utc::now() + chrono::Duration::hours(1);
        create_approval(
            &pool,
            crate::workflow::CreateApprovalParams {
                community_id: community,
                token: "secret",
                workflow_id,
                run_id,
                step_id: "approve",
                step_index: 1,
                approver_spec: "owner",
                expires_at: expires,
            },
        )
        .await
        .unwrap();
        assert!(get_approval(&pool, foreign, "secret").await.is_err());
        assert!(update_approval(
            &pool,
            community,
            "secret",
            crate::workflow::ApprovalStatus::Granted,
            Some(&owner),
            Some("ok")
        )
        .await
        .unwrap());
        assert!(!update_approval(
            &pool,
            community,
            "secret",
            crate::workflow::ApprovalStatus::Denied,
            Some(&owner),
            None
        )
        .await
        .unwrap());
        assert_eq!(
            get_run_approvals(&pool, community, workflow_id, run_id)
                .await
                .unwrap()[0]
                .status,
            crate::workflow::ApprovalStatus::Granted
        );
        delete_workflow(&pool, community, workflow_id)
            .await
            .unwrap();
        assert!(get_workflow_run(&pool, community, run_id).await.is_err());
    }

    #[tokio::test]
    async fn channel_lifecycle_bulk_canvas_and_reaper_match_contracts() {
        use crate::channel::{ChannelType, ChannelUpdate, ChannelVisibility, MemberRole};

        let pool = connect(":memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "channels.local")
            .await
            .unwrap()
            .id;
        let foreign = ensure_configured_community(&pool, "channels-foreign.local")
            .await
            .unwrap()
            .id;
        let owner = vec![61_u8; 32];
        let member = vec![62_u8; 32];
        ensure_user(&pool, community, &owner).await.unwrap();
        ensure_user(&pool, community, &member).await.unwrap();
        ensure_user(&pool, foreign, &owner).await.unwrap();

        let channel = create_channel(
            &pool,
            community,
            "  Field Operations  ",
            ChannelType::Stream,
            ChannelVisibility::Private,
            Some("initial"),
            &owner,
            Some(60),
        )
        .await
        .unwrap();
        assert_eq!(channel.name, "Field Operations");
        assert_eq!(
            get_member_count(&pool, community, channel.id)
                .await
                .unwrap(),
            1
        );
        assert!(get_channel(&pool, foreign, channel.id).await.is_err());

        set_canvas(&pool, community, channel.id, Some("# Plan"))
            .await
            .unwrap();
        assert_eq!(
            get_canvas(&pool, community, channel.id).await.unwrap(),
            Some("# Plan".into())
        );
        assert_eq!(get_canvas(&pool, foreign, channel.id).await.unwrap(), None);

        add_member(
            &pool,
            community,
            channel.id,
            &member,
            MemberRole::Member,
            Some(&owner),
        )
        .await
        .unwrap();
        assert_eq!(
            membership_pairs(
                &pool,
                community,
                &[channel.id],
                &[owner.clone(), member.clone()]
            )
            .await
            .unwrap()
            .len(),
            2
        );
        assert_eq!(
            get_members_bulk(&pool, community, &[channel.id])
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            get_member_counts_bulk(&pool, community, &[channel.id])
                .await
                .unwrap()
                .get(&channel.id),
            Some(&2)
        );
        assert_eq!(
            get_users_bulk(&pool, community, &[owner.clone(), member.clone()])
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            get_accessible_channels(&pool, community, &member, None, Some(true))
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            list_channels(&pool, community, Some("private"))
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(list_channels(&pool, foreign, None)
            .await
            .unwrap()
            .is_empty());

        let updated = update_channel(
            &pool,
            community,
            channel.id,
            ChannelUpdate {
                name: Some("Renamed Channel".into()),
                description: Some("updated".into()),
                visibility: Some("open".into()),
                ttl_seconds: Some(None),
            },
        )
        .await
        .unwrap();
        assert_eq!(updated.name, "Renamed Channel");
        assert_eq!(updated.description.as_deref(), Some("updated"));
        assert_eq!(updated.visibility, "open");
        assert_eq!(updated.ttl_seconds, None);
        assert_eq!(updated.ttl_deadline, None);

        archive_channel(&pool, community, channel.id).await.unwrap();
        assert!(archive_channel(&pool, community, channel.id).await.is_err());
        unarchive_channel(&pool, community, channel.id)
            .await
            .unwrap();
        assert!(unarchive_channel(&pool, community, channel.id)
            .await
            .is_err());
        remove_member(&pool, community, channel.id, &member, &owner)
            .await
            .unwrap();
        assert_eq!(
            get_member_count(&pool, community, channel.id)
                .await
                .unwrap(),
            1
        );

        let expiring = create_channel(
            &pool,
            community,
            "temporary",
            ChannelType::Stream,
            ChannelVisibility::Open,
            None,
            &owner,
            Some(1),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE channels SET ttl_deadline=0 WHERE community_id=?1 AND id=?2")
            .bind(community.as_uuid().to_string())
            .bind(expiring.id.to_string())
            .execute(&pool)
            .await
            .unwrap();
        let reaped = reap_expired_ephemeral_channels(&pool).await.unwrap();
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].community_id, community);
        assert_eq!(reaped[0].host, "channels.local");
        assert_eq!(reaped[0].channel_id, expiring.id);
        assert!(reap_expired_ephemeral_channels(&pool)
            .await
            .unwrap()
            .is_empty());

        assert!(soft_delete_channel(&pool, community, channel.id)
            .await
            .unwrap());
        assert!(!soft_delete_channel(&pool, community, channel.id)
            .await
            .unwrap());
        assert!(list_channels(&pool, community, None)
            .await
            .unwrap()
            .iter()
            .all(|row| row.id != channel.id));
    }

    #[tokio::test]
    async fn relay_member_mutations_preserve_policy_owner_and_role_contracts() {
        use crate::relay_members::RemoveResult;

        let pool = connect(":memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "members.example")
            .await
            .unwrap()
            .id;
        bootstrap_owner(&pool, community, "OWNER").await.unwrap();

        assert!(
            claim_relay_membership(&pool, community, "ALICE", "member", Some("v1"))
                .await
                .unwrap()
        );
        assert!(
            !claim_relay_membership(&pool, community, "alice", "member", Some("v1"))
                .await
                .unwrap()
        );
        assert!(has_join_policy_acceptance(&pool, community, "ALICE", "v1")
            .await
            .unwrap());
        assert_eq!(
            remove_relay_member(&pool, community, "alice", Some("admin"))
                .await
                .unwrap(),
            RemoveResult::RoleMismatch
        );
        assert!(update_relay_member_role(&pool, community, "alice", "admin")
            .await
            .unwrap());
        assert_eq!(
            remove_relay_member(&pool, community, "alice", Some("member"))
                .await
                .unwrap(),
            RemoveResult::RoleMismatch
        );
        assert_eq!(
            remove_relay_member(&pool, community, "alice", Some("admin"))
                .await
                .unwrap(),
            RemoveResult::Removed
        );
        assert_eq!(
            remove_relay_member(&pool, community, "owner", None)
                .await
                .unwrap(),
            RemoveResult::IsOwner
        );
        assert!(
            !update_relay_member_role(&pool, community, "owner", "member")
                .await
                .unwrap()
        );
        assert_eq!(
            remove_relay_member(&pool, community, "missing", None)
                .await
                .unwrap(),
            RemoveResult::NotFound
        );
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

    fn command_event(keys: &Keys, kind: u16, content: &str, tags: Vec<Tag>) -> nostr::Event {
        EventBuilder::new(Kind::Custom(kind), content)
            .tags(tags)
            .sign_with_keys(keys)
            .unwrap()
    }

    #[tokio::test]
    async fn dm_command_failure_rolls_back_event_and_retry_applies_mutation() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "dm-command.local")
            .await
            .unwrap()
            .id;
        let keys = Keys::generate();
        let alice = keys.public_key().to_bytes().to_vec();
        let bob = vec![2_u8; 32];
        let participants = [alice.as_slice(), bob.as_slice()];
        let (dm, _) = open_dm(&pool, community, &participants, &alice, None)
            .await
            .unwrap()
            .unwrap();
        let event = command_event(&keys, 41012, "", vec![]);

        let missing = Uuid::new_v4();
        assert!(hide_dm_command(&pool, community, missing, &alice, &event)
            .await
            .is_err());
        assert!(get_event_by_id(&pool, community, event.id.as_bytes())
            .await
            .unwrap()
            .is_none());

        assert_eq!(
            hide_dm_command(&pool, community, dm.id, &alice, &event)
                .await
                .unwrap(),
            Some(())
        );
        assert!(get_event_by_id(&pool, community, event.id.as_bytes())
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            hide_dm_command(&pool, community, dm.id, &alice, &event)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            list_hidden_dms(&pool, community, &alice).await.unwrap(),
            vec![dm.id]
        );
    }

    #[tokio::test]
    async fn workflow_command_failure_rolls_back_event_and_retry_creates_run() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "workflow-command.local")
            .await
            .unwrap()
            .id;
        let keys = Keys::generate();
        let owner = keys.public_key().to_bytes().to_vec();
        ensure_user(&pool, community, &owner).await.unwrap();
        let channel = Uuid::new_v4();
        create_channel_with_id(
            &pool,
            community,
            channel,
            "commands",
            crate::channel::ChannelType::Stream,
            crate::channel::ChannelVisibility::Private,
            None,
            &owner,
            None,
        )
        .await
        .unwrap();
        let workflow = Uuid::new_v4();
        let def_event = command_event(
            &keys,
            30311,
            "definition",
            vec![Tag::custom(nostr::TagKind::d(), [workflow.to_string()])],
        );
        let definition = r#"{"name":"test","trigger":{"on":"manual"},"steps":[]}"#;
        assert_eq!(
            upsert_workflow_command(
                &pool,
                community,
                workflow,
                Some(channel),
                &owner,
                "test",
                definition,
                &[1; 32],
                &def_event,
                &workflow.to_string()
            )
            .await
            .unwrap(),
            Some(())
        );
        assert_eq!(
            upsert_workflow_command(
                &pool,
                community,
                workflow,
                Some(channel),
                &owner,
                "test",
                definition,
                &[1; 32],
                &def_event,
                &workflow.to_string()
            )
            .await
            .unwrap(),
            None
        );

        let trigger = command_event(&keys, 30312, "", vec![]);
        let missing_workflow = Uuid::new_v4();
        assert!(create_workflow_run_command(
            &pool,
            community,
            missing_workflow,
            trigger.id.as_bytes(),
            None,
            Some(channel),
            &trigger
        )
        .await
        .is_err());
        assert!(get_event_by_id(&pool, community, trigger.id.as_bytes())
            .await
            .unwrap()
            .is_none());
        let run = create_workflow_run_command(
            &pool,
            community,
            workflow,
            trigger.id.as_bytes(),
            None,
            Some(channel),
            &trigger,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            get_workflow_run(&pool, community, run)
                .await
                .unwrap()
                .workflow_id,
            workflow
        );
        assert_eq!(
            create_workflow_run_command(
                &pool,
                community,
                workflow,
                trigger.id.as_bytes(),
                None,
                Some(channel),
                &trigger
            )
            .await
            .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn approval_command_failure_rolls_back_event_and_retry_updates_status() {
        let pool = connect("sqlite::memory:").await.unwrap();
        let community = ensure_configured_community(&pool, "approval-command.local")
            .await
            .unwrap()
            .id;
        let keys = Keys::generate();
        let owner = keys.public_key().to_bytes().to_vec();
        ensure_user(&pool, community, &owner).await.unwrap();
        let channel = Uuid::new_v4();
        create_channel_with_id(
            &pool,
            community,
            channel,
            "commands",
            crate::channel::ChannelType::Stream,
            crate::channel::ChannelVisibility::Private,
            None,
            &owner,
            None,
        )
        .await
        .unwrap();
        let workflow = create_workflow(
            &pool,
            community,
            Some(channel),
            &owner,
            "test",
            r#"{"trigger":{"on":"manual"}}"#,
            &[1; 32],
        )
        .await
        .unwrap();
        let run = create_workflow_run(&pool, community, workflow, None, None)
            .await
            .unwrap();
        create_approval(
            &pool,
            crate::workflow::CreateApprovalParams {
                community_id: community,
                workflow_id: workflow,
                run_id: run,
                step_id: "approve",
                step_index: 0,
                approver_spec: "any",
                token: "secret",
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            },
        )
        .await
        .unwrap();
        let hash = Sha256::digest(b"secret").to_vec();
        let event = command_event(&keys, 30313, "approved", vec![]);

        assert_eq!(
            update_approval_command(
                &pool,
                community,
                &[9; 32],
                crate::workflow::ApprovalStatus::Granted,
                Some(&owner),
                None,
                &event
            )
            .await
            .unwrap(),
            Some(false)
        );
        assert!(get_event_by_id(&pool, community, event.id.as_bytes())
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            update_approval_command(
                &pool,
                community,
                &hash,
                crate::workflow::ApprovalStatus::Granted,
                Some(&owner),
                Some("ok"),
                &event
            )
            .await
            .unwrap(),
            Some(true)
        );
        assert_eq!(
            get_approval_by_hash(&pool, community, &hash)
                .await
                .unwrap()
                .status,
            crate::workflow::ApprovalStatus::Granted
        );
        assert_eq!(
            update_approval_command(
                &pool,
                community,
                &hash,
                crate::workflow::ApprovalStatus::Granted,
                Some(&owner),
                None,
                &event
            )
            .await
            .unwrap(),
            None
        );
    }
}
