//! Backend-neutral normalization for event queries.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use buzz_core::CommunityId;

use crate::{DbError, EventQuery, Result, DEFAULT_MAX_PAGE_LIMIT};

/// A normalized event query, split into row predicates and result modifiers.
#[derive(Debug, Clone)]
pub(crate) struct QueryPlan {
    pub(crate) predicates: Vec<Predicate>,
    pub(crate) modifiers: Modifiers,
}

/// Backend-neutral logical row conditions.
#[derive(Debug, Clone)]
pub(crate) enum Predicate {
    MatchNone,
    Community(CommunityId),
    Channel(Uuid),
    GlobalOnly,
    ChannelsOrGlobal(Vec<Uuid>),
    Kinds(Vec<i32>),
    Author(Vec<u8>),
    Authors(Vec<Vec<u8>>),
    Ids(Vec<Vec<u8>>),
    HasPTag(String),
    HasETag(Vec<String>),
    HasDTag(String),
    HasAnyDTag(Vec<String>),
    Since(DateTime<Utc>),
    Until(DateTime<Utc>),
    CursorBefore { until: DateTime<Utc>, id: Vec<u8> },
    GatedReader(Vec<u8>),
    LiveOnly,
}

/// Ordering and pagination, deliberately excluded from count rendering.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Modifiers {
    pub(crate) limit: i64,
    pub(crate) offset: i64,
}

/// Validate and normalize every [`EventQuery`] field exactly once.
pub(crate) fn plan(query: &EventQuery) -> Result<QueryPlan> {
    let EventQuery {
        community_id,
        channel_id,
        kinds,
        pubkey,
        since,
        until,
        limit,
        offset,
        p_tag_hex,
        d_tag,
        d_tags,
        before_id,
        global_only,
        authors,
        ids,
        e_tags,
        channel_ids,
        max_limit,
        shared_gated_reader,
    } = query;

    if before_id.is_some() && until.is_none() {
        return Err(DbError::InvalidData(
            "before_id requires until to be set".to_string(),
        ));
    }
    if *global_only && channel_id.is_some() {
        return Err(DbError::InvalidData(
            "global_only and channel_id are mutually exclusive".to_string(),
        ));
    }

    let mut predicates = vec![Predicate::Community(*community_id), Predicate::LiveOnly];
    if kinds.as_ref().is_some_and(Vec::is_empty)
        || authors.as_ref().is_some_and(Vec::is_empty)
        || ids.as_ref().is_some_and(Vec::is_empty)
        || e_tags.as_ref().is_some_and(Vec::is_empty)
    {
        predicates.push(Predicate::MatchNone);
    }

    if let Some(channel_id) = channel_id {
        predicates.push(Predicate::Channel(*channel_id));
    } else if *global_only {
        predicates.push(Predicate::GlobalOnly);
    }
    if let Some(channel_ids) = channel_ids {
        predicates.push(Predicate::ChannelsOrGlobal(channel_ids.clone()));
    }
    if let Some(kinds) = kinds.as_ref().filter(|values| !values.is_empty()) {
        predicates.push(Predicate::Kinds(kinds.clone()));
    }
    if let Some(pubkey) = pubkey {
        predicates.push(Predicate::Author(pubkey.clone()));
    }
    if let Some(authors) = authors.as_ref().filter(|values| !values.is_empty()) {
        predicates.push(Predicate::Authors(authors.clone()));
    }
    if let Some(ids) = ids.as_ref().filter(|values| !values.is_empty()) {
        predicates.push(Predicate::Ids(ids.clone()));
    }
    if let Some(p_tag_hex) = p_tag_hex {
        predicates.push(Predicate::HasPTag(p_tag_hex.to_ascii_lowercase()));
    }
    if let Some(e_tags) = e_tags.as_ref().filter(|values| !values.is_empty()) {
        predicates.push(Predicate::HasETag(e_tags.clone()));
    }
    if let Some(since) = since {
        predicates.push(Predicate::Since(*since));
    }
    if let Some(until) = until {
        if let Some(id) = before_id {
            predicates.push(Predicate::CursorBefore {
                until: *until,
                id: id.clone(),
            });
        } else {
            predicates.push(Predicate::Until(*until));
        }
    }
    // A singular d-tag takes precedence over the multi-value form.
    if let Some(d_tag) = d_tag {
        predicates.push(Predicate::HasDTag(d_tag.clone()));
    } else if let Some(d_tags) = d_tags.as_ref().filter(|values| !values.is_empty()) {
        predicates.push(Predicate::HasAnyDTag(d_tags.clone()));
    }
    if let Some(reader) = shared_gated_reader {
        predicates.push(Predicate::GatedReader(reader.clone()));
    }

    Ok(QueryPlan {
        predicates,
        modifiers: Modifiers {
            limit: limit
                .unwrap_or(100)
                .min(max_limit.unwrap_or(DEFAULT_MAX_PAGE_LIMIT)),
            offset: offset.unwrap_or(0),
        },
    })
}
