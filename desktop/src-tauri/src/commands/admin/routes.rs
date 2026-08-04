//! Closed route enum and typed query parameters for the admin API.
//!
//! No IPC surface accepts an arbitrary path; every URL is constructed here
//! from a typed route and typed query parameters.

/// The five read routes exposed by `/api/admin/v1`.
///
/// Named `'_` lifetime on borrowed id/sha256 fields so callers can pass
/// `&str` slices without allocating.
#[derive(Debug)]
pub enum AdminRoute<'a> {
    ReportsList,
    ReportDetail { id: &'a str },
    FeedbackList,
    FeedbackDetail { id: &'a str },
    FeedbackAttachment { id: &'a str, sha256: &'a str },
}

impl<'a> AdminRoute<'a> {
    /// Return the URL path component (not including the `/api/admin/v1` prefix).
    pub fn path(&self) -> String {
        match self {
            AdminRoute::ReportsList => "/reports".to_string(),
            AdminRoute::ReportDetail { id } => format!("/reports/{id}"),
            AdminRoute::FeedbackList => "/feedback".to_string(),
            AdminRoute::FeedbackDetail { id } => format!("/feedback/{id}"),
            AdminRoute::FeedbackAttachment { id, sha256 } => {
                format!("/feedback/{id}/attachments/{sha256}")
            }
        }
    }
}

/// Optional query parameters for the reports-list endpoint.
///
/// All fields are `Option<String>` so the struct can be constructed with only
/// the fields the caller cares about; `to_query_string` omits `None` fields.
#[derive(Debug, Default)]
pub struct AdminQuery {
    pub community_id: Option<String>,
    pub status: Option<String>,
    pub report_type: Option<String>,
    pub target_kind: Option<String>,
    pub after: Option<String>,
    pub before: Option<String>,
    pub limit: Option<i64>,
}

impl AdminQuery {
    /// Serialise to a URL query string (no leading `?`). Returns an empty
    /// string when all fields are `None`.
    pub fn to_query_string(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(v) = &self.community_id {
            parts.push(format!("communityId={}", urlencoded(v)));
        }
        if let Some(v) = &self.status {
            parts.push(format!("status={}", urlencoded(v)));
        }
        if let Some(v) = &self.report_type {
            parts.push(format!("reportType={}", urlencoded(v)));
        }
        if let Some(v) = &self.target_kind {
            parts.push(format!("targetKind={}", urlencoded(v)));
        }
        if let Some(v) = &self.after {
            parts.push(format!("after={}", urlencoded(v)));
        }
        if let Some(v) = &self.before {
            parts.push(format!("before={}", urlencoded(v)));
        }
        if let Some(v) = &self.limit {
            parts.push(format!("limit={v}"));
        }
        parts.join("&")
    }
}

/// Percent-encode a query parameter value, matching `url::form_urlencoded`.
fn urlencoded(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_list_path() {
        assert_eq!(AdminRoute::ReportsList.path(), "/reports");
    }

    #[test]
    fn report_detail_path() {
        assert_eq!(
            AdminRoute::ReportDetail { id: "abc-123" }.path(),
            "/reports/abc-123"
        );
    }

    #[test]
    fn feedback_attachment_path() {
        let hash = "a".repeat(64);
        assert_eq!(
            AdminRoute::FeedbackAttachment {
                id: "fb-id",
                sha256: &hash
            }
            .path(),
            format!("/feedback/fb-id/attachments/{hash}")
        );
    }

    #[test]
    fn query_empty_produces_no_string() {
        assert_eq!(AdminQuery::default().to_query_string(), "");
    }

    #[test]
    fn query_limit_only() {
        let q = AdminQuery {
            limit: Some(50),
            ..Default::default()
        };
        assert_eq!(q.to_query_string(), "limit=50");
    }

    #[test]
    fn query_multiple_params() {
        let q = AdminQuery {
            status: Some("open".to_string()),
            limit: Some(100),
            ..Default::default()
        };
        let qs = q.to_query_string();
        assert!(qs.contains("status=open"), "expected status in {qs}");
        assert!(qs.contains("limit=100"), "expected limit in {qs}");
    }

    #[test]
    fn query_value_is_percent_encoded() {
        let q = AdminQuery {
            status: Some("open&active".to_string()),
            ..Default::default()
        };
        let qs = q.to_query_string();
        // & in value must be encoded so it doesn't split the query.
        assert!(!qs.contains("status=open&active"), "bare & leaked: {qs}");
        assert!(qs.contains("status="), "status key missing: {qs}");
    }
}
