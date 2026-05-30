//! Feedback models and DTOs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackStatus {
    New,
    Reviewed,
    Responded,
    Closed,
}

impl FeedbackStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            FeedbackStatus::New => "new",
            FeedbackStatus::Reviewed => "reviewed",
            FeedbackStatus::Responded => "responded",
            FeedbackStatus::Closed => "closed",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "new" => Some(Self::New),
            "reviewed" => Some(Self::Reviewed),
            "responded" => Some(Self::Responded),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Feedback {
    pub id: Uuid,
    pub name: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    pub tags: Vec<String>,
    pub message: String,
    pub page_path: Option<String>,
    pub status: String,
    pub admin_response: Option<String>,
    pub responded_by: Option<Uuid>,
    pub responded_at: Option<DateTime<Utc>>,
    pub is_spam: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CreateFeedback {
    pub name: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    pub tags: Vec<String>,
    pub message: String,
    pub page_path: Option<String>,
    pub is_spam: bool,
}

#[derive(Debug, Clone)]
pub struct RespondToFeedback {
    pub status: FeedbackStatus,
    pub admin_response: String,
    pub responded_by: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct CreateFeedbackRequest {
    pub name: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub message: String,
    pub page_path: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RespondToFeedbackRequest {
    pub response: String,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFeedbackStatusRequest {
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct FeedbackSubmissionResponse {
    pub id: Uuid,
    pub message: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ArchivedFeedbackItem {
    pub id: Uuid,
    pub archived_at: DateTime<Utc>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    pub tags: Vec<String>,
    pub message_excerpt: String,
    pub original_status: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct FeedbackAttachmentMeta {
    pub id: Uuid,
    pub feedback_id: Uuid,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AdminFeedbackSummary {
    pub id: Uuid,
    pub name: Option<String>,
    pub email_masked: Option<String>,
    pub subject: Option<String>,
    pub tags: Vec<String>,
    pub message_excerpt: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub responded_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct AdminFeedbackDetail {
    pub id: Uuid,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_masked: Option<String>,
    pub subject: Option<String>,
    pub tags: Vec<String>,
    pub message: String,
    pub page_path: Option<String>,
    pub status: String,
    pub admin_response: Option<String>,
    pub responded_by: Option<Uuid>,
    pub responded_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub attachments: Vec<FeedbackAttachmentMeta>,
}

impl Feedback {
    pub fn mask_email(email: &str) -> String {
        let mut parts = email.splitn(2, '@');
        let local = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();

        if local.is_empty() || domain.is_empty() {
            return "***".to_string();
        }

        let first = local.chars().next().unwrap_or('*');
        format!("{first}***@{domain}")
    }

    fn excerpt(message: &str) -> String {
        let trimmed = message.trim();
        let mut chars = trimmed.chars();
        let excerpt: String = chars.by_ref().take(120).collect();
        if chars.next().is_some() {
            format!("{excerpt}...")
        } else {
            excerpt
        }
    }

    pub fn to_admin_summary(&self) -> AdminFeedbackSummary {
        AdminFeedbackSummary {
            id: self.id,
            name: self.name.clone(),
            email_masked: self.email.as_deref().map(Self::mask_email),
            subject: self.subject.clone(),
            tags: self.tags.clone(),
            message_excerpt: Self::excerpt(&self.message),
            status: self.status.clone(),
            created_at: self.created_at,
            responded_at: self.responded_at,
        }
    }

    pub fn to_admin_detail(&self, attachments: Vec<FeedbackAttachmentMeta>) -> AdminFeedbackDetail {
        AdminFeedbackDetail {
            id: self.id,
            name: self.name.clone(),
            email: self.email.clone(),
            email_masked: self.email.as_deref().map(Self::mask_email),
            subject: self.subject.clone(),
            tags: self.tags.clone(),
            message: self.message.clone(),
            page_path: self.page_path.clone(),
            status: self.status.clone(),
            admin_response: self.admin_response.clone(),
            responded_by: self.responded_by,
            responded_at: self.responded_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
            attachments,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- FeedbackStatus --

    #[test]
    fn feedback_status_as_str() {
        assert_eq!(FeedbackStatus::New.as_str(), "new");
        assert_eq!(FeedbackStatus::Reviewed.as_str(), "reviewed");
        assert_eq!(FeedbackStatus::Responded.as_str(), "responded");
        assert_eq!(FeedbackStatus::Closed.as_str(), "closed");
    }

    #[test]
    fn feedback_status_from_str() {
        assert_eq!(FeedbackStatus::from_str("new"), Some(FeedbackStatus::New));
        assert_eq!(
            FeedbackStatus::from_str("reviewed"),
            Some(FeedbackStatus::Reviewed)
        );
        assert_eq!(
            FeedbackStatus::from_str("responded"),
            Some(FeedbackStatus::Responded)
        );
        assert_eq!(
            FeedbackStatus::from_str("closed"),
            Some(FeedbackStatus::Closed)
        );
        assert_eq!(FeedbackStatus::from_str("invalid"), None);
    }

    // -- Feedback::mask_email --

    #[test]
    fn mask_email_normal() {
        assert_eq!(
            Feedback::mask_email("alice@example.com"),
            "a***@example.com"
        );
    }

    #[test]
    fn mask_email_single_char_local() {
        assert_eq!(Feedback::mask_email("a@example.com"), "a***@example.com");
    }

    #[test]
    fn mask_email_no_at_sign() {
        assert_eq!(Feedback::mask_email("noemail"), "***");
    }

    #[test]
    fn mask_email_empty() {
        assert_eq!(Feedback::mask_email(""), "***");
    }

    #[test]
    fn mask_email_missing_local() {
        assert_eq!(Feedback::mask_email("@domain.com"), "***");
    }

    // -- Feedback::excerpt --

    #[test]
    fn excerpt_short_message() {
        let msg = "Short message";
        assert_eq!(Feedback::excerpt(msg), "Short message");
    }

    #[test]
    fn excerpt_long_message() {
        let msg = "a".repeat(200);
        let result = Feedback::excerpt(&msg);
        assert_eq!(result.len(), 123); // 120 chars + "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn excerpt_exactly_120_chars() {
        let msg = "a".repeat(120);
        let result = Feedback::excerpt(&msg);
        assert_eq!(result.len(), 120);
        assert!(!result.ends_with("..."));
    }
}
