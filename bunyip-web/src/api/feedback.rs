use serde::{Deserialize, Serialize};

use super::{get_json, post_json, ApiError};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackStatus {
    New,
    Triaged,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeedbackAttachment {
    pub filename: String,
    pub size: u64,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Feedback {
    pub id: String,
    pub user_id: Option<String>,
    pub org_id: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub message: String,
    pub page_path: Option<String>,
    #[serde(default)]
    pub attachments: Vec<FeedbackAttachment>,
    pub forgejo_issue_url: Option<String>,
    pub status: FeedbackStatus,
    pub created_at: String,
}

#[derive(Debug, Serialize, Default)]
pub struct SubmitRequest {
    pub name: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    pub tags: Vec<String>,
    pub message: String,
    pub page_path: Option<String>,
    pub website: Option<String>,
    pub attachments: Vec<FeedbackAttachment>,
}

pub async fn submit(req: &SubmitRequest) -> Result<Feedback, ApiError> {
    post_json("/v1/feedback", req).await
}

pub async fn list_admin(status: Option<&str>) -> Result<Vec<Feedback>, ApiError> {
    let path = match status {
        Some(s) => format!("/v1/admin/feedback?status={s}"),
        None => "/v1/admin/feedback".to_string(),
    };
    get_json(&path).await
}

#[derive(Debug, Serialize)]
pub struct UpdateStatusRequest {
    pub status: FeedbackStatus,
}

pub async fn update_status(id: &str, status: FeedbackStatus) -> Result<(), ApiError> {
    let resp = super::request("PATCH", &format!("/v1/admin/feedback/{id}"))
        .json(&UpdateStatusRequest { status })
        .map_err(|e| ApiError::Decode(e.to_string()))?
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(super::error_from_response_pub(resp).await)
    }
}
