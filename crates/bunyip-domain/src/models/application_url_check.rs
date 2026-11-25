//! Application URL health-check row (BUNYIP-1089). One per probe the
//! `UrlHealthWorker` writes; cascades off its parent application.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// The five values the migration's CHECK constraint allows.
pub const CHECK_STATUS_OK: &str = "ok";
pub const CHECK_STATUS_HTTP_ERROR: &str = "http_error";
pub const CHECK_STATUS_SCREEN_REFUSED: &str = "screen_refused";
pub const CHECK_STATUS_TIMEOUT: &str = "timeout";
pub const CHECK_STATUS_NETWORK_ERROR: &str = "network_error";

#[derive(Debug, Clone, FromRow, Serialize, Deserialize, PartialEq)]
pub struct ApplicationUrlCheck {
    pub id: Uuid,
    pub application_id: Uuid,
    pub checked_at: DateTime<Utc>,
    pub status: String,
    pub http_status: Option<i16>,
    pub latency_ms: Option<i32>,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateApplicationUrlCheck {
    pub application_id: Uuid,
    pub status: &'static str,
    pub http_status: Option<i16>,
    pub latency_ms: Option<i32>,
    pub error_detail: Option<String>,
}
