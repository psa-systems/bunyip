//! Auto-ban configuration models (BUNYIP-351)

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// Database row for the `auto_ban_config` singleton table.
///
/// Every tunable column is nullable: a NULL means this row's provider does not
/// hold that key, so the next provider down the declared stack serves it (see
/// [`AutoBanConfig::database_provider`](crate::config::AutoBanConfig::database_provider)
/// and [`crate::config_providers`]).
#[derive(Debug, sqlx::FromRow)]
pub struct AutoBanConfigRow {
    pub id: i32,
    pub enabled: Option<bool>,
    pub threshold: Option<i64>,
    pub window_secs: Option<i64>,
    pub ban_duration_secs: Option<i64>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

/// API response for auto-ban configuration.
#[derive(Debug, Serialize)]
pub struct AutoBanConfigResponse {
    pub enabled: bool,
    pub threshold: i64,
    pub window_secs: i64,
    pub ban_duration_secs: i64,
    /// Whether the resolved values come from "database" or "environment".
    pub source: &'static str,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}
