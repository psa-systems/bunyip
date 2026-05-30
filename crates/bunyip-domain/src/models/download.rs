//! Download proxy models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// DB row for the `download_cache` table.
#[derive(Debug, Clone, FromRow)]
pub struct DownloadCacheRow {
    pub id: Uuid,
    pub application_id: Uuid,
    pub release_tag: String,
    pub asset_name: String,
    pub content_sha256: String,
    pub size_bytes: i64,
    pub content_type: String,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: DateTime<Utc>,
}

/// Metadata for a single asset within a Forgejo release.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReleaseAsset {
    pub asset_id: i64,
    pub name: String,
    pub size: i64,
    pub content_type: String,
    /// Authenticated Forgejo download URL.
    pub browser_download_url: String,
}

/// Parsed Forgejo release metadata (the subset we care about).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReleaseMetadata {
    pub tag_name: String,
    pub assets: Vec<ReleaseAsset>,
}

/// API-facing asset (shown to members).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DownloadAsset {
    pub asset_name: String,
    pub size_bytes: i64,
    pub content_type: String,
    pub download_url: String,
}

/// API-facing response for `GET /v1/applications/{slug}/downloads`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AppDownloadsResponse {
    pub release_tag: Option<String>,
    pub assets: Vec<DownloadAsset>,
}

/// A group in the global `/v1/downloads` response.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AppDownloadGroup {
    pub app_slug: String,
    pub app_display_name: String,
    pub icon_url: Option<String>,
    pub release_tag: String,
    pub assets: Vec<DownloadAsset>,
}
