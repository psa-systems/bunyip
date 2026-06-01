//! Download proxy models: API-facing response types.
//!
//! The engine-side types (artifact sources, release/package metadata, and the
//! asset-cache bookkeeping rows) come from the generic `dunite-download`
//! engine and are re-exported here so domain and api code keeps using
//! `crate::models::download::*`.

use serde::Serialize;

pub use dunite_download::models::download::{
    ArtifactSource, DownloadCacheRow, NewCachedAsset, ReleaseAsset, ReleaseMetadata,
};

/// API-facing asset (shown to members).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DownloadAsset {
    pub asset_name: String,
    pub size_bytes: i64,
    pub content_type: String,
    pub download_url: String,
}

/// API-facing response for `GET /v1/applications/{slug}/downloads`.
///
/// The JSON field stays `release_tag` for API stability (bunyip-web depends on
/// it) even though the engine calls the value `version`; for generic-package
/// sources it carries the package version.
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
