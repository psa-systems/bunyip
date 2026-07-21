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

/// OCI pull coordinates for a product in the `/v1/downloads` response, so the
/// downloads page can render copy-paste `docker login` / `docker pull`
/// commands against the member-facing registry.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AppOciImage {
    /// Public registry hostname Docker clients log in to
    /// (`OCI_REGISTRY_SERVICE`), e.g. `oci.a8n.run`.
    pub registry: String,
    /// Repository inside the registry: the application slug.
    pub repository: String,
    /// The pinned image tag: the only tag the registry serves for this
    /// product (pinned-version distribution model).
    pub tag: String,
    /// Full pull reference: `{registry}/{repository}:{tag}`.
    pub reference: String,
}

/// A group in the global `/v1/downloads` response.
///
/// A product can carry binary assets (Forgejo downloads), an OCI image, or
/// both.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AppDownloadGroup {
    pub app_slug: String,
    pub app_display_name: String,
    pub icon_url: Option<String>,
    /// Version of the binary assets; EMPTY STRING for OCI-only products.
    /// Stays a plain string (not `Option`) for wire compatibility: deployed
    /// web clients deserialize this field as a required string, and `null`
    /// would fail their parse of the whole response.
    pub release_tag: String,
    pub assets: Vec<DownloadAsset>,
    /// OCI pull info, when the registry is enabled and the product has a
    /// pullable image.
    pub oci: Option<AppOciImage>,
    /// True when the application has at least one published documentation page
    /// (BUNYIP-388 follow-up), so the catalog can gate the Documentation link.
    pub has_docs: bool,
}
