//! Admin-only: manually refresh OCI caches for an app.

use actix_web::{web, HttpRequest, HttpResponse};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;

use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::oci::CachedManifest;
use crate::repositories::ApplicationRepository;
use crate::responses::{get_request_id, success_no_data};
use crate::services::{ForgejoRegistryClient, ManifestCache};

/// POST /v1/admin/applications/{slug}/oci/refresh
///
/// Invalidates the in-memory manifest cache for the app and best-effort
/// re-fetches the pinned manifest to warm it. Returns 404 if the OCI
/// registry is disabled or the app is not pullable.
pub async fn refresh_oci(
    req: HttpRequest,
    _admin: AdminUser,
    path: web::Path<String>,
    pool: web::Data<PgPool>,
    client: web::Data<Option<Arc<ForgejoRegistryClient>>>,
    manifest_cache: web::Data<Option<Arc<ManifestCache>>>,
) -> Result<HttpResponse, AppError> {
    let slug = path.into_inner();
    let request_id = get_request_id(&req);

    let client = client
        .get_ref()
        .as_ref()
        .ok_or_else(|| AppError::not_found("OCI registry disabled"))?;
    let mc = manifest_cache
        .get_ref()
        .as_ref()
        .ok_or_else(|| AppError::not_found("OCI registry disabled"))?;

    let app = ApplicationRepository::find_active_by_slug(pool.get_ref(), &slug)
        .await?
        .ok_or_else(|| AppError::not_found("Application"))?;
    if !app.is_pullable() {
        return Err(AppError::not_found("Application not pullable"));
    }

    mc.invalidate_app(app.id).await;

    // Best-effort: re-fetch the pinned tag's manifest and insert it into the
    // cache so the next member pull returns a hit.
    // is_pullable() guarantees these unwraps are safe.
    let owner = app.oci_image_owner.as_deref().unwrap();
    let name = app.oci_image_name.as_deref().unwrap();
    let tag = app.pinned_image_tag.as_deref().unwrap();
    match client
        .get_manifest(
            owner,
            name,
            tag,
            "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json",
        )
        .await
    {
        Ok(mr) => {
            let digest = if mr.digest.is_empty() {
                format!("sha256:{}", hex::encode(Sha256::digest(&mr.bytes)))
            } else {
                mr.digest
            };
            mc.insert(
                app.id,
                tag,
                CachedManifest {
                    bytes: mr.bytes,
                    media_type: mr.media_type,
                    digest,
                },
            )
            .await;
        }
        Err(e) => {
            tracing::warn!(error = ?e, slug = %slug, "oci refresh: upstream manifest refetch failed");
        }
    }

    Ok(success_no_data(request_id))
}
