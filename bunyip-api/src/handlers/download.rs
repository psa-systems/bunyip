//! Member and admin download handlers.
//!
//! Built on the dunite-download engine: `ReleaseCache` (artifact metadata),
//! `AppDownloadCache` (on-disk asset cache over the Postgres
//! `DownloadCacheRepository`), and `DownloadLimiter` (per-user limits backed
//! by `DownloadDailyCountRepository`).

use actix_web::{http::header, web, HttpRequest, HttpResponse};
use futures_util::StreamExt;
use sqlx::PgPool;
use std::sync::Arc;
use tokio_util::codec::{BytesCodec, FramedRead};

use crate::config::OciConfig;
use crate::errors::AppError;
use crate::middleware::{extract_client_ip, AdminUser, MemberUser};
use crate::models::download::{
    AppDownloadGroup, AppDownloadsResponse, ArtifactSource, DownloadAsset, ReleaseMetadata,
};
use crate::models::{Application, AuditAction, CreateAuditLog};
use crate::repositories::{
    ApplicationRepository, AuditLogRepository, DownloadDailyCountRepository, EntitlementRepository,
};
use crate::responses::{get_request_id, success};
use crate::services::{AppDownloadCache, DownloadLimiter, ErrorClass, LimitDenial, ReleaseCache};

fn asset_href(slug: &str, asset_name: &str) -> String {
    format!(
        "/v1/applications/{}/downloads/{}",
        urlencoding::encode(slug),
        urlencoding::encode(asset_name),
    )
}

fn to_public_asset(a: &crate::models::download::ReleaseAsset, slug: &str) -> DownloadAsset {
    DownloadAsset {
        asset_name: a.name.clone(),
        size_bytes: a.size,
        content_type: a.content_type.clone(),
        download_url: asset_href(slug, &a.name),
    }
}

/// GET /v1/applications/{slug}/downloads
pub async fn list_app_downloads(
    req: HttpRequest,
    user: MemberUser,
    pool: web::Data<PgPool>,
    release_cache: web::Data<Option<Arc<ReleaseCache>>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let release_cache = release_cache
        .get_ref()
        .as_ref()
        .ok_or_else(|| AppError::not_found("Downloads"))?;
    let request_id = get_request_id(&req);
    let slug = path.into_inner();
    let app = ApplicationRepository::find_active_by_slug(&pool, &slug)
        .await?
        .ok_or(AppError::not_found("Application"))?;

    // Restricted product the caller can't access: degrade to an empty asset
    // list (same shape as the no-download-config branch) so the page still
    // renders rather than surfacing a 403. Shared decision; a DB error
    // propagates (fails closed).
    if !EntitlementRepository::is_allowed(&pool, user.0.sub, user.0.role == "admin", &app).await? {
        return Ok(success(
            AppDownloadsResponse {
                release_tag: None,
                assets: vec![],
            },
            request_id,
        ));
    }

    let Some(source) = app.download_source() else {
        return Ok(success(
            AppDownloadsResponse {
                release_tag: None,
                assets: vec![],
            },
            request_id,
        ));
    };

    let release = fetch_release_or_502(release_cache, app.id, &source).await?;
    let assets = release
        .assets
        .iter()
        .map(|a| to_public_asset(a, &app.slug))
        .collect();

    Ok(success(
        AppDownloadsResponse {
            release_tag: Some(release.version.clone()),
            assets,
        },
        request_id,
    ))
}

/// GET /v1/downloads
///
/// One group per active product that has at least one distribution surface
/// with something to offer: downloadable binary assets, a pullable OCI
/// image, or both.
pub async fn list_all_downloads(
    req: HttpRequest,
    user: MemberUser,
    pool: web::Data<PgPool>,
    release_cache: web::Data<Option<Arc<ReleaseCache>>>,
    oci_config: web::Data<OciConfig>,
) -> Result<HttpResponse, AppError> {
    let release_cache = release_cache.get_ref().as_ref();
    // 404 only when BOTH distribution surfaces are disabled server-side.
    if release_cache.is_none() && !oci_config.enabled {
        return Err(AppError::not_found("Downloads"));
    }
    let request_id = get_request_id(&req);
    let apps = ApplicationRepository::list_active(&pool).await?;

    let is_admin = user.0.role == "admin";

    // Fetch the caller's full active-entitlement set in ONE query, then filter
    // restricted products in memory (avoids an is_entitled round-trip per
    // restricted product). Admins see everything, so skip the query entirely.
    let entitled: std::collections::HashSet<uuid::Uuid> = if is_admin {
        std::collections::HashSet::new()
    } else {
        EntitlementRepository::active_application_ids(&pool, user.0.sub)
            .await?
            .into_iter()
            .collect()
    };

    // Build every group concurrently: each app may need a Forgejo round-trip
    // (cold release cache), so driving them with join_all turns N sequential
    // round-trips into one wall-clock round-trip. join_all preserves input
    // order, so the sort_order from list_active carries through.
    let groups: Vec<AppDownloadGroup> = futures_util::future::join_all(
        apps.iter()
            .map(|app| build_download_group(app, release_cache, &oci_config, is_admin, &entitled)),
    )
    .await
    .into_iter()
    .flatten()
    .collect();

    Ok(success(serde_json::json!({ "groups": groups }), request_id))
}

/// Build the `/v1/downloads` group for one application, or `None` when it has
/// nothing to distribute (no downloadable assets AND no pullable image) or the
/// caller is not entitled to a restricted product.
async fn build_download_group(
    app: &Application,
    release_cache: Option<&Arc<ReleaseCache>>,
    oci_config: &OciConfig,
    is_admin: bool,
    entitled: &std::collections::HashSet<uuid::Uuid>,
) -> Option<AppDownloadGroup> {
    // Hide restricted products the caller can't access (shared decision; the
    // entitlement set was fetched once by the caller).
    if !app.entitlement_satisfied(is_admin, entitled.contains(&app.id)) {
        return None;
    }

    let oci = if oci_config.enabled {
        app.oci_pull_image(&oci_config.service)
    } else {
        None
    };

    // Binary assets, when the download proxy is enabled and this app has a
    // complete download config. Best-effort: a failed Forgejo call degrades
    // to an empty asset list so one bad config doesn't break the whole page
    // (the OCI block, if any, still renders).
    let (release_tag, assets) = match (release_cache, app.download_source()) {
        (Some(cache), Some(source)) => match cache.get(app.id, &source).await {
            Ok(release) => (
                release.version.clone(),
                release
                    .assets
                    .iter()
                    .map(|a| to_public_asset(a, &app.slug))
                    .collect(),
            ),
            Err(e) => {
                tracing::warn!(app = %app.slug, error = %e, "release fetch failed");
                (String::new(), Vec::new())
            }
        },
        _ => (String::new(), Vec::new()),
    };

    // Nothing actionable for this app: no assets to download (a release tag
    // with zero uploaded assets is not actionable either) and no image to
    // pull. Skip it rather than render a dead entry.
    if assets.is_empty() && oci.is_none() {
        return None;
    }

    Some(AppDownloadGroup {
        app_slug: app.slug.clone(),
        app_display_name: app.display_name.clone(),
        icon_url: app.icon_url.clone(),
        release_tag,
        assets,
        oci,
    })
}

/// GET /v1/applications/{slug}/downloads/{asset_name}
pub async fn download_asset(
    req: HttpRequest,
    user: MemberUser,
    pool: web::Data<PgPool>,
    release_cache: web::Data<Option<Arc<ReleaseCache>>>,
    download_cache: web::Data<Option<Arc<AppDownloadCache>>>,
    limiter: web::Data<Arc<DownloadLimiter>>,
    download_counter: web::Data<Arc<DownloadDailyCountRepository>>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AppError> {
    let release_cache = release_cache
        .get_ref()
        .as_ref()
        .ok_or_else(|| AppError::not_found("Downloads"))?;
    let download_cache = download_cache
        .get_ref()
        .as_ref()
        .ok_or_else(|| AppError::not_found("Downloads"))?;
    let (slug, asset_name) = path.into_inner();
    let ip = extract_client_ip(&req).map(ipnetwork::IpNetwork::from);

    let app = ApplicationRepository::find_active_by_slug(&pool, &slug)
        .await?
        .ok_or(AppError::not_found("Application"))?;
    let Some(source) = app.download_source() else {
        return Err(AppError::not_found("Asset"));
    };

    // Entitlement gate (shared decision): a restricted product requires the
    // caller to be an admin or hold an active entitlement. Checked before the
    // rate-limit acquire so an unentitled caller never consumes a slot. Denial
    // returns 404 (not 403), matching the unknown-asset/OCI paths so a
    // restricted product's existence does not leak by status code.
    if !EntitlementRepository::is_allowed(&pool, user.0.sub, user.0.role == "admin", &app).await? {
        AuditLogRepository::create(
            &pool,
            CreateAuditLog::new(AuditAction::DownloadDeniedEntitlement)
                .with_actor(user.0.sub, &user.0.email, &user.0.role)
                .with_resource("application", app.id)
                .with_ip(ip)
                .with_metadata(serde_json::json!({
                    "slug": slug,
                    "asset_name": asset_name,
                })),
        )
        .await?;
        return Err(AppError::not_found("Asset"));
    }

    // Rate limiting (before any upstream call). The durable daily count lives
    // in Postgres behind the DownloadCounter trait.
    match limiter
        .acquire(download_counter.get_ref().as_ref(), user.0.sub)
        .await?
    {
        Ok(guard) => {
            // Audit: requested.
            AuditLogRepository::create(
                &pool,
                CreateAuditLog::new(AuditAction::DownloadRequested)
                    .with_actor(user.0.sub, &user.0.email, &user.0.role)
                    .with_resource("application", app.id)
                    .with_ip(ip)
                    .with_metadata(serde_json::json!({
                        "slug": slug,
                        "asset_name": asset_name,
                    })),
            )
            .await?;

            let release = fetch_release_or_502(release_cache, app.id, &source).await?;

            let asset = release
                .assets
                .iter()
                .find(|a| a.name == asset_name)
                .ok_or(AppError::not_found("Asset"))?;

            // Cache rows are keyed by the CONFIGURED version (source.version()),
            // matching the key used by admin cache invalidation. Keying by the
            // upstream-returned release.version would diverge when Forgejo
            // normalizes tag names (e.g. case differences), leaking rows that
            // invalidation can never match.
            let row = match download_cache
                .get_or_fetch(app.id, source.version(), asset)
                .await
            {
                Ok(row) => row,
                Err(e) => {
                    // Classify the failure with dunite-download's own policy
                    // (PSA-38: `DownloadCacheError::class()`), rather than matching
                    // its variants here, so the upstream-vs-local decision lives
                    // next to the error type and cannot drift across consumers -
                    // the same way dunite-oci owns its mapping via
                    // `From<&BlobCacheError>`.
                    let app_err = match e.class() {
                        // NotFound is a permanent 404: the release or asset was
                        // deleted/renamed in Forgejo while the configured version
                        // still points at it. Handled like every other
                        // missing-asset path - a plain 404 with no
                        // upstream-failure audit.
                        ErrorClass::NotFound => return Err(AppError::not_found("Asset")),
                        // Upstream outage or an integrity mismatch (usually stale
                        // Forgejo metadata: a re-uploaded asset or lagging size).
                        ErrorClass::Upstream => {
                            tracing::warn!(
                                app = %app.slug,
                                asset = %asset_name,
                                error = %e,
                                "download upstream failure (Forgejo outage or stale/integrity metadata)"
                            );
                            AppError::upstream("Download upstream failed")
                        }
                        // Our own filesystem or store failed, not an upstream
                        // outage (before PSA-36 these round-tripped as Io and
                        // looked like a 502; now they are reported as a 500).
                        ErrorClass::Local => {
                            tracing::error!(
                                app = %app.slug,
                                asset = %asset_name,
                                error = ?e,
                                "download cache local failure (filesystem/store), not an upstream outage"
                            );
                            AppError::internal("Download failed")
                        }
                    };
                    AuditLogRepository::create(
                        &pool,
                        CreateAuditLog::new(AuditAction::DownloadFailedUpstream)
                            .with_actor(user.0.sub, &user.0.email, &user.0.role)
                            .with_resource("application", app.id)
                            .with_ip(ip)
                            .with_metadata(serde_json::json!({
                                "slug": slug,
                                "asset_name": asset_name,
                                "error": e.to_string(),
                            })),
                    )
                    .await?;
                    return Err(app_err);
                }
            };

            let file_path = download_cache.file_path(&row.content_sha256);
            let file = tokio::fs::File::open(&file_path).await.map_err(|e| {
                tracing::error!(error = %e, "cached file vanished");
                AppError::internal("Cached file missing")
            })?;

            // Audit is emitted based on stream outcome: DownloadCompleted on
            // clean EOF, DownloadFailedUpstream on mid-stream I/O error. The
            // `emitted` flag ensures exactly-once semantics if the stream is
            // dropped (client abort) after an error branch already fired.
            struct AuditCtx {
                pool: PgPool,
                user_id: uuid::Uuid,
                email: String,
                role: String,
                ip: Option<ipnetwork::IpNetwork>,
                app_id: uuid::Uuid,
                slug: String,
                asset_name: String,
                size_bytes: i64,
                emitted: bool,
            }
            let audit = AuditCtx {
                pool: pool.get_ref().clone(),
                user_id: user.0.sub,
                email: user.0.email.clone(),
                role: user.0.role.clone(),
                ip,
                app_id: app.id,
                slug: slug.clone(),
                asset_name: asset_name.clone(),
                size_bytes: row.size_bytes,
                emitted: false,
            };

            // Attach the DownloadGuard to the stream so it drops only when the
            // stream is fully consumed or dropped — ensuring the concurrency
            // slot stays held for the duration of the streaming response.
            let framed = FramedRead::new(file, BytesCodec::new());
            let stream = futures_util::stream::unfold(
                (framed, guard, audit),
                |(mut s, g, mut a)| async move {
                    match s.next().await {
                        Some(Ok(b)) => Some((Ok::<_, std::io::Error>(b.freeze()), (s, g, a))),
                        Some(Err(e)) => {
                            if !a.emitted {
                                a.emitted = true;
                                let _ = AuditLogRepository::create(
                                    &a.pool,
                                    CreateAuditLog::new(AuditAction::DownloadFailedUpstream)
                                        .with_actor(a.user_id, &a.email, &a.role)
                                        .with_resource("application", a.app_id)
                                        .with_ip(a.ip)
                                        .with_metadata(serde_json::json!({
                                            "slug": a.slug,
                                            "asset_name": a.asset_name,
                                            "error": e.to_string(),
                                        })),
                                )
                                .await;
                            }
                            Some((Err(e), (s, g, a)))
                        }
                        None => {
                            if !a.emitted {
                                a.emitted = true;
                                let _ = AuditLogRepository::create(
                                    &a.pool,
                                    CreateAuditLog::new(AuditAction::DownloadCompleted)
                                        .with_actor(a.user_id, &a.email, &a.role)
                                        .with_resource("application", a.app_id)
                                        .with_ip(a.ip)
                                        .with_metadata(serde_json::json!({
                                            "slug": a.slug,
                                            "asset_name": a.asset_name,
                                            "size_bytes": a.size_bytes,
                                        })),
                                )
                                .await;
                            }
                            drop(g);
                            None
                        }
                    }
                },
            );

            let resp = HttpResponse::Ok()
                .insert_header((header::CONTENT_TYPE, row.content_type.clone()))
                .insert_header((header::CONTENT_LENGTH, row.size_bytes.to_string()))
                .insert_header((
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", asset_name),
                ))
                .streaming(stream);
            Ok(resp)
        }
        Err(LimitDenial::Concurrency) => {
            AuditLogRepository::create(
                &pool,
                CreateAuditLog::new(AuditAction::DownloadDeniedRateLimit)
                    .with_actor(user.0.sub, &user.0.email, &user.0.role)
                    .with_resource("application", app.id)
                    .with_ip(ip)
                    .with_metadata(serde_json::json!({
                        "slug": slug,
                        "asset_name": asset_name,
                        "reason": "concurrency",
                    })),
            )
            .await?;
            Err(AppError::rate_limited("download_concurrency_limit", None))
        }
        Err(LimitDenial::DailyCap { reset_in_secs }) => {
            AuditLogRepository::create(
                &pool,
                CreateAuditLog::new(AuditAction::DownloadDeniedRateLimit)
                    .with_actor(user.0.sub, &user.0.email, &user.0.role)
                    .with_resource("application", app.id)
                    .with_ip(ip)
                    .with_metadata(serde_json::json!({
                        "slug": slug,
                        "asset_name": asset_name,
                        "reason": "daily_cap",
                        "reset_in_secs": reset_in_secs,
                    })),
            )
            .await?;
            Err(AppError::rate_limited(
                "download_daily_limit",
                Some(reset_in_secs),
            ))
        }
    }
}

async fn fetch_release_or_502(
    cache: &ReleaseCache,
    app_id: uuid::Uuid,
    source: &ArtifactSource,
) -> Result<Arc<ReleaseMetadata>, AppError> {
    cache.get(app_id, source).await.map_err(|e| {
        tracing::warn!(error = %e, "forgejo release fetch failed");
        AppError::upstream("Forgejo upstream error")
    })
}

/// POST /v1/admin/applications/{slug}/downloads/refresh
pub async fn admin_refresh_release(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    release_cache: web::Data<Option<Arc<ReleaseCache>>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let release_cache = release_cache
        .get_ref()
        .as_ref()
        .ok_or_else(|| AppError::not_found("Downloads"))?;
    let request_id = get_request_id(&req);
    let slug = path.into_inner();
    let app = ApplicationRepository::find_by_slug(&pool, &slug)
        .await?
        .ok_or(AppError::not_found("Application"))?;
    let Some(source) = app.download_source() else {
        return Err(AppError::validation(
            "application",
            "Application is not configured for downloads",
        ));
    };
    release_cache.invalidate(app.id, &source).await;
    let release = release_cache.get(app.id, &source).await.map_err(|e| {
        tracing::warn!(error = %e, "forgejo refresh failed");
        AppError::upstream("Forgejo upstream error")
    })?;

    let assets: Vec<_> = release
        .assets
        .iter()
        .map(|a| to_public_asset(a, &app.slug))
        .collect();
    Ok(success(
        AppDownloadsResponse {
            release_tag: Some(release.version.clone()),
            assets,
        },
        request_id,
    ))
}

#[cfg(test)]
mod integration_tests {
    //! Full-stack happy path: mock Forgejo + real Postgres via `DATABASE_URL`.
    //! Skipped automatically when `DATABASE_URL` is unset.

    use sqlx::PgPool;
    use std::sync::Arc;
    use wiremock::matchers::{method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::models::download::ArtifactSource;
    use crate::repositories::DownloadCacheRepository;
    use crate::services::{AppDownloadCache, ForgejoAssetClient, ReleaseCache};

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
    }

    #[actix_rt::test]
    async fn list_app_downloads_returns_empty_when_not_configured() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let slug = format!("test-noconf-{}", uuid::Uuid::new_v4());
        sqlx::query(
            r#"
            INSERT INTO applications (name, slug, display_name, container_name)
            VALUES ($1, $1, $1, $1)
        "#,
        )
        .bind(&slug)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query("DELETE FROM applications WHERE slug = $1")
            .bind(&slug)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[actix_rt::test]
    async fn download_asset_streams_bytes_from_forgejo() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        let server = MockServer::start().await;
        let payload: &[u8] = b"hello world";
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/repos/a8n/rus/releases/tags/v1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tag_name": "v1.0.0",
                "assets": [{
                    "id": 1,
                    "name": "rus.bin",
                    "size": payload.len() as i64,
                }]
            })))
            .mount(&server)
            .await;
        // The engine builds release download URLs from the configured base +
        // the canonical attachment route.
        Mock::given(method("GET"))
            .and(wm_path("/a8n/rus/releases/download/v1.0.0/rus.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(payload))
            .mount(&server)
            .await;

        let slug = format!("test-dl-{}", uuid::Uuid::new_v4());
        sqlx::query(r#"
            INSERT INTO applications
            (name, slug, display_name, container_name, forgejo_owner, forgejo_repo, pinned_release_tag)
            VALUES ($1, $1, $1, $1, 'a8n', 'rus', 'v1.0.0')
        "#).bind(&slug).execute(&pool).await.unwrap();

        let client = Arc::new(ForgejoAssetClient::new(server.uri(), "tok".into()));
        let release_cache = ReleaseCache::new(client.clone(), 60);
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(DownloadCacheRepository::new(pool.clone()));
        let download_cache: AppDownloadCache =
            AppDownloadCache::new(client, tmp.path(), 1024 * 1024, store);

        let app_row: (uuid::Uuid,) = sqlx::query_as("SELECT id FROM applications WHERE slug = $1")
            .bind(&slug)
            .fetch_one(&pool)
            .await
            .unwrap();
        let source = ArtifactSource::Release {
            owner: "a8n".into(),
            repo: "rus".into(),
            tag: "v1.0.0".into(),
        };
        let release = release_cache.get(app_row.0, &source).await.unwrap();
        let row = download_cache
            .get_or_fetch(app_row.0, &release.version, &release.assets[0])
            .await
            .unwrap();
        assert_eq!(row.size_bytes, payload.len() as i64);
        let bytes = tokio::fs::read(download_cache.file_path(&row.content_sha256))
            .await
            .unwrap();
        assert_eq!(bytes, payload);

        sqlx::query("DELETE FROM download_cache WHERE application_id = $1")
            .bind(app_row.0)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM applications WHERE id = $1")
            .bind(app_row.0)
            .execute(&pool)
            .await
            .unwrap();
    }
}
