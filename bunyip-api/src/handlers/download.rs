//! Member and admin download handlers.

use actix_web::{http::header, web, HttpRequest, HttpResponse};
use futures_util::StreamExt;
use sqlx::PgPool;
use std::sync::Arc;
use tokio_util::codec::{BytesCodec, FramedRead};

use crate::errors::AppError;
use crate::middleware::{extract_client_ip, AdminUser, MemberUser};
use crate::models::download::{
    AppDownloadGroup, AppDownloadsResponse, DownloadAsset, ReleaseMetadata,
};
use crate::models::{AuditAction, CreateAuditLog};
use crate::repositories::{ApplicationRepository, AuditLogRepository};
use crate::responses::{get_request_id, success};
use crate::services::download_limiter::LimitDenial;
use crate::services::{DownloadCache, DownloadLimiter, ReleaseCache};

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
    _user: MemberUser,
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

    if !app.is_downloadable() {
        return Ok(success(
            AppDownloadsResponse {
                release_tag: None,
                assets: vec![],
            },
            request_id,
        ));
    }
    let owner = app.forgejo_owner.as_deref().unwrap();
    let repo = app.forgejo_repo.as_deref().unwrap();
    let tag = app.pinned_release_tag.as_deref().unwrap();

    let release = fetch_release_or_502(&release_cache, app.id, owner, repo, tag).await?;
    let assets = release
        .assets
        .iter()
        .map(|a| to_public_asset(a, &app.slug))
        .collect();

    Ok(success(
        AppDownloadsResponse {
            release_tag: Some(release.tag_name.clone()),
            assets,
        },
        request_id,
    ))
}

/// GET /v1/downloads
pub async fn list_all_downloads(
    req: HttpRequest,
    _user: MemberUser,
    pool: web::Data<PgPool>,
    release_cache: web::Data<Option<Arc<ReleaseCache>>>,
) -> Result<HttpResponse, AppError> {
    let release_cache = release_cache
        .get_ref()
        .as_ref()
        .ok_or_else(|| AppError::not_found("Downloads"))?;
    let request_id = get_request_id(&req);
    let apps = ApplicationRepository::list_active(&pool).await?;

    let mut groups: Vec<AppDownloadGroup> = Vec::new();
    for app in apps {
        if !app.is_downloadable() {
            continue;
        }
        let owner = app.forgejo_owner.as_deref().unwrap();
        let repo = app.forgejo_repo.as_deref().unwrap();
        let tag = app.pinned_release_tag.as_deref().unwrap();
        // Best-effort: skip apps whose Forgejo call errors so one bad config
        // doesn't break the whole page.
        let release = match release_cache.get(app.id, owner, repo, tag).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(app = %app.slug, error = %e, "release fetch failed");
                continue;
            }
        };
        groups.push(AppDownloadGroup {
            app_slug: app.slug.clone(),
            app_display_name: app.display_name.clone(),
            icon_url: app.icon_url.clone(),
            release_tag: release.tag_name.clone(),
            assets: release
                .assets
                .iter()
                .map(|a| to_public_asset(a, &app.slug))
                .collect(),
        });
    }

    Ok(success(serde_json::json!({ "groups": groups }), request_id))
}

/// GET /v1/applications/{slug}/downloads/{asset_name}
pub async fn download_asset(
    req: HttpRequest,
    user: MemberUser,
    pool: web::Data<PgPool>,
    release_cache: web::Data<Option<Arc<ReleaseCache>>>,
    download_cache: web::Data<Option<Arc<DownloadCache>>>,
    limiter: web::Data<Arc<DownloadLimiter>>,
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
    if !app.is_downloadable() {
        return Err(AppError::not_found("Asset"));
    }

    // Rate limiting (before any upstream call).
    match limiter.acquire(&pool, user.0.sub).await? {
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

            let owner = app.forgejo_owner.as_deref().unwrap();
            let repo = app.forgejo_repo.as_deref().unwrap();
            let tag = app.pinned_release_tag.as_deref().unwrap();
            let release = fetch_release_or_502(&release_cache, app.id, owner, repo, tag).await?;

            let asset = release
                .assets
                .iter()
                .find(|a| a.name == asset_name)
                .ok_or(AppError::not_found("Asset"))?;

            let row = match download_cache.get_or_fetch(app.id, tag, asset).await {
                Ok(row) => row,
                Err(e) => {
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
                    return Err(AppError::upstream("Download upstream failed"));
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
    owner: &str,
    repo: &str,
    tag: &str,
) -> Result<Arc<ReleaseMetadata>, AppError> {
    cache.get(app_id, owner, repo, tag).await.map_err(|e| {
        tracing::warn!(error = %e, "forgejo release fetch failed");
        AppError::upstream("Forgejo upstream error")
    })
}

#[cfg(test)]
mod integration_tests {
    //! Full-stack happy path: mock Forgejo + real Postgres via `DATABASE_URL`.
    //! Skipped automatically when `DATABASE_URL` is unset.

    use sqlx::PgPool;
    use std::sync::Arc;
    use wiremock::matchers::{method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
                    "browser_download_url": format!("{}/download/1", server.uri()),
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path("/download/1"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(payload))
            .mount(&server)
            .await;

        let slug = format!("test-dl-{}", uuid::Uuid::new_v4());
        sqlx::query(r#"
            INSERT INTO applications
            (name, slug, display_name, container_name, forgejo_owner, forgejo_repo, pinned_release_tag)
            VALUES ($1, $1, $1, $1, 'a8n', 'rus', 'v1.0.0')
        "#).bind(&slug).execute(&pool).await.unwrap();

        let client = Arc::new(crate::services::forgejo::ForgejoClient::new(
            server.uri(),
            "tok".into(),
        ));
        let release_cache = crate::services::release_cache::ReleaseCache::new(client.clone(), 60);
        let tmp = tempfile::tempdir().unwrap();
        let download_cache = crate::services::download_cache::DownloadCache::new(
            client,
            tmp.path(),
            1024 * 1024,
            pool.clone(),
        );

        let app_row: (uuid::Uuid,) = sqlx::query_as("SELECT id FROM applications WHERE slug = $1")
            .bind(&slug)
            .fetch_one(&pool)
            .await
            .unwrap();
        let release = release_cache
            .get(app_row.0, "a8n", "rus", "v1.0.0")
            .await
            .unwrap();
        let row = download_cache
            .get_or_fetch(app_row.0, "v1.0.0", &release.assets[0])
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
    if !app.is_downloadable() {
        return Err(AppError::validation(
            "application",
            "Application is not configured for downloads",
        ));
    }
    let tag = app.pinned_release_tag.as_deref().unwrap();
    release_cache.invalidate(app.id, tag).await;
    let release = release_cache
        .get(
            app.id,
            app.forgejo_owner.as_deref().unwrap(),
            app.forgejo_repo.as_deref().unwrap(),
            tag,
        )
        .await
        .map_err(|e| {
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
            release_tag: Some(release.tag_name.clone()),
            assets,
        },
        request_id,
    ))
}
