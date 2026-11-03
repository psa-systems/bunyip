//! Admin Mirzam integration settings and connection check (BUNYIP-997).
//!
//! Modelled on the email-config and Stripe pairs: the four non-secret settings
//! are the singleton `mirzam_config` row, replaced whole on a save, and the API
//! token is the governed secret `MIRZAM_API_TOKEN`, read from and written to
//! the ONE provider `SECRETS_STORAGE` declares and never sent back.
//!
//! Keeping account holders on the lists reads these settings in
//! `bunyip_domain::services::mirzam_sync` (BUNYIP-998), which records its last
//! failure on the same row; the GET below returns it.

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;

use crate::config::{Config, GovernedSecret};
use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::{
    validate_mirzam_settings, AuditAction, CreateAuditLog, MirzamConfigResponse,
    UpdateMirzamConfigRequest,
};
use crate::repositories::{AuditLogRepository, MirzamConfigRepository};
use crate::responses::{get_request_id, success};
use crate::services::AppKeySet;

/// The token as the declared provider holds it, blank read as absent.
async fn stored_token(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
) -> Result<Option<String>, AppError> {
    Ok(
        crate::secrets::read_secret(pool, config, key_set, GovernedSecret::MirzamApiToken)
            .await?
            .filter(|t| !t.trim().is_empty()),
    )
}

/// `GET /v1/admin/mirzam`
pub async fn get_mirzam_config(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let row = MirzamConfigRepository::get(&pool).await?;
    let has_api_token = stored_token(&pool, &config, &app_key_set).await?.is_some();
    Ok(success(
        MirzamConfigResponse::new(&row, config.secrets_provider, has_api_token),
        request_id,
    ))
}

/// `PUT /v1/admin/mirzam`
///
/// The four settings are replaced whole. `api_token` empty or absent leaves
/// the stored token as it is; a value is written to the declared provider, and
/// in `SECRETS_STORAGE=environment` (the one read-only provider) it is a 409.
/// Validation failures are 400s naming the field, never a 5xx, so bunyip-web
/// can show the admin which field was wrong.
pub async fn update_mirzam_config(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
    body: web::Json<UpdateMirzamConfigRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let provider = config.secrets_provider;
    let token = body
        .api_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    if token.is_some() && !provider.is_writable() {
        return Err(crate::secrets::read_only_provider_error(
            GovernedSecret::MirzamApiToken,
        ));
    }

    // Nothing is written until every field passes.
    let settings = validate_mirzam_settings(
        body.enabled,
        &body.base_url,
        &body.updates_list,
        &body.notices_list,
    )
    .map_err(|e| AppError::validation(e.field.to_string(), e.message))?;
    if settings.enabled
        && token.is_none()
        && stored_token(&pool, &config, &app_key_set).await?.is_none()
    {
        return Err(AppError::validation(
            GovernedSecret::MirzamApiToken.form_field(),
            "Set the API token before switching the integration on.",
        ));
    }

    // The token goes first, so a failed Infisical write aborts the save with
    // its cause and leaves the row untouched.
    if let Some(token) = token {
        crate::secrets::write_secret(
            &pool,
            &config,
            &app_key_set,
            provider,
            GovernedSecret::MirzamApiToken,
            token,
            Some(admin.0.sub),
        )
        .await?;
    }
    let row = MirzamConfigRepository::update_settings(&pool, &settings, admin.0.sub).await?;

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminMirzamConfigUpdated)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_metadata(serde_json::json!({
                "setting": "mirzam_config",
                // An address and two slugs, not secrets: recording them is what
                // makes "who pointed bunyip at that list" answerable.
                "enabled": settings.enabled,
                "base_url": settings.base_url,
                "updates_list": settings.updates_list,
                "notices_list": settings.notices_list,
                // Never the token: only that it changed and where it went. The
                // metadata key stays `secret_store` like the other config saves.
                "token_changed": token.is_some(),
                "secret": token.map(|_| GovernedSecret::MirzamApiToken.name()),
                "secret_store": token.map(|_| provider.as_str()),
            })),
    )
    .await?;

    let has_api_token =
        token.is_some() || stored_token(&pool, &config, &app_key_set).await?.is_some();
    Ok(success(
        MirzamConfigResponse::new(&row, provider, has_api_token),
        request_id,
    ))
}

/// `POST /v1/admin/mirzam/check`
///
/// Reads both SAVED lists from Mirzam with the saved token and reports each
/// one's name and kind, or what is wrong. A failing Mirzam is a 200 carrying
/// `ok: false`: it is the result the admin asked for, not an API error. Only
/// missing settings, which leave nothing to check, are a 400.
pub async fn check_mirzam_connection(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let row = MirzamConfigRepository::get(&pool).await?;
    if row.base_url.trim().is_empty()
        || row.updates_list.trim().is_empty()
        || row.notices_list.trim().is_empty()
    {
        return Err(AppError::validation(
            "base_url",
            "Save the Mirzam address and both list slugs before checking the connection.",
        ));
    }
    let token = stored_token(&pool, &config, &app_key_set)
        .await?
        .ok_or_else(|| {
            AppError::validation(
                GovernedSecret::MirzamApiToken.form_field(),
                "No API token is set. Save one before checking the connection.",
            )
        })?;

    let report = bunyip_domain::services::mirzam::check_connection(
        &row.base_url,
        &token,
        &row.updates_list,
        &row.notices_list,
    )
    .await;
    if !report.ok {
        tracing::warn!(
            base_url = %row.base_url,
            "the Mirzam connection check failed: {}",
            report
                .lists
                .iter()
                .filter(|list| !list.ok)
                .map(|list| format!("{}: {}", list.list, list.message))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    Ok(success(report, request_id))
}
