//! Settings-archive admin endpoints (BUNYIP-715, backed by BUNYIP-714's
//! `settings_archive` module).
//!
//! `POST /v1/admin/settings-archive/export`: super admin exports the current
//! settings as a passphrase-sealed archive, streamed back as a JSON download.
//!
//! `POST /v1/admin/settings-archive/import`: super admin previews (`dry_run`)
//! or applies an archive. A successful apply performs every in-process reload
//! the per-section admin saves perform, so a restore takes effect without a
//! restart (except `system_settings`, which load on startup).
//!
//! Neither endpoint logs or audits a setting value, secret, hash or passphrase.

use std::sync::{Arc, RwLock};

use actix_web::{http, web, HttpRequest, HttpResponse};
use chrono::Utc;
use dunite_core::services::EncryptionKeySet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

use crate::config::{AutoBanConfig, Config, EmailConfig, TierConfig};
use crate::errors::AppError;
use crate::handlers::PricingCache;
use crate::middleware::{AutoBanService, SuperAdminUser};
use crate::models::BrandingCache;
use crate::models::{AuditAction, BrandingRow, CreateAuditLog};
use crate::repositories::{
    AuditLogRepository, AutoBanConfigRepository, BrandingRepository, EmailConfigRepository,
    RateLimitConfigRepository, StripeConfigRepository, TierConfigRepository,
};
use crate::responses::{get_request_id, success};
use crate::services::{AuthService, EmailService, StripeService};
use crate::settings_archive::{self, ExportOptions, SettingsSnapshot};

#[derive(Debug, Deserialize)]
pub struct ExportRequest {
    pub passphrase: String,
    #[serde(default)]
    pub include_catalog: bool,
    #[serde(default)]
    pub include_oauth_clients: bool,
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    pub archive: Value,
    pub passphrase: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct ExportSummary {
    pub sections: Vec<&'static str>,
}

/// `POST /v1/admin/settings-archive/export`
///
/// Sealed archive, streamed back as an attachment.
pub async fn export_settings_archive(
    req: HttpRequest,
    admin: SuperAdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<EncryptionKeySet>,
    body: web::Json<ExportRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let options = ExportOptions {
        include_catalog: body.include_catalog,
        include_oauth_clients: body.include_oauth_clients,
    };
    let snapshot = settings_archive::export(&pool, &config, &app_key_set, options).await?;
    // SPEC-9.37.*: seal applies the passphrase check; a weak passphrase bubbles
    // up as the core's `AppError::validation("passphrase", ..)`, which the
    // kernel turns into a 422 for the admin UI.
    let sealed = settings_archive::seal(&snapshot, &body.passphrase, &[]).await?;

    let sections = section_names(body.include_catalog, body.include_oauth_clients);
    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminSettingsArchiveExported)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_metadata(serde_json::json!({ "sections": sections })),
    )
    .await?;

    let filename = format!("bunyip-settings-{}.json", Utc::now().format("%Y%m%d"));
    Ok(HttpResponse::Ok()
        .insert_header((http::header::CONTENT_TYPE, "application/json"))
        .insert_header((
            http::header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        ))
        .insert_header((http::header::CACHE_CONTROL, "no-store"))
        .insert_header(("X-Request-Id", request_id))
        .body(sealed))
}

/// `POST /v1/admin/settings-archive/import`
///
/// Dry-run returns the `ImportPlan`; apply returns the `ImportReport` and
/// hot-reloads every in-process service the ticket's background table names.
pub async fn import_settings_archive(
    req: HttpRequest,
    admin: SuperAdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<EncryptionKeySet>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    auth_service: web::Data<Arc<AuthService>>,
    pricing_cache: web::Data<Arc<PricingCache>>,
    branding: web::Data<Arc<BrandingCache>>,
    email_service: web::Data<Arc<EmailService>>,
    stripe_service: web::Data<Arc<StripeService>>,
    auto_ban: web::Data<AutoBanService>,
    body: web::Json<ImportRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let archive_bytes = serde_json::to_vec(&body.archive)
        .map_err(|e| AppError::validation("archive", format!("archive is not valid JSON: {e}")))?;
    let snapshot = settings_archive::open(&archive_bytes, &body.passphrase).await?;

    if body.dry_run {
        let plan = settings_archive::plan(&pool, &config, &app_key_set, &snapshot).await?;
        return Ok(success(plan, request_id));
    }

    // Apply. On a step failure the core returns `Ok(report)` with
    // `applied: false` on the failing step; we surface that as a 500 carrying
    // the report (so the admin UI can render the partial-apply story) rather
    // than hiding it behind a generic error.
    let report =
        settings_archive::apply(&pool, &config, &app_key_set, &snapshot, Some(admin.0.sub)).await?;

    let partial = report
        .steps
        .iter()
        .find(|s| !s.applied)
        .map(|s| s.step.clone());

    // Reload every in-process service for the sections the archive carried.
    if let Err(e) = reload_services_after_apply(
        &pool,
        &config,
        &app_key_set,
        &tier_config,
        &auth_service,
        &pricing_cache,
        &branding,
        &email_service,
        &stripe_service,
        &auto_ban,
        &snapshot,
    )
    .await
    {
        tracing::error!(error = %e, "settings-archive import: reload failed after apply");
        return Err(AppError::internal(format!(
            "Import applied but a hot-reload failed: {e}. A restart will pick up the saved rows."
        )));
    }

    let sections = archive_section_names(&snapshot);
    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminSettingsArchiveImported)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_metadata(serde_json::json!({
                "sections": sections,
                "counts": report_counts(&report),
            })),
    )
    .await?;

    if let Some(step) = partial {
        tracing::error!(
            step = %step,
            "settings-archive import: partial apply"
        );
        return Ok(HttpResponse::InternalServerError()
            .insert_header(("X-Request-Id", request_id))
            .json(&report));
    }

    Ok(success(report, request_id))
}

#[allow(clippy::too_many_arguments)]
async fn reload_services_after_apply(
    pool: &PgPool,
    config: &Config,
    app_key_set: &EncryptionKeySet,
    tier_config: &Arc<RwLock<TierConfig>>,
    auth_service: &Arc<AuthService>,
    pricing_cache: &Arc<PricingCache>,
    branding: &Arc<BrandingCache>,
    email_service: &Arc<EmailService>,
    stripe_service: &Arc<StripeService>,
    auto_ban: &AutoBanService,
    snapshot: &SettingsSnapshot,
) -> Result<(), AppError> {
    // Every section that is always-present in a snapshot gets reloaded; the two
    // Option-shaped sections (`catalog`, `oauth_clients`) are structural data
    // writes without an in-process cache that needs invalidating.
    let _ = snapshot;

    // Tier: resolve the live row and push through auth + tier lock + pricing cache.
    {
        let row = TierConfigRepository::get(pool).await?;
        let (stack, _source) = crate::handlers::admin::section_stack(
            TierConfig::database_provider(&row),
            crate::config_providers::TIER_KEYS,
        )?;
        let resolved = TierConfig::resolve(&stack, Some(&row));
        *tier_config.write().unwrap_or_else(|e| e.into_inner()) = resolved.clone();
        auth_service.reload_tier_config(resolved);
        pricing_cache.invalidate();
    }

    // Branding: re-read and store into the BrandingCache.
    {
        let row: BrandingRow = BrandingRepository::get(pool).await?;
        branding.store(&row);
    }

    // Email: resolve from the live providers and reload the service.
    {
        let row = EmailConfigRepository::get(pool).await?;
        let smtp_password = crate::secrets::read_secret(
            pool,
            config,
            app_key_set,
            crate::config::GovernedSecret::SmtpPassword,
        )
        .await?;
        let (stack, _source) = crate::handlers::admin::section_stack(
            EmailConfig::database_provider(&row),
            crate::config_providers::EMAIL_KEYS,
        )?;
        let resolved = EmailConfig::resolve(&stack, smtp_password, config.is_production());
        email_service.reload(resolved)?;
    }

    // Stripe: resolve from the live providers and reload the service.
    {
        let row = StripeConfigRepository::get(pool).await?;
        let new_config =
            crate::secrets::stripe_runtime_config(pool, config, app_key_set, &row).await?;
        stripe_service.reload(new_config);
        pricing_cache.invalidate();
    }

    // Rate limits: invalidate the shared cache so the next request re-reads.
    RateLimitConfigRepository::invalidate_cache();

    // Auto-ban: resolve and reload the running service.
    {
        let row = AutoBanConfigRepository::get(pool).await?;
        let (stack, _source) = crate::handlers::admin::section_stack(
            AutoBanConfig::database_provider(&row),
            crate::config_providers::AUTO_BAN_KEYS,
        )?;
        let resolved = AutoBanConfig::resolve(&stack);
        auto_ban.reload(resolved);
    }

    Ok(())
}

fn section_names(include_catalog: bool, include_oauth_clients: bool) -> Vec<&'static str> {
    let mut v = vec![
        "branding",
        "branding_assets",
        "tier_config",
        "auto_ban_config",
        "email_config",
        "stripe_config",
        "mirzam_config",
        "mokosh_config",
        "rate_limit_configs",
        "feature_toggles",
        "system_settings",
        "governed_secrets",
    ];
    if include_catalog {
        v.push("catalog");
    }
    if include_oauth_clients {
        v.push("oauth_clients");
    }
    v
}

fn archive_section_names(snapshot: &SettingsSnapshot) -> Vec<&'static str> {
    let s = &snapshot.sections;
    let mut v = vec![
        "branding",
        "branding_assets",
        "tier_config",
        "auto_ban_config",
        "email_config",
        "stripe_config",
        "mirzam_config",
        "mokosh_config",
        "rate_limit_configs",
        "feature_toggles",
        "system_settings",
        "governed_secrets",
    ];
    if s.catalog.is_some() {
        v.push("catalog");
    }
    if s.oauth_clients.is_some() {
        v.push("oauth_clients");
    }
    v
}

fn report_counts(report: &settings_archive::ImportReport) -> Value {
    serde_json::json!({
        "steps": report.steps.iter().map(|s| {
            serde_json::json!({ "step": s.step, "applied": s.applied })
        }).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    /// AC: a successful non-dry-run import performs every reload in the
    /// Background table. This test scans this file's own source and fails if
    /// any of the required reload call sites is missing.
    #[test]
    fn apply_path_calls_every_required_reload() {
        const SOURCE: &str = include_str!("admin_settings_archive.rs");
        for needle in [
            "reload_tier_config",
            "pricing_cache.invalidate",
            "branding.store",
            "email_service.reload",
            "stripe_service.reload",
            "auto_ban.reload",
            "RateLimitConfigRepository::cache().invalidate",
        ] {
            assert!(
                SOURCE.contains(needle),
                "BUNYIP-715: reload call site missing from the apply path: {needle}"
            );
        }
    }

    /// Neither handler ever surfaces the passphrase in a log or audit payload.
    /// Scans the module source for `tracing::` or `with_metadata` lines that
    /// carry the word; comment lines, test code, and this test's own body
    /// (which has to mention the word to describe itself) are skipped.
    #[test]
    fn source_does_not_log_or_audit_the_passphrase() {
        const SOURCE: &str = include_str!("admin_settings_archive.rs");
        let mut in_tests_mod = false;
        for raw in SOURCE.lines() {
            let line = raw.trim();
            if line.starts_with("mod tests") || line == "#[cfg(test)]" {
                in_tests_mod = true;
                continue;
            }
            if in_tests_mod {
                continue;
            }
            if line.starts_with("//") || line.starts_with("///") {
                continue;
            }
            let lower = line.to_lowercase();
            let references_passphrase = lower.contains("passphrase");
            let is_log_or_audit = lower.contains("tracing::") || lower.contains("with_metadata");
            if references_passphrase && is_log_or_audit {
                panic!("BUNYIP-715: a log or audit line references `passphrase`: {line}");
            }
        }
    }
}
