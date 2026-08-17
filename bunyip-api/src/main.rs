//! bunyip-api - Main entry point
//!
//! This is the entry point for the backend API server.

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use tracing_actix_web::TracingLogger;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use bunyip_api::{
    config::{secret_env, AutoBanConfig, Config, EmailConfig, TierConfig},
    middleware::{
        auto_ban::{self, AutoBanService},
        request_id::RequestIdMiddleware,
        AutoBanMiddleware, CspConfig, SecurityHeaders,
    },
    models::{CreateUser, UserRole},
    mokosh_backup::MokoshHttpBackupAdapter,
    repositories::{
        DownloadCacheRepository, DownloadDailyCountRepository, FeedbackRepository,
        RateLimitRepository, UserRepository,
    },
    routes,
    services::{
        stripe_settings_from_db_model, unconfigured_stripe_config, AppBackupAdapter,
        AppDownloadCache, AuthService, BackupService, DownloadLimiter, EmailService,
        ForgejoAssetClient, GeoIpService, IpEnrichService, JwtConfig, JwtService,
        MokoshBackupAdapter, PasswordService, ReleaseCache, StripeService, TotpService,
        WebhookService,
    },
    version::UpdateChecker,
};
use bunyip_oci::{
    middleware::OciWwwAuthenticate,
    repositories::{OciBlobCacheRepository, OciPullDailyCountRepository},
    services::{BlobCache, ForgejoRegistryClient, ManifestCache, OciLimiter, OciTokenService},
};

/// The concrete blob cache: the generic dunite-oci `BlobCache` engine backed by
/// bunyip's Postgres `OciBlobCacheRepository` store.
type AppBlobCache = BlobCache<OciBlobCacheRepository>;
use bunyip_oidc::services::{oidc_keys::OidcKeySet, oidc_provider::OidcProvider};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load a local .env if present (dev convenience; no-op in containers that
    // inject real environment). Must run before Config::from_env().
    let _ = dotenvy::dotenv();

    // Initialize tracing/logging BEFORE the config loads (BUNYIP-537), so a
    // configuration failure is reported as operator-facing log lines instead of
    // vanishing: every warn/error raised while parsing the environment (missing
    // required variables, invalid TRUSTED_PROXY_CIDR entries) predates the
    // subscriber otherwise. RUST_LOG is read directly because `config.log_level`
    // does not exist yet; it is the same read.
    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    // The error-log buffer (BUNYIP-327) is created first so the capture layer
    // can be wired into the subscriber; the same buffer is registered as app
    // data below so the admin log view can read it.
    let error_log =
        bunyip_api::error_log::ErrorLogBuffer::new(bunyip_api::error_log::DEFAULT_CAPACITY);
    init_tracing(&log_level, error_log.clone());

    // Load configuration. A missing or malformed required variable is reported
    // as one error! line per variable (all of them, in this one run) and exits
    // non-zero: an operator message, not a panic and a backtrace (BUNYIP-537).
    let mut config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            e.log_startup_report();
            error!("Refusing to start: fix the configuration errors above and restart");
            std::process::exit(1);
        }
    };

    info!(
        version = env!("CARGO_PKG_VERSION"),
        environment = %config.environment,
        "Starting bunyip-api"
    );

    // One warn! per optional variable whose absence turns a feature off, from
    // the same inventory. Variables with a working default log nothing.
    bunyip_domain::config::log_feature_gaps();

    // BUNYIP-476: make the trusted-proxy posture visible at boot. With no
    // trusted proxy, X-Forwarded-For is ignored and the socket peer is used - on
    // the two-hop BFF path that is the bunyip-web container, so audited-login
    // actor_ip_address, the access-log IP, and the per-IP rate-limit key are all
    // attributed to bunyip-web instead of the real browser. That is safe but
    // silent, and is the "audit records a Docker IP" symptom; surface it so a
    // misconfiguration is diagnosable from the logs rather than the data.
    // The unset case is reported once by the inventory warning above; an entry
    // that is set but unparseable is reported by `parse_trusted_proxies`.
    if config.trusts_forwarded_client_ip() {
        info!(
            trusted_proxy_cidrs = config.trusted_proxies.len(),
            "TRUSTED_PROXY_CIDR set; forwarded client IPs (audit, access log, rate limit) resolve to the real client behind a trusted proxy"
        );
    }

    // Create database connection pool
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to connect to database");
            e
        })?;

    info!("Database connection pool established");

    // BUNYIP-483: `bunyip-api reencrypt-secrets` rewrites every at-rest secret
    // under the current APP_ENCRYPTION_KEY and exits, so an operator decides
    // when the pass runs and can take a database backup first. BUNYIP-542 adds
    // the `secrets-*` pre-flight family. Migrations stay owned by the server
    // path below, so a subcommand runs against the schema a running deployment
    // already has.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(subcommand) = args.first() {
        return run_subcommand(subcommand, &args[1..], &pool, &config).await;
    }

    // BUNYIP-79: heal the in-place-edited migration checksums before the
    // migrator's immutability check would abort on databases that applied the
    // pre-edit bodies. No-op on fresh and already-healed databases.
    bunyip_api::migrate_reconcile::reconcile_legacy_migration_checksums(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to reconcile legacy migration checksums");
            e
        })?;

    // BUNYIP-457: deliver the application_entitlements_source_check guard that
    // 20260605000010's in-place edit added but the reconcile above never
    // retro-applies, so 20260802000010's bare DROP CONSTRAINT does not abort
    // startup on databases that applied the pre-edit body. No-op elsewhere.
    bunyip_api::migrate_reconcile::backfill_entitlement_source_check(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to backfill entitlement source-check constraint");
            e
        })?;

    // Run database migrations
    info!("Running database migrations...");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to run database migrations");
            e
        })?;

    info!("Database migrations completed successfully");

    // BUNYIP-360: provision the unprivileged `bunyip_app` (NOSUPERUSER
    // NOBYPASSRLS) role that activates the per-user RLS policies (BUNYIP-344).
    // Runs AFTER migrations so the GRANT-on-all-tables covers every table the
    // migrations just created; idempotent, so it is safe to run every boot. The
    // primary `pool` connects as the DB owner/superuser (`bunyip`), which can
    // CREATE ROLE, so no separate admin connection is needed. Gated on
    // BUNYIP_APP_PASSWORD: unset means the role is not managed here and the app
    // pool below falls back to the primary pool (RLS no-op).
    if let Some(app_password) = config.app_password.as_deref() {
        bunyip_api::db::provision_app_role(&pool, app_password)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to provision the bunyip_app RLS role");
                e
            })?;
    } else {
        info!("BUNYIP_APP_PASSWORD unset; skipping bunyip_app role provisioning");
    }

    // BUNYIP-344: the self-service pool for per-user row level security. When
    // APP_DATABASE_URL is set it connects as the unprivileged NOBYPASSRLS
    // `bunyip_app` role so the `user_isolation` policy actually constrains
    // self-service reads; when unset it reuses the primary pool (RLS is then a
    // runtime no-op, because the primary role bypasses it). Either way the
    // rerouted handlers open transactions via `db::begin_with_user`, so the
    // fallback is safe. Built AFTER provisioning so the role exists before the
    // pool connects as it.
    let app_pool = match config.app_database_url.as_deref() {
        Some(url) => {
            let p = PgPoolOptions::new()
                .max_connections(10)
                .acquire_timeout(Duration::from_secs(5))
                .connect(url)
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to connect to the bunyip_app (RLS) database pool");
                    e
                })?;
            info!("Self-service RLS pool established (APP_DATABASE_URL, NOBYPASSRLS role)");
            p
        }
        None => {
            // The reason and the remedy come from the env inventory warning
            // emitted at boot (BUNYIP-537), so this branch stays silent.
            pool.clone()
        }
    };
    let app_pool = bunyip_api::db::AppPool(app_pool);

    // Seed default admin if SETUP_DEFAULT_ADMIN is set and no admin exists.
    // secret_env supports both the plain env var (dev) and the
    // SETUP_DEFAULT_ADMIN_FILE compose secret (production), and treats empty
    // values as unset.
    if let Some(setup_admin) = secret_env("SETUP_DEFAULT_ADMIN") {
        let admin_emails = UserRepository::find_admin_emails(&pool).await?;
        if admin_emails.is_empty() {
            let Some((email, password)) = setup_admin.split_once(':') else {
                fatal_config_error(
                    "SETUP_DEFAULT_ADMIN",
                    "the value is not in the required `email:password` format, so no bootstrap \
                     admin can be seeded",
                    "Set SETUP_DEFAULT_ADMIN (or the setup_default_admin secret file) to \
                     `email:password`, or unset it and use BOOTSTRAP_ADMIN_EMAIL instead.",
                );
            };

            let email = email.trim();
            let password = password.trim();

            // Exempt from the argon2_offload rule (BUNYIP-553): this runs once
            // at startup, before the server binds, so there is no worker
            // arbiter to block.
            let password_service = PasswordService::new();
            let password_hash = password_service.hash(password)?;

            let user = UserRepository::create(
                &pool,
                CreateUser {
                    email: email.to_string(),
                    password_hash: Some(password_hash),
                    role: UserRole::Admin,
                },
            )
            .await?;

            // BUNYIP-413: this IS the first setup account, so it carries the
            // super-admin flag. Without it a deployment seeded this way would
            // have no account able to manage rate limits or IP bans (the
            // migration backfill runs before any user exists, and the
            // bootstrap-email promotion is inert once an admin exists).
            UserRepository::set_super_admin(&pool, user.id, true).await?;

            info!(email = %user.email, "Default admin user created from SETUP_DEFAULT_ADMIN");
        } else {
            info!("Admin user(s) already exist, skipping SETUP_DEFAULT_ADMIN");
        }
    }

    // Register the browser SPA OIDC clients with redirect/post-logout/audience
    // values correct for THIS environment (BUNYIP-57). The static migration
    // 20260603000010 seeds env-blind staging (a8n.systems) URIs that break the
    // PKCE flow on every other host; this env-driven startup upsert is
    // authoritative and self-healing, correcting the stale row in place. Each
    // client is env-gated: unset vars -> skip + log (mirrors SETUP_DEFAULT_ADMIN).
    upsert_spa_oidc_client(
        &pool,
        "b0000000-0000-4000-8000-000000000002",
        "mokosh-apps",
        "MOKOSH_APPS_REDIRECT_URIS",
        "MOKOSH_APPS_POST_LOGOUT_REDIRECT_URIS",
        "MOKOSH_APPS_AUDIENCE",
    )
    .await?;
    upsert_spa_oidc_client(
        &pool,
        "b0000000-0000-4000-8000-000000000003",
        "drillmark",
        "DRILLMARK_REDIRECT_URIS",
        "DRILLMARK_POST_LOGOUT_REDIRECT_URIS",
        "DRILLMARK_AUDIENCE",
    )
    .await?;

    // Reconcile the lets-chat confidential RP for THIS environment (LC-448).
    // The static migration 20260618032217 seeds env-blind staging
    // (chat.a8n.systems) redirect/audience that break the auth-code flow on
    // every other host - the same class BUNYIP-57 fixed for the SPA clients
    // above, which lets-chat was never added to. Confidential variant so each
    // environment can also pin a dedicated client secret.
    upsert_lets_chat_oidc_client(&pool).await?;

    // BUNYIP-336: populate `applications.webhook_url` for the mokosh row from
    // env. The seed migration 20260603000020_seed_mokosh_hosted_application
    // inserted the row without a webhook_url, so `fan_out_account_deleted`
    // (bunyip-api/src/handlers/user.rs:713) skipped every dispatch to mokosh
    // and the account_deleted event never left bunyip. Staging and prod hit
    // different receiver hosts (`api.msp.a8n.systems` vs `api.msp.psa.systems`),
    // so a per-env migration cannot cover both; the URL is env-driven, the
    // same pattern the OIDC-client upserts above use for their per-env values.
    upsert_mokosh_webhook_url(&pool).await?;

    // Test database connection
    sqlx::query("SELECT 1").execute(&pool).await.map_err(|e| {
        error!(error = %e, "Database health check failed");
        e
    })?;

    info!("Database health check passed");

    // Initialize JWT service. secret_env reads JWT_SECRET_FILE (compose
    // secret) or JWT_SECRET (dev .env); empty counts as unset, so an
    // unconfigured production deployment fails fast here.
    let jwt_secret = secret_env("JWT_SECRET").unwrap_or_else(|| {
        if config.is_production() {
            // Unreachable in practice: the startup audit (BUNYIP-537) already
            // refused to build this Config. Kept as the defence in depth, and
            // reported the same way: an operator message, not a panic.
            fatal_config_error(
                "JWT_SECRET",
                "no signing key for session access/refresh tokens",
                "Set JWT_SECRET_FILE=/run/secrets/jwt_secret (compose) or JWT_SECRET (dev .env).",
            );
        }
        "development-secret-key-min-32-chars-long!".to_string()
    });
    let mut jwt_config = JwtConfig::from_secret(&jwt_secret, &config.app_name);
    // BUNYIP-381: cookie-session token lifetimes. Access token 30 min. The
    // refresh JWT exp is set to the longest cap (30 days) so it never expires
    // before the DB/cookie deadline, which is what enforces the real 1-day /
    // 30-day-"remember me" lifetime (see AuthService::refresh_absolute_ttl).
    jwt_config.access_token_expiry = chrono::Duration::minutes(30);
    jwt_config.refresh_token_expiry = chrono::Duration::days(30);
    let jwt_service = Arc::new(JwtService::new(jwt_config.clone()));

    info!("JWT service initialized");

    // BUNYIP-332: dedicated HMAC-SHA256 signing secret for outbound webhook
    // dispatches (account_deleted, maintenance_change, active_change). Before
    // this the WebhookService reused JWT_SECRET, which forced every RP that
    // verifies a bunyip webhook to hold bunyip's access-token signing key -
    // a far too broad grant. Now the shared secret is scoped to webhook
    // verification only; mokosh-server holds the matching value in its
    // BUNYIP_WEBHOOK_SECRET (mokosh-server/src/main.rs `resolve_secret`
    // path). Same file-or-env resolution as JWT_SECRET so a compose deploy
    // reads BUNYIP_WEBHOOK_SIGNING_SECRET_FILE, a dev .env reads
    // BUNYIP_WEBHOOK_SIGNING_SECRET. Production fails to boot if unset;
    // dev/test falls back to a stable placeholder.
    let webhook_signing_secret = secret_env("BUNYIP_WEBHOOK_SIGNING_SECRET").unwrap_or_else(|| {
        if config.is_production() {
            // Unreachable in practice (the startup audit already refused this
            // Config); reported as an operator message, never a panic.
            fatal_config_error(
                "BUNYIP_WEBHOOK_SIGNING_SECRET",
                "no HMAC key for outbound webhook dispatches",
                "Set BUNYIP_WEBHOOK_SIGNING_SECRET_FILE=/run/secrets/webhook_signing_secret \
                 (compose) or BUNYIP_WEBHOOK_SIGNING_SECRET (dev .env); `just init-secrets` \
                 generates the secret file.",
            );
        }
        "development-webhook-signing-secret-change-in-production".to_string()
    });

    // Initialize tier config — prefer DB overrides, fall back to env vars
    let tier_config = {
        use bunyip_api::repositories::TierConfigRepository;
        match TierConfigRepository::get(&pool).await {
            Ok(row) if TierConfig::has_db_overrides(&row) => {
                info!("Tier config initialized from database");
                TierConfig::from_db_row(&row)
            }
            _ => {
                info!("Tier config initialized from environment variables");
                config.tier.clone()
            }
        }
    };
    let tier_config = Arc::new(std::sync::RwLock::new(tier_config));

    // BUNYIP-483: ONE at-rest key set (APP_ENCRYPTION_KEY, plus any
    // APP_ENCRYPTION_KEY_PREV entries for the rotation / consolidation window)
    // guards the TOTP secrets, the Stripe secrets and the SMTP password.
    let app_key_set = config.app_key_set();

    // BUNYIP-542: read every governed integration secret from the ONE store
    // SECRETS_STORAGE declares, and enforce the store declaration. The old
    // three-level precedence chain (DB row, then the env slot, then a
    // conditional Infisical fetch that filled the slot only when it was empty)
    // is gone: which copy is live is now the operator's declaration.
    //
    // Infisical is contacted only when it IS the declared store, so `database`
    // and `environment` deployments keep the property that Infisical is never a
    // boot dependency. In `infisical` mode the read is deliberately fail-closed.
    let infisical_probe = if config.secrets_storage == bunyip_api::config::SecretsStorage::Infisical
    {
        bunyip_api::secrets::InfisicalProbe::Inspect
    } else {
        bunyip_api::secrets::InfisicalProbe::Skip
    };
    let secret_survey =
        bunyip_api::secrets::survey(&pool, &config, &app_key_set, infisical_probe).await?;
    let fatal_secret_reports = bunyip_api::secrets::enforce(&secret_survey);
    if !fatal_secret_reports.is_empty() {
        for report in &fatal_secret_reports {
            error!(env_var = "SECRETS_STORAGE", "{report}");
        }
        error!("Refusing to start: fix the secret storage errors above and restart");
        std::process::exit(1);
    }
    info!(
        secrets_storage = %config.secrets_storage,
        "Governed integration secrets resolved from the declared store"
    );
    // The env-fallback EmailConfig carries the same resolved password, so both
    // branches below agree on the one store's value.
    let smtp_password = secret_survey
        .value(bunyip_api::config::GovernedSecret::SmtpPassword)
        .map(str::to_string);
    config.email.smtp_password = smtp_password.clone().unwrap_or_default();

    // Initialize Email service: non-secret settings prefer the DB row (admin
    // UI) and fall back to the environment (BUNYIP-351); the SMTP password
    // comes from the declared store alone (BUNYIP-542). The auth service (built
    // below) also holds the email service for BUNYIP-366 login-location alerts,
    // so email is wired ahead of auth.
    let email_config = {
        use bunyip_api::repositories::EmailConfigRepository;
        match EmailConfigRepository::get(&pool).await {
            Ok(row) if EmailConfig::has_db_overrides(&row) => {
                info!("Email config initialized from database");
                EmailConfig::from_db_row(&row, smtp_password, config.is_production())
            }
            _ => {
                info!("Email config initialized from environment variables");
                config.email.clone()
            }
        }
    };
    // BUNYIP-204/351: a production deployment must not run with email disabled,
    // even when the effective config is resolved from the DB. The disabled path
    // suppresses transactional mail (magic links, resets), breaking auth flows.
    if config.is_production() && !email_config.enabled {
        fatal_config_error(
            "SMTP_HOST",
            "email is disabled in a production deployment (resolved from the DB email_config row \
             plus the environment), so magic links and password resets are never delivered \
             (BUNYIP-204)",
            "Configure SMTP on the admin Email page, or set SMTP_HOST / EMAIL_ENABLED in the api \
             environment.",
        );
    }
    let email_enabled = email_config.enabled;
    let email_service = Arc::new(EmailService::new(email_config).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "Failed to initialize email service, using dev mode");
        EmailService::new_dev()
    }));

    info!(enabled = email_enabled, "Email service initialized");

    // BUNYIP-366: IP -> country resolver for login-location alerts. Optional:
    // when IP2LOCATION_DB_PATH is unset or the .BIN fails to load, geoip stays
    // None and the alerts silently disable. Login is never blocked either way.
    let geoip = match config.ip2location_db_path.as_deref() {
        Some(path) => match GeoIpService::new(path) {
            Ok(svc) => {
                info!(path = %path, "GeoIP (IP2Location) service initialized");
                Some(Arc::new(svc))
            }
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "Failed to load IP2Location DB; login-location alerts disabled");
                None
            }
        },
        None => {
            info!("IP2LOCATION_DB_PATH unset; login-location alerts disabled");
            None
        }
    };

    // BUNYIP-437: IP -> ASN / VPN enrichment for the admin abuse surfaces.
    // Optional and independent of geoip: when IP2PROXY_DB_PATH is unset or the
    // .BIN fails to load, ip_enrich stays None and the admin enrichment endpoint
    // reports "no enrichment". The signal is advisory only and never gates a
    // request, so a missing dataset degrades cleanly.
    let ip_enrich: Option<Arc<IpEnrichService>> = match config.ip2proxy_db_path.as_deref() {
        Some(path) => match IpEnrichService::new(path) {
            Ok(svc) => {
                info!(path = %path, "IP enrichment (IP2Proxy) service initialized");
                Some(Arc::new(svc))
            }
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "Failed to load IP2Proxy DB; IP enrichment disabled");
                None
            }
        },
        None => {
            info!("IP2PROXY_DB_PATH unset; IP enrichment disabled");
            None
        }
    };

    // Initialize Auth service
    let auth_service = Arc::new(AuthService::new(
        pool.clone(),
        (*jwt_service).clone(),
        tier_config.clone(),
        config.bootstrap_admin_email.clone(),
        email_service.clone(),
        geoip,
        config.login_approval_enabled,
    ));

    info!("Auth service initialized");

    // BUNYIP-542: the non-secret Stripe settings (app tag, checkout URLs, trial
    // length) still come from the `stripe_config` row, but the two secrets come
    // from the declared store alone.
    let stripe_config = {
        use bunyip_api::config::GovernedSecret;
        use bunyip_api::repositories::StripeConfigRepository;
        // A row read failure is reported before it degrades to "Stripe
        // disabled", so a broken query never reads as an unconfigured account.
        let row = match StripeConfigRepository::get(&pool).await {
            Ok(row) => Some(row),
            Err(e) => {
                error!(error = %e, "Failed to read stripe_config; starting with Stripe disabled");
                None
            }
        };
        let secret_key = secret_survey.value(GovernedSecret::StripeSecretKey);
        match (&row, secret_key) {
            (Some(row), Some(secret_key)) => {
                // The non-secret columns come from the row in every mode; the
                // two secrets come from the declared store alone.
                let mut cfg = stripe_settings_from_db_model(row);
                cfg.secret_key = secret_key.to_string();
                cfg.webhook_secret = secret_survey
                    .value(GovernedSecret::StripeWebhookSecret)
                    .map(str::to_string)
                    .unwrap_or(unconfigured_stripe_config().webhook_secret);
                info!(
                    secrets_storage = %config.secrets_storage,
                    "Stripe service initialized with secrets from the declared store"
                );
                cfg
            }
            _ => {
                info!("No Stripe secret key in the declared store; starting with Stripe disabled");
                unconfigured_stripe_config()
            }
        }
    };
    let stripe_service = Arc::new(StripeService::new(stripe_config));

    info!("Stripe service initialized");

    // BUNYIP-203: warn loudly when Stripe is wired (real secret key) but no
    // webhook signing secret is configured. The webhook handler fails closed
    // in this state, so events will be rejected until a real webhook signing
    // secret is saved.
    if stripe_service.is_configured() && !stripe_service.webhook_secret_configured() {
        tracing::warn!(
            "Stripe secret key is configured but the webhook signing secret is unset or the \
             placeholder; the Stripe webhook endpoint will REJECT all events until a real \
             webhook signing secret is saved on the admin Stripe page. Forged-event protection \
             is fail-closed (BUNYIP-203)."
        );
    }

    // Initialize Forgejo download services (optional — degrade gracefully when unconfigured).
    // The mechanism comes from the dunite-download engine; bunyip supplies the
    // Postgres-backed store (DownloadCacheRepository) and counter
    // (DownloadDailyCountRepository) adapters.
    let forgejo_client = config.download.forgejo_base_url.as_ref().and_then(|base| {
        config
            .download
            .forgejo_api_token
            .as_ref()
            .map(|token| Arc::new(ForgejoAssetClient::new(base.clone(), token.clone())))
    });

    let release_cache = forgejo_client
        .clone()
        .map(|c| Arc::new(ReleaseCache::new(c, config.download.release_cache_ttl_secs)));

    // BUNYIP-487: keeps the public /v1/pricing page off Stripe's API on every
    // visit. Invalidated whenever an admin saves tier config.
    let pricing_cache = Arc::new(bunyip_api::handlers::PricingCache::new(
        bunyip_api::handlers::PRICING_CACHE_TTL_SECS,
    ));

    let download_cache: Option<Arc<AppDownloadCache>> = forgejo_client.clone().map(|c| {
        let store = Arc::new(DownloadCacheRepository::new(pool.clone()));
        Arc::new(AppDownloadCache::new(
            c,
            &config.download.cache_dir,
            config.download.cache_max_bytes,
            store,
        ))
    });

    if let Some(cache) = &download_cache {
        if let Err(e) = cache.ensure_dir().await {
            tracing::warn!(error = %e, "failed to create download cache dir");
        }
    }

    // Durable per-user daily counter used by the download limiter.
    let download_counter = Arc::new(DownloadDailyCountRepository::new(pool.clone()));

    let download_limiter = Arc::new(DownloadLimiter::new(
        config.download.concurrency_per_user,
        config.download.daily_limit_per_user,
    ));

    info!(
        enabled = config.download.enabled(),
        cache_dir = %config.download.cache_dir,
        "Download service initialized"
    );

    // Initialize OCI registry services (optional — degrade gracefully when Forgejo is unconfigured)
    let forgejo_registry_client: Option<Arc<ForgejoRegistryClient>> =
        config.download.forgejo_base_url.as_ref().and_then(|base| {
            config
                .download
                .forgejo_api_token
                .as_ref()
                .map(|token| Arc::new(ForgejoRegistryClient::new(base.clone(), token.clone())))
        });

    let manifest_cache: Option<Arc<ManifestCache>> = forgejo_registry_client
        .as_ref()
        .map(|_| Arc::new(ManifestCache::new(config.oci.manifest_cache_ttl_secs)));

    // Blob cache persistence adapter — the dunite-oci engine is generic over a
    // `BlobStore`; bunyip implements it with `OciBlobCacheRepository` over Postgres.
    let blob_cache: Option<Arc<AppBlobCache>> = forgejo_registry_client.clone().map(|c| {
        let store = Arc::new(OciBlobCacheRepository::new(pool.clone()));
        Arc::new(BlobCache::new(
            c,
            &config.oci.blob_cache_dir,
            config.oci.blob_cache_max_bytes,
            store,
        ))
    });

    if let Some(bc) = &blob_cache {
        if let Err(e) = bc.ensure_dir().await {
            tracing::warn!(error = %e, "failed to create oci blob cache dir");
        }
    }

    // Daily pull counter persistence adapter used by the OCI registry server.
    let oci_pull_counter = Arc::new(OciPullDailyCountRepository::new(pool.clone()));

    let oci_limiter = Arc::new(OciLimiter::new(
        config.oci.concurrent_manifests_per_user,
        config.oci.pulls_per_user_per_day,
    ));
    let oci_token_service = Arc::new(OciTokenService::new(&jwt_config, config.oci.token_ttl_secs));

    // Fail fast on a registry config that can never work (malformed realm).
    // Misconfiguration here otherwise only surfaces as opaque docker-login
    // failures on the client side.
    if config.oci.enabled {
        if let Err(e) = config.oci.validate() {
            anyhow::bail!("invalid OCI registry configuration: {e}");
        }
    }

    info!(
        enabled = config.oci.enabled,
        port = config.oci.port,
        "OCI registry service initialized"
    );

    // Initialize TOTP service
    let totp_service = Arc::new(TotpService::new(
        app_key_set.clone(),
        config.app_name.clone(),
        pool.clone(),
    ));

    info!("TOTP service initialized");

    // Initialize webhook service
    // BUNYIP-332: signed with the dedicated `BUNYIP_WEBHOOK_SIGNING_SECRET`
    // loaded above, NOT with `JWT_SECRET`. Rotating JWT_SECRET no longer
    // breaks webhook verification on the receiving RP, and a compromised
    // webhook secret does not let an attacker mint bunyip access tokens.
    let webhook_service = Arc::new(WebhookService::new(webhook_signing_secret));

    info!("Webhook service initialized");

    // BUNYIP-145: in-process event bus for SSE fan-out. Mutation handlers
    // publish; the /v1/events SSE handler subscribes per-user. Eliminates
    // the hard-refresh-after-admin-grant UX (Brendon@netcal.com triage).
    let event_bus = Arc::new(bunyip_domain::services::EventBus::new());
    info!("Event bus initialized");

    // Initialize OIDC provider (optional — only when OIDC_ISSUER is set)
    let oidc_provider: Option<Arc<OidcProvider>> = if config.oidc.enabled() {
        // BUNYIP-258's dev-kid guard is part of the startup audit in
        // `Config::from_env` (BUNYIP-537), so a `dev-` kid in production never
        // reaches this point.
        let key_set = OidcKeySet::load(
            &config.oidc.jwt_private_key_path,
            &config.oidc.jwt_active_kid,
            &config.oidc.jwt_public_keys_dir,
        )
        .map_err(|e| {
            error!(error = %e, "Failed to load OIDC key set");
            anyhow::anyhow!("{}", e)
        })?;
        let provider = Arc::new(OidcProvider::new(
            config.oidc.clone(),
            Arc::new(key_set),
            pool.clone(),
        ));
        info!(
            issuer = %config.oidc.issuer.as_deref().unwrap_or("(none)"),
            active_kid = %config.oidc.jwt_active_kid,
            public_keys_dir = %config.oidc.jwt_public_keys_dir,
            "OIDC provider initialized",
        );
        Some(provider)
    } else {
        info!("OIDC provider disabled (OIDC_ISSUER not set)");
        None
    };

    // Register the OIDC provider as an `AtJwtVerifier` so the auth
    // extractors (`AuthenticatedUser`, `AdminUser`, `MemberUser`,
    // `OptionalUser`) accept OIDC at+jwt tokens in addition to legacy
    // HS256 access tokens (BUNYIP-55). The extractor peeks at the JWT
    // header's `typ` claim and routes to whichever verifier matches;
    // when OIDC is disabled, `None` here means the extractor falls
    // back to HS256-only, preserving the pre-BUNYIP-55 behaviour.
    let at_jwt_verifier: Option<Arc<dyn bunyip_domain::middleware::auth::AtJwtVerifier>> =
        oidc_provider
            .as_ref()
            .map(|p| Arc::clone(p) as Arc<dyn bunyip_domain::middleware::auth::AtJwtVerifier>);

    // Initialize auto-ban config — prefer DB overrides, fall back to env vars
    // (BUNYIP-351). Mirrors the tier/stripe DB-overrides-env pattern.
    let auto_ban_config = {
        use bunyip_api::repositories::AutoBanConfigRepository;
        match AutoBanConfigRepository::get(&pool).await {
            Ok(row) if AutoBanConfig::has_db_overrides(&row) => {
                info!("Auto-ban config initialized from database");
                AutoBanConfig::from_db_row(&row)
            }
            _ => {
                info!("Auto-ban config initialized from environment variables");
                config.auto_ban
            }
        }
    };

    // Initialize account backup/restore service (BUNYIP-353 / BUNYIP-356). One
    // adapter per entitled app. When Mokosh is configured (MOKOSH_BACKUP_API_URL
    // + the OIDC provider + the Mokosh OAuth client all present) the real HTTP
    // adapter calls Mokosh's tenant data export/import; otherwise the domain's
    // pending stub is used. New adapters register here without touching the
    // orchestration.
    let mokosh_adapter: Arc<dyn AppBackupAdapter> = {
        let url = std::env::var("MOKOSH_BACKUP_API_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        match (oidc_provider.as_ref(), url) {
            (Some(provider), Some(url)) => {
                // The mokosh-apps OAuth client (seeded in this same startup)
                // sources the minted token's audience + TTL.
                let mokosh_client_id =
                    uuid::Uuid::parse_str("b0000000-0000-4000-8000-000000000002")
                        .expect("static mokosh-apps client id");
                match provider.load_client(mokosh_client_id).await? {
                    Some(client) => {
                        info!("Mokosh backup adapter enabled (BUNYIP-356)");
                        Arc::new(MokoshHttpBackupAdapter::new(
                            reqwest::Client::new(),
                            url,
                            provider.clone(),
                            client,
                            pool.clone(),
                        )) as Arc<dyn AppBackupAdapter>
                    }
                    None => {
                        error!(
                            "MOKOSH_BACKUP_API_URL is set but the mokosh-apps OAuth client is \
                             missing; account backup falls back to the pending stub"
                        );
                        Arc::new(MokoshBackupAdapter)
                    }
                }
            }
            _ => Arc::new(MokoshBackupAdapter),
        }
    };
    let backup_service = BackupService::new(vec![mokosh_adapter]);

    // Initialize auto-ban service
    let auto_ban_service = Arc::new(AutoBanService::new(auto_ban_config, pool.clone()));

    // Load existing bans from DB
    match auto_ban::load_active_bans(&pool).await {
        Ok(bans) => {
            auto_ban_service.load_bans(bans).await;
        }
        Err(e) => {
            error!(error = %e, "Failed to load IP bans from database");
        }
    }

    info!(
        enabled = auto_ban_config.enabled,
        threshold = auto_ban_config.threshold,
        "Auto-ban service initialized"
    );

    // Initialize the operator-facing update checker. Polls
    // BUNYIP_UPDATE_CHECK_URL (a Forgejo/Gitea releases/latest endpoint)
    // hourly with caching; disabled when the env var is unset.
    let update_check_url = std::env::var("BUNYIP_UPDATE_CHECK_URL")
        .ok()
        .filter(|s| !s.is_empty());
    // secret_env supports the {NAME}_FILE compose-secret convention,
    // falling back to the plain env var.
    let update_check_token = secret_env("BUNYIP_UPDATE_CHECK_TOKEN");
    info!(
        enabled = update_check_url.is_some(),
        "Update checker initialized"
    );
    let update_checker = Arc::new(UpdateChecker::new(
        update_check_url,
        update_check_token,
        bunyip_api::version::current_version().to_string(),
        concat!("bunyip-api/", env!("CARGO_PKG_VERSION")),
    ));

    let server_addr = config.server_addr();
    // CORS_ORIGIN is a comma-separated allow-list once multiple RPs register
    // (bunyip-web + mokosh-apps + drillmark). Parse it into a Vec so each
    // origin can be registered individually with the CorsLayer; passing the
    // raw comma-list as a single .allowed_origin() never matches any browser
    // Origin header.
    let cors_origins: Vec<String> = config
        .cors_origin
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    // The CSRF guard (BUNYIP-423) reuses the same allow-list: an origin trusted
    // to read responses is the same set trusted to originate a cookie write.
    // The guard itself lives in dunite-core (DEV-526); bunyip supplies its
    // app-specific exempt prefixes and ambient-cookie names. /oauth2/* and
    // /.well-known/* are cross-origin OIDC surfaces gated by PKCE + state +
    // nonce; /v1/webhooks/stripe is HMAC-authenticated by Stripe.
    const CSRF_EXEMPT_PREFIXES: [&str; 3] = ["/oauth2/", "/.well-known/", "/v1/webhooks/stripe"];
    const CSRF_AMBIENT_COOKIES: [&str; 2] = ["access_token", "refresh_token"];
    let csrf_guard = dunite_core::middleware::OriginGuard::new(
        &cors_origins,
        &CSRF_EXEMPT_PREFIXES,
        &CSRF_AMBIENT_COOKIES,
    );

    let config_data = config.clone();

    // Spawn rate limit cleanup background task
    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        info!("Rate limit cleanup task started");
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match RateLimitRepository::cleanup_expired(&cleanup_pool).await {
                Ok(deleted) => {
                    if deleted > 0 {
                        info!(deleted, "Cleaned up expired rate limit entries");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to cleanup expired rate limit entries");
                }
            }
        }
    });

    // Spawn auto-ban cleanup background task (every 5 minutes)
    let ban_cleanup_pool = pool.clone();
    let ban_cleanup_service = auto_ban_service.clone();
    tokio::spawn(async move {
        info!("Auto-ban cleanup task started");
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            // Clean in-memory state
            ban_cleanup_service.cleanup_expired().await;
            // Clean database
            match auto_ban::cleanup_expired_bans(&ban_cleanup_pool).await {
                Ok(deleted) => {
                    if deleted > 0 {
                        info!(deleted, "Cleaned up expired IP bans");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to cleanup expired IP bans");
                }
            }
        }
    });

    // Spawn feedback archive+purge background task (every 24h)
    // Archives closed feedback older than 90 days into feedback_archive, then hard-deletes it
    let feedback_purge_pool = pool.clone();
    tokio::spawn(async move {
        info!("Feedback archive/purge task started");
        let mut interval = tokio::time::interval(Duration::from_secs(86400));
        loop {
            interval.tick().await;
            match FeedbackRepository::archive_and_purge_closed(&feedback_purge_pool).await {
                Ok(purged) => {
                    if purged > 0 {
                        info!(purged, "Archived and purged closed feedback records");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to archive/purge closed feedback");
                }
            }
        }
    });

    // BUNYIP-246: e2e disposable-account reaper (non-production safety net).
    // Catches disposable test accounts a crashed e2e run created but never
    // self-deleted (its per-test `DELETE /v1/users/me?purge` never ran). Spawned
    // ONLY when hard-purge is permitted (non-production environment +
    // BUNYIP_E2E_BOOTSTRAP_ALLOW=true), so it can never touch a real user on
    // production. Hard-deletes rows whose email carries the disposable
    // subaddress marker `+e2e-` and that are older than the age threshold.
    if config.e2e_purge_enabled() {
        // Hourly sweep; only disposables older than 6h are eligible, so the
        // reaper can never race a live test mid-run. The `+e2e-` marker is the
        // plus-subaddress every disposable email carries (e2e/lib/accounts.ts).
        const E2E_REAPER_INTERVAL_SECS: u64 = 3600;
        const E2E_REAPER_MAX_AGE_SECS: i64 = 6 * 3600;
        const E2E_DISPOSABLE_EMAIL_PATTERN: &str = "%+e2e-%";
        let reaper_pool = pool.clone();
        tokio::spawn(async move {
            info!("E2E disposable-account reaper started (non-production)");
            let mut interval = tokio::time::interval(Duration::from_secs(E2E_REAPER_INTERVAL_SECS));
            loop {
                interval.tick().await;
                match UserRepository::hard_delete_stale_disposable(
                    &reaper_pool,
                    E2E_DISPOSABLE_EMAIL_PATTERN,
                    E2E_REAPER_MAX_AGE_SECS,
                )
                .await
                {
                    Ok(reaped) => {
                        if reaped > 0 {
                            info!(reaped, "Reaped stale e2e disposable accounts");
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to reap stale e2e disposable accounts");
                    }
                }
            }
        });
    }

    info!(address = %server_addr, "Starting HTTP server");

    // Pre-clone OCI handles for the OCI server (primary closure moves the originals)
    let manifest_cache_oci = manifest_cache.clone();
    let blob_cache_oci = blob_cache.clone();
    let oci_limiter_oci = oci_limiter.clone();
    let oci_token_service_oci = oci_token_service.clone();
    let forgejo_registry_client_oci = forgejo_registry_client.clone();
    let oci_pull_counter_oci = oci_pull_counter.clone();
    let pool_oci_server = pool.clone();
    let cfg_oci_server = config_data.oci.clone();

    // Process start instant, surfaced as SystemHealth.uptime_seconds. `Instant`
    // is `Copy`, so the per-worker `move` factory closure just copies it.
    let server_start = std::time::Instant::now();

    // Single shared reqwest client for OIDC backchannel-logout delivery
    // (BUNYIP-74). Built once at startup so a builder error fails fast instead
    // of being silently swallowed per request; cloned per worker (reqwest
    // clones share one connection pool).
    let backchannel_http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build backchannel logout HTTP client: {e}"))?;

    let primary = HttpServer::new(move || {
        // Configure CORS. Only the explicit CORS_ORIGIN entries are echoed
        // back with credentials; everything else gets no
        // Access-Control-Allow-Origin. Per the CORS policy (docs/cors.md /
        // PSA-21: "No wildcards. Always use an explicit, comma-separated
        // list"), we deliberately do NOT register an `allowed_origin_fn`:
        // actix evaluates that closure in addition to the explicit list, and a
        // prefix/suffix match there (`starts_with("http://localhost")` or a
        // bare `ends_with(".{apex}")`) reflects credentialed CORS to
        // attacker-controlled hosts (`http://localhost.attacker.com`, any
        // `*.{apex}` subdomain). For local dev, enumerate the dev origin (e.g.
        // `http://localhost:4400`) in CORS_ORIGIN instead. (BUNYIP-124)
        let mut cors = Cors::default();
        for o in &cors_origins {
            cors = cors.allowed_origin(o);
        }
        let cors = cors
            .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::ACCEPT,
                actix_web::http::header::CONTENT_TYPE,
                actix_web::http::header::COOKIE,
            ])
            .expose_headers(vec![actix_web::http::header::SET_COOKIE])
            .supports_credentials()
            .max_age(3600);

        // The OIDC authorize flow legitimately reaches the registered RP app
        // origins (an OAuth client `redirect_uri` origin; a public API origin
        // distinct from the serving origin). Those are exactly the configured
        // CORS_ORIGIN entries, so widen only `connect-src` / `form-action` of
        // the dunite CSP to allowlist them instead of relaxing the whole
        // policy or hardcoding a brand origin in the generic crate (BUNYIP-244).
        let csp = CspConfig {
            connect_src: cors_origins.clone(),
            form_action: cors_origins.clone(),
        };

        App::new()
            // Add middleware (order matters - executed in reverse order)
            // Root span records the trusted external client IP in
            // `http.client_ip` (BUNYIP-310), not the spoofable actix realip.
            .wrap(TracingLogger::<
                bunyip_api::root_span::ClientIpRootSpanBuilder,
            >::new())
            // Log the external client IP (trusted XFF behind Traefik), not the
            // proxy's socket peer, so request lines are attributable (BUNYIP-328).
            .wrap(bunyip_api::access_log::access_logger())
            .wrap(SecurityHeaders::with_csp(csp))
            .wrap(RequestIdMiddleware)
            // CSRF guard for cookie-authenticated writes (BUNYIP-423). Wrapped
            // before `cors` so it runs INSIDE it: CORS answers the preflight,
            // this rejects a state-changing cookie request whose Origin /
            // Referer is not a CORS_ORIGIN entry.
            .wrap(csrf_guard.clone())
            .wrap(cors)
            // BUNYIP-426 F7: default per-IP / per-user cap under every route, so
            // an endpoint added without its own `check_rate_limit` is still
            // throttled. Inside AutoBanMiddleware, so a banned IP is rejected
            // before it costs a rate-limit row.
            .wrap(bunyip_api::rate_limit_floor::RateLimitFloor::new(
                pool.clone(),
            ))
            // Auto-ban runs outermost — rejects banned IPs before CORS processing
            .wrap(AutoBanMiddleware::new(auto_ban_service.clone()))
            // Generic extractor errors (BUNYIP-481): malformed body / path /
            // query / form parameters return the AppError envelope with a
            // generic message instead of actix's raw parse text. JSON keeps its
            // 32 KB limit.
            .app_data(bunyip_api::extractors::json_config())
            .app_data(bunyip_api::extractors::path_config())
            .app_data(bunyip_api::extractors::query_config())
            .app_data(bunyip_api::extractors::form_config())
            // Add database pool to app state
            .app_data(web::Data::new(pool.clone()))
            // Self-service NOBYPASSRLS pool for per-user RLS reads (BUNYIP-344).
            .app_data(web::Data::new(app_pool.clone()))
            // Share the auto-ban service with the admin IP-ban handlers so they
            // can list/lift bans against the same in-memory map the middleware
            // enforces (BUNYIP-319). `Data::from` reuses the existing Arc
            // instead of double-wrapping it.
            .app_data(web::Data::from(auto_ban_service.clone()))
            // Server start instant for uptime reporting
            .app_data(web::Data::new(server_start))
            // In-memory error-log buffer for the admin log view (BUNYIP-327).
            .app_data(web::Data::new(error_log.clone()))
            // Add services to app state
            .app_data(jwt_service.clone())
            // Register the at+jwt verifier (BUNYIP-55) as an
            // `Arc<dyn AtJwtVerifier>` so the auth extractors can
            // accept OIDC at+jwt tokens. Cloned per worker; the
            // underlying `OidcProvider` is shared (it owns `Arc`s
            // internally). When OIDC is disabled (`oidc_provider ==
            // None`), this call is a no-op and the extractor falls
            // back to legacy HS256-only verification.
            .app_data(at_jwt_verifier.clone().unwrap_or_else(|| {
                Arc::new(bunyip_domain::middleware::auth::DisabledAtJwtVerifier)
                    as Arc<dyn bunyip_domain::middleware::auth::AtJwtVerifier>
            }))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(email_service.clone()))
            .app_data(web::Data::new(stripe_service.clone()))
            .app_data(web::Data::new(totp_service.clone()))
            .app_data(web::Data::new(webhook_service.clone()))
            .app_data(web::Data::new(backup_service.clone()))
            .app_data(web::Data::new(event_bus.clone()))
            .app_data(web::Data::new(app_key_set.clone()))
            .app_data(web::Data::new(config_data.clone()))
            .app_data(web::Data::new(download_limiter.clone()))
            .app_data(web::Data::new(download_counter.clone()))
            .app_data(web::Data::new(release_cache.clone()))
            .app_data(web::Data::new(download_cache.clone()))
            .app_data(web::Data::new(manifest_cache.clone()))
            .app_data(web::Data::new(blob_cache.clone()))
            .app_data(web::Data::new(oci_limiter.clone()))
            .app_data(web::Data::new(oci_token_service.clone()))
            .app_data(web::Data::new(config_data.oci.clone()))
            .app_data(web::Data::new(forgejo_registry_client.clone()))
            // OIDC provider (None when OIDC_ISSUER is not set; handlers return 404)
            .app_data(web::Data::new(oidc_provider.clone()))
            .app_data(web::Data::new(backchannel_http_client.clone()))
            .app_data(web::Data::new(tier_config.clone()))
            .app_data(web::Data::new(pricing_cache.clone()))
            // Update checker for the root-level /version endpoint
            .app_data(web::Data::new(update_checker.clone()))
            .app_data(web::Data::new(ip_enrich.clone()))
            // Configure routes
            .configure(routes::configure)
    })
    .bind(&server_addr)?
    .shutdown_timeout(30)
    .run();

    let oci_ready = config.oci.enabled && forgejo_registry_client_oci.is_some();
    if config.oci.enabled && forgejo_registry_client_oci.is_none() {
        tracing::warn!(
            "OCI_REGISTRY_ENABLED=true but FORGEJO_BASE_URL / FORGEJO_API_TOKEN are unset - \
             OCI registry server will NOT be started"
        );
    }

    // Startup banner (the primary listener is already bound at this point).
    println!();
    println!("  ===================================================");
    println!("   bunyip-api  (PSA Systems)");
    println!("   API listening on  http://{server_addr}");
    if let Some(issuer) = config.oidc.issuer.as_deref() {
        println!("   OIDC issuer       {issuer}");
    }
    if oci_ready {
        println!(
            "   OCI registry on   http://{}:{}",
            config.host, config.oci.port
        );
    }
    println!("  ===================================================");
    println!();

    if oci_ready {
        let oci_addr = format!("{}:{}", config.host, config.oci.port);
        let mc = manifest_cache_oci;
        let bc = blob_cache_oci;
        let ol = oci_limiter_oci;
        let ots = oci_token_service_oci;
        let cfg_oci = cfg_oci_server;
        let frc = forgejo_registry_client_oci;
        let counter = oci_pull_counter_oci;
        let pool_oci = pool_oci_server;

        info!(address = %oci_addr, "Starting OCI registry server");

        let oci = HttpServer::new(move || {
            App::new()
                // Same external-client-IP attribution in the root span as the
                // primary app (BUNYIP-310).
                .wrap(TracingLogger::<
                    bunyip_api::root_span::ClientIpRootSpanBuilder,
                >::new())
                // Same external-client-IP attribution as the primary app
                // (BUNYIP-328). The OCI server registers no `Config`, so no
                // proxy is trusted and this logs the socket peer, matching the
                // prior `%a` behaviour until trusted proxies are wired here.
                .wrap(bunyip_api::access_log::access_logger())
                // OCI registry serves no OIDC flow; the locked-down default CSP
                // (no extra allowlist origins) is correct here.
                .wrap(SecurityHeaders::new())
                .wrap(RequestIdMiddleware)
                .wrap(OciWwwAuthenticate {
                    cfg: std::sync::Arc::new(cfg_oci.clone()),
                })
                .app_data(web::Data::new(pool_oci.clone()))
                // Raw Arc for the OciBearerUser extractor
                .app_data(ots.clone())
                // web::Data for the issue_token handler
                .app_data(web::Data::new(ots.clone()))
                .app_data(web::Data::new(mc.clone()))
                .app_data(web::Data::new(bc.clone()))
                .app_data(web::Data::new(ol.clone()))
                .app_data(web::Data::new(counter.clone()))
                .app_data(web::Data::new(cfg_oci.clone()))
                .app_data(web::Data::new(frc.clone()))
                .configure(bunyip_oci::routes::configure)
        })
        .bind(&oci_addr)?
        .shutdown_timeout(30)
        .run();

        tokio::try_join!(primary, oci)?;
    } else {
        info!("OCI registry server disabled (requires OCI_REGISTRY_ENABLED=true + FORGEJO_BASE_URL + FORGEJO_API_TOKEN)");
        primary.await?;
    }

    Ok(())
}

/// Maintenance subcommands (BUNYIP-483, BUNYIP-542). Anything but a known
/// subcommand is an error rather than a silently-ignored argument.
async fn run_subcommand(
    subcommand: &str,
    args: &[String],
    pool: &sqlx::PgPool,
    config: &Config,
) -> anyhow::Result<()> {
    use bunyip_api::config::SecretsStorage;
    use bunyip_api::secrets;

    // BUNYIP-542: the `secrets-*` family is the non-destructive pre-flight the
    // operator runs on a HEALTHY deployment, before a cutover, instead of
    // discovering a mistake as a crash loop after the old configuration stopped
    // serving. Infisical is inspected when the deployment has it enabled, which
    // is what makes "is `--to infisical` ready?" answerable.
    let key_set = config.app_key_set();
    let probe = if config.infisical.enabled || config.secrets_storage == SecretsStorage::Infisical {
        secrets::InfisicalProbe::Inspect
    } else {
        secrets::InfisicalProbe::Skip
    };

    match subcommand {
        "secrets-status" => {
            let survey = secrets::survey(pool, config, &key_set, probe).await?;
            let report = secrets::status_report(&survey);
            if args.iter().any(|arg| arg == "--json") {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", secrets::render_status(&report));
            }
            Ok(())
        }
        "secrets-migrate" => {
            let target = match args.iter().position(|arg| arg == "--to") {
                Some(idx) => args.get(idx + 1).and_then(|raw| SecretsStorage::parse(raw)),
                None => None,
            };
            let Some(target) = target else {
                anyhow::bail!(
                    "secrets-migrate needs --to <{}>",
                    SecretsStorage::LEGAL_VALUES
                );
            };
            let survey = secrets::survey(pool, config, &key_set, probe).await?;
            let dry_run = args.iter().any(|arg| arg == "--dry-run");
            let summary =
                secrets::run_migration(pool, config, &key_set, &survey, target, dry_run).await?;
            print!("{summary}");
            Ok(())
        }
        "secrets-purge" => {
            let survey = secrets::survey(pool, config, &key_set, probe).await?;
            let confirm = args.iter().any(|arg| arg == "--confirm");
            let summary = secrets::run_purge(pool, config, &survey, confirm).await?;
            print!("{summary}");
            Ok(())
        }
        other => run_reencrypt_subcommand(other, pool, config).await,
    }
}

/// The BUNYIP-483 re-encryption pass, split out so the subcommand table above
/// reads as one match.
async fn run_reencrypt_subcommand(
    subcommand: &str,
    pool: &sqlx::PgPool,
    config: &Config,
) -> anyhow::Result<()> {
    match subcommand {
        "reencrypt-secrets" => {
            let summary = bunyip_api::reencrypt::reencrypt_all(pool, &config.app_key_set()).await?;
            info!(%summary, "reencrypt-secrets finished");
            println!("reencrypt-secrets: {summary}");
            for item in &summary.undecryptable {
                println!("  undecryptable, left untouched: {item}");
            }
            if !summary.undecryptable.is_empty() {
                anyhow::bail!(
                    "{} value(s) decrypt with neither APP_ENCRYPTION_KEY nor any \
                     APP_ENCRYPTION_KEY_PREV entry; add the missing key and re-run",
                    summary.undecryptable.len()
                );
            }
            Ok(())
        }
        other => anyhow::bail!(
            "unknown subcommand {other:?} (known: reencrypt-secrets, secrets-status, \
             secrets-migrate, secrets-purge)"
        ),
    }
}

/// Env-driven, idempotent upsert of a browser SPA OIDC client (BUNYIP-57).
///
/// Reads the per-client env vars (via `secret_env`, so the `{NAME}_FILE`
/// compose-secret convention works and empty counts as unset). Registration is
/// gated on the two vars login actually requires: `*_REDIRECT_URIS` and
/// `*_AUDIENCE`. When both are present it upserts the row keyed on the fixed
/// `client_id` UUID, writing only `redirect_uris`, `post_logout_redirect_uris`,
/// and `audience`; every other column (`client_type`, `name`, scopes, grant
/// types, auth method, `require_pkce`, TTL) keeps its migration-defined value
/// via `DO UPDATE` of only those three columns. `*_POST_LOGOUT_REDIRECT_URIS`
/// is optional (the column is `TEXT[] DEFAULT '{}'`); when unset it upserts an
/// empty array rather than skipping the whole client, so a partial config can
/// never silently leave the stale staging row in place. The `*_REDIRECT_URIS` /
/// `*_POST_LOGOUT_REDIRECT_URIS` vars are comma-separated. When either required
/// var is unset the client is skipped with a log line (env-gated, like
/// SETUP_DEFAULT_ADMIN) so an undeployed client never resurfaces a stale row.
async fn upsert_spa_oidc_client(
    pool: &sqlx::PgPool,
    client_id: &str,
    name: &str,
    redirect_uris_var: &str,
    post_logout_var: &str,
    audience_var: &str,
) -> anyhow::Result<()> {
    let (Some(redirect_uris), Some(audience)) =
        (secret_env(redirect_uris_var), secret_env(audience_var))
    else {
        // Silent here: the env inventory warns once at boot for each of this
        // client's variables, so the message lives in one place (BUNYIP-537).
        return Ok(());
    };
    // Optional: a client with no post-logout URIs upserts an empty array.
    let post_logout = secret_env(post_logout_var).unwrap_or_default();

    let split_csv = |s: &str| -> Vec<String> {
        s.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect()
    };
    let redirect_list = split_csv(&redirect_uris);
    let post_logout_list = split_csv(&post_logout);

    sqlx::query(
        r#"
        INSERT INTO oauth_clients (
            client_id, client_type, name,
            redirect_uris, post_logout_redirect_uris,
            allowed_scopes, allowed_grant_types,
            token_endpoint_auth_method, require_pkce,
            audience, access_token_ttl_seconds
        ) VALUES (
            $1::uuid, 'public', $2,
            $3, $4,
            ARRAY['openid', 'email', 'offline_access'],
            ARRAY['authorization_code', 'refresh_token'],
            'none', TRUE,
            $5, 600
        )
        ON CONFLICT (client_id) DO UPDATE SET
            redirect_uris = EXCLUDED.redirect_uris,
            post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
            audience = EXCLUDED.audience
        "#,
    )
    .bind(client_id)
    .bind(name)
    .bind(&redirect_list)
    .bind(&post_logout_list)
    .bind(&audience)
    .execute(pool)
    .await?;

    info!(
        client = name,
        redirect_uris = ?redirect_list,
        audience = %audience,
        "SPA OIDC client registered from environment"
    );

    Ok(())
}

/// Reconcile the lets-chat confidential OIDC client for THIS environment
/// (LC-448). Confidential analogue of `upsert_spa_oidc_client`: the static
/// migration `20260618032217_register_lets_chat_oidc_client.sql` seeds
/// env-blind staging (`chat.a8n.systems`) redirect/audience that reject the
/// callback on every other host, and a `client_secret_hash` shared across the
/// staging and prod bunyip DBs. This startup upsert is authoritative and
/// self-healing.
///
/// Keyed on the fixed `client_id` UUID, it `UPDATE`s the row the migration
/// pre-seeds (the migrator runs before this), writing `redirect_uris`,
/// `post_logout_redirect_uris`, and `audience` from the per-environment
/// `LETS_CHAT_REDIRECT_URIS` / `LETS_CHAT_POST_LOGOUT_REDIRECT_URIS` /
/// `LETS_CHAT_AUDIENCE` vars. `client_type` and `token_endpoint_auth_method`
/// are left at their migration values (confidential / client_secret_basic).
///
/// `LETS_CHAT_CLIENT_SECRET_HASH` (optional, an Argon2id PHC string) lets an
/// environment pin a DEDICATED client secret: `COALESCE` keeps the existing
/// (migration) hash when the var is unset, so staging stays on the shared
/// hash while prod overrides it. The hash is a verifier, not the secret; the
/// plaintext lives only in lets-chat's `LETS_CHAT_BUNYIP_SSO_CLIENT_SECRET`.
///
/// Gated on `LETS_CHAT_REDIRECT_URIS` + `LETS_CHAT_AUDIENCE` (skip + log when
/// unset, like the SPA path), so an environment that has not configured the
/// client never resurfaces a stale row.
async fn upsert_lets_chat_oidc_client(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    // Matches migration 20260618032217 and lets-chat's configured CLIENT_ID.
    let client_id = "b0000000-0000-4000-8000-00000000000c";

    let (Some(redirect_uris), Some(audience)) = (
        secret_env("LETS_CHAT_REDIRECT_URIS"),
        secret_env("LETS_CHAT_AUDIENCE"),
    ) else {
        // Silent here: the env inventory warns once at boot for each of the two
        // variables, so the message lives in exactly one place (BUNYIP-537).
        return Ok(());
    };
    let post_logout = secret_env("LETS_CHAT_POST_LOGOUT_REDIRECT_URIS").unwrap_or_default();
    // Optional per-environment dedicated secret. When unset, COALESCE below
    // preserves the migration's shared hash.
    let secret_hash = secret_env("LETS_CHAT_CLIENT_SECRET_HASH");

    let split_csv = |s: &str| -> Vec<String> {
        s.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect()
    };
    let redirect_list = split_csv(&redirect_uris);
    let post_logout_list = split_csv(&post_logout);

    // UPDATE (not INSERT...ON CONFLICT): the row is guaranteed by the
    // migration, which the migrator applies before this reconcile runs. A
    // missing row would touch zero rows and is surfaced by the rows_affected
    // log below rather than silently inserting a malformed client.
    let result = sqlx::query(
        r#"
        UPDATE oauth_clients SET
            redirect_uris = $2,
            post_logout_redirect_uris = $3,
            audience = $4,
            client_secret_hash = COALESCE($5, client_secret_hash)
        WHERE client_id = $1::uuid
        "#,
    )
    .bind(client_id)
    .bind(&redirect_list)
    .bind(&post_logout_list)
    .bind(&audience)
    .bind(secret_hash.as_deref())
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        tracing::warn!(
            client_id,
            "lets-chat OIDC client row not found; migration 20260618032217 may not have applied"
        );
    } else {
        info!(
            redirect_uris = ?redirect_list,
            audience = %audience,
            secret_pinned = secret_hash.is_some(),
            "lets-chat OIDC client reconciled from environment"
        );
    }

    Ok(())
}

/// BUNYIP-336: populate `applications.webhook_url` for `slug='mokosh'` from
/// the `MOKOSH_WEBHOOK_URL` env var, so `fan_out_account_deleted`
/// (bunyip-api/src/handlers/user.rs:694) actually POSTs the
/// `account_deleted` event to mokosh-server's receiver at
/// `POST /api/v1/bunyip/webhooks/account-deleted`. The seed migration
/// 20260603000020 inserted the mokosh row without a webhook_url, so the
/// fan-out's `if app.webhook_url.as_deref().is_none_or(str::is_empty)`
/// guard skipped every dispatch and the event never left bunyip. Same
/// env-driven-upsert pattern the OIDC clients above use, so staging and
/// production hosts (`api.msp.a8n.systems` vs `api.msp.psa.systems`) can
/// share the code path without either being baked into a migration.
///
/// Skips when the env var is unset (dev boot without the compose env
/// keeps working; there is nothing to dispatch to locally). Warns when
/// the mokosh row is missing (probably an incomplete migration state);
/// does not fail boot on that either, so an operator does not lose the
/// hub on a bad seed.
async fn upsert_mokosh_webhook_url(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    let Some(url) = secret_env("MOKOSH_WEBHOOK_URL") else {
        // Silent here: the env inventory warns once at boot (BUNYIP-537).
        return Ok(());
    };

    let rows = sqlx::query(
        r#"
        UPDATE applications
           SET webhook_url = $1
         WHERE slug = 'mokosh'
        "#,
    )
    .bind(&url)
    .execute(pool)
    .await?
    .rows_affected();

    if rows == 0 {
        tracing::warn!(
            "no applications row with slug='mokosh'; webhook_url not registered. \
             Expected seed migration 20260603000020_seed_mokosh_hosted_application \
             to have run first. Account-deleted dispatch to mokosh will not fire \
             until this is fixed."
        );
    } else {
        info!(
            webhook_url = %url,
            "mokosh applications.webhook_url reconciled from environment"
        );
    }

    Ok(())
}

/// Report a configuration error that only surfaces after the config has loaded
/// (a malformed value, or a feature resolved from the database), then exit
/// non-zero (BUNYIP-537).
///
/// Same operator-facing shape as [`ConfigError::log_startup_report`]: one
/// `tracing::error!` naming the variable, the reason and the remedy. Never a
/// `panic!`, which prints a panic location and exits 101, reading as a bug
/// rather than as a configuration error.
fn fatal_config_error(env_var: &str, reason: &str, remedy: &str) -> ! {
    error!(
        env_var,
        "Startup configuration error: {env_var} is not usable - {reason}. {remedy}"
    );
    error!("Refusing to start: fix the configuration error above and restart");
    std::process::exit(1);
}

/// Initialize tracing subscriber with compact human-readable output, plus the
/// BUNYIP-327 error-log capture layer that copies ERROR-level events into the
/// in-memory buffer backing the admin log view. The capture layer filters to
/// ERROR internally; ERROR outranks the usual `info`/`warn` verbosities, so the
/// shared `EnvFilter` admits those events to it in any normal configuration.
fn init_tracing(log_level: &str, error_log: bunyip_api::error_log::ErrorLogBuffer) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().compact())
        .with(bunyip_api::error_log::ErrorLogLayer::new(error_log))
        .init();
}
