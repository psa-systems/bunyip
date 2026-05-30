//! bunyip-api - Main entry point
//!
//! This is the entry point for the backend API server.

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use tracing_actix_web::TracingLogger;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use bunyip_api::{
    config::{Config, TierConfig},
    middleware::{
        auto_ban::{self, AutoBanService},
        request_id::RequestIdMiddleware,
        AutoBanMiddleware, SecurityHeaders,
    },
    models::{CreateUser, UserRole},
    repositories::{FeedbackRepository, RateLimitRepository, UserRepository},
    routes,
    version::UpdateChecker,
    services::{
        AuthService, DownloadCache, DownloadLimiter, EmailService, EncryptionKeySet,
        ForgejoClient, JwtConfig, JwtService, PasswordService, ReleaseCache, StripeConfig,
        StripeService, TotpService, WebhookService,
    },
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

    // Load configuration
    let config = Config::from_env()?;

    // Initialize tracing/logging
    init_tracing(&config.log_level);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        environment = %config.environment,
        "Starting bunyip-api"
    );

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

    // Seed default admin if SETUP_DEFAULT_ADMIN is set and no admin exists
    if let Ok(setup_admin) = std::env::var("SETUP_DEFAULT_ADMIN") {
        let admin_emails = UserRepository::find_admin_emails(&pool).await?;
        if admin_emails.is_empty() {
            let (email, password) = setup_admin.split_once(':').unwrap_or_else(|| {
                panic!("SETUP_DEFAULT_ADMIN must be in format 'email:password'");
            });

            let email = email.trim();
            let password = password.trim();

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

            info!(email = %user.email, "Default admin user created from SETUP_DEFAULT_ADMIN");
        } else {
            info!("Admin user(s) already exist, skipping SETUP_DEFAULT_ADMIN");
        }
    }

    // Test database connection
    sqlx::query("SELECT 1").execute(&pool).await.map_err(|e| {
        error!(error = %e, "Database health check failed");
        e
    })?;

    info!("Database health check passed");

    // Initialize JWT service
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        if config.is_production() {
            panic!("JWT_SECRET must be set in production");
        }
        "development-secret-key-min-32-chars-long!".to_string()
    });
    let jwt_config = JwtConfig::from_secret(&jwt_secret, &config.app_name);
    let jwt_service = Arc::new(JwtService::new(jwt_config.clone()));

    info!("JWT service initialized");

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

    // Initialize Auth service
    let auth_service = Arc::new(AuthService::new(
        pool.clone(),
        (*jwt_service).clone(),
        tier_config.clone(),
    ));

    info!("Auth service initialized");

    // Initialize Email service
    let email_service = Arc::new(EmailService::new(config.email.clone()).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "Failed to initialize email service, using dev mode");
        EmailService::new_dev()
    }));

    info!(enabled = config.email.enabled, "Email service initialized");

    // Build encryption key sets for key rotation support
    let totp_key_set = EncryptionKeySet {
        current: config.totp_encryption_key,
        current_version: config.totp_key_version,
        previous: config.totp_encryption_key_prev,
    };
    let stripe_key_set = EncryptionKeySet {
        current: config.stripe_encryption_key,
        current_version: config.stripe_key_version,
        previous: config.stripe_encryption_key_prev,
    };

    // Initialize Stripe service — prefer DB config (set via admin UI), fall back to env vars
    let stripe_config = {
        use bunyip_api::repositories::StripeConfigRepository;
        match StripeConfigRepository::get(&pool).await {
            Ok(db_config) if db_config.secret_key.is_some() => {
                match StripeConfig::from_db_model(&db_config, &stripe_key_set) {
                    Ok(cfg) => {
                        info!("Stripe service initialized from database config");
                        cfg
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to decrypt DB Stripe config, falling back to env vars");
                        StripeConfig::from_env()?
                    }
                }
            }
            _ => StripeConfig::from_env()?,
        }
    };
    let stripe_service = Arc::new(StripeService::new(stripe_config));

    info!("Stripe service initialized");

    // Initialize Forgejo download services (optional — degrade gracefully when unconfigured)
    let forgejo_client = config.download.forgejo_base_url.as_ref().and_then(|base| {
        config
            .download
            .forgejo_api_token
            .as_ref()
            .map(|token| Arc::new(ForgejoClient::new(base.clone(), token.clone())))
    });

    let release_cache = forgejo_client
        .clone()
        .map(|c| Arc::new(ReleaseCache::new(c, config.download.release_cache_ttl_secs)));

    let download_cache = forgejo_client.clone().map(|c| {
        Arc::new(DownloadCache::new(
            c,
            &config.download.cache_dir,
            config.download.cache_max_bytes,
            pool.clone(),
        ))
    });

    if let Some(cache) = &download_cache {
        if let Err(e) = cache.ensure_dir().await {
            tracing::warn!(error = %e, "failed to create download cache dir");
        }
    }

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

    info!(
        enabled = config.oci.enabled,
        port = config.oci.port,
        "OCI registry service initialized"
    );

    // Initialize TOTP service
    let totp_service = Arc::new(TotpService::new(
        totp_key_set,
        config.app_name.clone(),
        pool.clone(),
    ));

    info!("TOTP service initialized");

    // Initialize webhook service
    let webhook_service = Arc::new(WebhookService::new(jwt_secret.clone()));

    info!("Webhook service initialized");

    // Initialize OIDC provider (optional — only when OIDC_ISSUER is set)
    let oidc_provider: Option<Arc<OidcProvider>> = if config.oidc.enabled() {
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

    // Initialize auto-ban service
    let auto_ban_service = Arc::new(AutoBanService::new(config.auto_ban.clone(), pool.clone()));

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
        enabled = config.auto_ban.enabled,
        threshold = config.auto_ban.threshold,
        "Auto-ban service initialized"
    );

    // Initialize the operator-facing update checker. Polls
    // BUNYIP_UPDATE_CHECK_URL (a Forgejo/Gitea releases/latest endpoint)
    // hourly with caching; disabled when the env var is unset.
    let update_check_url = std::env::var("BUNYIP_UPDATE_CHECK_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let update_check_token = std::env::var("BUNYIP_UPDATE_CHECK_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    info!(
        enabled = update_check_url.is_some(),
        "Update checker initialized"
    );
    let update_checker = Arc::new(UpdateChecker::new(update_check_url, update_check_token));

    let server_addr = config.server_addr();
    let cors_origin = config.cors_origin.clone();

    // Extract the domain from CORS_ORIGIN for subdomain matching
    // e.g. "https://example.net" → ".example.net"
    let cors_domain = cors_origin
        .split("://")
        .nth(1)
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .map(|host| format!(".{host}"))
        .unwrap_or_default();

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

    let primary = HttpServer::new(move || {
        // Configure CORS
        let domain = cors_domain.clone();
        let cors = Cors::default()
            .allowed_origin(&cors_origin)
            .allowed_origin_fn(move |origin, _req_head| {
                let origin = origin.as_bytes();
                // Allow localhost (development)
                if origin.starts_with(b"http://localhost") {
                    return true;
                }
                // Allow the configured domain and its subdomains
                if !domain.is_empty() {
                    return origin.ends_with(domain.as_bytes());
                }
                false
            })
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

        App::new()
            // Add middleware (order matters - executed in reverse order)
            .wrap(TracingLogger::default())
            .wrap(Logger::default())
            .wrap(SecurityHeaders)
            .wrap(RequestIdMiddleware)
            .wrap(cors)
            // Auto-ban runs outermost — rejects banned IPs before CORS processing
            .wrap(AutoBanMiddleware::new(auto_ban_service.clone()))
            // Explicit JSON body size limit (32 KB)
            .app_data(web::JsonConfig::default().limit(32_768))
            // Add database pool to app state
            .app_data(web::Data::new(pool.clone()))
            // Add services to app state
            .app_data(jwt_service.clone())
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(email_service.clone()))
            .app_data(web::Data::new(stripe_service.clone()))
            .app_data(web::Data::new(totp_service.clone()))
            .app_data(web::Data::new(webhook_service.clone()))
            .app_data(web::Data::new(stripe_key_set.clone()))
            .app_data(web::Data::new(config_data.clone()))
            .app_data(web::Data::new(download_limiter.clone()))
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
            .app_data(web::Data::new(tier_config.clone()))
            // Update checker for the root-level /version endpoint
            .app_data(web::Data::new(update_checker.clone()))
            // Configure routes
            .configure(routes::configure)
    })
    .bind(&server_addr)?
    .shutdown_timeout(30)
    .run();

    let oci_ready = config.oci.enabled && forgejo_registry_client_oci.is_some();
    if config.oci.enabled && forgejo_registry_client_oci.is_none() {
        tracing::warn!(
            "OCI_REGISTRY_ENABLED=true but FORGEJO_BASE_URL / FORGEJO_API_TOKEN are unset — \
             OCI registry server will NOT be started"
        );
    }

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
                .wrap(TracingLogger::default())
                .wrap(Logger::default())
                .wrap(SecurityHeaders)
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

/// Initialize tracing subscriber with compact human-readable output
fn init_tracing(log_level: &str) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().compact())
        .init();
}
