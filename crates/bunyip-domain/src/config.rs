use std::env;
use tracing::info;

/// Read a secret from the environment, supporting the Docker Compose
/// file-based secret convention (BUNYIP-38).
///
/// Resolution order:
/// 1. `{NAME}_FILE`: if set and non-empty, the secret is the trimmed contents
///    of that file (a compose `secrets:` mount under `/run/secrets/...`).
///    An unreadable file panics: a misconfigured secret mount must fail fast
///    at startup, never silently fall back to a weaker source.
/// 2. `{NAME}`: the plain environment variable (the dev `.env` path).
///
/// Empty values (empty file or empty env var) are treated as unset and return
/// `None`, so compose interpolation defaults (`${VAR:-}`) and empty secret
/// files both mean "not configured".
pub fn secret_env(name: &str) -> Option<String> {
    let file_var = format!("{name}_FILE");
    if let Ok(path) = env::var(&file_var) {
        let path = path.trim();
        if !path.is_empty() {
            let contents = std::fs::read_to_string(path).unwrap_or_else(|e| {
                panic!("{file_var} points to an unreadable file ({path}): {e}")
            });
            let value = contents.trim().to_string();
            return if value.is_empty() { None } else { Some(value) };
        }
    }
    env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Application configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct Config {
    /// Database connection URL
    pub database_url: String,
    /// Server host address
    pub host: String,
    /// Server port
    pub port: u16,
    /// Log level (RUST_LOG)
    pub log_level: String,
    /// CORS allowed origin
    pub cors_origin: String,
    /// Environment (development, production)
    pub environment: String,
    /// Application name used in emails, JWT issuer, etc.
    pub app_name: String,
    /// Email configuration
    pub email: EmailConfig,
    /// Cookie domain (e.g., ".yourdomain.com" for production, empty for localhost)
    pub cookie_domain: Option<String>,
    /// Auto-ban configuration
    pub auto_ban: AutoBanConfig,
    /// TOTP encryption key (32 bytes) for encrypting TOTP secrets at rest
    pub totp_encryption_key: [u8; 32],
    /// Previous TOTP encryption key for rotation (optional)
    pub totp_encryption_key_prev: Option<[u8; 32]>,
    /// Current TOTP key version (incremented on each rotation)
    pub totp_key_version: i16,
    /// Stripe encryption key (32 bytes) for encrypting Stripe secrets at rest
    pub stripe_encryption_key: [u8; 32],
    /// Previous Stripe encryption key for rotation (optional)
    pub stripe_encryption_key_prev: Option<[u8; 32]>,
    /// Current Stripe key version (incremented on each rotation)
    pub stripe_key_version: i16,
    /// Membership tier thresholds
    pub tier: TierConfig,
    /// Download proxy configuration.
    pub download: DownloadConfig,
    /// OCI registry configuration.
    pub oci: OciConfig,
    /// OIDC / OpenID Provider configuration.
    pub oidc: OidcConfig,
}

/// SMTP TLS mode
#[derive(Debug, Clone, PartialEq)]
pub enum SmtpTls {
    /// Implicit TLS (port 465) — connection is TLS from the start
    Implicit,
    /// STARTTLS (port 587) — plaintext connection upgraded to TLS
    Starttls,
}

/// Email configuration
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// SMTP server host
    pub smtp_host: String,
    /// SMTP server port
    pub smtp_port: u16,
    /// SMTP TLS mode
    pub smtp_tls: SmtpTls,
    /// SMTP username
    pub smtp_username: String,
    /// SMTP password
    pub smtp_password: String,
    /// From email address
    pub from_email: String,
    /// From name
    pub from_name: String,
    /// Base URL for links in emails
    pub base_url: String,
    /// Whether to actually send emails (false in dev mode)
    pub enabled: bool,
    /// Application name for email subjects and templates
    pub app_name: String,
    /// Admin recipients for operational notifications
    pub admin_notification_emails: Vec<String>,
}

impl EmailConfig {
    /// Load email configuration from environment variables
    pub fn from_env(is_production: bool) -> Self {
        // Allow forcing email enabled in development via env var
        let force_enabled = env::var("EMAIL_ENABLED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let smtp_host = env::var("SMTP_HOST").unwrap_or_else(|_| "localhost".to_string());
        let has_smtp = !smtp_host.is_empty() && smtp_host != "localhost";

        // SMTP_TLS: "implicit" (port 465) or "starttls" (port 587)
        let smtp_tls = match env::var("SMTP_TLS")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "starttls" => SmtpTls::Starttls,
            // Default to implicit TLS (port 465)
            _ => SmtpTls::Implicit,
        };

        let default_port: u16 = match smtp_tls {
            SmtpTls::Implicit => 465,
            SmtpTls::Starttls => 587,
        };

        Self {
            smtp_host,
            smtp_port: env::var("SMTP_PORT")
                .unwrap_or_else(|_| default_port.to_string())
                .parse()
                .unwrap_or(default_port),
            smtp_tls,
            smtp_username: env::var("SMTP_USERNAME").unwrap_or_default(),
            smtp_password: env::var("SMTP_PASSWORD").unwrap_or_default(),
            from_email: parse_smtp_from_email(
                &env::var("SMTP_FROM").unwrap_or_else(|_| "noreply@localhost".to_string()),
            ),
            from_name: parse_smtp_from_name(
                &env::var("SMTP_FROM").unwrap_or_else(|_| "noreply@localhost".to_string()),
            ),
            base_url: env::var("APP_URL")
                .or_else(|_| env::var("CORS_ORIGIN"))
                .unwrap_or_else(|_| "http://localhost:5173".to_string()),
            enabled: (is_production && has_smtp) || force_enabled,
            app_name: env::var("APP_NAME").unwrap_or_else(|_| "localhost".to_string()),
            admin_notification_emails: env::var("ADMIN_NOTIFICATION_EMAILS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
        }
    }
}

/// Parse email address from SMTP_FROM.
/// Supports "Display Name <email>" or plain "email" format.
fn parse_smtp_from_email(smtp_from: &str) -> String {
    if let Some(start) = smtp_from.find('<') {
        if let Some(end) = smtp_from.find('>') {
            return smtp_from[start + 1..end].trim().to_string();
        }
    }
    smtp_from.trim().to_string()
}

/// Parse display name from SMTP_FROM.
/// Returns the part before `<`, or "localhost" if no display name is present.
fn parse_smtp_from_name(smtp_from: &str) -> String {
    if let Some(start) = smtp_from.find('<') {
        let name = smtp_from[..start].trim();
        if !name.is_empty() {
            return name.to_string();
        }
    }
    "localhost".to_string()
}

/// Auto-ban configuration
#[derive(Debug, Clone)]
pub struct AutoBanConfig {
    /// Whether auto-banning is enabled
    pub enabled: bool,
    /// Number of suspicious requests before banning an IP
    pub threshold: u32,
    /// Time window in seconds for counting strikes
    pub window_secs: u64,
    /// How long a ban lasts in seconds
    pub ban_duration_secs: u64,
}

impl AutoBanConfig {
    /// Load auto-ban configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            enabled: env::var("AUTO_BAN_ENABLED")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            threshold: env::var("AUTO_BAN_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            window_secs: env::var("AUTO_BAN_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            ban_duration_secs: env::var("AUTO_BAN_DURATION_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400),
        }
    }
}

/// Membership tier threshold configuration
#[derive(Debug, Clone)]
pub struct TierConfig {
    /// Number of lifetime slots (first N verified users get lifetime tier)
    pub lifetime_slots: i64,
    /// Number of early adopter slots (next N verified users get early adopter tier)
    pub early_adopter_slots: i64,
    /// Trial duration in days for early adopter tier
    pub early_adopter_trial_days: i64,
    /// Trial duration in days for standard tier
    pub standard_trial_days: i64,
    /// Stripe Price ID for lifetime members ($0 recurring). Falls back to STRIPE_FREE_PRICE_ID env var.
    pub free_price_id: Option<String>,
    /// Stripe Price ID unlocked after early adopter trial ends.
    pub early_adopter_price_id: Option<String>,
    /// Stripe Price ID unlocked after standard trial ends.
    pub standard_price_id: Option<String>,
    /// Stripe Product ID that maps to the Lifetime tier.
    pub lifetime_product_id: Option<String>,
    /// Stripe Product ID that maps to the Early Adopter tier.
    pub early_adopter_product_id: Option<String>,
    /// Stripe Product ID that maps to the Standard tier.
    pub standard_product_id: Option<String>,
}

impl TierConfig {
    /// Load tier configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            lifetime_slots: env::var("TIER_LIFETIME_SLOTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            early_adopter_slots: env::var("TIER_EARLY_ADOPTER_SLOTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            early_adopter_trial_days: env::var("TIER_EARLY_ADOPTER_TRIAL_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(90),
            standard_trial_days: env::var("TIER_STANDARD_TRIAL_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            free_price_id: env::var("STRIPE_FREE_PRICE_ID")
                .ok()
                .filter(|s| !s.is_empty()),
            early_adopter_price_id: None,
            standard_price_id: None,
            lifetime_product_id: None,
            early_adopter_product_id: None,
            standard_product_id: None,
        }
    }

    /// Build a `TierConfig` from the DB row, falling back to env defaults
    /// for any column that is NULL.
    pub fn from_db_row(row: &crate::models::tier::TierConfigRow) -> Self {
        let env = Self::from_env();
        Self {
            lifetime_slots: row.lifetime_slots.unwrap_or(env.lifetime_slots),
            early_adopter_slots: row.early_adopter_slots.unwrap_or(env.early_adopter_slots),
            early_adopter_trial_days: row
                .early_adopter_trial_days
                .unwrap_or(env.early_adopter_trial_days),
            standard_trial_days: row.standard_trial_days.unwrap_or(env.standard_trial_days),
            // free_price_id: DB value takes precedence; fall back to STRIPE_FREE_PRICE_ID env var
            free_price_id: row.free_price_id.clone().or(env.free_price_id),
            early_adopter_price_id: row.early_adopter_price_id.clone(),
            standard_price_id: row.standard_price_id.clone(),
            lifetime_product_id: row.lifetime_product_id.clone(),
            early_adopter_product_id: row.early_adopter_product_id.clone(),
            standard_product_id: row.standard_product_id.clone(),
        }
    }

    /// Returns `true` if the DB row has at least one non-NULL override.
    pub fn has_db_overrides(row: &crate::models::tier::TierConfigRow) -> bool {
        row.lifetime_slots.is_some()
            || row.early_adopter_slots.is_some()
            || row.early_adopter_trial_days.is_some()
            || row.standard_trial_days.is_some()
            || row.free_price_id.is_some()
            || row.early_adopter_price_id.is_some()
            || row.standard_price_id.is_some()
            || row.lifetime_product_id.is_some()
            || row.early_adopter_product_id.is_some()
            || row.standard_product_id.is_some()
    }
}

/// Download proxy configuration.
#[derive(Debug, Clone)]
pub struct DownloadConfig {
    pub forgejo_base_url: Option<String>,
    pub forgejo_api_token: Option<String>,
    pub cache_dir: String,
    pub cache_max_bytes: u64,
    pub concurrency_per_user: u32,
    pub daily_limit_per_user: u32,
    pub release_cache_ttl_secs: u64,
}

impl DownloadConfig {
    pub fn from_env() -> Self {
        Self {
            forgejo_base_url: env::var("FORGEJO_BASE_URL").ok().filter(|s| !s.is_empty()),
            forgejo_api_token: secret_env("FORGEJO_API_TOKEN"),
            cache_dir: env::var("DOWNLOAD_CACHE_DIR")
                .unwrap_or_else(|_| "/var/cache/bunyip-downloads".to_string()),
            cache_max_bytes: env::var("DOWNLOAD_CACHE_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_737_418_240),
            concurrency_per_user: env::var("DOWNLOAD_CONCURRENCY_PER_USER")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2),
            daily_limit_per_user: env::var("DOWNLOAD_DAILY_LIMIT_PER_USER")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50),
            release_cache_ttl_secs: env::var("FORGEJO_RELEASE_CACHE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
        }
    }

    pub fn enabled(&self) -> bool {
        self.forgejo_base_url.is_some() && self.forgejo_api_token.is_some()
    }
}

/// OCI registry configuration.
#[derive(Debug, Clone)]
pub struct OciConfig {
    pub enabled: bool,
    pub port: u16,
    pub service: String,
    /// Full token-endpoint realm URL advertised in `WWW-Authenticate`.
    /// Defaults to `https://{service}/auth/token`. Override for deployments
    /// where the registry is not served over HTTPS on the service hostname
    /// (e.g. local verification: `http://localhost:18081/auth/token`).
    pub realm: Option<String>,
    pub blob_cache_dir: String,
    pub blob_cache_max_bytes: u64,
    pub manifest_cache_ttl_secs: u64,
    pub concurrent_manifests_per_user: u32,
    pub pulls_per_user_per_day: u32,
    pub token_ttl_secs: u64,
}

impl OciConfig {
    /// The realm URL Docker clients must hit to exchange credentials for a
    /// registry bearer token.
    pub fn realm_url(&self) -> String {
        self.realm
            .clone()
            .unwrap_or_else(|| format!("https://{}/auth/token", self.service))
    }

    /// Validate the realm/service pair. Called at startup when the registry is
    /// enabled so misconfiguration fails fast instead of surfacing as opaque
    /// docker-login failures.
    ///
    /// Hard errors: an empty/missing service hostname (the realm would derive
    /// to `https:///auth/token`), a realm that is not a valid URL or has no
    /// host, or one containing quotes or control characters (it is
    /// interpolated into a quoted `WWW-Authenticate` header value, where such
    /// characters produce a malformed or silently-dropped header). A realm
    /// host that differs from the service host is only a warning:
    /// split-horizon setups exist, but it is almost always a mistake.
    pub fn validate(&self) -> Result<(), String> {
        let service_host = self.service.split(':').next().unwrap_or("");
        if service_host.is_empty() {
            return Err(
                "OCI_REGISTRY_SERVICE is empty; set it to the public registry hostname \
                 (e.g. registry.example.com)"
                    .to_string(),
            );
        }

        let realm = self.realm_url();
        if realm.chars().any(|c| c == '"' || c.is_control()) {
            return Err(format!(
                "OCI registry realm contains quotes or control characters: {realm:?}"
            ));
        }
        let parsed = url::Url::parse(&realm)
            .map_err(|e| format!("OCI registry realm is not a valid URL ({realm}): {e}"))?;

        let realm_host = parsed.host_str().unwrap_or("");
        if realm_host.is_empty() {
            return Err(format!(
                "OCI registry realm has no host ({realm}); check OCI_REGISTRY_SERVICE / \
                 OCI_REGISTRY_REALM"
            ));
        }
        if realm_host != service_host {
            tracing::warn!(
                realm = %realm,
                service = %self.service,
                "OCI realm host does not match OCI_REGISTRY_SERVICE; docker clients will \
                 be told to fetch tokens from a different host than the registry they use"
            );
        }
        Ok(())
    }

    pub fn from_env() -> Self {
        Self {
            enabled: env::var("OCI_REGISTRY_ENABLED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            port: env::var("OCI_REGISTRY_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(18081),
            service: env::var("OCI_REGISTRY_SERVICE")
                .unwrap_or_else(|_| "oci.example.com".to_string()),
            realm: env::var("OCI_REGISTRY_REALM")
                .ok()
                .filter(|s| !s.is_empty()),
            blob_cache_dir: env::var("OCI_BLOB_CACHE_DIR")
                .unwrap_or_else(|_| "/var/cache/bunyip-oci".to_string()),
            blob_cache_max_bytes: env::var("OCI_BLOB_CACHE_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(53_687_091_200), // 50 GiB
            manifest_cache_ttl_secs: env::var("OCI_MANIFEST_CACHE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            concurrent_manifests_per_user: env::var("OCI_CONCURRENT_MANIFESTS_PER_USER")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2),
            pulls_per_user_per_day: env::var("OCI_PULLS_PER_USER_PER_DAY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50),
            token_ttl_secs: env::var("OCI_TOKEN_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(900),
        }
    }
}

/// OIDC / OpenID Provider configuration.
///
/// When `issuer` is empty the OIDC feature is disabled; all `/oauth2/*` and
/// `/.well-known/*` endpoints return 404.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Full issuer URL, e.g. `https://msp-api.bunyip.example.com`.
    /// Unset or empty disables the OIDC feature.
    pub issuer: Option<String>,
    /// Path to the active Ed25519 private key PEM (PKCS#8, as generated by
    /// `openssl genpkey -algorithm ED25519`).
    pub jwt_private_key_path: String,
    /// kid for the active signing key (e.g. `2026-04-primary`).
    pub jwt_active_kid: String,
    /// Directory holding every kid's `<kid>.pub.pem` public key files.
    /// All files in the directory are served in the JWKS response.
    pub jwt_public_keys_dir: String,
    /// Access token TTL in seconds (60–900, default 600).
    pub access_token_ttl_secs: u32,
    /// Refresh token absolute TTL in seconds (default 30 d).
    pub refresh_token_ttl_secs: u32,
    /// Refresh token idle TTL in seconds (default 14 d).
    pub refresh_idle_ttl_secs: u32,
    /// Authorization code TTL in seconds (default 60, max 120).
    pub code_ttl_secs: u32,
    /// Event-type URI used as the key for the lifecycle-event claim in minted
    /// lifecycle JWTs. This is part of the event contract consumed by relying
    /// parties, so deployments that already publish a specific URI must pin it
    /// via `OIDC_LIFECYCLE_EVENT_KEY`. Defaults to a generic URN.
    pub lifecycle_event_key: String,
}

impl OidcConfig {
    pub fn from_env() -> Self {
        let issuer = env::var("OIDC_ISSUER").ok().filter(|s| !s.is_empty());
        Self {
            issuer,
            jwt_private_key_path: env::var("OIDC_JWT_PRIVATE_KEY_PATH")
                .unwrap_or_else(|_| "secrets/jwt_private.pem".to_string()),
            jwt_active_kid: env::var("OIDC_JWT_ACTIVE_KID")
                .unwrap_or_else(|_| "dev-key".to_string()),
            jwt_public_keys_dir: env::var("OIDC_JWT_PUBLIC_KEYS_DIR")
                .unwrap_or_else(|_| "secrets".to_string()),
            access_token_ttl_secs: env::var("OIDC_ACCESS_TOKEN_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600)
                .clamp(60, 900),
            refresh_token_ttl_secs: env::var("OIDC_REFRESH_TOKEN_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2_592_000),
            refresh_idle_ttl_secs: env::var("OIDC_REFRESH_IDLE_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_209_600),
            code_ttl_secs: env::var("OIDC_CODE_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60)
                .min(120),
            lifecycle_event_key: env::var("OIDC_LIFECYCLE_EVENT_KEY")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "urn:bunyip:event:user-lifecycle".to_string()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.issuer.is_some()
    }
}

impl Config {
    /// Load configuration from environment variables
    ///
    /// # Errors
    /// Returns an error if required environment variables are missing
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load .env file if it exists (ignore errors if not found)
        let _ = dotenvy::dotenv();

        // DATABASE_URL embeds the postgres password, so it supports the
        // DATABASE_URL_FILE secret convention like every other secret.
        let database_url = secret_env("DATABASE_URL")
            .ok_or_else(|| ConfigError::MissingEnv("DATABASE_URL".to_string()))?;

        let host = env::var("HOST_IP").unwrap_or_else(|_| "0.0.0.0".to_string());

        let port = env::var("APP_PORT")
            .unwrap_or_else(|_| "4000".to_string())
            .parse::<u16>()
            .map_err(|_| {
                ConfigError::InvalidValue(
                    "APP_PORT".to_string(),
                    "must be a valid port number".to_string(),
                )
            })?;

        let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

        let cors_origin =
            env::var("CORS_ORIGIN").unwrap_or_else(|_| "http://localhost:5173".to_string());

        let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "production".to_string());
        let app_name = env::var("APP_NAME").unwrap_or_else(|_| "localhost".to_string());
        let is_production = environment == "production";
        let email = EmailConfig::from_env(is_production);

        // Cookie domain: must be set explicitly via COOKIE_DOMAIN env var.
        // None means cookies are scoped to the exact hostname (suitable for localhost).
        let cookie_domain = env::var("COOKIE_DOMAIN").ok().filter(|s| !s.is_empty());

        let auto_ban = AutoBanConfig::from_env();

        let totp_encryption_key = Self::load_totp_encryption_key(&environment);
        let stripe_encryption_key = Self::load_stripe_encryption_key(&environment);
        let totp_encryption_key_prev =
            Self::load_optional_encryption_key("TOTP_ENCRYPTION_KEY_PREV");
        let stripe_encryption_key_prev =
            Self::load_optional_encryption_key("STRIPE_ENCRYPTION_KEY_PREV");
        let totp_key_version: i16 = env::var("TOTP_KEY_VERSION")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let stripe_key_version: i16 = env::var("STRIPE_KEY_VERSION")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let tier = TierConfig::from_env();
        let download = DownloadConfig::from_env();
        let oci = OciConfig::from_env();
        let oidc = OidcConfig::from_env();

        let config = Self {
            database_url,
            host,
            port,
            log_level,
            cors_origin,
            environment,
            app_name,
            email,
            cookie_domain,
            auto_ban,
            totp_encryption_key,
            totp_encryption_key_prev,
            totp_key_version,
            stripe_encryption_key,
            stripe_encryption_key_prev,
            stripe_key_version,
            tier,
            download,
            oci,
            oidc,
        };

        info!(
            host = %config.host,
            port = %config.port,
            environment = %config.environment,
            "Configuration loaded"
        );

        Ok(config)
    }

    /// Returns true if running in production environment
    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }

    /// Load TOTP encryption key from TOTP_ENCRYPTION_KEY (env var or _FILE
    /// secret, hex-encoded 32 bytes). In development, defaults to 32 zero bytes.
    fn load_totp_encryption_key(environment: &str) -> [u8; 32] {
        match secret_env("TOTP_ENCRYPTION_KEY") {
            Some(hex_str) => {
                let bytes =
                    hex::decode(hex_str.trim()).expect("TOTP_ENCRYPTION_KEY must be valid hex");
                let key: [u8; 32] = bytes
                    .try_into()
                    .expect("TOTP_ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars)");
                key
            }
            None => {
                if environment == "production" {
                    panic!("TOTP_ENCRYPTION_KEY must be set in production");
                }
                [0u8; 32]
            }
        }
    }

    /// Load Stripe encryption key from STRIPE_ENCRYPTION_KEY (env var or _FILE
    /// secret, hex-encoded 32 bytes). In development, defaults to 32 zero bytes.
    fn load_stripe_encryption_key(environment: &str) -> [u8; 32] {
        match secret_env("STRIPE_ENCRYPTION_KEY") {
            Some(hex_str) => {
                let bytes =
                    hex::decode(hex_str.trim()).expect("STRIPE_ENCRYPTION_KEY must be valid hex");
                let key: [u8; 32] = bytes
                    .try_into()
                    .expect("STRIPE_ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars)");
                key
            }
            None => {
                if environment == "production" {
                    panic!("STRIPE_ENCRYPTION_KEY must be set in production");
                }
                [0u8; 32]
            }
        }
    }

    /// Load an optional encryption key (hex-encoded 32 bytes) from an env var
    /// or its `_FILE` secret. Returns `None` if not set.
    fn load_optional_encryption_key(env_var: &str) -> Option<[u8; 32]> {
        secret_env(env_var).map(|hex_str| {
            let bytes = hex::decode(hex_str.trim())
                .unwrap_or_else(|_| panic!("{env_var} must be valid hex"));
            let key: [u8; 32] = bytes
                .try_into()
                .unwrap_or_else(|_| panic!("{env_var} must be exactly 32 bytes (64 hex chars)"));
            key
        })
    }

    /// Get the server bind address
    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Configuration errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    MissingEnv(String),

    #[error("Invalid value for {0}: {1}")]
    InvalidValue(String, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    // Crate-wide lock serializing env-var-mutating tests (BUNYIP-36); every
    // test below that touches process env must hold it.
    use crate::test_support::env_lock;
    use std::env;

    #[test]
    fn test_config_defaults() {
        let _env = env_lock();
        // Set required env vars
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        // Use development to avoid requiring TOTP_ENCRYPTION_KEY
        env::set_var("ENVIRONMENT", "development");
        env::remove_var("HOST_IP");
        env::remove_var("APP_PORT");
        env::remove_var("RUST_LOG");
        env::remove_var("CORS_ORIGIN");
        env::remove_var("SMTP_HOST");
        env::remove_var("EMAIL_ENABLED");
        env::remove_var("COOKIE_DOMAIN");

        let config = Config::from_env().unwrap();

        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 4000);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.cors_origin, "http://localhost:5173");
        assert_eq!(config.environment, "development");
        assert!(!config.email.enabled);
        // In development mode without COOKIE_DOMAIN set, it should be None (for localhost)
        assert!(config.cookie_domain.is_none());
    }

    #[test]
    fn test_missing_database_url() {
        // Test that MissingEnv error is returned for missing DATABASE_URL
        // by checking the error variant directly (avoids env var race with parallel tests)
        let err = ConfigError::MissingEnv("DATABASE_URL".to_string());
        assert!(err.to_string().contains("DATABASE_URL"));
    }

    #[test]
    fn test_parse_smtp_from_with_display_name() {
        let input = "Bunyip Staging <staging@bunyip.example.com>";
        assert_eq!(parse_smtp_from_email(input), "staging@bunyip.example.com");
        assert_eq!(parse_smtp_from_name(input), "Bunyip Staging");
    }

    #[test]
    fn test_parse_smtp_from_plain_email() {
        let input = "noreply@localhost";
        assert_eq!(parse_smtp_from_email(input), "noreply@localhost");
        assert_eq!(parse_smtp_from_name(input), "localhost");
    }

    // ---- Key rotation config ----

    #[test]
    fn test_load_optional_encryption_key_returns_none_when_unset() {
        env::remove_var("TEST_OPTIONAL_KEY_UNSET");
        let result = Config::load_optional_encryption_key("TEST_OPTIONAL_KEY_UNSET");
        assert!(result.is_none());
    }

    #[test]
    fn test_load_optional_encryption_key_parses_hex() {
        let hex_key = "aa".repeat(32); // 64 hex chars = 32 bytes
        env::set_var("TEST_OPTIONAL_KEY_HEX", &hex_key);
        let result = Config::load_optional_encryption_key("TEST_OPTIONAL_KEY_HEX");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), [0xAA; 32]);
        env::remove_var("TEST_OPTIONAL_KEY_HEX");
    }

    #[test]
    #[should_panic(expected = "must be valid hex")]
    fn test_load_optional_encryption_key_panics_on_invalid_hex() {
        env::set_var("TEST_OPTIONAL_KEY_BAD", "not-valid-hex!");
        Config::load_optional_encryption_key("TEST_OPTIONAL_KEY_BAD");
    }

    #[test]
    #[should_panic(expected = "must be exactly 32 bytes")]
    fn test_load_optional_encryption_key_panics_on_wrong_length() {
        env::set_var("TEST_OPTIONAL_KEY_SHORT", "aabb"); // only 2 bytes
        Config::load_optional_encryption_key("TEST_OPTIONAL_KEY_SHORT");
    }

    // ---- secret_env (file-based secrets, BUNYIP-38) ----
    //
    // Each test uses a unique env-var prefix touched by no other test, so no
    // env lock is needed (same convention as the TEST_OPTIONAL_KEY_* tests).

    #[test]
    fn secret_env_falls_back_to_plain_env_var() {
        env::remove_var("TEST_SECRET_PLAIN_FILE");
        env::set_var("TEST_SECRET_PLAIN", "  env-value\n");
        assert_eq!(
            secret_env("TEST_SECRET_PLAIN").as_deref(),
            Some("env-value")
        );
        env::remove_var("TEST_SECRET_PLAIN");
    }

    #[test]
    fn secret_env_unset_and_empty_are_none() {
        env::remove_var("TEST_SECRET_ABSENT_FILE");
        env::remove_var("TEST_SECRET_ABSENT");
        assert_eq!(secret_env("TEST_SECRET_ABSENT"), None);

        env::set_var("TEST_SECRET_BLANK", "   ");
        assert_eq!(secret_env("TEST_SECRET_BLANK"), None);
        env::remove_var("TEST_SECRET_BLANK");
    }

    #[test]
    fn secret_env_reads_file_and_takes_precedence_over_env_var() {
        let path = env::temp_dir().join("bunyip-test-secret-env-file");
        std::fs::write(&path, "file-value\n").unwrap();

        env::set_var("TEST_SECRET_FILEPREC_FILE", &path);
        env::set_var("TEST_SECRET_FILEPREC", "env-value");
        assert_eq!(
            secret_env("TEST_SECRET_FILEPREC").as_deref(),
            Some("file-value")
        );

        env::remove_var("TEST_SECRET_FILEPREC_FILE");
        env::remove_var("TEST_SECRET_FILEPREC");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn secret_env_empty_file_is_none() {
        let path = env::temp_dir().join("bunyip-test-secret-env-empty-file");
        std::fs::write(&path, "\n").unwrap();

        env::set_var("TEST_SECRET_EMPTYFILE_FILE", &path);
        assert_eq!(secret_env("TEST_SECRET_EMPTYFILE"), None);

        env::remove_var("TEST_SECRET_EMPTYFILE_FILE");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    #[should_panic(expected = "unreadable file")]
    fn secret_env_panics_on_unreadable_file() {
        env::set_var(
            "TEST_SECRET_MISSINGFILE_FILE",
            "/nonexistent/bunyip-test-secret",
        );
        secret_env("TEST_SECRET_MISSINGFILE");
    }

    #[test]
    fn download_config_defaults_when_forgejo_unset() {
        let _env = env_lock();
        env::remove_var("FORGEJO_BASE_URL");
        env::remove_var("FORGEJO_API_TOKEN");
        env::remove_var("DOWNLOAD_CACHE_DIR");
        env::remove_var("DOWNLOAD_CACHE_MAX_BYTES");
        env::remove_var("DOWNLOAD_CONCURRENCY_PER_USER");
        env::remove_var("DOWNLOAD_DAILY_LIMIT_PER_USER");
        env::remove_var("FORGEJO_RELEASE_CACHE_TTL_SECS");

        let cfg = DownloadConfig::from_env();
        assert!(!cfg.enabled());
        assert_eq!(cfg.cache_dir, "/var/cache/bunyip-downloads");
        assert_eq!(cfg.cache_max_bytes, 10_737_418_240);
        assert_eq!(cfg.concurrency_per_user, 2);
        assert_eq!(cfg.daily_limit_per_user, 50);
        assert_eq!(cfg.release_cache_ttl_secs, 300);
    }

    #[test]
    fn download_config_enabled_when_forgejo_set() {
        let _env = env_lock();
        env::set_var("FORGEJO_BASE_URL", "https://git.example.com");
        env::set_var("FORGEJO_API_TOKEN", "test-token");
        let cfg = DownloadConfig::from_env();
        assert!(cfg.enabled());
        assert_eq!(
            cfg.forgejo_base_url.as_deref(),
            Some("https://git.example.com")
        );
        env::remove_var("FORGEJO_BASE_URL");
        env::remove_var("FORGEJO_API_TOKEN");
    }

    #[test]
    fn test_key_version_parsing() {
        // Test the parsing logic directly to avoid env var races with parallel tests.
        // Key versions use: env::var("X").ok().and_then(|v| v.parse().ok()).unwrap_or(1)
        assert_eq!("3".parse::<i16>().unwrap(), 3);
        assert_eq!("7".parse::<i16>().unwrap(), 7);
        assert_eq!(
            None::<String>
                .and_then(|v: String| v.parse::<i16>().ok())
                .unwrap_or(1),
            1
        );
        assert_eq!(
            Some("invalid".to_string())
                .and_then(|v| v.parse::<i16>().ok())
                .unwrap_or(1),
            1
        );
    }

    #[test]
    fn oci_config_defaults() {
        let _env = env_lock();
        env::remove_var("OCI_REGISTRY_ENABLED");
        env::remove_var("OCI_REGISTRY_PORT");
        env::remove_var("OCI_REGISTRY_SERVICE");
        env::remove_var("OCI_BLOB_CACHE_DIR");
        env::remove_var("OCI_BLOB_CACHE_MAX_BYTES");
        env::remove_var("OCI_MANIFEST_CACHE_TTL_SECS");
        env::remove_var("OCI_CONCURRENT_MANIFESTS_PER_USER");
        env::remove_var("OCI_PULLS_PER_USER_PER_DAY");
        env::remove_var("OCI_TOKEN_TTL_SECS");

        let cfg = OciConfig::from_env();
        assert!(!cfg.enabled);
        assert_eq!(cfg.port, 18081);
        assert_eq!(cfg.blob_cache_dir, "/var/cache/bunyip-oci");
        assert_eq!(cfg.blob_cache_max_bytes, 53_687_091_200);
        assert_eq!(cfg.manifest_cache_ttl_secs, 300);
        assert_eq!(cfg.concurrent_manifests_per_user, 2);
        assert_eq!(cfg.pulls_per_user_per_day, 50);
        assert_eq!(cfg.token_ttl_secs, 900);
    }

    // Realm assertions live in ONE self-contained test module (and
    // OCI_REGISTRY_REALM is touched by no env-var test) to avoid the parallel
    // env-var races tracked in BUNYIP-36. All assertions are computed from
    // explicit structs, never from process env.
    fn oci_cfg(service: &str, realm: Option<&str>) -> OciConfig {
        OciConfig {
            enabled: false,
            port: 18081,
            service: service.to_string(),
            realm: realm.map(str::to_string),
            blob_cache_dir: String::new(),
            blob_cache_max_bytes: 0,
            manifest_cache_ttl_secs: 0,
            concurrent_manifests_per_user: 0,
            pulls_per_user_per_day: 0,
            token_ttl_secs: 0,
        }
    }

    #[test]
    fn oci_config_realm_default_and_override() {
        let cfg = oci_cfg("registry.example.com", None);
        assert_eq!(cfg.realm_url(), "https://registry.example.com/auth/token");

        let with_override = oci_cfg(
            "registry.example.com",
            Some("http://localhost:18081/auth/token"),
        );
        assert_eq!(
            with_override.realm_url(),
            "http://localhost:18081/auth/token"
        );
    }

    #[test]
    fn oci_config_validate_accepts_sane_configs() {
        // Default realm derived from the service host.
        assert!(oci_cfg("registry.example.com", None).validate().is_ok());
        // Explicit realm on the same host, different port (dev: localhost).
        assert!(
            oci_cfg("localhost:18081", Some("http://localhost:18081/auth/token"))
                .validate()
                .is_ok()
        );
        // Mismatched hosts only warn; still Ok.
        assert!(oci_cfg(
            "registry.example.com",
            Some("https://auth.example.com/token")
        )
        .validate()
        .is_ok());
    }

    #[test]
    fn oci_config_validate_rejects_malformed_realms() {
        // Not a URL.
        assert!(oci_cfg("svc", Some("not a url")).validate().is_err());
        // Embedded double quote would break the WWW-Authenticate header.
        assert!(oci_cfg("svc", Some("https://h/\"evil")).validate().is_err());
        // Control character (e.g. stray CR from a mis-edited .env).
        assert!(oci_cfg("svc", Some("https://h/auth\r")).validate().is_err());
    }

    #[test]
    fn oci_config_validate_rejects_empty_service() {
        // Empty service (e.g. OCI_REGISTRY_ENABLED=true with the compose
        // default ${OCI_REGISTRY_SERVICE:-}) must fail fast at startup: the
        // derived realm would be unusable.
        assert!(oci_cfg("", None).validate().is_err());
        // Port-only service is still an empty host.
        assert!(oci_cfg(":18081", None).validate().is_err());
        // Note: an EXPLICIT realm written as https:///auth/token is not
        // rejected here because the WHATWG URL parser normalizes it (extra
        // slashes are skipped, so "auth" becomes the host). The empty-service
        // check above is what protects the derived-realm path; an explicit
        // realm pointing at the wrong host triggers the mismatch warning.
        assert!(oci_cfg("svc", Some("https:///auth/token"))
            .validate()
            .is_ok());
    }

    #[test]
    fn oci_config_enabled_when_set() {
        let _env = env_lock();
        env::set_var("OCI_REGISTRY_ENABLED", "true");
        let cfg = OciConfig::from_env();
        assert!(cfg.enabled);
        env::remove_var("OCI_REGISTRY_ENABLED");
    }
}
