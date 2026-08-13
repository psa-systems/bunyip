use lettre::transport::smtp::extension::ClientId;
use std::env;
use tracing::info;
use url::Url;

/// The file-or-env secret reader now lives in dunite-core (PSA-37), shared by
/// every dunite consumer. Re-exported here so existing `secret_env(...)` and
/// `crate::config::secret_env(...)` call sites keep resolving unchanged.
pub use dunite_core::services::secret_env;

/// Application configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct Config {
    /// Database connection URL
    pub database_url: String,
    /// Optional connection URL for the unprivileged, NOBYPASSRLS `bunyip_app`
    /// role used to serve self-service reads under per-user row level security
    /// (BUNYIP-344). When unset, self-service handlers fall back to the primary
    /// `database_url` pool, so RLS is a runtime no-op (the primary role bypasses
    /// RLS). Point this at a NOBYPASSRLS role to activate DB-level per-user
    /// isolation. Supports the `_FILE` secret convention like `database_url`.
    pub app_database_url: Option<String>,
    /// Password for the unprivileged `bunyip_app` RLS role (BUNYIP-360). When
    /// set, bunyip-api idempotently provisions the role (NOSUPERUSER
    /// NOBYPASSRLS) at startup over the primary superuser pool and sets this
    /// password on it; the value must match the password embedded in
    /// `app_database_url`. When unset, the role is not managed here. Supports
    /// the `_FILE` secret convention.
    pub app_password: Option<String>,
    /// Server host address
    pub host: String,
    /// Server port
    pub port: u16,
    /// Log level (RUST_LOG)
    pub log_level: String,
    /// CORS allowed origin(s). Comma-separated when multiple SPAs hit bunyip-api
    /// from different origins (bunyip-web + mokosh-apps + drillmark, etc.).
    pub cors_origin: String,
    /// Single absolute URL of the bunyip-web login UI (e.g. `https://a8n.systems`).
    /// Used by the OIDC `/oauth2/authorize` handler to redirect unauthenticated
    /// requests to the login page. Distinct from `cors_origin` because the
    /// latter is now a comma-list and can't be used to build URLs.
    pub web_origin: String,
    /// Environment (development, production)
    pub environment: String,
    /// Application name used in emails, JWT issuer, etc.
    pub app_name: String,
    /// Email configuration
    pub email: EmailConfig,
    /// Cookie domain (e.g., ".yourdomain.com" for production, empty for localhost)
    pub cookie_domain: Option<String>,
    /// BUNYIP-266: when `true`, the OP session cookie respects
    /// `cookie_domain` and is sent to every sibling subdomain. When `false`
    /// (the default), `cookie_domain` is ignored on the OP session cookie
    /// and the cookie is host-scoped to the OP origin only, closing the
    /// "sibling subdomain reads the session cookie" surface. Override with
    /// `BUNYIP_COOKIE_SHARED_DOMAIN=true` in deployments that genuinely
    /// need cross-subdomain sharing (e.g. an integration that reads the
    /// cookie from a sibling host). Hub access/refresh cookies still
    /// honour `cookie_domain` for now; tightened in a follow-up.
    pub cookie_shared_domain: bool,
    /// Auto-ban configuration
    pub auto_ban: AutoBanConfig,
    /// CIDR ranges of trusted reverse proxies. `X-Forwarded-For` / `X-Real-IP`
    /// are honoured only when the immediate socket peer falls inside one of
    /// these ranges; otherwise the real socket address is used. This closes the
    /// IP-spoofing vector where any client could forge its IP to evade the
    /// auto-ban or to ban a victim. Parsed from `TRUSTED_PROXY_CIDR`
    /// (comma-separated CIDRs); empty by default, meaning forwarding headers
    /// are never trusted.
    pub trusted_proxies: Vec<ipnetwork::IpNetwork>,
    /// BUNYIP-483: the one at-rest key (32 bytes) protecting every secret
    /// bunyip encrypts in Postgres: TOTP secrets, Stripe credentials and the
    /// SMTP password.
    pub app_encryption_key: [u8; 32],
    /// Previous at-rest keys, newest first, still needed to read rows written
    /// before the current key (the two retired key families during the
    /// consolidation window, or the prior key during an ordinary rotation).
    pub app_encryption_key_prev: Vec<[u8; 32]>,
    /// Version stamped on rows written under `app_encryption_key`.
    pub app_key_version: i16,
    /// Membership tier thresholds
    pub tier: TierConfig,
    /// Download proxy configuration.
    pub download: DownloadConfig,
    /// OCI registry configuration.
    pub oci: OciConfig,
    /// OIDC / OpenID Provider configuration.
    pub oidc: OidcConfig,
    /// BUNYIP-290: email of the bootstrap admin. When set (via
    /// `BOOTSTRAP_ADMIN_EMAIL`, trimmed + lowercased) and no admin yet exists,
    /// the user who authenticates with this email is promoted to `admin` on
    /// sign-up or sign-in. Inert once any admin exists; further admin changes
    /// go through the admin-invite and role-management flows. `None` when
    /// unset/empty: the site still comes up, just without an auto-created admin.
    pub bootstrap_admin_email: Option<String>,
    /// Path to the IP2Location LITE `.BIN` database used to resolve a login's
    /// client IP to a country for login-location alerts (BUNYIP-366). `None`
    /// when unset: the login-location-alert feature is disabled.
    pub ip2location_db_path: Option<String>,
    /// Path to the IP2Proxy PX `.BIN` database used to enrich a client IP with
    /// its ASN, owning organization, network category and VPN/proxy likelihood
    /// (BUNYIP-437). `None` when unset: the enrichment feature is disabled and
    /// admin views simply show no enrichment. Advisory only; never drives an
    /// automatic abuse verdict.
    pub ip2proxy_db_path: Option<String>,
    /// BUNYIP-373: opt-in switch for the suspicious-login notify-and-approve
    /// gate (`LOGIN_APPROVAL_ENABLED`). Off by default: the gate can withhold a
    /// login, so it is enabled per deployment for a staged rollout.
    pub login_approval_enabled: bool,
    /// BUNYIP-377: opt-in switch for the signup bot guard (honeypot + submit
    /// timing) at `/register` (`SIGNUP_BOT_GUARD_ENABLED`). Off by default: it
    /// rejects registrations, so it stays off until every register form (bunyip-
    /// web and the mokosh-apps SPA) carries the hidden honeypot + timing token,
    /// then is flipped on per deployment.
    pub signup_bot_guard_enabled: bool,
    /// BUNYIP-525: settings for the app-native runtime fetch of Group-2
    /// integration secrets from Infisical. Group-1 startup secrets stay
    /// file/SOPS-based; this covers only post-startup integration secrets
    /// (SMTP first). Disabled by default.
    pub infisical: InfisicalSettings,
}

/// BUNYIP-525: configuration for the app-native Infisical runtime fetch of
/// Group-2 (post-startup / integration) secrets. Credentials honour the
/// `{NAME}_FILE` convention like every other secret. Disabled by default so a
/// dev box or a host without a machine identity behaves exactly as before.
#[derive(Debug, Clone)]
pub struct InfisicalSettings {
    /// Enable the runtime fetch (`INFISICAL_ENABLED`). Off by default.
    pub enabled: bool,
    /// Base URL of the Infisical instance (`INFISICAL_ADDRESS`),
    /// e.g. `https://infisical.a8n.systems`.
    pub address: String,
    /// Infisical project id (`INFISICAL_PROJECT_ID`).
    pub project_id: String,
    /// Infisical environment slug (`INFISICAL_ENVIRONMENT`, legacy `INFISICAL_ENV`), e.g. `staging` / `prod`.
    pub environment: String,
    /// Secret folder path (`INFISICAL_SECRET_PATH`), e.g. `/runtime` (project-relative).
    pub secret_path: String,
    /// Universal Auth machine-identity client id (`INFISICAL_CLIENT_ID`).
    pub client_id: String,
    /// Universal Auth machine-identity client secret (`INFISICAL_CLIENT_SECRET`).
    pub client_secret: String,
}

impl InfisicalSettings {
    /// Load from the environment. `client_id` / `client_secret` are credentials
    /// and honour the `{NAME}_FILE` convention via `secret_env`.
    pub fn from_env() -> Self {
        Self {
            enabled: env::var("INFISICAL_ENABLED")
                .map(|v| matches!(v.trim(), "true" | "1"))
                .unwrap_or(false),
            address: env::var("INFISICAL_ADDRESS").unwrap_or_default(),
            project_id: env::var("INFISICAL_PROJECT_ID").unwrap_or_default(),
            environment: env::var("INFISICAL_ENVIRONMENT")
                .or_else(|_| env::var("INFISICAL_ENV"))
                .unwrap_or_default(),
            secret_path: env::var("INFISICAL_SECRET_PATH").unwrap_or_else(|_| "/".to_string()),
            client_id: secret_env("INFISICAL_CLIENT_ID").unwrap_or_default(),
            client_secret: secret_env("INFISICAL_CLIENT_SECRET").unwrap_or_default(),
        }
    }
}

/// SMTP TLS mode
#[derive(Debug, Clone, PartialEq)]
pub enum SmtpTls {
    /// Implicit TLS (port 465) — connection is TLS from the start
    Implicit,
    /// STARTTLS (port 587) — plaintext connection upgraded to TLS
    Starttls,
}

impl SmtpTls {
    /// Stable lowercase slug used in the DB (`email_config.smtp_tls`), the admin
    /// API, and audit metadata. Inverse of the `from_db_row` string match.
    pub fn as_str(&self) -> &'static str {
        match self {
            SmtpTls::Implicit => "implicit",
            SmtpTls::Starttls => "starttls",
        }
    }
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
    /// EHLO/HELO name announced to the relay (`SMTP_EHLO_NAME`), when the
    /// operator pins one. Empty/whitespace is treated as unset (BUNYIP-507).
    pub smtp_ehlo_name: Option<String>,
    /// From email address
    pub from_email: String,
    /// From name
    pub from_name: String,
    /// Base URL for links in emails
    pub base_url: String,
    /// Whether to actually send emails (false in dev mode)
    pub enabled: bool,
    /// Whether to log magic-link/reset/email-change URLs (token included) at
    /// DEBUG when email sending is disabled. Opt-in for local development only
    /// (EMAIL_LOG_TOKENS=true); forced off in production so single-use bearer
    /// tokens are never written to logs (BUNYIP-204).
    pub log_tokens: bool,
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

        // EMAIL_LOG_TOKENS lets local development log the full magic-link /
        // reset / email-change URL (token included) at DEBUG when email sending
        // is disabled. It defaults off and is forced off in production so the
        // single-use bearer token can never reach a production log (BUNYIP-204).
        let log_tokens = !is_production
            && env::var("EMAIL_LOG_TOKENS")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);

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
            // SMTP_PASSWORD is a secret: supports the SMTP_PASSWORD_FILE
            // compose-secret convention.
            smtp_password: secret_env("SMTP_PASSWORD").unwrap_or_default(),
            smtp_ehlo_name: env::var("SMTP_EHLO_NAME")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
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
            log_tokens,
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

    /// Build an `EmailConfig` from the DB row, falling back to env defaults for
    /// any NULL column (BUNYIP-351). Mirrors [`TierConfig::from_db_row`]. The
    /// SMTP password is decrypted with the application [`AppKeySet`]
    /// (`APP_ENCRYPTION_KEY`, the same set guarding TOTP and Stripe secrets); a
    /// decryption failure (e.g. a rotated key) falls back to the env password
    /// rather than aborting startup.
    ///
    /// [`AppKeySet`]: crate::services::AppKeySet
    ///
    /// System-level fields (`base_url`, `app_name`, `smtp_ehlo_name`) and the dev-only
    /// `log_tokens` gate stay env-derived: they are branding / bootstrap
    /// concerns, not SMTP tuning. `enabled` is recomputed from the resolved
    /// host so the BUNYIP-204 production semantics still hold against DB config.
    pub fn from_db_row(
        row: &crate::models::email::EmailConfigRow,
        key_set: &crate::services::AppKeySet,
        is_production: bool,
    ) -> Self {
        let env = Self::from_env(is_production);

        let smtp_host = row
            .smtp_host
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or(env.smtp_host);
        let smtp_port = row
            .smtp_port
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(env.smtp_port);
        let smtp_tls = match row.smtp_tls.as_deref() {
            Some("starttls") => SmtpTls::Starttls,
            Some("implicit") => SmtpTls::Implicit,
            _ => env.smtp_tls,
        };
        let smtp_username = row.smtp_username.clone().unwrap_or(env.smtp_username);
        let smtp_password = match (&row.smtp_password, &row.smtp_password_nonce) {
            (Some(ct), Some(nonce)) => {
                crate::models::stripe::decrypt_secret(key_set, ct, nonce, row.key_version)
                    .unwrap_or(env.smtp_password)
            }
            _ => env.smtp_password,
        };
        let from_email = row
            .from_email
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or(env.from_email);
        let from_name = row
            .from_name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or(env.from_name);
        let admin_notification_emails = match &row.admin_notification_emails {
            Some(raw) => raw
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            None => env.admin_notification_emails,
        };

        // Recompute `enabled` from the resolved host so a DB-supplied SMTP host
        // flips sending on exactly like the env path does. An explicit
        // `enabled` column still wins when set.
        let has_smtp = !smtp_host.is_empty() && smtp_host != "localhost";
        let force_enabled = env::var("EMAIL_ENABLED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let enabled = row
            .enabled
            .unwrap_or((is_production && has_smtp) || force_enabled);

        Self {
            smtp_host,
            smtp_port,
            smtp_tls,
            smtp_username,
            smtp_password,
            // Deployment/network identity, not a per-tenant email setting, so
            // it stays env-derived like `base_url` (BUNYIP-507).
            smtp_ehlo_name: env.smtp_ehlo_name,
            from_email,
            from_name,
            base_url: env.base_url,
            enabled,
            log_tokens: env.log_tokens,
            app_name: env.app_name,
            admin_notification_emails,
        }
    }

    /// Resolve the EHLO/HELO name announced on every SMTP session (BUNYIP-507).
    ///
    /// Order: `SMTP_EHLO_NAME`, else the host of `base_url` (`APP_URL`), else
    /// the domain of `from_email`, else lettre's default. The fallback chain
    /// makes this a no-config fix: lettre's default is the OS hostname, which
    /// inside a container is the container id - not a FQDN, so relays that
    /// enforce `reject-non-fqdn` on EHLO reject or penalise the mail.
    pub fn ehlo_name(&self) -> ClientId {
        if let Some(name) = self
            .smtp_ehlo_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            return client_id_from_host(name);
        }

        if let Some(host) = Url::parse(&self.base_url)
            .ok()
            .and_then(|url| url.host_str().map(ToOwned::to_owned))
            .filter(|host| !host.is_empty())
        {
            return client_id_from_host(&host);
        }

        match self
            .from_email
            .rsplit_once('@')
            .map(|(_, domain)| domain.trim())
            .filter(|domain| !domain.is_empty())
        {
            Some(domain) => client_id_from_host(domain),
            None => ClientId::default(),
        }
    }

    /// Returns `true` if the DB row has at least one non-NULL override.
    pub fn has_db_overrides(row: &crate::models::email::EmailConfigRow) -> bool {
        row.enabled.is_some()
            || row.smtp_host.is_some()
            || row.smtp_port.is_some()
            || row.smtp_tls.is_some()
            || row.smtp_username.is_some()
            || row.smtp_password.is_some()
            || row.from_email.is_some()
            || row.from_name.is_some()
            || row.admin_notification_emails.is_some()
    }
}

/// Wrap a host in the right `ClientId` variant: an IP literal must go on the
/// wire as an address literal (`[10.0.0.1]`), per RFC 5321 4.1.3.
fn client_id_from_host(host: &str) -> ClientId {
    // `Url::host_str` strips the brackets from an IPv6 literal; accept both.
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(addr)) => ClientId::Ipv4(addr),
        Ok(std::net::IpAddr::V6(addr)) => ClientId::Ipv6(addr),
        Err(_) => ClientId::Domain(host.to_string()),
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

/// Parse a comma-separated list of CIDR ranges into trusted-proxy networks.
/// Invalid entries are logged and skipped rather than aborting startup, so a
/// single typo cannot take the whole service down; an empty or all-invalid
/// list means no proxy is trusted and forwarding headers are ignored.
fn parse_trusted_proxies(raw: &str) -> Vec<ipnetwork::IpNetwork> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|entry| match entry.parse::<ipnetwork::IpNetwork>() {
            Ok(net) => Some(net),
            Err(e) => {
                tracing::warn!(entry, error = %e, "ignoring invalid TRUSTED_PROXY_CIDR entry");
                None
            }
        })
        .collect()
}

/// Auto-ban configuration
///
/// `Copy` so the [`AutoBanService`](crate::middleware::auto_ban::AutoBanService)
/// can cheaply snapshot it out from behind its `RwLock` on the hot request path
/// without cloning (BUNYIP-351).
#[derive(Debug, Clone, Copy)]
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

    /// Build an `AutoBanConfig` from the DB row, falling back to env defaults
    /// for any column that is NULL (BUNYIP-351). Mirrors
    /// [`TierConfig::from_db_row`]. The `BIGINT` columns are stored as `i64`
    /// and narrowed back to the in-memory `u32`/`u64` widths; a stored negative
    /// or over-wide value is clamped to the env default rather than wrapping.
    pub fn from_db_row(row: &crate::models::auto_ban::AutoBanConfigRow) -> Self {
        let env = Self::from_env();
        Self {
            enabled: row.enabled.unwrap_or(env.enabled),
            threshold: row
                .threshold
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(env.threshold),
            window_secs: row
                .window_secs
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(env.window_secs),
            ban_duration_secs: row
                .ban_duration_secs
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(env.ban_duration_secs),
        }
    }

    /// Returns `true` if the DB row has at least one non-NULL override.
    pub fn has_db_overrides(row: &crate::models::auto_ban::AutoBanConfigRow) -> bool {
        row.enabled.is_some()
            || row.threshold.is_some()
            || row.window_secs.is_some()
            || row.ban_duration_secs.is_some()
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
    /// Stripe Price ID for lifetime members ($0 recurring). BUNYIP-482: the
    /// `tier_config` DB row (admin tier-settings page) is the only source.
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
    /// BUNYIP-487: whether the public `/pricing` page is published. DB only
    /// (admin Pricing tiers page); false until an admin turns it on.
    pub pricing_enabled: bool,
    /// BUNYIP-527: per-tier visibility on the public `/pricing` page. DB only,
    /// default true; a hidden tier is not advertised even when mapped.
    pub lifetime_visible: bool,
    pub early_adopter_visible: bool,
    pub standard_visible: bool,
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
            // BUNYIP-482: no env source; the admin tier-settings page writes it.
            free_price_id: None,
            early_adopter_price_id: None,
            standard_price_id: None,
            lifetime_product_id: None,
            early_adopter_product_id: None,
            standard_product_id: None,
            // BUNYIP-487: no env source; the admin Pricing tiers page writes it.
            pricing_enabled: false,
            // BUNYIP-527: no env source; default visible.
            lifetime_visible: true,
            early_adopter_visible: true,
            standard_visible: true,
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
            // BUNYIP-482: DB only; NULL means no $0 price is configured.
            free_price_id: row.free_price_id.clone(),
            early_adopter_price_id: row.early_adopter_price_id.clone(),
            standard_price_id: row.standard_price_id.clone(),
            lifetime_product_id: row.lifetime_product_id.clone(),
            early_adopter_product_id: row.early_adopter_product_id.clone(),
            standard_product_id: row.standard_product_id.clone(),
            pricing_enabled: row.pricing_enabled,
            lifetime_visible: row.lifetime_visible,
            early_adopter_visible: row.early_adopter_visible,
            standard_visible: row.standard_visible,
        }
    }

    /// Returns `true` if the DB row has at least one non-NULL override.
    ///
    /// BUNYIP-487: `pricing_enabled` is `NOT NULL`, so "overridden" means "set
    /// to true". Without it, enabling pricing and changing nothing else would
    /// send startup down the env-fallback branch and silently unpublish the
    /// page on the next restart.
    pub fn has_db_overrides(row: &crate::models::tier::TierConfigRow) -> bool {
        row.pricing_enabled
            || row.lifetime_slots.is_some()
            || row.early_adopter_slots.is_some()
            || row.early_adopter_trial_days.is_some()
            || row.standard_trial_days.is_some()
            || row.free_price_id.is_some()
            || row.early_adopter_price_id.is_some()
            || row.standard_price_id.is_some()
            || row.lifetime_product_id.is_some()
            || row.early_adopter_product_id.is_some()
            || row.standard_product_id.is_some()
            // BUNYIP-527: hiding a tier (visible = false) is a DB override too, so
            // the choice survives a restart instead of falling back to env.
            || !row.lifetime_visible
            || !row.early_adopter_visible
            || !row.standard_visible
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
            // Trimmed like its paired token so a stray trailing newline/space
            // (echo/heredoc artifact) cannot produce malformed upstream URLs.
            forgejo_base_url: env::var("FORGEJO_BASE_URL")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
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
    /// Daily cap on pulls per user, metered per TAG-addressed manifest request
    /// (BUNYIP-43). Digest-addressed requests (the multi-arch platform-manifest
    /// follow-ups within a pull) are NOT metered, so one `docker pull` no longer
    /// burns 3+; a client that issues both HEAD and GET by tag meters twice, so
    /// effective logical pulls are roughly half this number for such clients.
    /// (A direct by-digest pull, `docker pull slug@sha256:...`, is unmetered.)
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
    /// BUNYIP-252: audience value bunyip-API enforces on `Bearer at+jwt`
    /// presentations to `/v1/*` via the `AtJwtVerifier` extractor. An at+jwt
    /// whose `aud` claim does NOT equal this value is rejected by
    /// `verify_at_jwt_for_rs`, closing the cross-RP confused-deputy that
    /// `validate_aud = false` left open on `verify_at_jwt_claims`. The
    /// userinfo endpoint keeps the permissive verifier per OIDC spec.
    /// Defaults to `"urn:bunyip:rs"`; override with `OIDC_RS_AUDIENCE`.
    pub rs_audience: String,
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
            rs_audience: env::var("OIDC_RS_AUDIENCE")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "urn:bunyip:rs".to_string()),
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
        // Load .env file if it exists (ignore errors if not found), then parse
        // the resulting process env. The load is kept separate from parsing so
        // tests can exercise `from_env_inner` against a controlled process env
        // without a repo-root `.env` re-injecting values mid-test (BUNYIP-102).
        let _ = dotenvy::dotenv();
        Self::from_env_inner()
    }

    /// Parse configuration from the current process environment only.
    ///
    /// Unlike [`Config::from_env`], this does NOT load a `.env` file; it reads
    /// solely the variables already present in the process env. Production code
    /// should call [`Config::from_env`]; this exists so tests can pin the env
    /// deterministically (BUNYIP-102).
    ///
    /// # Errors
    /// Returns an error if required environment variables are missing.
    pub fn from_env_inner() -> Result<Self, ConfigError> {
        // DATABASE_URL embeds the postgres password, so it supports the
        // DATABASE_URL_FILE secret convention like every other secret.
        let database_url = secret_env("DATABASE_URL")
            .ok_or_else(|| ConfigError::MissingEnv("DATABASE_URL".to_string()))?;

        // Optional NOBYPASSRLS pool for per-user RLS (BUNYIP-344). Absent on
        // deployments that have not provisioned the `bunyip_app` role yet.
        let app_database_url = secret_env("APP_DATABASE_URL");

        // Password used to self-provision the `bunyip_app` RLS role (BUNYIP-360).
        let app_password = secret_env("BUNYIP_APP_PASSWORD");

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

        // BUNYIP_WEB_ORIGIN is the single absolute URL of the bunyip-web login
        // UI. Falls back to the first entry of CORS_ORIGIN for ergonomics on
        // single-RP deployments (dev, RP-less self-hosters); on a multi-RP
        // deployment (c-01: bunyip + mokosh-apps + drillmark) the operator MUST
        // set it explicitly so the OIDC authorize handler doesn't try to
        // concatenate a comma-list onto `/login`.
        let web_origin = env::var("BUNYIP_WEB_ORIGIN")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                cors_origin
                    .split(',')
                    .next()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("http://localhost:5173")
                    .to_string()
            });

        let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "production".to_string());
        let app_name = env::var("APP_NAME").unwrap_or_else(|_| "localhost".to_string());
        let is_production = environment == "production";
        let email = EmailConfig::from_env(is_production);

        // Fail fast: a production deployment with email disabled would silently
        // degrade to the dev-mode path. Before BUNYIP-204 that path logged the
        // full magic-link / reset / email-change URL (single-use bearer token
        // included) at INFO, handing account-takeover credentials to anyone with
        // log read access. Refuse to start instead of degrading silently.
        if is_production && !email.enabled {
            return Err(ConfigError::EmailDisabledInProduction);
        }

        // Cookie domain: must be set explicitly via COOKIE_DOMAIN env var.
        // None means cookies are scoped to the exact hostname (suitable for localhost).
        let cookie_domain = env::var("COOKIE_DOMAIN").ok().filter(|s| !s.is_empty());
        // BUNYIP-266: opt-in cross-subdomain cookie sharing. When unset,
        // the OP session cookie is host-scoped even if `cookie_domain` is
        // set. Mismatch (cookie_domain Some + shared false) logs a warn so
        // an operator who relied on the previous default sees the change.
        let cookie_shared_domain = env::var("BUNYIP_COOKIE_SHARED_DOMAIN")
            .ok()
            .map(|v| matches!(v.as_str(), "true" | "1"))
            .unwrap_or(false);
        if cookie_domain.is_some() && !cookie_shared_domain {
            tracing::warn!(
                "COOKIE_DOMAIN is set but BUNYIP_COOKIE_SHARED_DOMAIN is not enabled; \
                 the OP session cookie will be host-only (BUNYIP-266). Set \
                 BUNYIP_COOKIE_SHARED_DOMAIN=true to restore cross-subdomain sharing."
            );
        }

        let auto_ban = AutoBanConfig::from_env();
        let trusted_proxies =
            parse_trusted_proxies(&env::var("TRUSTED_PROXY_CIDR").unwrap_or_default());

        let app_encryption_key = Self::load_app_encryption_key(&environment);
        let app_encryption_key_prev =
            Self::load_previous_encryption_keys("APP_ENCRYPTION_KEY_PREV");
        let app_key_version: i16 = env::var("APP_KEY_VERSION")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let tier = TierConfig::from_env();
        let download = DownloadConfig::from_env();
        let oci = OciConfig::from_env();
        let oidc = OidcConfig::from_env();

        // BUNYIP-290: the bootstrap admin email. Trimmed + lowercased so it
        // compares equal to stored emails (which `normalize_email` lowercases)
        // and to the rows returned by `find_admin_emails`. Empty = None.
        let bootstrap_admin_email = env::var("BOOTSTRAP_ADMIN_EMAIL")
            .ok()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty());

        // BUNYIP-366: IP2Location DB path for login-location alerts (optional).
        let ip2location_db_path = env::var("IP2LOCATION_DB_PATH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        // BUNYIP-437: IP2Proxy PX DB path for ASN / VPN enrichment (optional).
        let ip2proxy_db_path = env::var("IP2PROXY_DB_PATH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        // BUNYIP-373: opt-in switch for the suspicious-login approval gate.
        // Default false (the gate can withhold a login; enable per deployment).
        let login_approval_enabled = env::var("LOGIN_APPROVAL_ENABLED")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // BUNYIP-377: opt-in switch for the signup bot guard. Default false;
        // enable only once every register form carries the honeypot + timing
        // token, or real signups without those fields are rejected.
        let signup_bot_guard_enabled = env::var("SIGNUP_BOT_GUARD_ENABLED")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // BUNYIP-525: app-native Infisical fetch settings for Group-2 secrets.
        let infisical = InfisicalSettings::from_env();

        let config = Self {
            database_url,
            app_database_url,
            app_password,
            host,
            port,
            log_level,
            cors_origin,
            web_origin,
            environment,
            app_name,
            email,
            cookie_domain,
            cookie_shared_domain,
            auto_ban,
            trusted_proxies,
            app_encryption_key,
            app_encryption_key_prev,
            app_key_version,
            tier,
            download,
            oci,
            oidc,
            bootstrap_admin_email,
            ip2location_db_path,
            ip2proxy_db_path,
            login_approval_enabled,
            signup_bot_guard_enabled,
            infisical,
        };

        info!(
            host = %config.host,
            port = %config.port,
            environment = %config.environment,
            bootstrap_admin_configured = config.bootstrap_admin_email.is_some(),
            "Configuration loaded"
        );

        Ok(config)
    }

    /// Returns true if running in production environment
    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }

    /// Whether any trusted proxy is configured, i.e. whether bunyip-api will
    /// honour a forwarded client IP at all (BUNYIP-476).
    ///
    /// With no trusted proxy, every `X-Forwarded-For` is ignored and the socket
    /// peer is used. On the two-hop BFF path (Traefik -> bunyip-web ->
    /// bunyip-api) that peer is the bunyip-web container, so SSR-proxied client
    /// IPs - the audit `actor_ip_address`, the access-log IP, and the per-IP
    /// rate-limit key - are attributed to bunyip-web instead of the real
    /// browser. This is safe (never a forged IP) but silent; `main.rs` logs it
    /// at boot so the misconfiguration is visible. See
    /// `docs/client-ip-forwarding.md`.
    pub fn trusts_forwarded_client_ip(&self) -> bool {
        !self.trusted_proxies.is_empty()
    }

    /// Whether a cookie issued for `req` must carry the `Secure` attribute
    /// (BUNYIP-426 F4).
    ///
    /// Deriving this from `is_production()` alone shipped session cookies
    /// without `Secure` on every TLS deployment whose `ENVIRONMENT` was not
    /// exactly `production` - notably the publicly reachable `dev-sso` stack,
    /// where `COOKIE_DOMAIN=.a8n.run` then leaked them in cleartext to any
    /// sibling `http://*.a8n.run` name. The transport is the authority.
    ///
    /// `X-Forwarded-Proto` is honoured only when the immediate socket peer is a
    /// configured trusted proxy, the same gate
    /// [`crate::middleware::auth::extract_client_ip`] uses, so a direct client
    /// cannot forge it. Plain-HTTP `just dev` on localhost still gets
    /// `secure(false)` and keeps working.
    pub fn cookies_secure(&self, req: &actix_web::HttpRequest) -> bool {
        if self.is_production() || req.app_config().secure() {
            return true;
        }

        // Absolute-form request line (and the test harness). Not authoritative
        // against a hostile client, but a forged `https` here only makes the
        // browser refuse the cookie over plaintext, which fails safe.
        if req.uri().scheme_str() == Some("https") {
            return true;
        }

        let peer_is_trusted_proxy = req
            .peer_addr()
            .map(|addr| addr.ip())
            .is_some_and(|peer| self.trusted_proxies.iter().any(|net| net.contains(peer)));

        peer_is_trusted_proxy
            && req
                .headers()
                .get("X-Forwarded-Proto")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(',').next().unwrap_or("").trim())
                .is_some_and(|proto| proto.eq_ignore_ascii_case("https"))
    }

    /// BUNYIP-266: cookie `Domain` applied to the OP session cookie.
    /// Returns the configured `cookie_domain` only when the operator has
    /// explicitly enabled cross-subdomain sharing via
    /// `BUNYIP_COOKIE_SHARED_DOMAIN=true`; otherwise the cookie is
    /// host-scoped and siblings never receive it.
    pub fn op_session_cookie_domain(&self) -> Option<&str> {
        if self.cookie_shared_domain {
            self.cookie_domain.as_deref()
        } else {
            None
        }
    }

    /// True when this process may HARD-delete e2e test accounts: a real
    /// non-production environment AND the operator-set
    /// `BUNYIP_E2E_BOOTSTRAP_ALLOW=true`. Mirrors the `bunyip-e2e-bootstrap`
    /// guards so the `?purge` flag on `DELETE /v1/users/me` and the
    /// disposable-account reaper can never fire in production (BUNYIP-246).
    pub fn e2e_purge_enabled(&self) -> bool {
        let allowed = secret_env("BUNYIP_E2E_BOOTSTRAP_ALLOW")
            .map(|v| v.trim() == "true")
            .unwrap_or(false);
        e2e_env_allows_purge(&self.environment) && allowed
    }

    /// BUNYIP-483: the one at-rest key set, built from `APP_ENCRYPTION_KEY`,
    /// `APP_ENCRYPTION_KEY_PREV` and `APP_KEY_VERSION`. Every consumer (TOTP,
    /// Stripe, email) gets this same set.
    pub fn app_key_set(&self) -> crate::services::AppKeySet {
        crate::services::AppKeySet {
            current: self.app_encryption_key,
            current_version: self.app_key_version,
            previous: self.app_encryption_key_prev.clone(),
        }
    }

    /// Load the at-rest key from APP_ENCRYPTION_KEY (env var or _FILE secret,
    /// hex-encoded 32 bytes). In development, defaults to 32 zero bytes.
    fn load_app_encryption_key(environment: &str) -> [u8; 32] {
        match secret_env("APP_ENCRYPTION_KEY") {
            Some(hex_str) => parse_encryption_key("APP_ENCRYPTION_KEY", &hex_str),
            None => {
                if environment == "production" {
                    panic!("APP_ENCRYPTION_KEY must be set in production");
                }
                // Loud, because data encrypted under the zero key is not
                // protected and will fail to decrypt once a real key is set.
                tracing::warn!(
                    "APP_ENCRYPTION_KEY is not set; using the all-zero DEVELOPMENT key. \
                     TOTP, Stripe and SMTP secrets encrypted with it are NOT protected."
                );
                [0u8; 32]
            }
        }
    }

    /// Load the previous at-rest keys (comma-separated hex, 32 bytes each) from
    /// an env var or its `_FILE` secret. Empty when unset: nothing to fall back
    /// to. A list rather than one key because the consolidation window has to
    /// read rows written under BOTH retired key families (BUNYIP-483).
    fn load_previous_encryption_keys(env_var: &str) -> Vec<[u8; 32]> {
        secret_env(env_var)
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|hex_str| parse_encryption_key(env_var, hex_str))
            .collect()
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

    #[error(
        "Email sending is disabled in a production deployment. Set SMTP_HOST (not \"localhost\") \
         so transactional emails can be delivered, or set EMAIL_ENABLED=true. Refusing to start: \
         the disabled path would log single-use login/reset tokens instead of emailing them."
    )]
    EmailDisabledInProduction,
}

/// Decode one hex-encoded 32-byte at-rest key. Panics (at startup, before any
/// request) on a malformed value rather than silently encrypting under a key the
/// operator did not intend.
fn parse_encryption_key(env_var: &str, hex_str: &str) -> [u8; 32] {
    let bytes =
        hex::decode(hex_str.trim()).unwrap_or_else(|_| panic!("{env_var} must be valid hex"));
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{env_var} must be exactly 32 bytes (64 hex chars)"))
}

/// Pure half of [`Config::e2e_purge_enabled`]: the environment must be a real
/// non-production name. Empty / unset (which `Config` treats as production) and
/// `production` / `prod` all forbid e2e hard-deletes (BUNYIP-246).
pub(crate) fn e2e_env_allows_purge(environment: &str) -> bool {
    let env_name = environment.trim();
    !env_name.is_empty()
        && !env_name.eq_ignore_ascii_case("production")
        && !env_name.eq_ignore_ascii_case("prod")
}

#[cfg(test)]
mod tests {
    use super::*;
    // Crate-wide lock serializing env-var-mutating tests (BUNYIP-36); every
    // test below that touches process env must hold it.
    use crate::test_support::env_lock;
    use std::env;

    #[test]
    fn e2e_env_allows_purge_only_for_real_non_prod_names() {
        // Real non-production names permit the e2e hard-delete path.
        for env_name in ["staging", "Staging", "dev", "development", "test", "ci"] {
            assert!(
                e2e_env_allows_purge(env_name),
                "{env_name} should allow purge"
            );
        }
        // Production-like and empty/unset names forbid it, so `?purge` and the
        // reaper can never hard-delete on prod (BUNYIP-246).
        for env_name in ["production", "Production", "PROD", "prod", "", "   "] {
            assert!(
                !e2e_env_allows_purge(env_name),
                "{env_name:?} must forbid purge"
            );
        }
    }

    /// BUNYIP-535: the environment slug reads canonical INFISICAL_ENVIRONMENT
    /// first, falling back to the legacy INFISICAL_ENV for one release.
    #[test]
    fn infisical_environment_prefers_canonical_then_legacy() {
        let _env = env_lock();
        // Canonical wins when both are present.
        env::set_var("INFISICAL_ENVIRONMENT", "staging");
        env::set_var("INFISICAL_ENV", "prod");
        assert_eq!(InfisicalSettings::from_env().environment, "staging");
        // Legacy still resolves when only it is set.
        env::remove_var("INFISICAL_ENVIRONMENT");
        assert_eq!(InfisicalSettings::from_env().environment, "prod");
        // Neither set yields the empty default.
        env::remove_var("INFISICAL_ENV");
        assert_eq!(InfisicalSettings::from_env().environment, "");
    }

    /// BUNYIP-483: unset outside production keeps the loud all-zero dev key.
    #[test]
    fn app_encryption_key_falls_back_to_the_dev_zero_key_outside_production() {
        let _env = env_lock();
        env::remove_var("APP_ENCRYPTION_KEY");
        env::remove_var("APP_ENCRYPTION_KEY_FILE");
        assert_eq!(Config::load_app_encryption_key("development"), [0u8; 32]);
    }

    /// BUNYIP-483: production still refuses to boot without the key.
    #[test]
    #[should_panic(expected = "APP_ENCRYPTION_KEY must be set in production")]
    fn app_encryption_key_is_required_in_production() {
        let _env = env_lock();
        env::remove_var("APP_ENCRYPTION_KEY");
        env::remove_var("APP_ENCRYPTION_KEY_FILE");
        Config::load_app_encryption_key("production");
    }

    /// BUNYIP-483: the consolidation window lists BOTH retired keys, so the
    /// previous-key var parses as a comma-separated list.
    #[test]
    fn previous_encryption_keys_parse_as_a_comma_separated_list() {
        let _env = env_lock();
        env::set_var(
            "APP_ENCRYPTION_KEY_PREV",
            format!("{},  {}", "a1".repeat(32), "b2".repeat(32)),
        );
        assert_eq!(
            Config::load_previous_encryption_keys("APP_ENCRYPTION_KEY_PREV"),
            vec![[0xA1u8; 32], [0xB2u8; 32]]
        );

        env::remove_var("APP_ENCRYPTION_KEY_PREV");
        assert!(Config::load_previous_encryption_keys("APP_ENCRYPTION_KEY_PREV").is_empty());
    }

    #[test]
    fn test_config_defaults() {
        let _env = env_lock();
        // Exercise the parse via from_env_inner so dotenvy::dotenv() is NOT
        // called: a repo-root `.env` (e.g. one setting RUST_LOG=info,bunyip_api=debug)
        // can no longer re-inject values after the removals below and clobber the
        // code defaults asserted here. This keeps the test deterministic regardless
        // of the working tree's `.env` (BUNYIP-102).
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        // Use development to avoid requiring APP_ENCRYPTION_KEY
        env::set_var("ENVIRONMENT", "development");
        env::set_var("HOST_IP", "0.0.0.0");
        env::set_var("APP_PORT", "4000");
        env::remove_var("RUST_LOG");
        env::remove_var("CORS_ORIGIN");
        env::remove_var("SMTP_HOST");
        env::remove_var("EMAIL_ENABLED");
        env::remove_var("COOKIE_DOMAIN");

        let config = Config::from_env_inner().unwrap();

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
    fn test_production_email_disabled_fails_fast() {
        // A production deployment without SMTP configured must refuse to start
        // rather than silently degrade to the token-logging dev path (BUNYIP-204).
        // The email check runs before the TOTP/Stripe key loading, so no
        // encryption keys are required to exercise it.
        let _env = env_lock();
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        env::set_var("ENVIRONMENT", "production");
        env::remove_var("SMTP_HOST");
        env::remove_var("EMAIL_ENABLED");

        let err = Config::from_env_inner().expect_err("production without SMTP must fail");
        assert!(matches!(err, ConfigError::EmailDisabledInProduction));

        env::remove_var("ENVIRONMENT");
    }

    #[test]
    fn test_email_log_tokens_forced_off_in_production() {
        // EMAIL_LOG_TOKENS only takes effect outside production; in production it
        // is forced off so single-use tokens never reach a log (BUNYIP-204).
        let _env = env_lock();
        env::set_var("EMAIL_LOG_TOKENS", "true");

        assert!(
            EmailConfig::from_env(false).log_tokens,
            "EMAIL_LOG_TOKENS=true should enable token logging in development"
        );
        assert!(
            !EmailConfig::from_env(true).log_tokens,
            "EMAIL_LOG_TOKENS must be ignored in production"
        );

        env::remove_var("EMAIL_LOG_TOKENS");
        // Default (unset) is off.
        assert!(!EmailConfig::from_env(false).log_tokens);
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
    fn test_previous_encryption_keys_empty_when_unset() {
        let _env = env_lock();
        env::remove_var("TEST_PREV_KEY_UNSET");
        assert!(Config::load_previous_encryption_keys("TEST_PREV_KEY_UNSET").is_empty());
    }

    #[test]
    fn test_previous_encryption_keys_parse_hex() {
        let _env = env_lock();
        env::set_var("TEST_PREV_KEY_HEX", "aa".repeat(32)); // 64 hex chars = 32 bytes
        assert_eq!(
            Config::load_previous_encryption_keys("TEST_PREV_KEY_HEX"),
            vec![[0xAAu8; 32]]
        );
        env::remove_var("TEST_PREV_KEY_HEX");
    }

    #[test]
    #[should_panic(expected = "must be valid hex")]
    fn test_previous_encryption_keys_panic_on_invalid_hex() {
        let _env = env_lock();
        env::set_var("TEST_PREV_KEY_BAD", "not-valid-hex!");
        Config::load_previous_encryption_keys("TEST_PREV_KEY_BAD");
    }

    #[test]
    #[should_panic(expected = "must be exactly 32 bytes")]
    fn test_previous_encryption_keys_panic_on_wrong_length() {
        let _env = env_lock();
        env::set_var("TEST_PREV_KEY_SHORT", "aabb"); // only 2 bytes
        Config::load_previous_encryption_keys("TEST_PREV_KEY_SHORT");
    }

    // secret_env tests moved to dunite-core with the function (PSA-37).

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

    // ---- Email config DB-overrides-env merge (BUNYIP-351) ----

    fn test_key_set() -> crate::services::AppKeySet {
        crate::services::AppKeySet {
            current: [7u8; 32],
            current_version: 1,
            previous: Vec::new(),
        }
    }

    fn email_row() -> crate::models::email::EmailConfigRow {
        crate::models::email::EmailConfigRow {
            id: 1,
            enabled: None,
            smtp_host: None,
            smtp_port: None,
            smtp_tls: None,
            smtp_username: None,
            smtp_password: None,
            smtp_password_nonce: None,
            key_version: 1,
            from_email: None,
            from_name: None,
            admin_notification_emails: None,
            updated_at: chrono::Utc::now(),
            updated_by: None,
        }
    }

    fn clear_email_env() {
        for var in [
            "SMTP_HOST",
            "SMTP_PORT",
            "SMTP_TLS",
            "SMTP_USERNAME",
            "SMTP_PASSWORD",
            "SMTP_EHLO_NAME",
            "SMTP_FROM",
            "EMAIL_ENABLED",
            "ADMIN_NOTIFICATION_EMAILS",
        ] {
            env::remove_var(var);
        }
    }

    /// BUNYIP-507: an `EmailConfig` carrying only the fields the EHLO
    /// resolution reads; everything else is inert filler.
    fn ehlo_config(ehlo: Option<&str>, base_url: &str, from_email: &str) -> EmailConfig {
        EmailConfig {
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 465,
            smtp_tls: SmtpTls::Implicit,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_ehlo_name: ehlo.map(ToOwned::to_owned),
            from_email: from_email.to_string(),
            from_name: "PSA".to_string(),
            base_url: base_url.to_string(),
            enabled: false,
            log_tokens: false,
            app_name: "PSA".to_string(),
            admin_notification_emails: Vec::new(),
        }
    }

    /// BUNYIP-507: an explicit `SMTP_EHLO_NAME` beats both fallbacks.
    #[test]
    fn ehlo_name_prefers_the_explicit_override() {
        let cfg = ehlo_config(
            Some("  mail.example.com  "),
            "https://app.example.org",
            "noreply@from.example.net",
        );
        assert_eq!(
            cfg.ehlo_name(),
            ClientId::Domain("mail.example.com".to_string())
        );
    }

    /// BUNYIP-507: with no override, `APP_URL`'s host is announced (port and
    /// path excluded), which is what fixes existing deployments on upgrade.
    #[test]
    fn ehlo_name_falls_back_to_the_app_url_host() {
        let cfg = ehlo_config(
            None,
            "https://app.example.org:4400/x",
            "noreply@from.example.net",
        );
        assert_eq!(
            cfg.ehlo_name(),
            ClientId::Domain("app.example.org".to_string())
        );
    }

    /// BUNYIP-507: an empty/whitespace override falls through rather than
    /// announcing an empty name.
    #[test]
    fn ehlo_name_treats_an_empty_override_as_unset() {
        for override_value in ["", "   "] {
            let cfg = ehlo_config(
                Some(override_value),
                "https://app.example.org",
                "noreply@from.example.net",
            );
            assert_eq!(
                cfg.ehlo_name(),
                ClientId::Domain("app.example.org".to_string()),
                "override {override_value:?} must fall through"
            );
        }
    }

    /// BUNYIP-507: with no override and an unusable `APP_URL`, the `from_email`
    /// domain is announced.
    #[test]
    fn ehlo_name_falls_back_to_the_from_email_domain() {
        let cfg = ehlo_config(None, "not a url", "noreply@from.example.net");
        assert_eq!(
            cfg.ehlo_name(),
            ClientId::Domain("from.example.net".to_string())
        );
    }

    /// BUNYIP-507: with every source unusable, lettre's default stands (the
    /// pre-BUNYIP-507 behaviour), never an empty EHLO name.
    #[test]
    fn ehlo_name_falls_back_to_the_lettre_default() {
        let cfg = ehlo_config(None, "not a url", "noreply-without-a-domain");
        assert_eq!(cfg.ehlo_name(), ClientId::default());
    }

    /// BUNYIP-507: an IP-literal source goes on the wire as an address literal
    /// (`EHLO [10.1.2.3]`), which is what RFC 5321 requires.
    #[test]
    fn ehlo_name_wraps_an_ip_literal_as_an_address_literal() {
        let cfg = ehlo_config(None, "http://10.1.2.3:4400", "noreply@from.example.net");
        assert_eq!(cfg.ehlo_name().to_string(), "[10.1.2.3]");
    }

    /// BUNYIP-507: `SMTP_EHLO_NAME` reaches the config, and an all-whitespace
    /// value is read as unset.
    #[test]
    fn smtp_ehlo_name_env_is_trimmed_and_empty_means_unset() {
        let _env = env_lock();
        clear_email_env();

        env::set_var("SMTP_EHLO_NAME", "  mail.example.com  ");
        assert_eq!(
            EmailConfig::from_env(false).smtp_ehlo_name.as_deref(),
            Some("mail.example.com")
        );

        env::set_var("SMTP_EHLO_NAME", "   ");
        assert_eq!(EmailConfig::from_env(false).smtp_ehlo_name, None);

        clear_email_env();
    }

    #[test]
    fn email_from_db_row_falls_back_to_env_when_all_null() {
        let _env = env_lock();
        clear_email_env();

        let row = email_row();
        assert!(!EmailConfig::has_db_overrides(&row));

        // dev (is_production=false) with no SMTP env => the env defaults.
        let cfg = EmailConfig::from_db_row(&row, &test_key_set(), false);
        assert_eq!(cfg.smtp_host, "localhost");
        assert!(!cfg.enabled);
        assert!(cfg.admin_notification_emails.is_empty());
    }

    #[test]
    fn email_from_db_row_applies_overrides() {
        let _env = env_lock();
        clear_email_env();

        let mut row = email_row();
        row.enabled = Some(true);
        row.smtp_host = Some("smtp.example.com".to_string());
        row.smtp_port = Some(587);
        row.smtp_tls = Some("starttls".to_string());
        row.smtp_username = Some("relay-user".to_string());
        row.from_email = Some("noreply@example.com".to_string());
        row.from_name = Some("Example".to_string());
        row.admin_notification_emails = Some("ops@example.com, alerts@example.com".to_string());
        assert!(EmailConfig::has_db_overrides(&row));

        let cfg = EmailConfig::from_db_row(&row, &test_key_set(), false);
        assert!(cfg.enabled);
        assert_eq!(cfg.smtp_host, "smtp.example.com");
        assert_eq!(cfg.smtp_port, 587);
        assert_eq!(cfg.smtp_tls, SmtpTls::Starttls);
        assert_eq!(cfg.smtp_username, "relay-user");
        assert_eq!(cfg.from_email, "noreply@example.com");
        assert_eq!(cfg.from_name, "Example");
        assert_eq!(
            cfg.admin_notification_emails,
            vec![
                "ops@example.com".to_string(),
                "alerts@example.com".to_string()
            ]
        );
    }

    #[test]
    fn email_from_db_row_decrypts_stored_password() {
        let _env = env_lock();
        clear_email_env();

        let key_set = test_key_set();
        let (ct, nonce, ver) =
            crate::models::stripe::encrypt_secret(&key_set, "s3cr3t-relay-pass").unwrap();

        let mut row = email_row();
        row.smtp_password = Some(ct);
        row.smtp_password_nonce = Some(nonce);
        row.key_version = ver;

        let cfg = EmailConfig::from_db_row(&row, &key_set, false);
        assert_eq!(cfg.smtp_password, "s3cr3t-relay-pass");
        assert!(EmailConfig::has_db_overrides(&row));
    }

    #[test]
    fn email_from_db_row_ignores_out_of_range_port() {
        let _env = env_lock();
        clear_email_env();

        // A negative or >u16 port cannot narrow to u16, so the env default port
        // (465 for the default implicit TLS) is kept rather than wrapping.
        let mut row = email_row();
        row.smtp_port = Some(-1);
        let cfg = EmailConfig::from_db_row(&row, &test_key_set(), false);
        assert_eq!(cfg.smtp_port, 465);
    }

    // ---- Auto-ban config DB-overrides-env merge (BUNYIP-351) ----

    /// Build an `AutoBanConfigRow` with the given nullable overrides. `id`,
    /// `updated_at`, `updated_by` are fixed since the merge ignores them.
    fn auto_ban_row(
        enabled: Option<bool>,
        threshold: Option<i64>,
        window_secs: Option<i64>,
        ban_duration_secs: Option<i64>,
    ) -> crate::models::auto_ban::AutoBanConfigRow {
        crate::models::auto_ban::AutoBanConfigRow {
            id: 1,
            enabled,
            threshold,
            window_secs,
            ban_duration_secs,
            updated_at: chrono::Utc::now(),
            updated_by: None,
        }
    }

    /// Clear the `AUTO_BAN_*` env so `from_env` yields the documented defaults.
    fn clear_auto_ban_env() {
        env::remove_var("AUTO_BAN_ENABLED");
        env::remove_var("AUTO_BAN_THRESHOLD");
        env::remove_var("AUTO_BAN_WINDOW_SECS");
        env::remove_var("AUTO_BAN_DURATION_SECS");
    }

    #[test]
    fn auto_ban_from_db_row_falls_back_to_env_when_all_null() {
        let _env = env_lock();
        clear_auto_ban_env();

        let row = auto_ban_row(None, None, None, None);
        assert!(!AutoBanConfig::has_db_overrides(&row));

        let cfg = AutoBanConfig::from_db_row(&row);
        // Documented env defaults.
        assert!(cfg.enabled);
        assert_eq!(cfg.threshold, 5);
        assert_eq!(cfg.window_secs, 3600);
        assert_eq!(cfg.ban_duration_secs, 86400);
    }

    #[test]
    fn auto_ban_from_db_row_applies_overrides() {
        let _env = env_lock();
        clear_auto_ban_env();

        let row = auto_ban_row(Some(false), Some(10), Some(120), Some(600));
        assert!(AutoBanConfig::has_db_overrides(&row));

        let cfg = AutoBanConfig::from_db_row(&row);
        assert!(!cfg.enabled);
        assert_eq!(cfg.threshold, 10);
        assert_eq!(cfg.window_secs, 120);
        assert_eq!(cfg.ban_duration_secs, 600);
    }

    #[test]
    fn auto_ban_from_db_row_ignores_out_of_range_values() {
        let _env = env_lock();
        clear_auto_ban_env();

        // A negative BIGINT cannot narrow to the unsigned in-memory widths, so
        // the env default is kept rather than wrapping to a huge value.
        let row = auto_ban_row(None, Some(-1), Some(-5), Some(-9));
        // Non-NULL columns still count as overrides even if out of range.
        assert!(AutoBanConfig::has_db_overrides(&row));

        let cfg = AutoBanConfig::from_db_row(&row);
        assert_eq!(cfg.threshold, 5);
        assert_eq!(cfg.window_secs, 3600);
        assert_eq!(cfg.ban_duration_secs, 86400);
    }

    #[test]
    fn oci_config_enabled_when_set() {
        let _env = env_lock();
        env::set_var("OCI_REGISTRY_ENABLED", "true");
        let cfg = OciConfig::from_env();
        assert!(cfg.enabled);
        env::remove_var("OCI_REGISTRY_ENABLED");
    }

    // BUNYIP-476: the boot diagnostic keys off this. A configured CIDR means
    // forwarded client IPs (audit actor_ip_address, access log, rate-limit key)
    // resolve to the real client; an empty list means they fall back to the
    // socket peer (bunyip-web on the two-hop path).
    #[test]
    fn trusts_forwarded_client_ip_tracks_the_cidr_list() {
        let _env = env_lock();
        let cfg = dev_config_with_trusted_proxy();
        assert!(
            cfg.trusts_forwarded_client_ip(),
            "a configured TRUSTED_PROXY_CIDR trusts forwarding"
        );

        env::set_var("TRUSTED_PROXY_CIDR", "");
        let cfg = Config::from_env_inner().expect("development config must load");
        assert!(
            !cfg.trusts_forwarded_client_ip(),
            "an empty TRUSTED_PROXY_CIDR trusts no forwarding"
        );
        assert!(cfg.trusted_proxies.is_empty());
    }

    // -- BUNYIP-426 F4: Secure cookie attribute derives from the transport ----

    /// A `development` config whose only trusted proxy is `10.0.0.0/8`.
    fn dev_config_with_trusted_proxy() -> Config {
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        env::set_var("ENVIRONMENT", "development");
        env::set_var("TRUSTED_PROXY_CIDR", "10.0.0.0/8");
        env::remove_var("SMTP_HOST");
        env::remove_var("EMAIL_ENABLED");
        Config::from_env_inner().expect("development config must load")
    }

    #[test]
    fn cookies_secure_true_for_https_request_in_development() {
        let _env = env_lock();
        let config = dev_config_with_trusted_proxy();
        assert!(!config.is_production());

        let req = actix_web::test::TestRequest::with_uri("https://dev-bunyip-api.a8n.run/v1/login")
            .to_http_request();
        assert!(config.cookies_secure(&req));
    }

    #[test]
    fn cookies_secure_true_for_trusted_proxy_forwarded_https() {
        let _env = env_lock();
        let config = dev_config_with_trusted_proxy();

        let req = actix_web::test::TestRequest::with_uri("/v1/login")
            .peer_addr("10.1.2.3:52000".parse().unwrap())
            .insert_header(("X-Forwarded-Proto", "https"))
            .to_http_request();
        assert!(config.cookies_secure(&req));
    }

    #[test]
    fn cookies_secure_false_for_forged_forwarded_proto_from_untrusted_peer() {
        let _env = env_lock();
        let config = dev_config_with_trusted_proxy();

        // Same header, but the socket peer is outside TRUSTED_PROXY_CIDR, so
        // the header is a client-controlled forgery and must not be believed.
        let req = actix_web::test::TestRequest::with_uri("/v1/login")
            .peer_addr("203.0.113.9:52000".parse().unwrap())
            .insert_header(("X-Forwarded-Proto", "https"))
            .to_http_request();
        assert!(!config.cookies_secure(&req));
    }

    #[test]
    fn cookies_secure_false_for_plain_http_in_development() {
        let _env = env_lock();
        let config = dev_config_with_trusted_proxy();

        // Plain-HTTP `just dev` on localhost keeps working.
        let req = actix_web::test::TestRequest::with_uri("/v1/login")
            .peer_addr("127.0.0.1:52000".parse().unwrap())
            .to_http_request();
        assert!(!config.cookies_secure(&req));
    }

    #[test]
    fn cookies_secure_true_in_production_regardless_of_transport() {
        let _env = env_lock();
        // Production is the unconditional-Secure branch; build the Config from
        // the development parse and flip `environment`, so the test does not
        // need the production boot guards' secrets (TOTP key, SMTP host).
        let mut config = dev_config_with_trusted_proxy();
        config.environment = "production".to_string();
        assert!(config.is_production());

        let req = actix_web::test::TestRequest::with_uri("/v1/login")
            .peer_addr("203.0.113.9:52000".parse().unwrap())
            .to_http_request();
        assert!(config.cookies_secure(&req));
    }
}
