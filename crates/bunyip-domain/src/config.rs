use lettre::transport::smtp::extension::ClientId;
use std::env;
use tracing::info;
use url::Url;

/// BUNYIP-643: the declared configuration providers the three admin-managed
/// configs resolve through. The environment provider is `ENV_INVENTORY` below
/// as it stands, so the default resolution is unchanged.
use crate::config_providers::{ConfigProviderKind, ConfigStack, DatabaseProvider};

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
    /// BUNYIP-579/581: ISO 3166-1 alpha-2 country codes allowed / denied to sign
    /// in, resolved through the YAML system-config layer. `country_allow` empty
    /// means allow all; `country_deny` is applied after allow. Enforced in the
    /// login path.
    pub country_allow: Vec<String>,
    pub country_deny: Vec<String>,
    /// BUNYIP-525: how to reach the Infisical provider of the Group-2 integration
    /// secrets. Group-1 startup secrets stay file/SOPS-based and are never held
    /// here. Whether this provider is read at all is `secrets_provider`.
    pub infisical: InfisicalSettings,
    /// BUNYIP-542: the ONE provider the deployment declares for its governed
    /// integration secrets (`SECRETS_STORAGE`). Required, with no default: the
    /// app consults only this provider, so which copy is live is an operator
    /// declaration rather than a precedence chain.
    pub secrets_provider: SecretsProvider,
}

/// BUNYIP-542: where a deployment keeps its governed integration secrets.
///
/// Declared by `SECRETS_STORAGE` and required, because inferring it from what
/// happens to be populated cannot tell "deliberately in the database" from
/// "left behind in the database". The declared provider is the ONLY one
/// consulted: there is no fallback to a second provider.
///
/// The variable keeps its `SECRETS_STORAGE` spelling while the type says
/// provider (BUNYIP-642): renaming it would break every running deployment and
/// every runbook for a vocabulary change with no functional gain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsProvider {
    /// The process environment, through `{NAME}_FILE` compose secrets.
    Environment,
    /// The `email_config` / `stripe_config` rows, encrypted under
    /// `APP_ENCRYPTION_KEY`.
    Database,
    /// The Infisical folder at `INFISICAL_SECRET_PATH`.
    Infisical,
}

impl SecretsProvider {
    /// The legal values, for the operator-facing error on an unrecognised one.
    pub const LEGAL_VALUES: &'static str = "environment, database, infisical";

    /// Every provider, in declaration order.
    pub const ALL: [Self; 3] = [Self::Environment, Self::Database, Self::Infisical];

    /// The wire/env spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Database => "database",
            Self::Infisical => "infisical",
        }
    }

    /// Parse the `SECRETS_STORAGE` value. `None` for anything else, which the
    /// caller reports as a startup configuration failure.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "environment" => Some(Self::Environment),
            "database" => Some(Self::Database),
            "infisical" => Some(Self::Infisical),
            _ => None,
        }
    }

    /// Whether the admin pages can write a governed secret to this provider.
    ///
    /// `environment` is the one read-only provider: a process cannot set an
    /// environment variable for its own next boot, and the compose secret files
    /// are mounted read-only. That is a property of the provider, not a policy.
    pub fn is_writable(self) -> bool {
        !matches!(self, Self::Environment)
    }
}

impl std::fmt::Display for SecretsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// BUNYIP-542: an integration secret with more than one possible provider, and
/// so governed by `SECRETS_STORAGE`.
///
/// Group-1 startup secrets are structurally excluded (the database cannot hold
/// the credential used to reach the database), and an integration secret with
/// exactly one provider today is excluded because the declaration would be a
/// no-op. Either joins this list the moment it gains a second provider.
///
/// The name stays `GovernedSecret` (BUNYIP-642): it names the registry entry,
/// not the provider, and "governed" is the accurate word for a secret with more
/// than one possible home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernedSecret {
    /// `email_config.smtp_password` / `SMTP_PASSWORD` / `/runtime/SMTP_PASSWORD`.
    SmtpPassword,
    /// `stripe_config.secret_key` / `STRIPE_SECRET_KEY`.
    StripeSecretKey,
    /// `stripe_config.webhook_secret` / `STRIPE_WEBHOOK_SECRET`.
    StripeWebhookSecret,
    /// `email_config.imap_password` / `SUPPORT_IMAP_PASSWORD` (BUNYIP-571).
    SupportImapPassword,
}

impl GovernedSecret {
    /// Every governed secret, in report order.
    pub const ALL: [Self; 4] = [
        Self::SmtpPassword,
        Self::StripeSecretKey,
        Self::StripeWebhookSecret,
        Self::SupportImapPassword,
    ];

    /// The variable name in the `environment` provider, which is also the key
    /// name in the `infisical` provider.
    pub fn name(self) -> &'static str {
        match self {
            Self::SmtpPassword => "SMTP_PASSWORD",
            Self::StripeSecretKey => "STRIPE_SECRET_KEY",
            Self::StripeWebhookSecret => "STRIPE_WEBHOOK_SECRET",
            Self::SupportImapPassword => "SUPPORT_IMAP_PASSWORD",
        }
    }

    /// What stops working when no provider holds this secret.
    pub fn feature(self) -> &'static str {
        match self {
            Self::SmtpPassword => {
                "transactional email: the SMTP relay is never authenticated, so magic links, \
                 password resets and notifications are not delivered"
            }
            Self::StripeSecretKey => {
                "Stripe billing: checkout, subscriptions and the pricing catalogue are disabled"
            }
            Self::StripeWebhookSecret => {
                "Stripe webhook verification: /v1/webhooks/stripe fails closed and every event \
                 is rejected"
            }
            Self::SupportImapPassword => {
                "support-queue ingestion: replies to the system mailbox are not polled into \
                 support tickets"
            }
        }
    }

    /// The admin form field this secret is typed into, so a failed save reports
    /// against the field the admin is looking at.
    pub fn form_field(self) -> &'static str {
        match self {
            Self::SmtpPassword => "smtp_password",
            Self::StripeSecretKey => "secret_key",
            Self::StripeWebhookSecret => "webhook_secret",
            Self::SupportImapPassword => "imap_password",
        }
    }

    /// The `environment`-provider secret file this value belongs in, as the
    /// `{NAME}_FILE` target `secrets-migrate --to environment` emits.
    pub fn secret_file(self) -> &'static str {
        match self {
            Self::SmtpPassword => "smtp_password",
            Self::StripeSecretKey => "stripe_secret_key",
            Self::StripeWebhookSecret => "stripe_webhook_secret",
            Self::SupportImapPassword => "support_imap_password",
        }
    }

    /// This secret's value in the `environment` provider.
    ///
    /// File-backed ONLY: the plain variable is deliberately not consulted. A
    /// `STRIPE_SECRET_KEY=sk_live_...` in a compose `environment:` block is the
    /// exposure BUNYIP-38 removed - it is visible to `docker inspect` and to
    /// every child process - so the environment provider means a `{NAME}_FILE`
    /// compose secret, in every mode.
    pub fn read_environment(self) -> Option<String> {
        secret_file_env(self.name())
    }
}

/// Read one secret from a `{NAME}_FILE` compose secret, and only from there
/// (BUNYIP-542). An unreadable path is reported at `error` and treated as
/// absent, so the boot enforcement below turns it into either the fatal
/// "declared provider is empty but another provider holds it" report or the
/// feature-off warning, never a silent success.
fn secret_file_env(name: &str) -> Option<String> {
    let file_var = format!("{name}_FILE");
    let path = env::var(&file_var).ok()?;
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    match std::fs::read_to_string(path) {
        Ok(contents) => Some(contents.trim().to_string()).filter(|value| !value.is_empty()),
        Err(e) => {
            tracing::error!(
                env_var = %file_var,
                path = %path,
                error = %e,
                "{file_var} points at an unreadable file, so the environment provider holds \
                 no value for {name}"
            );
            None
        }
    }
}

/// BUNYIP-525: how to reach the Infisical provider of the Group-2 (integration)
/// secrets. Credentials honour the `{NAME}_FILE` convention like every other
/// secret. Whether this provider is READ is [`SecretsProvider`]; `enabled` only
/// decides whether it is inspected outside `SECRETS_STORAGE=infisical`, which
/// is what `bunyip-api secrets-status` needs to report readiness.
#[derive(Debug, Clone)]
pub struct InfisicalSettings {
    /// Inspect the Infisical provider outside `SECRETS_STORAGE=infisical`
    /// (`INFISICAL_ENABLED`). Off by default; the declared provider is read
    /// regardless.
    pub enabled: bool,
    /// Base URL of the Infisical instance (`INFISICAL_ADDRESS`),
    /// e.g. `https://infisical.a8n.systems`.
    pub address: String,
    /// Infisical project id (`INFISICAL_PROJECT_ID`).
    pub project_id: String,
    /// Infisical environment slug (`INFISICAL_ENVIRONMENT`), e.g. `staging` / `prod`.
    /// Read verbatim (trimmed only): the value must match the slug configured
    /// under Infisical > Secrets > Project > Settings > Environments exactly.
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
                .map(|v| v.trim().to_string())
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
    /// API, and audit metadata. Inverse of the match in `smtp_tls_from`, which
    /// is what the database provider's value is read back through.
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
    /// Reply-To for all system mail: the monitored support inbox that inbound
    /// replies are ingested from (BUNYIP-571). `None` emits no Reply-To, so a
    /// reply falls back to `from_email` (typically an unattended noreply@).
    pub support_inbox_email: Option<String>,
    /// BUNYIP-571: inbound IMAP poller settings. An empty host/username or
    /// `imap_enabled == false` means the support-queue poller does not run. The
    /// password is the governed secret [`GovernedSecret::SupportImapPassword`],
    /// resolved separately at the call site.
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_username: String,
    pub imap_mailbox: String,
    pub imap_enabled: bool,
    pub imap_poll_secs: u64,
}

impl EmailConfig {
    /// Load email configuration from the environment provider alone.
    ///
    /// The same resolution [`Self::resolve`] performs, through a stack holding
    /// only [`EnvironmentProvider`]: no file, no database.
    pub fn from_env(is_production: bool) -> Self {
        Self::resolve(&ConfigStack::environment_only(), None, is_production)
    }

    /// The `email_config` row as a configuration provider (BUNYIP-643).
    ///
    /// This is where `from_db_row`'s per-field fallback went. A column is held
    /// only when it would have won that fallback, so an existing deployment
    /// resolves exactly the values it resolved before: a NULL is not held, an
    /// empty string is not held where the old code filtered one, and an
    /// out-of-range port is not held (it fell back to the environment then and
    /// falls back to the environment now). The encrypted `smtp_password` /
    /// `imap_password` columns are deliberately absent: they are governed
    /// secrets and follow `SECRETS_STORAGE`, not this stack.
    pub fn database_provider(
        row: &crate::models::email::EmailConfigRow,
    ) -> Result<DatabaseProvider, ConfigFailure> {
        let mut db = DatabaseProvider::new();
        db.set_non_empty("SMTP_HOST", row.smtp_host.clone())?;
        db.set_opt(
            "SMTP_PORT",
            row.smtp_port
                .and_then(|p| u16::try_from(p).ok())
                .map(|p| p.to_string()),
        )?;
        db.set_opt(
            "SMTP_TLS",
            row.smtp_tls
                .clone()
                .filter(|tls| matches!(tls.as_str(), "starttls" | "implicit")),
        )?;
        db.set_opt("SMTP_USERNAME", row.smtp_username.clone())?;
        db.set_non_empty("SMTP_FROM_EMAIL", row.from_email.clone())?;
        db.set_non_empty("SMTP_FROM_NAME", row.from_name.clone())?;
        db.set_opt(
            "ADMIN_NOTIFICATION_EMAILS",
            row.admin_notification_emails.clone(),
        )?;
        db.set_opt("EMAIL_ENABLED", row.enabled.map(|v| v.to_string()))?;
        db.set_non_empty("SUPPORT_IMAP_HOST", row.imap_host.clone())?;
        db.set_opt(
            "SUPPORT_IMAP_PORT",
            row.imap_port
                .and_then(|p| u16::try_from(p).ok())
                .map(|p| p.to_string()),
        )?;
        db.set_opt("SUPPORT_IMAP_USERNAME", row.imap_username.clone())?;
        db.set_non_empty("SUPPORT_IMAP_MAILBOX", row.imap_mailbox.clone())?;
        db.set_opt(
            "SUPPORT_IMAP_ENABLED",
            row.imap_enabled.map(|v| v.to_string()),
        )?;
        Ok(db)
    }

    /// Resolve the email configuration through the provider stack (BUNYIP-643).
    ///
    /// BUNYIP-542: `smtp_password` is passed in, already resolved from the ONE
    /// provider `SECRETS_STORAGE` declares. It is a governed secret and never a
    /// configuration key.
    ///
    /// The fields with no second source stay direct environment reads, per the
    /// registry rule in [`crate::config_providers`]: `SMTP_EHLO_NAME`, `APP_URL`,
    /// `APP_NAME`, `SUPPORT_INBOX_EMAIL`, `SUPPORT_IMAP_POLL_SECS` and the
    /// dev-only `EMAIL_LOG_TOKENS` gate have exactly one provider today, so a
    /// declaration would be a no-op.
    pub fn resolve(
        stack: &ConfigStack,
        smtp_password: Option<String>,
        is_production: bool,
    ) -> Self {
        // EMAIL_LOG_TOKENS lets local development log the full magic-link /
        // reset / email-change URL (token included) at DEBUG when email sending
        // is disabled. It defaults off and is forced off in production so the
        // single-use bearer token can never reach a production log (BUNYIP-204).
        let log_tokens = !is_production
            && env::var("EMAIL_LOG_TOKENS")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);

        // SMTP_TLS: "implicit" (port 465) or "starttls" (port 587).
        let smtp_tls = smtp_tls_from(stack.get("SMTP_TLS").as_deref());

        // The port default follows the TLS mode the DEPLOYMENT providers
        // declare, not the database's. That is what `from_db_row` did (its port
        // fallback came from `from_env`, whose default followed the environment
        // TLS), and keeping it is what makes every existing deployment's
        // resolved port identical. The admin page writes the port alongside the
        // TLS mode, so the database never relies on this default.
        let default_port: u16 = match smtp_tls_from(
            stack
                .get_below(ConfigProviderKind::Database, "SMTP_TLS")
                .as_deref(),
        ) {
            SmtpTls::Implicit => 465,
            SmtpTls::Starttls => 587,
        };

        let smtp_host = stack
            .get("SMTP_HOST")
            .unwrap_or_else(|| "localhost".to_string());
        let has_smtp = !smtp_host.is_empty() && smtp_host != "localhost";

        // EMAIL_ENABLED is a force-ON switch in the environment, not a plain
        // value: `EMAIL_ENABLED=false` never turned sending off, it left the
        // production-and-SMTP rule to decide. So the environment's value feeds
        // the computed default below, and only the providers ABOVE it (the
        // database column the admin page writes, and the file) answer outright.
        let force_enabled = stack
            .get_below(ConfigProviderKind::File, "EMAIL_ENABLED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let enabled = stack
            .get_above(ConfigProviderKind::Environment, "EMAIL_ENABLED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or((is_production && has_smtp) || force_enabled);

        Self {
            smtp_host,
            smtp_port: stack.get_parsed::<u16>("SMTP_PORT").unwrap_or(default_port),
            smtp_tls,
            smtp_username: stack.get("SMTP_USERNAME").unwrap_or_default(),
            smtp_password: smtp_password.unwrap_or_default(),
            smtp_ehlo_name: env::var("SMTP_EHLO_NAME")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            from_email: stack
                .get("SMTP_FROM_EMAIL")
                .unwrap_or_else(|| "noreply@localhost".to_string()),
            from_name: stack
                .get("SMTP_FROM_NAME")
                .unwrap_or_else(|| "localhost".to_string()),
            base_url: env::var("APP_URL")
                .or_else(|_| env::var("CORS_ORIGIN"))
                .unwrap_or_else(|_| "http://localhost:5173".to_string()),
            enabled,
            log_tokens,
            app_name: env::var("APP_NAME").unwrap_or_else(|_| "localhost".to_string()),
            admin_notification_emails: stack
                .get("ADMIN_NOTIFICATION_EMAILS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            // BUNYIP-571: the monitored support inbox, emitted as Reply-To so
            // replies to system mail land where the inbound poller ingests them.
            support_inbox_email: env::var("SUPPORT_INBOX_EMAIL")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            // BUNYIP-571: inbound IMAP poller config. The poll interval is the
            // one field with no database column, so it stays an env read.
            imap_host: stack.get("SUPPORT_IMAP_HOST").unwrap_or_default(),
            imap_port: stack.get_parsed::<u16>("SUPPORT_IMAP_PORT").unwrap_or(993),
            imap_username: stack.get("SUPPORT_IMAP_USERNAME").unwrap_or_default(),
            imap_mailbox: stack
                .get("SUPPORT_IMAP_MAILBOX")
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "INBOX".to_string()),
            imap_enabled: stack
                .get("SUPPORT_IMAP_ENABLED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            imap_poll_secs: env::var("SUPPORT_IMAP_POLL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
        }
    }

    /// The `database` provider's copy of the SMTP password: the decrypted
    /// `email_config.smtp_password` ciphertext (BUNYIP-542).
    ///
    /// `None` when the row holds no ciphertext. A ciphertext no key in the set
    /// can read is logged at `error` and reported as absent, so the boot
    /// enforcement treats it as "the declared provider holds nothing" rather
    /// than silently substituting another provider's value.
    ///
    /// [`AppKeySet`]: crate::services::AppKeySet
    pub fn db_smtp_password(
        row: &crate::models::email::EmailConfigRow,
        key_set: &crate::services::AppKeySet,
    ) -> Option<String> {
        let (ciphertext, nonce) = match (&row.smtp_password, &row.smtp_password_nonce) {
            (Some(ct), Some(nonce)) => (ct, nonce),
            _ => return None,
        };
        match crate::models::stripe::decrypt_secret(key_set, ciphertext, nonce, row.key_version) {
            Ok(password) => Some(password),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    key_version = row.key_version,
                    "email_config.smtp_password does not decrypt with APP_ENCRYPTION_KEY or any \
                     APP_ENCRYPTION_KEY_PREV entry; treating the database provider as holding \
                     no SMTP password"
                );
                None
            }
        }
    }

    /// Decrypt the governed IMAP password from the DB row (BUNYIP-571),
    /// mirroring [`Self::db_smtp_password`]. A ciphertext no key decrypts is
    /// treated as no password, not a fatal, so a stale row never blocks boot.
    pub fn db_imap_password(
        row: &crate::models::email::EmailConfigRow,
        key_set: &crate::services::AppKeySet,
    ) -> Option<String> {
        let (ciphertext, nonce) = match (&row.imap_password, &row.imap_password_nonce) {
            (Some(ct), Some(nonce)) => (ct, nonce),
            _ => return None,
        };
        match crate::models::stripe::decrypt_secret(key_set, ciphertext, nonce, row.key_version) {
            Ok(password) => Some(password),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    key_version = row.key_version,
                    "email_config.imap_password does not decrypt with APP_ENCRYPTION_KEY or any \
                     APP_ENCRYPTION_KEY_PREV entry; treating the database provider as holding \
                     no IMAP password"
                );
                None
            }
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
}

/// The SMTP TLS mode a provider's raw value names. Anything but `starttls`
/// (case-insensitively) is implicit TLS, which is what the environment read has
/// always done; the database provider only ever holds one of the two spellings.
fn smtp_tls_from(raw: Option<&str>) -> SmtpTls {
    match raw.unwrap_or_default().to_lowercase().as_str() {
        "starttls" => SmtpTls::Starttls,
        _ => SmtpTls::Implicit,
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
pub(crate) fn parse_smtp_from_email(smtp_from: &str) -> String {
    if let Some(start) = smtp_from.find('<') {
        if let Some(end) = smtp_from.find('>') {
            return smtp_from[start + 1..end].trim().to_string();
        }
    }
    smtp_from.trim().to_string()
}

/// Parse display name from SMTP_FROM.
/// Returns the part before `<`, or "localhost" if no display name is present.
pub(crate) fn parse_smtp_from_name(smtp_from: &str) -> String {
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
    /// Load auto-ban configuration from the environment provider alone.
    pub fn from_env() -> Self {
        Self::resolve(&ConfigStack::environment_only())
    }

    /// The `auto_ban_config` row as a configuration provider (BUNYIP-643).
    ///
    /// The `BIGINT` columns are stored as `i64` and narrowed back to the
    /// in-memory `u32`/`u64` widths here; a stored negative or over-wide value
    /// is not held, so it falls back to the next provider exactly as it fell
    /// back to the environment before.
    pub fn database_provider(
        row: &crate::models::auto_ban::AutoBanConfigRow,
    ) -> Result<DatabaseProvider, ConfigFailure> {
        let mut db = DatabaseProvider::new();
        db.set_opt("AUTO_BAN_ENABLED", row.enabled.map(|v| v.to_string()))?;
        db.set_opt(
            "AUTO_BAN_THRESHOLD",
            row.threshold
                .and_then(|v| u32::try_from(v).ok())
                .map(|v| v.to_string()),
        )?;
        db.set_opt(
            "AUTO_BAN_WINDOW_SECS",
            row.window_secs
                .and_then(|v| u64::try_from(v).ok())
                .map(|v| v.to_string()),
        )?;
        db.set_opt(
            "AUTO_BAN_DURATION_SECS",
            row.ban_duration_secs
                .and_then(|v| u64::try_from(v).ok())
                .map(|v| v.to_string()),
        )?;
        Ok(db)
    }

    /// Resolve the auto-ban configuration through the provider stack.
    pub fn resolve(stack: &ConfigStack) -> Self {
        Self {
            // Anything but `false` / `0` is on, which is what the environment
            // read has always done and what the database column serialises to.
            enabled: stack
                .get("AUTO_BAN_ENABLED")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            threshold: stack.get_parsed::<u32>("AUTO_BAN_THRESHOLD").unwrap_or(5),
            window_secs: stack
                .get_parsed::<u64>("AUTO_BAN_WINDOW_SECS")
                .unwrap_or(3600),
            ban_duration_secs: stack
                .get_parsed::<u64>("AUTO_BAN_DURATION_SECS")
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
    /// BUNYIP-493: whether the organizations and teams feature is switched on.
    /// DB only (admin Pricing tiers page); false until an admin turns it on, so
    /// the feature is dark from its first commit rather than after a retrofit.
    pub orgs_enabled: bool,
}

impl TierConfig {
    /// Load tier configuration from the environment provider alone.
    pub fn from_env() -> Self {
        Self::resolve(&ConfigStack::environment_only(), None)
    }

    /// The `tier_config` row as a configuration provider (BUNYIP-643).
    ///
    /// Only the four slot/trial columns are here. The price and product ids and
    /// the `pricing_enabled` / visibility / `orgs_enabled` switches have exactly
    /// ONE possible provider - the admin pages write them and no environment
    /// variable exists for them (BUNYIP-482/487/493/527) - so they are not
    /// declared keys, for the same reason `GovernedSecret` excludes a secret
    /// with one provider: the declaration would be a no-op, and declaring them
    /// would hand the file provider a feature flag `CLAUDE.md` requires to be
    /// admin-managed. They are read straight from the row by [`Self::resolve`].
    pub fn database_provider(
        row: &crate::models::tier::TierConfigRow,
    ) -> Result<DatabaseProvider, ConfigFailure> {
        let mut db = DatabaseProvider::new();
        db.set_opt(
            "TIER_LIFETIME_SLOTS",
            row.lifetime_slots.map(|v| v.to_string()),
        )?;
        db.set_opt(
            "TIER_EARLY_ADOPTER_SLOTS",
            row.early_adopter_slots.map(|v| v.to_string()),
        )?;
        db.set_opt(
            "TIER_EARLY_ADOPTER_TRIAL_DAYS",
            row.early_adopter_trial_days.map(|v| v.to_string()),
        )?;
        db.set_opt(
            "TIER_STANDARD_TRIAL_DAYS",
            row.standard_trial_days.map(|v| v.to_string()),
        )?;
        Ok(db)
    }

    /// Resolve the tier configuration through the provider stack.
    ///
    /// `row` carries the database-only columns; `None` is the no-database
    /// caller, which takes their built-in defaults.
    pub fn resolve(stack: &ConfigStack, row: Option<&crate::models::tier::TierConfigRow>) -> Self {
        Self {
            lifetime_slots: stack.get_parsed::<i64>("TIER_LIFETIME_SLOTS").unwrap_or(5),
            early_adopter_slots: stack
                .get_parsed::<i64>("TIER_EARLY_ADOPTER_SLOTS")
                .unwrap_or(5),
            early_adopter_trial_days: stack
                .get_parsed::<i64>("TIER_EARLY_ADOPTER_TRIAL_DAYS")
                .unwrap_or(90),
            standard_trial_days: stack
                .get_parsed::<i64>("TIER_STANDARD_TRIAL_DAYS")
                .unwrap_or(30),
            // BUNYIP-482: database only; NULL means no $0 price is configured.
            free_price_id: row.and_then(|row| row.free_price_id.clone()),
            early_adopter_price_id: row.and_then(|row| row.early_adopter_price_id.clone()),
            standard_price_id: row.and_then(|row| row.standard_price_id.clone()),
            lifetime_product_id: row.and_then(|row| row.lifetime_product_id.clone()),
            early_adopter_product_id: row.and_then(|row| row.early_adopter_product_id.clone()),
            standard_product_id: row.and_then(|row| row.standard_product_id.clone()),
            // BUNYIP-487/493: database only, off until an admin turns it on.
            pricing_enabled: row.is_some_and(|row| row.pricing_enabled),
            orgs_enabled: row.is_some_and(|row| row.orgs_enabled),
            // BUNYIP-527: database only, visible until an admin hides it.
            lifetime_visible: row.is_none_or(|row| row.lifetime_visible),
            early_adopter_visible: row.is_none_or(|row| row.early_adopter_visible),
            standard_visible: row.is_none_or(|row| row.standard_visible),
        }
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
        let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "production".to_string());
        let is_production = environment == "production";

        // BUNYIP-537: collect EVERY startup failure in one pass, so an operator
        // fixes them all before the next restart instead of discovering the next
        // one each time. Nothing below returns early on a required variable;
        // the single `finish_startup_audit` at the end of this function decides.
        let mut failures = audit_required(is_production);

        // BUNYIP-622: the application-level deployment settings (feature toggles,
        // country access) resolve through the file-based YAML layer: an env var
        // (or its {NAME}_FILE indirection) over the YAML file over the built-in
        // default. The system-level origins and domains (cors_origin, web_origin,
        // cookie_domain) resolve from the environment ONLY inside `SysConfig`;
        // BUNYIP-579 first placed them in the file, which put them on the
        // API-writable side of the boundary, and BUNYIP-622 moved them out.
        // Generated on first run, never overwritten, loaded once here.
        let sys = crate::sys_config::SysConfig::load();

        // DATABASE_URL embeds the postgres password, so it supports the
        // DATABASE_URL_FILE secret convention like every other secret. Its
        // absence is already recorded by the audit above; the placeholder here
        // is never observed, because a non-empty `failures` returns Err before
        // this Config is built.
        let database_url = secret_env("DATABASE_URL").unwrap_or_default();

        // Optional NOBYPASSRLS pool for per-user RLS (BUNYIP-344). Absent on
        // deployments that have not provisioned the `bunyip_app` role yet.
        let app_database_url = secret_env("APP_DATABASE_URL");

        // Password used to self-provision the `bunyip_app` RLS role (BUNYIP-360).
        let app_password = secret_env("BUNYIP_APP_PASSWORD");

        let host = env::var("HOST_IP").unwrap_or_else(|_| "0.0.0.0".to_string());

        let port = match env::var("APP_PORT")
            .unwrap_or_else(|_| "4000".to_string())
            .parse::<u16>()
        {
            Ok(port) => port,
            Err(e) => {
                failures.push(ConfigFailure {
                    var: "APP_PORT",
                    reason: format!("the value is not a valid port number ({e})"),
                    remedy: "Set it to a TCP port in 1..=65535 (the api listens on 4401 in the \
                             reference compose deployment)."
                        .to_string(),
                });
                4000
            }
        };

        let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

        let cors_origin = sys.cors_origin.clone();

        // BUNYIP_WEB_ORIGIN is the single absolute URL of the bunyip-web login
        // UI. Falls back to the first entry of CORS_ORIGIN for ergonomics on
        // single-RP deployments (dev, RP-less self-hosters); on a multi-RP
        // deployment (c-01: bunyip + mokosh-apps + drillmark) the operator MUST
        // set it explicitly so the OIDC authorize handler doesn't try to
        // concatenate a comma-list onto `/login`.
        let web_origin = sys.web_origin.clone().unwrap_or_else(|| {
            cors_origin
                .split(',')
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("http://localhost:5173")
                .to_string()
        });

        let app_name = env::var("APP_NAME").unwrap_or_else(|_| "localhost".to_string());

        // BUNYIP-643: the deployment providers (the file provider when
        // BUNYIP_CONFIG_DIR names a directory, then the environment). The
        // database provider joins the stack in main.rs, once the pool is open
        // and the admin-managed rows have been read.
        let deployment = ConfigStack::deployment();
        let email = EmailConfig::resolve(&deployment, None, is_production);

        // BUNYIP-542: the declared provider for every governed integration secret.
        // Absence is reported by the presence audit above, so the placeholder in
        // that arm is never observed: a non-empty `failures` returns Err before
        // this Config is built. An unrecognised value is its own failure, named
        // with the legal set.
        let secrets_provider = match secret_env("SECRETS_STORAGE") {
            Some(raw) => SecretsProvider::parse(&raw).unwrap_or_else(|| {
                failures.push(ConfigFailure {
                    var: "SECRETS_STORAGE",
                    reason: format!(
                        "the value {raw:?} is not one of the providers bunyip can read secrets from"
                    ),
                    remedy: format!(
                        "Set SECRETS_STORAGE to one of: {}. See docs/configuration.md.",
                        SecretsProvider::LEGAL_VALUES
                    ),
                });
                SecretsProvider::Database
            }),
            None => SecretsProvider::Database,
        };

        // BUNYIP-623: a self-hosted production deployment with email not yet
        // configured must start, degraded, rather than refuse. A missing
        // integration key must never disable the application (Yousif, 2026-08-24
        // standup). This was BUNYIP-204's fatal, whose stated risk was the
        // disabled dev path logging the single-use magic-link / reset token; that
        // risk is handled independently by `log_tokens`, which is forced off in
        // production (above), so the token can never reach a production log
        // regardless of this branch. What remains is a degraded capability, so it
        // is a warning here and a named `Failing` / `Unconfigured` row on the
        // admin System Status page (`GET /v1/admin/integrations`), not a boot
        // failure.
        if is_production && !email.enabled {
            tracing::warn!(
                "SMTP is not configured (SMTP_HOST unset or \"localhost\"), so transactional \
                 email is disabled: magic links, password resets and notifications are not \
                 delivered. Set SMTP_HOST to a real relay, or EMAIL_ENABLED=true. The admin \
                 System Status page names this."
            );
        }

        // Cookie domain: must be set explicitly via COOKIE_DOMAIN env var.
        // None means cookies are scoped to the exact hostname (suitable for localhost).
        let cookie_domain = sys.cookie_domain.clone();
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

        let auto_ban = AutoBanConfig::resolve(&deployment);
        let trusted_proxies =
            parse_trusted_proxies(&env::var("TRUSTED_PROXY_CIDR").unwrap_or_default());

        let app_encryption_key = match Self::load_app_encryption_key(&environment) {
            Ok(key) => key,
            Err(failure) => {
                failures.push(failure);
                [0u8; 32]
            }
        };
        let app_encryption_key_prev =
            match Self::load_previous_encryption_keys("APP_ENCRYPTION_KEY_PREV") {
                Ok(keys) => keys,
                Err(failure) => {
                    failures.push(failure);
                    Vec::new()
                }
            };
        let app_key_version: i16 = env::var("APP_KEY_VERSION")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let tier = TierConfig::resolve(&deployment, None);
        let download = DownloadConfig::from_env();
        let oci = OciConfig::from_env();
        let oidc = OidcConfig::from_env();

        // BUNYIP-258: a `dev-` kid in production is the paste-error case (a
        // staging .env copied into prod). Tokens minted under it are advertised
        // by JWKS and consumed by RPs as legitimate, masking the
        // misconfiguration until rotation. Presence is covered by the audit;
        // this is the value-level half.
        if is_production
            && oidc.enabled()
            && oidc.jwt_active_kid.to_ascii_lowercase().starts_with("dev-")
        {
            failures.push(ConfigFailure {
                var: "OIDC_JWT_ACTIVE_KID",
                reason: format!(
                    "the value {} starts with `dev-` in production, so RPs would consume \
                     dev-signed tokens as legitimate",
                    oidc.jwt_active_kid
                ),
                remedy: "Set it to a production kid name (e.g. prod-2026) and \
                         OIDC_JWT_PRIVATE_KEY_PATH to the matching production key."
                    .to_string(),
            });
        }

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
        let login_approval_enabled = sys.login_approval_enabled;

        // BUNYIP-377: opt-in switch for the signup bot guard. Default false;
        // enable only once every register form carries the honeypot + timing
        // token, or real signups without those fields are rejected.
        let signup_bot_guard_enabled = sys.signup_bot_guard_enabled;

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
            country_allow: sys.country_allow.clone(),
            country_deny: sys.country_deny.clone(),
            infisical,
            secrets_provider,
        };

        // BUNYIP-537: the one place startup failures are reported. Every branch
        // above pushes instead of returning, so a deployment missing four
        // variables learns about all four in this run.
        finish_startup_audit(failures)?;

        info!(
            host = %config.host,
            port = %config.port,
            environment = %config.environment,
            bootstrap_admin_configured = config.bootstrap_admin_email.is_some(),
            secrets_provider = %config.secrets_provider,
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
    ///
    /// # Errors
    /// Returns the operator-facing failure when the key is absent in production
    /// or the material is malformed. Never panics (BUNYIP-537).
    fn load_app_encryption_key(environment: &str) -> Result<[u8; 32], ConfigFailure> {
        match secret_env("APP_ENCRYPTION_KEY") {
            Some(hex_str) => parse_encryption_key("APP_ENCRYPTION_KEY", &hex_str),
            None => {
                if environment == "production" {
                    // `audit_required` already recorded this; repeat it rather
                    // than return a key the operator never chose. The caller
                    // dedupes by variable name.
                    return Err(required_failure("APP_ENCRYPTION_KEY"));
                }
                // Loud, because data encrypted under the zero key is not
                // protected and will fail to decrypt once a real key is set.
                tracing::warn!(
                    "APP_ENCRYPTION_KEY is not set; using the all-zero DEVELOPMENT key. \
                     TOTP, Stripe and SMTP secrets encrypted with it are NOT protected."
                );
                Ok([0u8; 32])
            }
        }
    }

    /// Load the previous at-rest keys (comma-separated hex, 32 bytes each) from
    /// an env var or its `_FILE` secret. Empty when unset: nothing to fall back
    /// to. A list rather than one key because the consolidation window has to
    /// read rows written under BOTH retired key families (BUNYIP-483).
    ///
    /// # Errors
    /// Returns the operator-facing failure on malformed key material. Never
    /// panics (BUNYIP-537).
    fn load_previous_encryption_keys(
        env_var: &'static str,
    ) -> Result<Vec<[u8; 32]>, ConfigFailure> {
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

    /// The collected startup-configuration failures (BUNYIP-537). Every missing
    /// or malformed required variable found in one pass, so an operator fixes
    /// them all before the next restart instead of one per restart.
    #[error(
        "{} startup configuration error(s): {}",
        .0.len(),
        .0.iter().map(|f| f.var).collect::<Vec<_>>().join(", ")
    )]
    Startup(Vec<ConfigFailure>),
}

impl ConfigError {
    /// Log this error as operator-facing lines: one `tracing::error!` per
    /// failure naming the variable, why it is required, and how to supply it.
    /// The caller exits non-zero afterwards; nothing here panics, so the
    /// operator sees a configuration report rather than a crash report.
    pub fn log_startup_report(&self) {
        match self {
            Self::Startup(failures) => {
                for failure in failures {
                    tracing::error!(
                        env_var = failure.var,
                        "Startup configuration error: {} is not usable - {}. {}",
                        failure.var,
                        failure.reason,
                        failure.remedy
                    );
                }
            }
            other => tracing::error!("Startup configuration error: {other}"),
        }
    }
}

/// One operator-facing startup-configuration failure: which variable, why the
/// api will not start without it, and what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFailure {
    /// The environment variable at fault.
    pub var: &'static str,
    /// Why the api cannot start.
    pub reason: String,
    /// What the operator must do to supply it.
    pub remedy: String,
}

/// How a variable is reported at startup (BUNYIP-537).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvClass {
    /// Absent means the api must not start, in every environment.
    Required,
    /// Absent means the api must not start in production; other environments
    /// fall back to a documented development value.
    RequiredInProduction,
    /// Optional, but its absence turns a feature off: one `warn!` at boot.
    FeatureGating,
    /// Optional with a working default: no boot-time log at all.
    Defaulted,
}

/// One classified environment variable the api reads.
pub struct EnvVarSpec {
    /// The variable name. Secrets also resolve through `{NAME}_FILE`.
    pub name: &'static str,
    /// How its absence is reported.
    pub class: EnvClass,
    /// What it configures, or what stops working when it is absent.
    pub feature: &'static str,
    /// How the operator supplies it.
    pub remedy: &'static str,
    /// Only report this variable when the named variable is itself set. Keeps a
    /// deliberately-unused integration to one warning instead of one per member
    /// of its variable group.
    pub gate: Option<&'static str>,
}

impl EnvVarSpec {
    const fn required(name: &'static str, feature: &'static str, remedy: &'static str) -> Self {
        Self {
            name,
            class: EnvClass::Required,
            feature,
            remedy,
            gate: None,
        }
    }

    const fn required_in_production(
        name: &'static str,
        feature: &'static str,
        remedy: &'static str,
    ) -> Self {
        Self {
            name,
            class: EnvClass::RequiredInProduction,
            feature,
            remedy,
            gate: None,
        }
    }

    const fn gating(name: &'static str, feature: &'static str, remedy: &'static str) -> Self {
        Self {
            name,
            class: EnvClass::FeatureGating,
            feature,
            remedy,
            gate: None,
        }
    }

    const fn defaulted(name: &'static str, feature: &'static str) -> Self {
        Self {
            name,
            class: EnvClass::Defaulted,
            feature,
            remedy: "",
            gate: None,
        }
    }

    const fn gated_by(mut self, gate: &'static str) -> Self {
        self.gate = Some(gate);
        self
    }

    /// The failure this variable produces when it is required and absent.
    fn failure(&self) -> ConfigFailure {
        ConfigFailure {
            var: self.name,
            reason: self.feature.to_string(),
            remedy: self.remedy.to_string(),
        }
    }
}

/// The one classified inventory of every environment variable bunyip-api reads
/// (BUNYIP-537). A new variable is added here with its classification, gated
/// feature and remediation text, or `env_inventory_covers_every_api_env_read`
/// (bunyip-api/tests/env_inventory.rs) fails the build.
///
/// The reporting contract:
///
/// - [`EnvClass::Required`] / [`EnvClass::RequiredInProduction`]: one
///   `tracing::error!` naming the variable, the reason and the remedy, then a
///   non-zero exit. No panic, no backtrace.
/// - [`EnvClass::FeatureGating`]: one `tracing::warn!` naming the variable and
///   the functionality that is off.
/// - [`EnvClass::Defaulted`]: nothing. The defaults are documented in
///   `docs/configuration.md`; a line per default would drown the two cases
///   above.
pub static ENV_INVENTORY: &[EnvVarSpec] = &[
    // ---- Required ---------------------------------------------------------
    EnvVarSpec::required(
        "DATABASE_URL",
        "the api cannot connect to postgres without it",
        "Set DATABASE_URL_FILE=/run/secrets/database_url (compose) or DATABASE_URL (dev .env); \
         `just init-secrets` generates the secret file.",
    ),
    EnvVarSpec::required(
        "SECRETS_STORAGE",
        "the deployment has not declared where its integration secrets live, so bunyip cannot \
         tell a deliberate copy from a leftover one (BUNYIP-542)",
        "Set SECRETS_STORAGE to environment, database or infisical. `database` matches a \
         deployment whose SMTP and Stripe secrets were entered on the admin pages. See \
         docs/configuration.md.",
    ),
    EnvVarSpec::required_in_production(
        "JWT_SECRET",
        "no signing key for session access/refresh tokens",
        "Set JWT_SECRET_FILE=/run/secrets/jwt_secret (compose) or JWT_SECRET (dev .env); \
         `just init-secrets` generates the secret file.",
    ),
    EnvVarSpec::required_in_production(
        "APP_ENCRYPTION_KEY",
        "no at-rest key for the TOTP, Stripe and SMTP secrets (BUNYIP-483)",
        "Set APP_ENCRYPTION_KEY_FILE=/run/secrets/app_encryption_key (compose) or \
         APP_ENCRYPTION_KEY (dev .env) to 32 hex-encoded bytes (`openssl rand -hex 32`); \
         `just init-secrets` generates the secret file.",
    ),
    EnvVarSpec::required_in_production(
        "BUNYIP_WEBHOOK_SIGNING_SECRET",
        "no HMAC key for outbound webhook dispatches, so every receiving RP would have to \
         hold bunyip's access-token signing key (BUNYIP-332)",
        "Set BUNYIP_WEBHOOK_SIGNING_SECRET_FILE=/run/secrets/webhook_signing_secret (compose) \
         or BUNYIP_WEBHOOK_SIGNING_SECRET (dev .env); `just init-secrets` generates the secret \
         file. The receiving app holds the same value (mokosh-server: BUNYIP_WEBHOOK_SECRET).",
    ),
    EnvVarSpec::required_in_production(
        "OIDC_JWT_PRIVATE_KEY_PATH",
        "the OIDC provider is enabled but would sign with the development key path",
        "Set it to the production signing-key path (e.g. /run/secrets/oidc/prod-2026.pem).",
    )
    .gated_by("OIDC_ISSUER"),
    EnvVarSpec::required_in_production(
        "OIDC_JWT_ACTIVE_KID",
        "the OIDC provider is enabled but would advertise a development kid, which RPs would \
         consume as legitimate (BUNYIP-258)",
        "Set it to a production kid name (e.g. prod-2026) matching \
         OIDC_JWT_PRIVATE_KEY_PATH.",
    )
    .gated_by("OIDC_ISSUER"),
    // ---- Feature-gating ---------------------------------------------------
    EnvVarSpec::gating(
        "APP_DATABASE_URL",
        "per-user row level security is inactive: self-service reads fall back to the primary \
         pool, which bypasses RLS (BUNYIP-344)",
        "Set APP_DATABASE_URL_FILE=/run/secrets/app_database_url to a NOBYPASSRLS bunyip_app \
         connection URL.",
    ),
    EnvVarSpec::gating(
        "BUNYIP_APP_PASSWORD",
        "the unprivileged bunyip_app RLS role is not provisioned (BUNYIP-360)",
        "Set BUNYIP_APP_PASSWORD_FILE=/run/secrets/bunyip_app_password to the password embedded \
         in APP_DATABASE_URL.",
    ),
    EnvVarSpec::gating(
        "MAILER_WEBHOOK_SECRET",
        "the mailer bounce/complaint feedback webhook is disabled: with no signing secret the \
         endpoint fails closed, so the shared suppression list is never fed and the relay keeps \
         sending to addresses that bounce or complain (BUNYIP-603)",
        "Set MAILER_WEBHOOK_SECRET_FILE=/run/secrets/mailer_webhook_secret (compose) or \
         MAILER_WEBHOOK_SECRET (dev .env) to the value shared with the SMTP provider's \
         bounce/complaint webhook.",
    ),
    EnvVarSpec::gating(
        "SETUP_DEFAULT_ADMIN",
        "no bootstrap admin is seeded on first boot",
        "Set SETUP_DEFAULT_ADMIN_FILE=/run/secrets/setup_default_admin to `email:password`, or \
         use BOOTSTRAP_ADMIN_EMAIL instead.",
    ),
    EnvVarSpec::gating(
        "BOOTSTRAP_ADMIN_EMAIL",
        "no account is auto-promoted to the first admin / super admin (BUNYIP-290)",
        "Set it to the email that signs up first; it is inert once any admin exists.",
    ),
    EnvVarSpec::gating(
        "TRUSTED_PROXY_CIDR",
        "forwarded client IPs are dropped: sessions and audit rows record the proxy address \
         instead of the end user (BUNYIP-409)",
        "Set it to the CIDRs of the peers allowed to set X-Forwarded-For (see \
         docs/client-ip-forwarding.md).",
    ),
    EnvVarSpec::gating(
        "OIDC_ISSUER",
        "the OIDC provider is off: /.well-known/* and /oauth2/* serve nothing, so no RP can log \
         in through bunyip",
        "Set it to the public issuer URL of this deployment (e.g. https://api.example.com).",
    ),
    EnvVarSpec::gating(
        "FORGEJO_BASE_URL",
        "the distribution proxy is off: member downloads and the OCI registry have no upstream",
        "Set it to the Forgejo base URL and supply FORGEJO_API_TOKEN (see \
         docs/oci-registry-verification.md).",
    ),
    EnvVarSpec::gating(
        "FORGEJO_API_TOKEN",
        "the distribution proxy is off: downloads cannot authenticate to Forgejo",
        "Set FORGEJO_API_TOKEN_FILE=/run/secrets/forgejo_api_token to a token with read access \
         to the release packages.",
    ),
    EnvVarSpec::gating(
        "OCI_REGISTRY_ENABLED",
        "the OCI registry endpoint is off",
        "Set OCI_REGISTRY_ENABLED=true and OCI_REGISTRY_SERVICE to serve it.",
    ),
    EnvVarSpec::gating(
        "OCI_REGISTRY_SERVICE",
        "the OCI registry is enabled but has no public hostname, so the token realm cannot be \
         derived",
        "Set it to the public registry hostname behind the TLS proxy (e.g. \
         registry.example.com).",
    )
    .gated_by("OCI_REGISTRY_ENABLED"),
    EnvVarSpec::gating(
        "SMTP_HOST",
        "transactional email is disabled: magic links, password resets and notifications are \
         not delivered",
        "Set it to the SMTP relay hostname (production refuses to start without it).",
    ),
    EnvVarSpec::gating(
        "ADMIN_NOTIFICATION_EMAILS",
        "admin notification emails have no recipient",
        "Set it to a comma-separated list of admin addresses.",
    )
    .gated_by("SMTP_HOST"),
    EnvVarSpec::gating(
        "IP2LOCATION_DB_PATH",
        "GeoIP enrichment is off: login-location alerts cannot name a country (BUNYIP-366)",
        "Set it to the IP2Location .BIN path (see docs/ip2-dataset-refresh.md).",
    ),
    EnvVarSpec::gating(
        "IP2PROXY_DB_PATH",
        "ASN / VPN enrichment is off: login alerts cannot flag proxy or hosting IPs \
         (BUNYIP-437)",
        "Set it to the IP2Proxy PX .BIN path (see docs/ip2-dataset-refresh.md).",
    ),
    EnvVarSpec::gating(
        "BUNYIP_UPDATE_CHECK_URL",
        "the operator update checker is off: no new-release notice on the admin pages",
        "Set it to a Forgejo/Gitea releases/latest endpoint.",
    ),
    EnvVarSpec::gating(
        "BUNYIP_UPDATE_CHECK_TOKEN",
        "the update check runs unauthenticated, so a private release feed returns nothing",
        "Set BUNYIP_UPDATE_CHECK_TOKEN_FILE=/run/secrets/update_check_token to a read token.",
    )
    .gated_by("BUNYIP_UPDATE_CHECK_URL"),
    EnvVarSpec::gating(
        "INFISICAL_ENABLED",
        "the Infisical provider is not inspected: `bunyip-api secrets-status` cannot report \
         whether SECRETS_STORAGE=infisical is ready to switch to (BUNYIP-525, BUNYIP-542)",
        "Set INFISICAL_ENABLED=true plus the INFISICAL_* credentials (see \
         docs/secrets-infisical.md). SECRETS_STORAGE=infisical inspects it either way.",
    ),
    EnvVarSpec::gating(
        "INFISICAL_ADDRESS",
        "the Infisical fetch is enabled but has no server address",
        "Set it to the Infisical base URL.",
    )
    .gated_by("INFISICAL_ENABLED"),
    EnvVarSpec::gating(
        "INFISICAL_PROJECT_ID",
        "the Infisical fetch is enabled but has no project",
        "Set it to the Infisical project id holding the /runtime folder.",
    )
    .gated_by("INFISICAL_ENABLED"),
    EnvVarSpec::gating(
        "INFISICAL_CLIENT_ID",
        "the Infisical fetch is enabled but has no machine identity",
        "Set INFISICAL_CLIENT_ID_FILE or INFISICAL_CLIENT_ID to the Universal Auth client id.",
    )
    .gated_by("INFISICAL_ENABLED"),
    EnvVarSpec::gating(
        "INFISICAL_CLIENT_SECRET",
        "the Infisical fetch is enabled but has no machine-identity secret",
        "Set INFISICAL_CLIENT_SECRET_FILE or INFISICAL_CLIENT_SECRET to the Universal Auth \
         client secret.",
    )
    .gated_by("INFISICAL_ENABLED"),
    EnvVarSpec::gating(
        "MOKOSH_APPS_REDIRECT_URIS",
        "the mokosh-apps SPA OIDC client is not reconciled from the environment, so it keeps the \
         redirect URIs the migration seeded (BUNYIP-57)",
        "Set it to the comma-separated redirect URIs of this deployment's mokosh-apps.",
    ),
    EnvVarSpec::gating(
        "MOKOSH_APPS_AUDIENCE",
        "the mokosh-apps SPA OIDC client is not reconciled from the environment (BUNYIP-57)",
        "Set it to the mokosh-apps API audience.",
    ),
    EnvVarSpec::gating(
        "MOKOSH_APPS_POST_LOGOUT_REDIRECT_URIS",
        "the mokosh-apps client is reconciled with an empty post-logout redirect list",
        "Set it to the comma-separated post-logout redirect URIs.",
    )
    .gated_by("MOKOSH_APPS_REDIRECT_URIS"),
    EnvVarSpec::gating(
        "DRILLMARK_REDIRECT_URIS",
        "the drillmark SPA OIDC client is not reconciled from the environment, so it keeps the \
         redirect URIs the migration seeded (BUNYIP-57)",
        "Set it to the comma-separated redirect URIs of this deployment's drillmark.",
    ),
    EnvVarSpec::gating(
        "DRILLMARK_AUDIENCE",
        "the drillmark SPA OIDC client is not reconciled from the environment (BUNYIP-57)",
        "Set it to the drillmark API audience.",
    ),
    EnvVarSpec::gating(
        "DRILLMARK_POST_LOGOUT_REDIRECT_URIS",
        "the drillmark client is reconciled with an empty post-logout redirect list",
        "Set it to the comma-separated post-logout redirect URIs.",
    )
    .gated_by("DRILLMARK_REDIRECT_URIS"),
    EnvVarSpec::gating(
        "LETS_CHAT_REDIRECT_URIS",
        "the lets-chat OIDC client is not reconciled from the environment, so it keeps whatever \
         the migration seeded",
        "Set it to the comma-separated redirect URIs of this deployment's lets-chat.",
    ),
    EnvVarSpec::gating(
        "LETS_CHAT_AUDIENCE",
        "the lets-chat OIDC client is not reconciled from the environment, so it keeps whatever \
         the migration seeded",
        "Set it to the lets-chat API audience.",
    ),
    EnvVarSpec::gating(
        "LETS_CHAT_POST_LOGOUT_REDIRECT_URIS",
        "the lets-chat client is reconciled with an empty post-logout redirect list",
        "Set it to the comma-separated post-logout redirect URIs.",
    )
    .gated_by("LETS_CHAT_REDIRECT_URIS"),
    EnvVarSpec::gating(
        "LETS_CHAT_CLIENT_SECRET_HASH",
        "the lets-chat client keeps the migration's shared client-secret hash instead of a \
         per-environment one",
        "Set it to an Argon2id PHC hash of this environment's lets-chat client secret.",
    )
    .gated_by("LETS_CHAT_REDIRECT_URIS"),
    EnvVarSpec::gating(
        "MOKOSH_WEBHOOK_URL",
        "the mokosh application row has no webhook_url, so account-deleted events are never \
         dispatched (BUNYIP-336)",
        "Set it to mokosh-server's bunyip webhook receiver URL.",
    ),
    EnvVarSpec::gating(
        "MOKOSH_BACKUP_API_URL",
        "account backup/restore falls back to the pending stub: Mokosh tenant data is not \
         exported or imported (BUNYIP-356)",
        "Set it to mokosh-server's tenant export/import base URL.",
    ),
    // ---- Defaulted (documented in docs/configuration.md; no boot-time log) --
    EnvVarSpec::defaulted(
        "ENVIRONMENT",
        "deployment environment name; unset means production",
    ),
    EnvVarSpec::defaulted(
        "BUNYIP_CONFIG_FILE",
        "path to the application-level config YAML layer (BUNYIP-579/622); default \
         /app/config/config.yaml, generated on first run and never overwritten",
    ),
    EnvVarSpec::defaulted(
        "BUNYIP_CONFIG_DIR",
        "directory the FILE configuration provider reads, one file per key (BUNYIP-643); unset \
         means that provider is not enabled and configuration resolves from the database and the \
         environment alone, which is every deployment until an operator mounts one",
    ),
    // BUNYIP-561: demoted to a bootstrap default. The product name is the
    // admin-managed `branding.brand_name`; this value is used only while that
    // row is still empty, i.e. a database that has never been branded.
    EnvVarSpec::defaulted(
        "APP_NAME",
        "bootstrap product name for an unbranded database; the admin Branding page is the source \
         of truth once brand_name is set",
    ),
    EnvVarSpec::defaulted(
        "APP_URL",
        "public base URL used in email bodies and the EHLO name",
    ),
    // BUNYIP-559 F10: off unless a load run asks for it. The acquire-timeout
    // count is always collected; only the periodic size/idle sample is gated.
    EnvVarSpec::defaulted(
        "DB_POOL_METRICS_INTERVAL_SECS",
        "seconds between database pool size/idle samples; unset or 0 means no sampling",
    ),
    EnvVarSpec::defaulted("HOST_IP", "bind address"),
    EnvVarSpec::defaulted("APP_PORT", "listen port"),
    EnvVarSpec::defaulted("RUST_LOG", "log filter"),
    EnvVarSpec::defaulted("CORS_ORIGIN", "browser origins allowed to call /v1"),
    EnvVarSpec::defaulted(
        "BUNYIP_WEB_ORIGIN",
        "login UI origin; falls back to CORS_ORIGIN",
    ),
    EnvVarSpec::defaulted(
        "COOKIE_DOMAIN",
        "cookie domain; unset scopes cookies to the host",
    ),
    EnvVarSpec::defaulted(
        "BUNYIP_COOKIE_SHARED_DOMAIN",
        "opt-in cross-subdomain OP session cookie (BUNYIP-266)",
    ),
    EnvVarSpec::defaulted(
        "APP_ENCRYPTION_KEY_PREV",
        "retired at-rest keys still needed to read old rows",
    ),
    EnvVarSpec::defaulted("APP_KEY_VERSION", "version stamped on newly encrypted rows"),
    EnvVarSpec::defaulted(
        "EMAIL_ENABLED",
        "force-enable email without a real SMTP_HOST",
    ),
    EnvVarSpec::defaulted(
        "EMAIL_LOG_TOKENS",
        "dev-only token logging; forced off in production",
    ),
    EnvVarSpec::defaulted("SMTP_PORT", "SMTP port"),
    EnvVarSpec::defaulted("SMTP_TLS", "SMTP TLS mode"),
    EnvVarSpec::defaulted("SMTP_USERNAME", "SMTP username"),
    EnvVarSpec::defaulted(
        "SMTP_PASSWORD",
        "SMTP password; governed by SECRETS_STORAGE, read only as SMTP_PASSWORD_FILE",
    ),
    EnvVarSpec::defaulted(
        "STRIPE_SECRET_KEY",
        "Stripe secret key; governed by SECRETS_STORAGE, read only as STRIPE_SECRET_KEY_FILE",
    ),
    EnvVarSpec::defaulted(
        "STRIPE_WEBHOOK_SECRET",
        "Stripe webhook signing secret; governed by SECRETS_STORAGE, read only as \
         STRIPE_WEBHOOK_SECRET_FILE",
    ),
    EnvVarSpec::defaulted(
        "SMTP_EHLO_NAME",
        "EHLO name; falls back to the APP_URL host",
    ),
    EnvVarSpec::defaulted("SMTP_FROM", "From address"),
    EnvVarSpec::defaulted(
        "SUPPORT_INBOX_EMAIL",
        "Reply-To for system mail: the monitored support inbox (BUNYIP-571)",
    ),
    EnvVarSpec::defaulted(
        "SUPPORT_IMAP_HOST",
        "inbound IMAP host for the support-queue poller (BUNYIP-571)",
    ),
    EnvVarSpec::defaulted("SUPPORT_IMAP_PORT", "inbound IMAP port (default 993)"),
    EnvVarSpec::defaulted("SUPPORT_IMAP_USERNAME", "inbound IMAP username"),
    EnvVarSpec::defaulted(
        "SUPPORT_IMAP_MAILBOX",
        "inbound IMAP mailbox to poll (default INBOX)",
    ),
    EnvVarSpec::defaulted(
        "SUPPORT_IMAP_ENABLED",
        "enable the support-queue inbound poller",
    ),
    EnvVarSpec::defaulted(
        "SUPPORT_IMAP_POLL_SECS",
        "support-queue poll interval in seconds (default 60)",
    ),
    EnvVarSpec::defaulted(
        "SUPPORT_IMAP_PASSWORD",
        "inbound IMAP password; governed by SECRETS_STORAGE, read only as \
         SUPPORT_IMAP_PASSWORD_FILE",
    ),
    EnvVarSpec::defaulted("AUTO_BAN_ENABLED", "auto-ban switch"),
    EnvVarSpec::defaulted("AUTO_BAN_THRESHOLD", "auto-ban failure threshold"),
    EnvVarSpec::defaulted("AUTO_BAN_WINDOW_SECS", "auto-ban window"),
    EnvVarSpec::defaulted("AUTO_BAN_DURATION_SECS", "auto-ban duration"),
    EnvVarSpec::defaulted("LOGIN_APPROVAL_ENABLED", "suspicious-login approval gate"),
    EnvVarSpec::defaulted("SIGNUP_BOT_GUARD_ENABLED", "signup honeypot / timing guard"),
    EnvVarSpec::defaulted("TIER_LIFETIME_SLOTS", "lifetime tier slots"),
    EnvVarSpec::defaulted("TIER_EARLY_ADOPTER_SLOTS", "early-adopter tier slots"),
    EnvVarSpec::defaulted(
        "TIER_EARLY_ADOPTER_TRIAL_DAYS",
        "early-adopter trial length",
    ),
    EnvVarSpec::defaulted("TIER_STANDARD_TRIAL_DAYS", "standard trial length"),
    EnvVarSpec::defaulted(
        "BUNYIP_BILLING_TRIAL_PERIOD_DAYS",
        "Stripe trial period fallback",
    ),
    EnvVarSpec::defaulted("DOWNLOAD_CACHE_DIR", "download cache directory"),
    EnvVarSpec::defaulted("DOWNLOAD_CACHE_MAX_BYTES", "download cache size cap"),
    EnvVarSpec::defaulted(
        "DOWNLOAD_CONCURRENCY_PER_USER",
        "concurrent downloads per user",
    ),
    EnvVarSpec::defaulted("DOWNLOAD_DAILY_LIMIT_PER_USER", "daily downloads per user"),
    EnvVarSpec::defaulted(
        "FORGEJO_RELEASE_CACHE_TTL_SECS",
        "release listing cache TTL",
    ),
    EnvVarSpec::defaulted("OCI_REGISTRY_PORT", "OCI registry listener port"),
    EnvVarSpec::defaulted(
        "OCI_REGISTRY_REALM",
        "token realm; derived from the service host",
    ),
    EnvVarSpec::defaulted("OCI_BLOB_CACHE_DIR", "OCI blob cache directory"),
    EnvVarSpec::defaulted("OCI_BLOB_CACHE_MAX_BYTES", "OCI blob cache size cap"),
    EnvVarSpec::defaulted("OCI_MANIFEST_CACHE_TTL_SECS", "OCI manifest cache TTL"),
    EnvVarSpec::defaulted(
        "OCI_CONCURRENT_MANIFESTS_PER_USER",
        "concurrent manifest pulls",
    ),
    EnvVarSpec::defaulted("OCI_PULLS_PER_USER_PER_DAY", "daily OCI pulls per user"),
    EnvVarSpec::defaulted("OCI_TOKEN_TTL_SECS", "OCI token TTL"),
    EnvVarSpec::defaulted("OIDC_JWT_PUBLIC_KEYS_DIR", "JWKS public-key directory"),
    EnvVarSpec::defaulted("OIDC_ACCESS_TOKEN_TTL_SECONDS", "OIDC access token TTL"),
    EnvVarSpec::defaulted("OIDC_REFRESH_TOKEN_TTL_SECONDS", "OIDC refresh token TTL"),
    EnvVarSpec::defaulted("OIDC_REFRESH_IDLE_TTL_SECONDS", "OIDC refresh idle TTL"),
    EnvVarSpec::defaulted("OIDC_CODE_TTL_SECONDS", "authorization code TTL"),
    EnvVarSpec::defaulted(
        "OIDC_LIFECYCLE_EVENT_KEY",
        "back-channel lifecycle event key",
    ),
    EnvVarSpec::defaulted("OIDC_RS_AUDIENCE", "resource-server audience"),
    EnvVarSpec::defaulted(
        "INFISICAL_SECRET_PATH",
        "Infisical folder, relative to the project",
    ),
    EnvVarSpec::defaulted(
        "INFISICAL_ENVIRONMENT",
        "Infisical environment slug, e.g. staging / prod (BUNYIP-600)",
    ),
    EnvVarSpec::defaulted(
        "BUNYIP_E2E_BOOTSTRAP_ALLOW",
        "non-production e2e hard-delete switch (BUNYIP-246)",
    ),
    EnvVarSpec::defaulted("BUNYIP_E2E_TOTP_SECRET", "e2e bootstrap TOTP seed"),
    EnvVarSpec::defaulted("BUNYIP_SEED_ALLOW", "non-production demo-seed switch"),
    EnvVarSpec::defaulted(
        "BUNYIP_GIT_SHA",
        "build stamp shown on the version endpoint",
    ),
];

/// Look up one variable's spec.
pub fn env_spec(name: &str) -> Option<&'static EnvVarSpec> {
    ENV_INVENTORY.iter().find(|spec| spec.name == name)
}

/// The failure for an inventory variable that is required and absent. Falls
/// back to a generic message for a name the inventory does not carry, which the
/// coverage test in `bunyip-api/tests/env_inventory.rs` prevents.
fn required_failure(name: &'static str) -> ConfigFailure {
    match env_spec(name) {
        Some(spec) => spec.failure(),
        None => ConfigFailure {
            var: name,
            reason: "is required but missing".to_string(),
            remedy: "Set it in the api environment.".to_string(),
        },
    }
}

/// Turn the collected failures into the startup error, one entry per variable.
/// A variable reported by both the presence audit and a value-level check
/// (`APP_ENCRYPTION_KEY` absent in production, say) appears once.
fn finish_startup_audit(mut failures: Vec<ConfigFailure>) -> Result<(), ConfigError> {
    if failures.is_empty() {
        return Ok(());
    }
    let mut seen = std::collections::HashSet::new();
    failures.retain(|failure| seen.insert(failure.var));
    Err(ConfigError::Startup(failures))
}

/// True when the variable resolves to a non-empty value, through either the
/// `{NAME}_FILE` secret convention or the plain variable.
fn env_present(name: &str) -> bool {
    secret_env(name).is_some()
}

/// The startup presence pass: every [`EnvClass::Required`] /
/// [`EnvClass::RequiredInProduction`] variable that is absent, in one report
/// (BUNYIP-537). Gated entries only count when their gate is set, so an
/// OIDC-less deployment is not asked for OIDC key material.
pub fn audit_required(is_production: bool) -> Vec<ConfigFailure> {
    ENV_INVENTORY
        .iter()
        .filter(|spec| match spec.class {
            EnvClass::Required => true,
            EnvClass::RequiredInProduction => is_production,
            EnvClass::FeatureGating | EnvClass::Defaulted => false,
        })
        .filter(|spec| spec.gate.is_none_or(env_present))
        .filter(|spec| !env_present(spec.name))
        .map(EnvVarSpec::failure)
        .collect()
}

/// The feature-gating variables that are absent, in inventory order. Pure, so
/// the classification is testable without a log subscriber;
/// [`log_feature_gaps`] is the thin emitting half.
pub fn feature_gaps() -> Vec<&'static EnvVarSpec> {
    ENV_INVENTORY
        .iter()
        .filter(|spec| spec.class == EnvClass::FeatureGating)
        .filter(|spec| spec.gate.is_none_or(env_present))
        .filter(|spec| !env_present(spec.name))
        .collect()
}

/// Emit one `tracing::warn!` per absent feature-gating variable, naming the
/// functionality that is off. Defaulted variables log nothing. Called once at
/// startup, after the config loads, so the message for each variable lives in
/// exactly one place instead of at its call site.
pub fn log_feature_gaps() {
    for spec in feature_gaps() {
        tracing::warn!(
            env_var = spec.name,
            "{} is not set: {}. {}",
            spec.name,
            spec.feature,
            spec.remedy
        );
    }
}

/// Decode one hex-encoded 32-byte at-rest key. Returns an operator-facing
/// failure (never a panic) on malformed material rather than silently
/// encrypting under a key the operator did not intend.
fn parse_encryption_key(env_var: &'static str, hex_str: &str) -> Result<[u8; 32], ConfigFailure> {
    let remedy = "Set it to 32 hex-encoded bytes (64 hex chars), e.g. `openssl rand -hex 32`.";
    let bytes = hex::decode(hex_str.trim()).map_err(|e| ConfigFailure {
        var: env_var,
        reason: format!("the value is not valid hex ({e})"),
        remedy: remedy.to_string(),
    })?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| ConfigFailure {
        var: env_var,
        reason: format!("the value decodes to {len} bytes, not the required 32"),
        remedy: remedy.to_string(),
    })
}

/// Pure half of [`Config::e2e_purge_enabled`]: the environment must be a real
/// non-production name. Empty / unset (which `Config` treats as production) and
/// `production` both forbid e2e hard-deletes (BUNYIP-246). `ENVIRONMENT` has
/// exactly one production spelling, `production` (BUNYIP-600); there is no
/// `prod` variant to recognize.
pub(crate) fn e2e_env_allows_purge(environment: &str) -> bool {
    let env_name = environment.trim();
    !env_name.is_empty() && !env_name.eq_ignore_ascii_case("production")
}

#[cfg(test)]
mod tests {
    use super::*;
    // Crate-wide lock serializing env-var-mutating tests (BUNYIP-36); every
    // test below that touches process env must hold it.
    use crate::test_support::env_lock;
    use std::env;

    /// BUNYIP-592: point the system config file at a throwaway temp path before
    /// any call that reaches `SysConfig::load()`, which GENERATES the file when
    /// it is absent. Unset, the path is the in-container default under `/app`,
    /// which `compose.dev.yml` bind-mounts to the repo, so the generation lands
    /// in the developer's working tree. Callers hold `env_lock()`, so the
    /// variable cannot leak into a parallel test.
    fn redirect_sys_config_to_temp() {
        let path = env::temp_dir().join(format!("bunyip-test-config-{}.yaml", std::process::id()));
        env::set_var(crate::sys_config::PATH_ENV, path);
    }

    /// BUNYIP-592: a test reaching `from_env_inner` without the redirect above
    /// writes `config/config.yaml` into the working tree, so `git status` is
    /// dirty after `just test`. Fails the build on a new call site that skips it.
    #[test]
    fn every_test_that_loads_the_config_redirects_the_sys_config_file() {
        let module = include_str!("config.rs")
            .split_once("\nmod tests {")
            .expect("the test module")
            .1;

        fn check(name: &str, body: &str, offenders: &mut Vec<String>) {
            if body.contains("from_env_inner(") && !body.contains("redirect_sys_config_to_temp()") {
                offenders.push(name.to_string());
            }
        }

        let mut offenders: Vec<String> = Vec::new();
        let mut name = String::from("<module prologue>");
        let mut body = String::new();
        for line in module.lines() {
            if let Some(rest) = line.strip_prefix("    fn ") {
                check(&name, &body, &mut offenders);
                name = rest.split('(').next().unwrap_or(rest).to_string();
                body.clear();
            }
            body.push_str(line);
            body.push('\n');
        }
        check(&name, &body, &mut offenders);

        assert!(
            offenders.is_empty(),
            "these tests call Config::from_env_inner without redirecting BUNYIP_CONFIG_FILE \
             to a temp path first, so they generate config/config.yaml in the working tree: \
             {offenders:?}"
        );
    }

    #[test]
    fn e2e_env_allows_purge_only_for_real_non_production_names() {
        // Real non-production names permit the e2e hard-delete path. `prod` is
        // not a recognized production spelling (BUNYIP-600): `ENVIRONMENT` has
        // exactly one production value, `production`.
        for env_name in [
            "staging",
            "Staging",
            "dev",
            "development",
            "test",
            "ci",
            "prod",
            "PROD",
        ] {
            assert!(
                e2e_env_allows_purge(env_name),
                "{env_name} should allow purge"
            );
        }
        // `production` and empty/unset forbid it, so `?purge` and the reaper
        // can never hard-delete on production (BUNYIP-246).
        for env_name in ["production", "Production", "PRODUCTION", "", "   "] {
            assert!(
                !e2e_env_allows_purge(env_name),
                "{env_name:?} must forbid purge"
            );
        }
    }

    /// BUNYIP-600: `INFISICAL_ENVIRONMENT` is read verbatim (trimmed only).
    /// Must match the slug under Infisical > Secrets > Project > Settings > Environments.
    #[test]
    fn infisical_environment_reads_verbatim_and_drops_legacy_alias() {
        let _env = env_lock();
        env::set_var("INFISICAL_ENVIRONMENT", "production");
        assert_eq!(InfisicalSettings::from_env().environment, "production");
        env::set_var("INFISICAL_ENVIRONMENT", "  staging  ");
        assert_eq!(InfisicalSettings::from_env().environment, "staging");
        // The legacy alias is no longer read, even when it holds a value.
        env::remove_var("INFISICAL_ENVIRONMENT");
        env::set_var("INFISICAL_ENV", "production");
        assert_eq!(InfisicalSettings::from_env().environment, "");
        env::remove_var("INFISICAL_ENV");
        assert_eq!(InfisicalSettings::from_env().environment, "");
    }

    /// BUNYIP-483: unset outside production keeps the loud all-zero dev key.
    #[test]
    fn app_encryption_key_falls_back_to_the_dev_zero_key_outside_production() {
        let _env = env_lock();
        env::remove_var("APP_ENCRYPTION_KEY");
        env::remove_var("APP_ENCRYPTION_KEY_FILE");
        assert_eq!(
            Config::load_app_encryption_key("development").unwrap(),
            [0u8; 32]
        );
    }

    /// BUNYIP-483: production still refuses to boot without the key.
    /// BUNYIP-537: as an operator-facing failure, not a panic.
    #[test]
    fn app_encryption_key_is_required_in_production() {
        let _env = env_lock();
        env::remove_var("APP_ENCRYPTION_KEY");
        env::remove_var("APP_ENCRYPTION_KEY_FILE");
        let failure = Config::load_app_encryption_key("production")
            .expect_err("production without the key must fail");
        assert_eq!(failure.var, "APP_ENCRYPTION_KEY");
        assert!(!failure.remedy.is_empty());
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
            Config::load_previous_encryption_keys("APP_ENCRYPTION_KEY_PREV").unwrap(),
            vec![[0xA1u8; 32], [0xB2u8; 32]]
        );

        env::remove_var("APP_ENCRYPTION_KEY_PREV");
        assert!(
            Config::load_previous_encryption_keys("APP_ENCRYPTION_KEY_PREV")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_config_defaults() {
        let _env = env_lock();
        // Exercise the parse via from_env_inner so dotenvy::dotenv() is NOT
        // called: a repo-root `.env` (e.g. one setting RUST_LOG=info,bunyip_api=debug)
        // can no longer re-inject values after the removals below and clobber the
        // code defaults asserted here. This keeps the test deterministic regardless
        // of the working tree's `.env` (BUNYIP-102).
        redirect_sys_config_to_temp();
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        // Use development to avoid requiring APP_ENCRYPTION_KEY
        env::set_var("ENVIRONMENT", "development");
        env::set_var("SECRETS_STORAGE", "database");
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
    fn test_production_without_smtp_is_not_a_startup_failure() {
        // BUNYIP-623: a production deployment with email not yet configured must
        // start, degraded, not refuse. Yousif's point on the 2026-08-24 standup:
        // a missing integration key must never disable the application. The
        // token-leak this once guarded against is handled independently
        // (`log_tokens` is forced off in production, asserted separately), so
        // SMTP_HOST is no longer a fatal startup failure. Other required
        // production vars are absent in this minimal env, so `from_env_inner`
        // still errors, but SMTP_HOST is never among the failures.
        let _env = env_lock();
        redirect_sys_config_to_temp();
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        env::set_var("ENVIRONMENT", "production");
        env::set_var("SECRETS_STORAGE", "database");
        env::remove_var("SMTP_HOST");
        env::remove_var("EMAIL_ENABLED");

        match Config::from_env_inner() {
            Ok(_) => {}
            Err(ConfigError::Startup(failures)) => assert!(
                !failures.iter().any(|f| f.var == "SMTP_HOST"),
                "SMTP_HOST must no longer be a startup failure: {failures:?}"
            ),
            Err(other) => panic!("expected a startup report, got {other:?}"),
        }

        env::remove_var("ENVIRONMENT");
    }

    /// BUNYIP-623: turning every integration off can never fail startup, because
    /// no integration-gating variable is classified Required. Proven statically
    /// over the inventory so a new integration cannot be added as Required by
    /// mistake and quietly break the self-hosting default.
    #[test]
    fn no_integration_variable_is_required_so_a_zero_integration_deployment_boots() {
        let required: Vec<&str> = ENV_INVENTORY
            .iter()
            .filter(|s| matches!(s.class, EnvClass::Required | EnvClass::RequiredInProduction))
            .map(|s| s.name)
            .collect();
        for integration_var in [
            "SMTP_HOST",
            "FORGEJO_BASE_URL",
            "FORGEJO_API_TOKEN",
            "OCI_REGISTRY_ENABLED",
            "OCI_REGISTRY_SERVICE",
            "INFISICAL_ENABLED",
            "IP2LOCATION_DB_PATH",
            "IP2PROXY_DB_PATH",
            "BUNYIP_UPDATE_CHECK_URL",
            "MOKOSH_BACKUP_API_URL",
        ] {
            assert!(
                !required.contains(&integration_var),
                "{integration_var} must be optional: a self-hosted deployment turns it off"
            );
        }
    }

    /// BUNYIP-537: several missing required variables are reported in ONE run,
    /// so an operator fixes them all before the next restart rather than
    /// discovering the next one each time.
    #[test]
    fn missing_required_variables_are_reported_in_one_run() {
        let _env = env_lock();
        redirect_sys_config_to_temp();
        env::set_var("ENVIRONMENT", "production");
        for var in [
            "DATABASE_URL",
            "DATABASE_URL_FILE",
            "JWT_SECRET",
            "JWT_SECRET_FILE",
            "APP_ENCRYPTION_KEY",
            "APP_ENCRYPTION_KEY_FILE",
            "BUNYIP_WEBHOOK_SIGNING_SECRET",
            "BUNYIP_WEBHOOK_SIGNING_SECRET_FILE",
            "SECRETS_STORAGE",
            "SECRETS_STORAGE_FILE",
            "SMTP_HOST",
            "EMAIL_ENABLED",
        ] {
            env::remove_var(var);
        }

        let err = Config::from_env_inner().expect_err("an unconfigured production must fail");
        env::remove_var("ENVIRONMENT");

        let ConfigError::Startup(failures) = &err else {
            panic!("expected a startup report, got {err:?}");
        };
        let reported: Vec<&str> = failures.iter().map(|f| f.var).collect();
        for expected in [
            "DATABASE_URL",
            "SECRETS_STORAGE",
            "JWT_SECRET",
            "APP_ENCRYPTION_KEY",
            "BUNYIP_WEBHOOK_SIGNING_SECRET",
        ] {
            assert!(
                reported.contains(&expected),
                "{expected} missing from {reported:?}"
            );
        }
        // BUNYIP-623: email is an optional integration now, so an unconfigured
        // SMTP is a warning, not a startup failure. It must NOT appear here.
        assert!(
            !reported.contains(&"SMTP_HOST"),
            "SMTP_HOST must no longer be a startup failure: {reported:?}"
        );
        // One entry per variable: APP_ENCRYPTION_KEY is found by both the
        // presence audit and the key loader, and must not be reported twice.
        let mut unique = reported.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            reported.len(),
            "duplicate report: {reported:?}"
        );
        // Every failure carries the reason and the remedy the operator needs.
        for failure in failures {
            assert!(!failure.reason.is_empty(), "{failure:?}");
            assert!(!failure.remedy.is_empty(), "{failure:?}");
        }
        // ... and the aggregate message names them, so the `Display` half of
        // the error is usable on its own too.
        assert!(err.to_string().contains("JWT_SECRET"), "{err}");
    }

    /// BUNYIP-537: outside production the same variables are not required, so a
    /// dev boot needs only DATABASE_URL.
    #[test]
    fn production_only_requirements_do_not_apply_outside_production() {
        let _env = env_lock();
        for var in [
            "JWT_SECRET",
            "JWT_SECRET_FILE",
            "APP_ENCRYPTION_KEY",
            "APP_ENCRYPTION_KEY_FILE",
            "BUNYIP_WEBHOOK_SIGNING_SECRET",
            "BUNYIP_WEBHOOK_SIGNING_SECRET_FILE",
        ] {
            env::remove_var(var);
        }
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        // SECRETS_STORAGE is Required in EVERY environment (BUNYIP-542), so it
        // is set here: this test is about the production-only entries.
        env::set_var("SECRETS_STORAGE", "database");

        assert!(audit_required(false).is_empty());
        assert_eq!(
            audit_required(true)
                .iter()
                .map(|f| f.var)
                .collect::<Vec<_>>(),
            vec![
                "JWT_SECRET",
                "APP_ENCRYPTION_KEY",
                "BUNYIP_WEBHOOK_SIGNING_SECRET"
            ]
        );
    }

    /// BUNYIP-537: a required variable that is gated (the OIDC key material) is
    /// only demanded once its gate is set, so an OIDC-less deployment is not
    /// asked for key material it has no use for.
    #[test]
    fn gated_required_variables_only_apply_once_their_gate_is_set() {
        let _env = env_lock();
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        env::set_var("SECRETS_STORAGE", "database");
        env::set_var("JWT_SECRET", "x".repeat(32));
        env::set_var("APP_ENCRYPTION_KEY", "aa".repeat(32));
        env::set_var("BUNYIP_WEBHOOK_SIGNING_SECRET", "y".repeat(32));
        env::remove_var("OIDC_ISSUER");
        env::remove_var("OIDC_JWT_PRIVATE_KEY_PATH");
        env::remove_var("OIDC_JWT_ACTIVE_KID");

        assert!(audit_required(true).is_empty());

        env::set_var("OIDC_ISSUER", "https://api.example.com");
        assert_eq!(
            audit_required(true)
                .iter()
                .map(|f| f.var)
                .collect::<Vec<_>>(),
            vec!["OIDC_JWT_PRIVATE_KEY_PATH", "OIDC_JWT_ACTIVE_KID"]
        );

        for var in [
            "OIDC_ISSUER",
            "DATABASE_URL",
            "JWT_SECRET",
            "APP_ENCRYPTION_KEY",
            "BUNYIP_WEBHOOK_SIGNING_SECRET",
        ] {
            env::remove_var(var);
        }
    }

    /// BUNYIP-537: a missing feature-gating variable is reported (one warning
    /// naming the variable and the functionality that is off) and boot
    /// continues; a defaulted variable is never reported at all.
    #[test]
    fn feature_gating_variables_are_reported_and_defaulted_ones_are_not() {
        let _env = env_lock();
        redirect_sys_config_to_temp();
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        env::set_var("ENVIRONMENT", "development");
        env::set_var("SECRETS_STORAGE", "database");
        env::remove_var("IP2LOCATION_DB_PATH");
        env::remove_var("APP_PORT");
        env::remove_var("RUST_LOG");

        // Boot continues: the missing optional variable is not an error.
        Config::from_env_inner().expect("a missing optional variable must not fail the boot");

        let gaps: Vec<&str> = feature_gaps().iter().map(|spec| spec.name).collect();
        assert!(
            gaps.contains(&"IP2LOCATION_DB_PATH"),
            "feature-gating variable missing from {gaps:?}"
        );
        // Defaulted variables produce nothing, however absent they are.
        for defaulted in ["APP_PORT", "RUST_LOG"] {
            assert!(!gaps.contains(&defaulted), "{defaulted} must not warn");
        }

        // The warning carries the functionality that is off plus the remedy.
        let spec = env_spec("IP2LOCATION_DB_PATH").expect("classified in the inventory");
        assert_eq!(spec.class, EnvClass::FeatureGating);
        assert!(spec.feature.contains("GeoIP enrichment is off"));
        assert!(!spec.remedy.is_empty());

        // Setting it clears the warning.
        env::set_var("IP2LOCATION_DB_PATH", "/data/IP2LOCATION.BIN");
        assert!(!feature_gaps()
            .iter()
            .any(|spec| spec.name == "IP2LOCATION_DB_PATH"));
        env::remove_var("IP2LOCATION_DB_PATH");
        env::remove_var("ENVIRONMENT");
    }

    /// BUNYIP-537: a group member only warns once its gate is set, so an
    /// unused integration costs one line, not one per variable.
    #[test]
    fn gated_feature_warnings_wait_for_their_gate() {
        let _env = env_lock();
        for var in [
            "INFISICAL_ENABLED",
            "INFISICAL_ADDRESS",
            "INFISICAL_PROJECT_ID",
            "INFISICAL_CLIENT_ID",
            "INFISICAL_CLIENT_SECRET",
        ] {
            env::remove_var(var);
        }

        let gaps: Vec<&str> = feature_gaps().iter().map(|spec| spec.name).collect();
        assert!(gaps.contains(&"INFISICAL_ENABLED"), "{gaps:?}");
        assert!(!gaps.contains(&"INFISICAL_ADDRESS"), "{gaps:?}");

        env::set_var("INFISICAL_ENABLED", "true");
        let gaps: Vec<&str> = feature_gaps().iter().map(|spec| spec.name).collect();
        assert!(gaps.contains(&"INFISICAL_ADDRESS"), "{gaps:?}");
        env::remove_var("INFISICAL_ENABLED");
    }

    /// BUNYIP-537: every inventory entry is usable as an operator message -
    /// unique name, a feature sentence, and a remedy wherever one is reported.
    #[test]
    fn every_inventory_entry_is_complete() {
        let mut names: Vec<&str> = ENV_INVENTORY.iter().map(|spec| spec.name).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate entry in ENV_INVENTORY");

        for spec in ENV_INVENTORY {
            assert!(
                !spec.feature.is_empty(),
                "{} has no feature text",
                spec.name
            );
            match spec.class {
                EnvClass::Defaulted => {}
                _ => assert!(!spec.remedy.is_empty(), "{} has no remedy", spec.name),
            }
            if let Some(gate) = spec.gate {
                assert!(
                    env_spec(gate).is_some(),
                    "{} is gated by unclassified {gate}",
                    spec.name
                );
            }
        }
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

    // -- BUNYIP-542: SECRETS_STORAGE ----------------------------------------

    /// Every legal value round-trips, and nothing else parses: an operator
    /// typo must be a startup error, never a silent fallback to some default
    /// provider.
    #[test]
    fn secrets_provider_parses_exactly_the_three_legal_values() {
        for (raw, expected) in [
            ("environment", SecretsProvider::Environment),
            ("database", SecretsProvider::Database),
            ("infisical", SecretsProvider::Infisical),
            // Case and surrounding whitespace are operator noise, not intent.
            ("  DataBase ", SecretsProvider::Database),
        ] {
            assert_eq!(SecretsProvider::parse(raw), Some(expected), "{raw}");
        }
        for raw in ["", "db", "vault", "environmnet", "database,infisical"] {
            assert_eq!(SecretsProvider::parse(raw), None, "{raw}");
        }
    }

    /// An unrecognised value is a startup failure naming the variable and the
    /// legal set, collected with every other failure in the one report.
    #[test]
    fn an_unrecognised_secrets_provider_is_a_startup_failure() {
        let _env = env_lock();
        redirect_sys_config_to_temp();
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        env::set_var("ENVIRONMENT", "development");
        env::set_var("SECRETS_STORAGE", "vault");

        let err =
            Config::from_env_inner().expect_err("an unrecognised provider must fail the boot");
        let ConfigError::Startup(failures) = &err else {
            panic!("expected a startup report, got {err:?}");
        };
        let failure = failures
            .iter()
            .find(|f| f.var == "SECRETS_STORAGE")
            .unwrap_or_else(|| panic!("SECRETS_STORAGE not reported in {failures:?}"));
        assert!(failure.reason.contains("vault"), "{failure:?}");
        for legal in ["environment", "database", "infisical"] {
            assert!(failure.remedy.contains(legal), "{failure:?}");
        }

        env::set_var("SECRETS_STORAGE", "infisical");
        let config = Config::from_env_inner().expect("a legal provider loads");
        assert_eq!(config.secrets_provider, SecretsProvider::Infisical);

        env::remove_var("SECRETS_STORAGE");
        env::remove_var("ENVIRONMENT");
    }

    /// The environment provider is `{NAME}_FILE` only. A plain variable holding
    /// a governed secret is the compose-`environment:` exposure BUNYIP-38
    /// removed, so it resolves to nothing rather than quietly working.
    #[test]
    fn the_environment_provider_reads_the_file_and_ignores_the_plain_variable() {
        let _env = env_lock();
        let dir = std::env::temp_dir().join("bunyip-542-env-store");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("smtp_password");
        std::fs::write(&path, "  from-the-file\n").expect("write the secret file");

        env::remove_var("SMTP_PASSWORD_FILE");
        env::set_var("SMTP_PASSWORD", "from-the-plain-variable");
        assert_eq!(GovernedSecret::SmtpPassword.read_environment(), None);

        env::set_var("SMTP_PASSWORD_FILE", &path);
        assert_eq!(
            GovernedSecret::SmtpPassword.read_environment().as_deref(),
            Some("from-the-file")
        );

        // An empty file counts as unset, matching every other secret read.
        std::fs::write(&path, "\n").expect("truncate the secret file");
        assert_eq!(GovernedSecret::SmtpPassword.read_environment(), None);

        env::remove_var("SMTP_PASSWORD_FILE");
        env::remove_var("SMTP_PASSWORD");
        let _ = std::fs::remove_file(&path);
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
        assert!(Config::load_previous_encryption_keys("TEST_PREV_KEY_UNSET")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_previous_encryption_keys_parse_hex() {
        let _env = env_lock();
        env::set_var("TEST_PREV_KEY_HEX", "aa".repeat(32)); // 64 hex chars = 32 bytes
        assert_eq!(
            Config::load_previous_encryption_keys("TEST_PREV_KEY_HEX").unwrap(),
            vec![[0xAAu8; 32]]
        );
        env::remove_var("TEST_PREV_KEY_HEX");
    }

    /// BUNYIP-537: malformed key material is an operator-facing failure naming
    /// the variable and the remedy, not a panic.
    #[test]
    fn test_previous_encryption_keys_fail_on_invalid_hex() {
        let _env = env_lock();
        env::set_var("TEST_PREV_KEY_BAD", "not-valid-hex!");
        let failure = Config::load_previous_encryption_keys("TEST_PREV_KEY_BAD")
            .expect_err("invalid hex must fail");
        env::remove_var("TEST_PREV_KEY_BAD");
        assert_eq!(failure.var, "TEST_PREV_KEY_BAD");
        assert!(failure.reason.contains("not valid hex"), "{failure:?}");
        assert!(failure.remedy.contains("64 hex chars"), "{failure:?}");
    }

    #[test]
    fn test_previous_encryption_keys_fail_on_wrong_length() {
        let _env = env_lock();
        env::set_var("TEST_PREV_KEY_SHORT", "aabb"); // only 2 bytes
        let failure = Config::load_previous_encryption_keys("TEST_PREV_KEY_SHORT")
            .expect_err("a short key must fail");
        env::remove_var("TEST_PREV_KEY_SHORT");
        assert_eq!(failure.var, "TEST_PREV_KEY_SHORT");
        assert!(
            failure.reason.contains("2 bytes, not the required 32"),
            "{failure:?}"
        );
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
            imap_host: None,
            imap_port: None,
            imap_username: None,
            imap_password: None,
            imap_password_nonce: None,
            imap_mailbox: None,
            imap_enabled: None,
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
            support_inbox_email: None,
            imap_host: String::new(),
            imap_port: 993,
            imap_username: String::new(),
            imap_mailbox: "INBOX".to_string(),
            imap_enabled: false,
            imap_poll_secs: 60,
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

    /// A stack of the database provider over the environment, the shape
    /// `from_db_row` used to hard-code (BUNYIP-643). The file provider is left
    /// out so these tests keep asserting exactly the old two-provider answer.
    fn db_over_env(db: DatabaseProvider) -> ConfigStack {
        ConfigStack::new(vec![
            std::sync::Arc::new(db),
            std::sync::Arc::new(crate::config_providers::EnvironmentProvider),
        ])
    }

    #[test]
    fn email_database_provider_falls_back_to_env_when_all_null() {
        let _env = env_lock();
        clear_email_env();

        let row = email_row();
        let db = EmailConfig::database_provider(&row).expect("no Group-1 key in the email row");
        assert!(db.is_empty(), "an all-NULL row holds nothing");

        // dev (is_production=false) with no SMTP env => the env defaults.
        let cfg = EmailConfig::resolve(&db_over_env(db), None, false);
        assert_eq!(cfg.smtp_host, "localhost");
        assert!(!cfg.enabled);
        assert!(cfg.admin_notification_emails.is_empty());
    }

    #[test]
    fn email_database_provider_applies_overrides() {
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
        let db = EmailConfig::database_provider(&row).expect("no Group-1 key in the email row");
        assert!(!db.is_empty());

        let cfg = EmailConfig::resolve(&db_over_env(db), None, false);
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
    fn email_database_provider_never_holds_the_governed_password() {
        let _env = env_lock();
        clear_email_env();

        let key_set = test_key_set();
        let (ct, nonce, ver) =
            crate::models::stripe::encrypt_secret(&key_set, "s3cr3t-relay-pass").unwrap();

        let mut row = email_row();
        row.smtp_password = Some(ct);
        row.smtp_password_nonce = Some(nonce);
        row.key_version = ver;

        // BUNYIP-542: the caller resolves the password from the declared
        // provider; `db_smtp_password` is the database provider's half of that
        // resolution.
        let from_provider = EmailConfig::db_smtp_password(&row, &key_set);
        assert_eq!(from_provider.as_deref(), Some("s3cr3t-relay-pass"));
        let db = EmailConfig::database_provider(&row).expect("no Group-1 key in the email row");
        let cfg = EmailConfig::resolve(&db_over_env(db.clone()), from_provider, false);
        assert_eq!(cfg.smtp_password, "s3cr3t-relay-pass");
        // The governed secret is NOT a configuration key: the ciphertext column
        // never enters the provider (BUNYIP-542 owns it, not this stack).
        assert!(db.is_empty());
    }

    use crate::config_providers::ConfigVerdict;

    /// A stand-in environment provider: it answers for the same PRIORITY as the
    /// real one without touching the process environment, which this suite can
    /// only mutate under a lock that does not stop other threads reading.
    #[derive(Debug)]
    struct FakeEnvironment(std::collections::BTreeMap<String, String>);

    impl crate::config_providers::ConfigProvider for FakeEnvironment {
        fn kind(&self) -> ConfigProviderKind {
            ConfigProviderKind::Environment
        }
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    /// AC3, the resolved-values-are-unchanged proof: with the environment AND
    /// the database both holding email settings, every field the database holds
    /// comes from the database and every field it leaves NULL comes from the
    /// environment. That IS the `from_db_row` contract, now stated as a declared
    /// priority rather than as the order two functions were called in.
    #[test]
    fn the_database_provider_wins_per_field_and_the_environment_fills_the_rest() {
        let _env = env_lock();
        clear_email_env();

        let environment = FakeEnvironment(
            [
                ("SMTP_HOST", "env.example.net"),
                ("SMTP_PORT", "2525"),
                ("SMTP_USERNAME", "env-user"),
                ("SMTP_FROM_EMAIL", "env@example.net"),
                ("ADMIN_NOTIFICATION_EMAILS", "env-ops@example.net"),
            ]
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        );

        let mut row = email_row();
        row.smtp_host = Some("db.example.com".to_string());
        row.from_name = Some("Database Sender".to_string());

        let db = EmailConfig::database_provider(&row).expect("no Group-1 key in the email row");
        let stack = ConfigStack::new(vec![
            std::sync::Arc::new(db),
            std::sync::Arc::new(environment),
        ]);
        let cfg = EmailConfig::resolve(&stack, None, false);

        // Held by the database: the database serves it.
        assert_eq!(cfg.smtp_host, "db.example.com");
        assert_eq!(cfg.from_name, "Database Sender");
        // Left NULL: the environment serves it, exactly as before.
        assert_eq!(cfg.smtp_port, 2525);
        assert_eq!(cfg.smtp_username, "env-user");
        assert_eq!(cfg.from_email, "env@example.net");
        assert_eq!(cfg.admin_notification_emails, vec!["env-ops@example.net"]);

        // And the provenance says so, per key, without anyone having to read
        // the resolution code to find out.
        assert_eq!(
            stack.resolve("SMTP_HOST"),
            ConfigVerdict::Overridden {
                serving: ConfigProviderKind::Database,
                ignored: vec![ConfigProviderKind::Environment],
            }
        );
        assert_eq!(
            stack.resolve("SMTP_PORT"),
            ConfigVerdict::Shadowed {
                serving: ConfigProviderKind::Environment,
                absent_from: ConfigProviderKind::Database,
                ignored: vec![],
            }
        );
        assert_eq!(stack.resolve("SMTP_TLS"), ConfigVerdict::Default);
    }

    #[test]
    fn email_database_provider_ignores_an_out_of_range_port() {
        let _env = env_lock();
        clear_email_env();

        // A negative or >u16 port cannot narrow to u16, so the env default port
        // (465 for the default implicit TLS) is kept rather than wrapping.
        let mut row = email_row();
        row.smtp_port = Some(-1);
        let db = EmailConfig::database_provider(&row).expect("no Group-1 key in the email row");
        assert!(
            db.is_empty(),
            "an unusable port is not held, so it cannot serve"
        );
        let cfg = EmailConfig::resolve(&db_over_env(db), None, false);
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
    fn auto_ban_database_provider_falls_back_to_env_when_all_null() {
        let _env = env_lock();
        clear_auto_ban_env();

        let row = auto_ban_row(None, None, None, None);
        let db =
            AutoBanConfig::database_provider(&row).expect("no Group-1 key in the auto-ban row");
        assert!(db.is_empty(), "an all-NULL row holds nothing");

        let cfg = AutoBanConfig::resolve(&db_over_env(db));
        // Documented env defaults.
        assert!(cfg.enabled);
        assert_eq!(cfg.threshold, 5);
        assert_eq!(cfg.window_secs, 3600);
        assert_eq!(cfg.ban_duration_secs, 86400);
    }

    #[test]
    fn auto_ban_database_provider_applies_overrides() {
        let _env = env_lock();
        clear_auto_ban_env();

        let row = auto_ban_row(Some(false), Some(10), Some(120), Some(600));
        let db =
            AutoBanConfig::database_provider(&row).expect("no Group-1 key in the auto-ban row");
        assert!(!db.is_empty());

        let cfg = AutoBanConfig::resolve(&db_over_env(db));
        assert!(!cfg.enabled);
        assert_eq!(cfg.threshold, 10);
        assert_eq!(cfg.window_secs, 120);
        assert_eq!(cfg.ban_duration_secs, 600);
    }

    #[test]
    fn auto_ban_database_provider_ignores_out_of_range_values() {
        let _env = env_lock();
        clear_auto_ban_env();

        // A negative BIGINT cannot narrow to the unsigned in-memory widths, so
        // the env default is kept rather than wrapping to a huge value.
        let row = auto_ban_row(None, Some(-1), Some(-5), Some(-9));
        let db =
            AutoBanConfig::database_provider(&row).expect("no Group-1 key in the auto-ban row");
        // An unusable value is not held, so it cannot serve and the next
        // provider (here the environment default) answers.
        assert!(db.is_empty());

        let cfg = AutoBanConfig::resolve(&db_over_env(db));
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
        redirect_sys_config_to_temp();
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
        redirect_sys_config_to_temp();
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        env::set_var("ENVIRONMENT", "development");
        env::set_var("SECRETS_STORAGE", "database");
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
