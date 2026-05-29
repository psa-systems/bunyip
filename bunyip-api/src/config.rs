use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid bind address `{0}`: {1}")]
    InvalidBindAddr(String, std::net::AddrParseError),
    /// A production deployment was started with one or more dev-only mock
    /// auth knobs still active. Refuse to boot rather than ship an
    /// always-pass login / TOTP into prod.
    #[error("refusing to start in production with insecure mock auth enabled: {0}")]
    InsecureMockInProduction(String),
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub public_base_url: String,
    pub seeds_dir: PathBuf,
    pub cookie_secret: String,
    pub mock_password: String,
    pub mock_totp_code: String,
    pub feedback_forgejo_repo: Option<String>,
    /// Endpoint the update checker polls for the latest published release.
    /// Expected to return JSON containing a `tag_name` field (the Forgejo /
    /// Gitea `releases/latest` shape). When unset, update checking is
    /// disabled and `/version` reports `update.enabled = false`.
    pub update_check_url: Option<String>,
    /// Optional bearer token for the update-check endpoint (private repos).
    pub update_check_token: Option<String>,
    /// All origins permitted to make credentialed CORS requests against the
    /// API. Set via the `CORS_ORIGIN` env var as a comma-separated list
    /// (e.g. `https://a8n.tools,https://pugtsurani.net`). Defaults to the
    /// `public_base_url` so local dev works without explicit config. See
    /// docs/cors.md in the docker repo.
    pub cors_origins: Vec<String>,
    /// Deployment environment, read from `ENVIRONMENT` (falling back to
    /// `APP_ENV`). Empty / unset means "not production" (dev). The only
    /// value treated specially is `production`, which arms the mock-auth
    /// startup guard (see `from_env`).
    pub environment: String,
}

impl Config {
    /// True when the deployment self-identifies as production via
    /// `ENVIRONMENT` (or `APP_ENV`) == `production` (case-insensitive).
    pub fn is_production(&self) -> bool {
        self.environment.eq_ignore_ascii_case("production")
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr_str =
            std::env::var("BUNYIP_API_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let bind_addr = bind_addr_str
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::InvalidBindAddr(bind_addr_str.clone(), e))?;

        let public_base_url = std::env::var("BUNYIP_PUBLIC_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:4400".to_string());

        // Deployment environment. `ENVIRONMENT` is the primary key;
        // `APP_ENV` is accepted as a fallback for deploys that already
        // standardised on that name. Default empty == dev.
        let environment = std::env::var("ENVIRONMENT")
            .or_else(|_| std::env::var("APP_ENV"))
            .unwrap_or_default();

        let cors_origins = std::env::var("CORS_ORIGIN")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec![public_base_url.clone()]);

        let config = Self {
            bind_addr,
            public_base_url,
            seeds_dir: PathBuf::from(
                std::env::var("BUNYIP_SEEDS_DIR").unwrap_or_else(|_| "./seeds".to_string()),
            ),
            cookie_secret: std::env::var("COOKIE_SECRET").unwrap_or_else(|_| {
                "dev-only-do-not-use-in-prod-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
            }),
            mock_password: std::env::var("MOCK_PASSWORD").unwrap_or_else(|_| "demo".to_string()),
            mock_totp_code: std::env::var("MOCK_TOTP_CODE")
                .unwrap_or_else(|_| "000000".to_string()),
            feedback_forgejo_repo: std::env::var("FEEDBACK_FORGEJO_REPO")
                .ok()
                .filter(|s| !s.is_empty()),
            update_check_url: std::env::var("BUNYIP_UPDATE_CHECK_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            update_check_token: std::env::var("BUNYIP_UPDATE_CHECK_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            cors_origins,
            environment,
        };

        config.guard_production_mocks()?;
        Ok(config)
    }

    /// Refuse to boot a PRODUCTION deployment while the dev-only mock
    /// auth shortcuts are active. These knobs are intentional and stay
    /// for local development; they must never reach production because
    /// they turn login + TOTP into always-pass paths:
    ///
    /// - `MOCK_PASSWORD` non-empty: `/v1/auth/login` accepts that single
    ///   shared password for every account.
    /// - `MOCK_TOTP_CODE` non-empty AND/OR the unconditional any-6-digit
    ///   acceptance in `routes::auth::is_valid_mock_totp`: any 6-digit
    ///   string satisfies MFA.
    ///
    /// The any-6-digit path is compiled in, not env-gated, so a production
    /// build of this mock backend is inherently insecure. We therefore
    /// treat *being in production at all* as a hard stop and additionally
    /// name the env-driven knobs so the operator sees exactly what to
    /// unset (for the case where this guard is later relaxed to allow a
    /// hardened prod build with all mock knobs cleared).
    fn guard_production_mocks(&self) -> Result<(), ConfigError> {
        if !self.is_production() {
            return Ok(());
        }

        let mut reasons = Vec::new();
        if !self.mock_password.is_empty() {
            reasons.push("MOCK_PASSWORD is set (shared always-pass login password)");
        }
        if !self.mock_totp_code.is_empty() {
            reasons.push("MOCK_TOTP_CODE is set (fixed always-pass MFA code)");
        }
        // The any-6-digit TOTP acceptance lives in
        // routes::auth::is_valid_mock_totp and is NOT env-gated, so it is
        // always active in this binary. Surface it explicitly.
        reasons
            .push("is_valid_mock_totp accepts any 6-digit code (dev-only MFA bypass compiled in)");

        Err(ConfigError::InsecureMockInProduction(reasons.join("; ")))
    }
}
