use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid bind address `{0}`: {1}")]
    InvalidBindAddr(String, std::net::AddrParseError),
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
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr_str =
            std::env::var("BUNYIP_API_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let bind_addr = bind_addr_str
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::InvalidBindAddr(bind_addr_str.clone(), e))?;

        Ok(Self {
            bind_addr,
            public_base_url: std::env::var("BUNYIP_PUBLIC_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:4400".to_string()),
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
        })
    }
}
