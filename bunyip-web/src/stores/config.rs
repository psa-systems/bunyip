//! Compile-time OIDC config baked into the wasm bundle via `option_env!`.
//!
//! Reads:
//! - `BUNYIP_OIDC_ISSUER` (REQUIRED) - URL of the mokosh-server IdP.
//! - `BUNYIP_OIDC_CLIENT_ID` (REQUIRED) - UUID of the OAuth client row
//!   registered for bunyip-web in `mokosh_auth.oauth_clients`.
//! - `BUNYIP_OIDC_REDIRECT_URI` (REQUIRED) - the post-OIDC-callback URL.
//! - `BUNYIP_OIDC_SCOPES` (optional) - defaults to
//!   `openid email offline_access`.
//!
//! "REQUIRED" here means missing at build time -> `OidcConfig::from_env()`
//! returns the placeholder; the SPA's API calls 401/404 and the user
//! sees a sane error. Set them in `bunyip/.env` and `compose.dev.yml`'s
//! `web.environment:` block before `dx build`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: String,
}

impl OidcConfig {
    pub fn from_env() -> Self {
        Self {
            issuer: option_env!("BUNYIP_OIDC_ISSUER")
                .unwrap_or("")
                .to_string(),
            client_id: option_env!("BUNYIP_OIDC_CLIENT_ID")
                .unwrap_or("")
                .to_string(),
            redirect_uri: option_env!("BUNYIP_OIDC_REDIRECT_URI")
                .unwrap_or("")
                .to_string(),
            scopes: option_env!("BUNYIP_OIDC_SCOPES")
                .unwrap_or("openid email offline_access")
                .to_string(),
        }
    }

    /// Trim trailing `/` so callers can `format!("{issuer}{path}")`
    /// without worrying about doubled slashes.
    pub fn issuer_trimmed(&self) -> &str {
        self.issuer.trim_end_matches('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_present() {
        let cfg = OidcConfig::from_env();
        // At build time without env, fields are empty strings; the
        // scopes default still applies.
        assert!(!cfg.scopes.is_empty(), "scopes should default");
    }
}
