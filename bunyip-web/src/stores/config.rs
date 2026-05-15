//! Runtime-resolved OIDC config.
//!
//! The SPA derives its API base and issuer URL from `window.location.host`
//! at runtime so a single WASM build serves every environment (staging,
//! prod, future deployments). The build-time `option_env!` values still
//! work as fallbacks - useful for local `dx serve` against a remote
//! mokosh-server.
//!
//! Resolution order per field:
//!
//! - **`issuer`**: derived as `https://msp-api.<window.location.host>`
//!   when the SPA is served from a non-localhost origin, else falls
//!   back to `option_env!("BUNYIP_OIDC_ISSUER")`. The convention
//!   matches docker repo PR #48: bunyip-web sits at the apex
//!   (`a8n.systems` / `psa.systems`) and mokosh-api at `msp-api.<apex>`.
//!
//! - **`client_id`**: `option_env!("BUNYIP_OIDC_CLIENT_ID")` only.
//!   Operators must register the SAME client_id UUID in every
//!   mokosh-server instance (staging + prod) so one image talks to
//!   both. (A future runtime-injected JS global `window.__BUNYIP_CONFIG__`
//!   could override this; the hook is intentionally left open.)
//!
//! - **`redirect_uri`**: `<window.location.origin>/auth/callback`
//!   when the page is loaded in a browser; else falls back to the
//!   `option_env!` value (rarely matters, since this code only runs in
//!   the browser).
//!
//! - **`scopes`**: `option_env!("BUNYIP_OIDC_SCOPES")` else
//!   `openid email offline_access`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: String,
}

/// `true` for hosts where we want to use the build-time env-baked
/// issuer rather than deriving `msp-api.<host>`. Covers `dx serve`,
/// docker-compose dev, and direct-IP testing.
fn is_local_host(host: &str) -> bool {
    let bare = host.split(':').next().unwrap_or(host);
    matches!(bare, "localhost" | "127.0.0.1" | "::1" | "0.0.0.0")
        || bare.starts_with("192.168.")
        || bare.starts_with("10.")
        || bare.starts_with("172.")
}

/// Browser host + scheme. None when called outside a browser (tests).
fn window_host_and_scheme() -> Option<(String, String)> {
    let win = web_sys::window()?;
    let loc = win.location();
    let host = loc.host().ok().filter(|s| !s.is_empty())?;
    let scheme = loc.protocol().ok().unwrap_or_else(|| "https:".into());
    Some((host, scheme))
}

impl OidcConfig {
    /// Build the config by combining browser-runtime values (host +
    /// origin) with build-time `option_env!` fallbacks. Cheap; safe to
    /// call from any component. Cache at the call site if you care.
    pub fn from_env() -> Self {
        let env_issuer = option_env!("BUNYIP_OIDC_ISSUER").unwrap_or("").to_string();
        let env_redirect = option_env!("BUNYIP_OIDC_REDIRECT_URI")
            .unwrap_or("")
            .to_string();

        let (browser_issuer, browser_redirect) = match window_host_and_scheme() {
            Some((host, scheme)) => {
                if is_local_host(&host) {
                    // Local dev: env-baked issuer points at the
                    // dev mokosh-server (typically https://${USER}-mokosh-api.a8n.run).
                    (None, None)
                } else {
                    // Production: derive issuer + redirect from host.
                    let issuer = format!("{scheme}//msp-api.{host}");
                    let origin = format!("{scheme}//{host}");
                    let redirect = format!("{origin}/auth/callback");
                    (Some(issuer), Some(redirect))
                }
            }
            None => (None, None),
        };

        Self {
            issuer: browser_issuer.unwrap_or(env_issuer),
            client_id: option_env!("BUNYIP_OIDC_CLIENT_ID")
                .unwrap_or("")
                .to_string(),
            redirect_uri: browser_redirect.unwrap_or(env_redirect),
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

    /// Resolve the redirect_uri. Returns the configured value if
    /// non-empty; otherwise re-derives `<origin>/auth/callback` from
    /// `window.location.origin` as a last resort.
    pub fn resolve_redirect_uri(&self) -> Result<String, &'static str> {
        if !self.redirect_uri.is_empty() {
            return Ok(self.redirect_uri.clone());
        }
        let win = web_sys::window().ok_or("no window")?;
        let origin = win.location().origin().map_err(|_| "no origin")?;
        Ok(format!("{origin}/auth/callback"))
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

    #[test]
    fn local_host_detection() {
        assert!(is_local_host("localhost"));
        assert!(is_local_host("localhost:4400"));
        assert!(is_local_host("127.0.0.1:8080"));
        assert!(is_local_host("192.168.1.5"));
        assert!(!is_local_host("a8n.systems"));
        assert!(!is_local_host("psa.systems"));
        assert!(!is_local_host("a contributor-bunyip.a8n.run"));
    }
}
