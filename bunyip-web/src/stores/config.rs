//! Runtime-resolved OIDC config.
//!
//! The SPA loads its OIDC client config from a same-origin `/config.json`
//! at boot (see [`OidcConfig::load`]). One WASM build therefore serves
//! every environment (staging, prod, future deployments): the container
//! generates `/config.json` from `BUNYIP_OIDC_*` environment variables at
//! startup (`bunyip-web/oci-build/entrypoint.sh`) and Caddy serves it with
//! `Cache-Control: no-store`, so changing the env and restarting the
//! container changes the SPA's effective config with no rebuild.
//!
//! `/config.json` shape (all fields optional; missing values fall back as
//! described below):
//!
//! ```json
//! {
//!   "issuer": "https://msp-api.example.com",
//!   "client_id": "00000000-0000-0000-0000-000000000000",
//!   "redirect_uri": "https://example.com/auth/callback",
//!   "scopes": "openid email offline_access"
//! }
//! ```
//!
//! Resolution order per field (applied once at load time):
//!
//! - **`issuer`**: the `/config.json` value when non-empty; otherwise
//!   derived from `window.location.host` (`msp-api.<host>` at an apex,
//!   `<user>-mokosh-api.<rest>` for `<user>-bunyip.<rest>` dev hosts);
//!   otherwise empty.
//!
//! - **`client_id`**: the `/config.json` value verbatim. There is no
//!   runtime fallback (operators register the SAME client_id UUID in every
//!   mokosh-server instance).
//!
//! - **`redirect_uri`**: the `/config.json` value when non-empty; otherwise
//!   derived as `<window.location.origin>/auth/callback`. When still empty,
//!   [`OidcConfig::resolve_redirect_uri`] re-derives it from the live
//!   `window.location.origin` as a last resort.
//!
//! - **`scopes`**: the `/config.json` value when non-empty; otherwise
//!   `openid email offline_access`.

use std::sync::OnceLock;

use serde::Deserialize;

const DEFAULT_SCOPES: &str = "openid email offline_access";

/// Wire shape of `/config.json`. Every field is optional so a partial or
/// missing file degrades to host-derivation rather than failing the boot.
#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    scopes: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: String,
}

/// Config resolved once by [`OidcConfig::load`] at boot, then read
/// synchronously by [`OidcConfig::from_env`]. WASM is single-threaded, so
/// the `OnceLock` is only ever written once before any auth UI mounts.
static RUNTIME_CONFIG: OnceLock<OidcConfig> = OnceLock::new();

/// `true` for hosts where the build-derived issuer should NOT be guessed
/// from `msp-api.<host>`. Covers `dx serve`, docker-compose dev, and
/// direct-IP testing.
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

/// Derive the mokosh-api host from the bunyip-web host. Two patterns
/// are supported:
///
/// 1. **Dev** (`<user>-bunyip.<rest>`): rewrite the first label to
///    `<user>-mokosh-api`. So `a contributor-bunyip.a8n.run` ->
///    `a contributor-mokosh-api.a8n.run`. Used by per-user dev environments
///    on a8n.run.
///
/// 2. **Apex** (everything else): return the host unchanged so the API
///    base is same-origin. So `a8n.systems` -> `a8n.systems`,
///    `psa.systems` -> `psa.systems`. The apex c-01 deployment
///    co-locates bunyip-api and bunyip-web behind the same hostname
///    (replacing the old cross-origin `msp-api.<tld>` topology), so the
///    SPA reaches the API at the same origin it was loaded from.
fn derive_api_host(host: &str) -> String {
    if let Some((first, rest)) = host.split_once('.') {
        if let Some(user) = first.strip_suffix("-bunyip") {
            return format!("{user}-mokosh-api.{rest}");
        }
    }
    host.to_string()
}

/// Fetch and parse the same-origin `/config.json`. Returns `None` on any
/// network error, non-2xx status, or malformed body so the caller can fall
/// back to host-derivation.
async fn fetch_config() -> Option<RawConfig> {
    let resp = gloo_net::http::Request::get("/config.json")
        .send()
        .await
        .ok()?;
    if !resp.ok() {
        return None;
    }
    resp.json::<RawConfig>().await.ok()
}

impl OidcConfig {
    /// Fetch `/config.json` once and cache the resolved config. Idempotent:
    /// later calls are no-ops. Always populates [`RUNTIME_CONFIG`] (even
    /// when the fetch fails) so [`from_env`](Self::from_env) never observes
    /// an unset value once `load` has returned. Call this once at app boot,
    /// before any auth-dependent UI renders.
    pub async fn load() {
        if RUNTIME_CONFIG.get().is_some() {
            return;
        }
        let raw = fetch_config().await.unwrap_or_default();
        let _ = RUNTIME_CONFIG.set(Self::resolve(raw));
    }

    /// Combine the `/config.json` values with browser-runtime host
    /// derivation. `/config.json` always wins when it supplies a value so
    /// operators can override the host-derived defaults via env.
    fn resolve(raw: RawConfig) -> Self {
        let (derived_issuer, derived_redirect) = match window_host_and_scheme() {
            Some((host, scheme)) if !is_local_host(&host) => {
                let api_host = derive_api_host(&host);
                (
                    Some(format!("{scheme}//{api_host}")),
                    Some(format!("{scheme}//{host}/auth/callback")),
                )
            }
            _ => (None, None),
        };

        let issuer = if raw.issuer.is_empty() {
            derived_issuer.unwrap_or_default()
        } else {
            raw.issuer
        };
        let redirect_uri = if raw.redirect_uri.is_empty() {
            derived_redirect.unwrap_or_default()
        } else {
            raw.redirect_uri
        };
        let scopes = if raw.scopes.is_empty() {
            DEFAULT_SCOPES.to_string()
        } else {
            raw.scopes
        };

        Self {
            issuer,
            client_id: raw.client_id,
            redirect_uri,
            scopes,
        }
    }

    /// Synchronous accessor for the config loaded by [`load`](Self::load).
    /// Cheap; safe to call from any component. Before `load` completes (and
    /// in non-browser tests) it returns a host-derived fallback with the
    /// default scopes so callers never panic or see a half-initialised
    /// value; gating the auth UI behind `load` (see `main.rs`) keeps the
    /// pre-load fallback off the auth path in practice.
    pub fn from_env() -> Self {
        RUNTIME_CONFIG
            .get()
            .cloned()
            .unwrap_or_else(|| Self::resolve(RawConfig::default()))
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
    fn scopes_default_when_absent() {
        // An empty/absent /config.json yields the default scopes.
        let cfg = OidcConfig::resolve(RawConfig::default());
        assert_eq!(cfg.scopes, DEFAULT_SCOPES);
    }

    #[test]
    fn config_values_win_over_derivation() {
        let raw = RawConfig {
            issuer: "https://issuer.example".into(),
            client_id: "client-123".into(),
            redirect_uri: "https://app.example/auth/callback".into(),
            scopes: "openid".into(),
        };
        let cfg = OidcConfig::resolve(raw);
        assert_eq!(cfg.issuer, "https://issuer.example");
        assert_eq!(cfg.client_id, "client-123");
        assert_eq!(cfg.redirect_uri, "https://app.example/auth/callback");
        assert_eq!(cfg.scopes, "openid");
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

    #[test]
    fn api_host_derivation() {
        // Apex: bunyip-api co-resident with bunyip-web -> same-origin host.
        assert_eq!(derive_api_host("a8n.systems"), "a8n.systems");
        assert_eq!(derive_api_host("psa.systems"), "psa.systems");
        // Dev: <user>-bunyip.<rest> -> <user>-mokosh-api.<rest>.
        assert_eq!(
            derive_api_host("a contributor-bunyip.a8n.run"),
            "a contributor-mokosh-api.a8n.run"
        );
        assert_eq!(
            derive_api_host("alice-bunyip.example.com"),
            "alice-mokosh-api.example.com"
        );
        // Subdomain without `-bunyip` suffix falls back to same-origin.
        assert_eq!(derive_api_host("app.psa.systems"), "app.psa.systems");
    }
}
