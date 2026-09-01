//! Server configuration from the environment. Unlike the old WASM build (which
//! read `window.__RUNTIME_CONFIG__`), this is a normal server process, so plain
//! env vars are the source of truth.

// BUNYIP-560/568: the palette is not configuration. The theme CSS and the two
// browser-chrome colours are fields of the admin-managed branding record and
// have no environment variable behind them; an unset field OMITS its markup
// rather than painting every deployment's browser chrome one product's green.

#[derive(Debug, Clone)]
pub struct Config {
    /// Address the server binds to (e.g. `0.0.0.0:4400`).
    pub bind_addr: String,
    /// Base URL of the separate bunyip-api service, WITHOUT the trailing `/v1`
    /// (e.g. `http://localhost:4401` in dev, `https://api.example.com` in prod).
    /// This same origin is bunyip's OWN OIDC issuer (it serves
    /// `/.well-known/*` + `/oauth2/*` alongside the `/v1` API).
    ///
    /// Used by the bunyip-web SERVER PROCESS for outbound HTTP to bunyip-api
    /// (the `reqwest` calls in `crate::api`). On dev this is
    /// `http://localhost:4401`; on dev-sso and prod it's typically the
    /// internal docker hostname `http://bunyip-api-app:4401` so the BFF
    /// reaches the api on the compose network without going back out
    /// through Traefik.
    pub api_url: String,
    /// BUNYIP-192: PUBLIC-facing origin of bunyip-api the BROWSER hits
    /// (HTML JS, EventSource subscriptions, the SSE shell injected into
    /// every authenticated page). Defaults to `api_url` for back-compat
    /// (dev does not need to split them); production overrides via
    /// `BUNYIP_API_PUBLIC_ORIGIN` to the HTTPS public hostname (e.g.
    /// `https://api.a8n.systems`). Without this override the browser is
    /// asked to open an EventSource against the internal docker
    /// hostname which (a) it cannot resolve and (b) is HTTP from an
    /// HTTPS page so the browser blocks it as Mixed Content.
    pub api_public_origin: String,
    /// OIDC issuer the BFF trusts. Defaults to `api_url` (bunyip-api is the
    /// issuer); override with `BUNYIP_OIDC_ISSUER` only if the issuer origin
    /// differs from the API origin.
    pub oidc_issuer: String,
    /// Apex domain child apps live under (e.g. `example.com`).
    pub app_domain: String,
    /// BUNYIP-329: URL of the team Let's Chat ("Community") instance the
    /// authenticated Community button opens. Empty disables the feature (the
    /// button is hidden and `/community` sends the user back to the dashboard),
    /// so a deploy without a Let's Chat instance never shows a dead link.
    /// Let's Chat is already registered as an OIDC client of bunyip-api, so
    /// opening this URL logs the member in via their existing OP session (the
    /// same single-sign-in bridge the app tiles use). Set it to the login-init
    /// path (e.g. `https://chat.a8n.systems/auth/bunyip`) so the OIDC flow
    /// fires immediately rather than landing on Let's Chat's own login page.
    pub community_url: String,
    /// BUNYIP-311: CIDR ranges of the reverse proxies that front bunyip-web
    /// (typically Traefik). The inbound `X-Forwarded-For` / `X-Real-IP` is
    /// honoured (to resolve the end-user IP the BFF forwards to bunyip-api)
    /// ONLY when the immediate socket peer sits inside one of these ranges;
    /// for every other peer the BFF forwards nothing, so a direct client
    /// cannot spoof its IP into bunyip-api's logs. Parsed from
    /// `TRUSTED_PROXY_CIDR` (comma-separated), analogous to bunyip-api's own
    /// `TRUSTED_PROXY_CIDR`. Empty = trust no forwarding headers.
    pub trusted_proxies: Vec<ipnetwork::IpNetwork>,
    // BUNYIP-568: `theme_css`, `theme_color_light` and `theme_color_dark` are
    // gone, along with the three brand-theme variables that fed them. They were
    // the one-release bootstrap defaults BUNYIP-560 left behind when it moved
    // the palette into the admin-managed branding record; the record is now the
    // only source, so a rebrand is one admin edit and no deployment can hold a
    // second palette that silently loses to the row.
    // `scripts/check-no-retired-env.nu` holds the variable names out.
    // BUNYIP-561: `app_name` (`APP_NAME`) and `brand_description`
    // (`BRAND_DESCRIPTION`) are gone. The product name, tagline, meta
    // description and Open Graph image are the admin-managed branding record
    // bunyip-web fetches from `/v1/branding` (see `crate::branding`), so a
    // rebrand is one admin edit rather than an environment change plus a
    // redeploy of both services.
    /// BUNYIP-503: cross-origin hosts a skin appends to the CSP.
    pub csp: CspConfig,
}

/// BUNYIP-503: the CSP hosts a skin adds, so a deploy with different third-party
/// integrations extends the allow-list without forking `security.rs`. Mirrors
/// dunite-core's `CspConfig` shape (the web-edge modules unify on it in B4).
/// Only `connect-src` and `form-action` are extensible; the `script-src 'self'`
/// / `default-src` / `frame-ancestors 'none'` lockdown (BUNYIP-424) is never
/// relaxed by config.
#[derive(Debug, Clone, Default)]
pub struct CspConfig {
    /// Extra origins appended to `connect-src` (a skin's fetch / XHR / SSE hosts).
    pub connect_src: Vec<String>,
    /// Extra origins appended to `form-action` (a skin's cross-origin form posts,
    /// e.g. a payment provider other than Stripe).
    pub form_action: Vec<String>,
}

/// BUNYIP-503: parse a comma-separated CSP host list; blanks are dropped.
fn parse_csp_hosts(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// BUNYIP-311: parse a comma-separated list of CIDR ranges into trusted-proxy
/// networks. Invalid entries are logged and skipped rather than aborting
/// startup, so a single typo cannot take the BFF down; an empty or all-invalid
/// list means no proxy is trusted and inbound forwarding headers are ignored.
/// Mirrors bunyip-api's `parse_trusted_proxies` so both hops of the trust
/// chain parse the CIDR the same way.
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

impl Config {
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let api_url = var("BUNYIP_API_URL").unwrap_or_else(|| "http://localhost:4401".into());
        // BUNYIP-192: the public-facing origin for the browser. Falls
        // back to `api_url` so dev keeps working without configuration
        // (loopback IS the public URL in dev). Production must set
        // `BUNYIP_API_PUBLIC_ORIGIN` to the HTTPS hostname or the SSE
        // subscriber on the dashboard will be blocked by the browser
        // as Mixed Content.
        let api_public_origin = var("BUNYIP_API_PUBLIC_ORIGIN").unwrap_or_else(|| api_url.clone());
        Config {
            bind_addr: var("BUNYIP_BIND_ADDR").unwrap_or_else(|| "0.0.0.0:4400".into()),
            // The OIDC issuer is bunyip-api's own origin by default.
            oidc_issuer: var("BUNYIP_OIDC_ISSUER").unwrap_or_else(|| api_url.clone()),
            api_url,
            api_public_origin,
            app_domain: var("BUNYIP_APP_DOMAIN").unwrap_or_default(),
            community_url: var("BUNYIP_COMMUNITY_URL").unwrap_or_default(),
            // BUNYIP-311: the reverse proxies (Traefik) allowed to set the
            // inbound X-Forwarded-For the BFF trusts when resolving the
            // end-user IP. Same comma-separated CIDR form bunyip-api parses.
            trusted_proxies: parse_trusted_proxies(&var("TRUSTED_PROXY_CIDR").unwrap_or_default()),
            csp: CspConfig {
                connect_src: parse_csp_hosts(&var("CSP_CONNECT_SRC").unwrap_or_default()),
                form_action: parse_csp_hosts(&var("CSP_FORM_ACTION").unwrap_or_default()),
            },
        }
    }

    /// BUNYIP-329: whether the Community (Let's Chat) feature is configured.
    /// Gates the dashboard Community button so it only renders when an
    /// instance URL is set.
    pub fn community_enabled(&self) -> bool {
        !self.community_url.is_empty()
    }

    /// Apex domain or `localhost` fallback (used for app launch URLs + legal copy).
    pub fn domain_or_localhost(&self) -> String {
        if self.app_domain.is_empty() {
            "localhost".into()
        } else {
            self.app_domain.clone()
        }
    }

    /// BUNYIP-255: whether the BFF is serving over HTTPS. Derived from
    /// the configured `api_public_origin`: a production deploy points
    /// the browser at `https://api.<tld>`, dev points at `http://...`.
    /// Used to set the `Secure` attribute on cookies bunyip-web emits
    /// directly (e.g. the `bunyip_2fa` challenge cookie) so the cookie
    /// is HTTPS-only in production but still usable in local dev.
    pub fn use_secure_cookies(&self) -> bool {
        self.api_public_origin.starts_with("https://")
    }

    /// Absolute URL of the committed share image, for the Open Graph tags when
    /// the branding record carries no uploaded one. `None` when no app domain
    /// is configured: a relative path is not resolvable by every scraper, and
    /// a wrong absolute one is worse than an omitted tag.
    pub fn default_share_image(&self) -> Option<String> {
        if self.app_domain.is_empty() {
            return None;
        }
        let scheme = if self.use_secure_cookies() {
            "https"
        } else {
            "http"
        };
        Some(format!(
            "{scheme}://{}{}",
            self.app_domain,
            web_kit::shell::asset(DEFAULT_SHARE_IMAGE_PATH)
        ))
    }
}

/// The committed share image every deployment falls back to. Product identity
/// ships with the product: a deployment that uploads nothing still has one.
pub const DEFAULT_SHARE_IMAGE_PATH: &str = "/assets/bunyip-hero-718.webp";
