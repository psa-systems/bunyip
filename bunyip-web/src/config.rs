//! Server configuration from the environment. Unlike the old WASM build (which
//! read `window.__RUNTIME_CONFIG__`), this is a normal server process, so plain
//! env vars are the source of truth.

// BUNYIP-560: the compiled-in `#2f4e2e` / `#161a16` pair is gone. The palette
// is a field of the admin-managed branding record; `BRAND_THEME_COLOR_LIGHT` /
// `_DARK` below are bootstrap defaults for a database that has never been
// branded, and with neither set the `theme-color` meta is OMITTED rather than
// painting every deployment's browser chrome one product's green.

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
    /// BUNYIP-500: optional theme override. Raw CSS custom-property
    /// declarations (e.g. `--skin-primary-500: #123456; ...`) emitted into a
    /// `:root { ... }` block in the document head, overriding the default brand
    /// ramp the `@theme` tokens fall back to. `BRAND_THEME_CSS`; `None`
    /// (default) emits nothing, so the default palette is unchanged.
    ///
    /// BUNYIP-560: this is a BOOTSTRAP DEFAULT only. The palette is a field of
    /// the admin-managed branding record, which wins whenever it is set; the
    /// variable answers solely for a database that has never been branded and
    /// is removed in 0.16.0 (BUNYIP-568; `docs/configuration.md`).
    pub theme_css: Option<String>,
    /// BUNYIP-549: the `<meta name="theme-color">` value for the light scheme
    /// (the browser chrome: Android address bar, iOS status bar, PWA splash).
    /// `BRAND_THEME_COLOR_LIGHT`.
    ///
    /// BUNYIP-560: bootstrap default only, like [`Config::theme_css`], and
    /// removed with it. `None` and an empty record field mean the meta is
    /// omitted; no colour is compiled in.
    pub theme_color_light: Option<String>,
    /// BUNYIP-549: the dark-scheme twin of [`Config::theme_color_light`].
    /// `BRAND_THEME_COLOR_DARK`.
    pub theme_color_dark: Option<String>,
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
            theme_css: var("BRAND_THEME_CSS"),
            theme_color_light: var("BRAND_THEME_COLOR_LIGHT"),
            theme_color_dark: var("BRAND_THEME_COLOR_DARK"),
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
}
