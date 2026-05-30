//! Server configuration from the environment. Unlike the old WASM build (which
//! read `window.__RUNTIME_CONFIG__`), this is a normal server process, so plain
//! env vars are the source of truth.

#[derive(Debug, Clone)]
pub struct Config {
    /// Address the server binds to (e.g. `0.0.0.0:4400`).
    pub bind_addr: String,
    /// Base URL of the separate bunyip-api service, WITHOUT the trailing `/v1`
    /// (e.g. `http://localhost:4401` in dev, `https://api.example.com` in prod).
    /// This same origin is bunyip's OWN OIDC issuer (it serves
    /// `/.well-known/*` + `/oauth2/*` alongside the `/v1` API).
    pub api_url: String,
    /// OIDC issuer the BFF trusts. Defaults to `api_url` (bunyip-api is the
    /// issuer); override with `BUNYIP_OIDC_ISSUER` only if the issuer origin
    /// differs from the API origin.
    pub oidc_issuer: String,
    /// Apex domain child apps live under (e.g. `example.com`).
    pub app_domain: String,
    /// Show the business pricing tier on the pricing page.
    pub show_business_pricing: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let api_url = var("BUNYIP_API_URL").unwrap_or_else(|| "http://localhost:4401".into());
        Config {
            bind_addr: var("BUNYIP_BIND_ADDR").unwrap_or_else(|| "0.0.0.0:4400".into()),
            // The OIDC issuer is bunyip-api's own origin by default.
            oidc_issuer: var("BUNYIP_OIDC_ISSUER").unwrap_or_else(|| api_url.clone()),
            api_url,
            app_domain: var("BUNYIP_APP_DOMAIN").unwrap_or_default(),
            show_business_pricing: var("BUNYIP_SHOW_BUSINESS_PRICING")
                .map(|v| v == "true")
                .unwrap_or(false),
        }
    }

    /// Apex domain or `localhost` fallback (used for app launch URLs + legal copy).
    pub fn domain_or_localhost(&self) -> String {
        if self.app_domain.is_empty() {
            "localhost".into()
        } else {
            self.app_domain.clone()
        }
    }
}
