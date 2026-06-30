//! OIDC / OAuth 2.0 Authorization Server handlers.
//!
//! Implements:
//!   GET  /.well-known/openid-configuration   — OIDC Discovery
//!   GET  /.well-known/jwks.json              — JWKS
//!   GET  /oauth2/authorize                   — Authorization endpoint
//!   POST /oauth2/token                       — Token endpoint
//!   GET  /oauth2/userinfo                    — Userinfo endpoint
//!   POST /oauth2/revoke                      — Revocation endpoint (RFC 7009)
//!   GET  /oauth2/logout                      — RP-Initiated Logout

use actix_web::{web, HttpRequest, HttpResponse};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio;
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::auth::OptionalUser;
use crate::repositories::UserRepository;
use crate::services::oidc_provider::{sha256_bytes, OAuthClient, OidcProvider};

/// Unwrap `Option<Arc<OidcProvider>>` from `web::Data`, returning 404 when absent.
/// Yields `&OidcProvider`.
macro_rules! require_provider {
    ($opt:expr) => {
        match $opt.as_ref().as_ref() {
            // p: &Arc<OidcProvider>; &**p: &OidcProvider
            Some(p) => &**p,
            None => return Ok(HttpResponse::NotFound().finish()),
        }
    };
    // variant for handlers that return HttpResponse directly (not Result)
    ($opt:expr, plain) => {
        match $opt.as_ref().as_ref() {
            Some(p) => &**p,
            None => return HttpResponse::NotFound().finish(),
        }
    };
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn oidc_error(error: &str, description: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({
        "error": error,
        "error_description": description,
    }))
}

/// HTML-escape `s` for safe embedding in attribute values and text
/// nodes. Bunyip does not pull in a template engine for the OIDC
/// pages, so this hand-rolled escaper is what stops a forged client
/// `name` or a forged `redirect_uri` from injecting markup into the
/// picker page (BUNYIP-62). Covers the five characters that matter
/// for both attribute (`"`, `'`) and content (`<`, `>`, `&`) contexts.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Render the tenant picker for the multi-tenant `/authorize` branch
/// (BUNYIP-62). Returns an HTML page with one radio per assignment;
/// the form re-submits to `/oauth2/authorize` (GET) with every
/// original `AuthorizeQuery` field preserved as a hidden input plus
/// the chosen `selected_tenant_id`. The handler then re-enters its
/// multi-tenant branch, validates the pick is one of the user's
/// assignments, and proceeds to mint the auth code.
///
/// `silent_cookies` are forwarded so a Set-Cookie that the silent-SSO
/// branch emitted (rotated access + refresh + op_session) is preserved
/// across the picker round-trip; without this the user would lose
/// their newly-minted session if they happened to land in the picker
/// branch on first hit.
fn render_tenant_picker(
    q: &AuthorizeQuery,
    client: &crate::services::OAuthClient,
    assignments: &[bunyip_domain::models::OAuthClientUserTenant],
    silent_cookies: &[actix_web::cookie::Cookie<'static>],
) -> HttpResponse {
    let mut body = String::new();
    body.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    body.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    body.push_str("<title>Choose a tenant</title>");
    body.push_str("<style>");
    body.push_str("body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#0f172a;}");
    body.push_str("h1{font-size:1.5rem;margin-bottom:0.25rem;}");
    body.push_str("p{color:#475569;line-height:1.5;}");
    body.push_str("form{margin-top:2rem;display:flex;flex-direction:column;gap:0.75rem;}");
    body.push_str("label.choice{display:flex;align-items:center;gap:0.5rem;padding:0.75rem 1rem;border:1px solid #e2e8f0;border-radius:0.5rem;cursor:pointer;}");
    body.push_str("label.choice:hover{border-color:#94a3b8;}");
    body.push_str("button{margin-top:1rem;padding:0.6rem 1rem;border:0;border-radius:0.5rem;background:#0f172a;color:#fff;font-weight:600;cursor:pointer;}");
    body.push_str(
        ".tenant-id{color:#94a3b8;font-size:0.75rem;font-family:ui-monospace,monospace;}",
    );
    body.push_str("</style></head><body>");
    body.push_str(&format!(
        "<h1>Choose a tenant for {}</h1>",
        html_escape(&client.name)
    ));
    body.push_str(
        "<p>You belong to more than one tenant on this app. Pick the one to sign in to. \
         You can switch tenants later by signing in again.</p>",
    );
    body.push_str("<form method=\"GET\" action=\"/oauth2/authorize\">");
    // Preserve every original AuthorizeQuery field as a hidden input
    // so the handler re-runs with the same context after the user picks.
    let hidden = [
        ("response_type", q.response_type.as_str()),
        ("client_id", q.client_id.as_str()),
        ("redirect_uri", q.redirect_uri.as_str()),
        ("scope", q.scope.as_str()),
        ("state", q.state.as_str()),
        ("nonce", q.nonce.as_str()),
        ("code_challenge", q.code_challenge.as_str()),
        ("code_challenge_method", q.code_challenge_method.as_str()),
    ];
    for (k, v) in hidden {
        body.push_str(&format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            k,
            html_escape(v)
        ));
    }
    if let Some(p) = q.prompt.as_deref() {
        body.push_str(&format!(
            "<input type=\"hidden\" name=\"prompt\" value=\"{}\">",
            html_escape(p)
        ));
    }
    for (i, a) in assignments.iter().enumerate() {
        let role = a.role.as_deref().unwrap_or("");
        let role_suffix = if role.is_empty() {
            String::new()
        } else {
            format!(" - {}", html_escape(role))
        };
        body.push_str(&format!(
            "<label class=\"choice\"><input type=\"radio\" name=\"selected_tenant_id\" value=\"{}\"{}><span>Tenant{}</span> <span class=\"tenant-id\">{}</span></label>",
            a.tenant_id,
            if i == 0 { " checked" } else { "" },
            role_suffix,
            a.tenant_id,
        ));
    }
    body.push_str("<button type=\"submit\">Continue</button>");
    body.push_str("</form></body></html>");

    let mut response = HttpResponse::Ok();
    response.content_type("text/html; charset=utf-8");
    for cookie in silent_cookies {
        response.cookie(cookie.clone());
    }
    response.body(body)
}

// ── Discovery ─────────────────────────────────────────────────────────────────

/// GET /.well-known/openid-configuration
pub async fn discovery(provider: web::Data<Option<Arc<OidcProvider>>>) -> HttpResponse {
    let provider = require_provider!(provider, plain);
    let issuer = match provider.config.issuer.as_deref() {
        Some(i) if !i.is_empty() => i.to_string(),
        _ => return HttpResponse::NotFound().finish(),
    };

    let doc = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "userinfo_endpoint": format!("{issuer}/oauth2/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "revocation_endpoint": format!("{issuer}/oauth2/revoke"),
        "end_session_endpoint": format!("{issuer}/oauth2/logout"),
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic", "none"
        ],
        "scopes_supported": [
            "openid", "email", "offline_access",
            "dmarc:read", "dmarc:write"
        ],
        "claims_supported": [
            "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "azp",
            "email", "email_verified", "membership_status", "has_member_access",
            "bunyip_role"
        ],
        "code_challenge_methods_supported": ["S256"],
        "require_pkce": true,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
    });

    HttpResponse::Ok()
        .content_type("application/json")
        .append_header(("Cache-Control", "public, max-age=300"))
        .json(doc)
}

// ── JWKS ──────────────────────────────────────────────────────────────────────

/// GET /.well-known/jwks.json
pub async fn jwks(provider: web::Data<Option<Arc<OidcProvider>>>) -> HttpResponse {
    let provider = require_provider!(provider, plain);

    HttpResponse::Ok()
        .content_type("application/json")
        .append_header(("Cache-Control", "public, max-age=300"))
        .json(&provider.keys.jwks)
}

// ── Authorization endpoint ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[serde(default)]
    pub prompt: Option<String>,
    /// BUNYIP-62: when the resolved client gates on
    /// `oauth_client_user_tenants` AND the user has more than one
    /// assignment, the picker page submits the chosen tenant as
    /// `selected_tenant_id` and the handler re-runs with this set.
    /// Validated against the user's assignments before use.
    #[serde(default)]
    pub selected_tenant_id: Option<Uuid>,
}

/// GET /oauth2/authorize
///
/// If no SaaS session exists, redirects to the SaaS login page with the full
/// authorize URL as `?redirect=` so the user is sent back after authenticating.
/// On success, redirects to the client's redirect_uri with code and state.
pub async fn authorize(
    req: HttpRequest,
    provider: web::Data<Option<Arc<OidcProvider>>>,
    query: web::Query<AuthorizeQuery>,
    config: web::Data<crate::config::Config>,
    auth_service: web::Data<Arc<crate::services::AuthService>>,
) -> Result<HttpResponse, AppError> {
    let provider = require_provider!(provider);

    // BUNYIP-264: per-IP rate limit before any DB / discovery work.
    let ip_key = crate::middleware::auth::extract_client_ip(&req)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into());
    crate::repositories::RateLimitRepository::check_rate_limit(
        &provider.pool,
        &ip_key,
        &crate::models::RateLimitConfig::OAUTH_AUTHORIZE,
    )
    .await?;

    // JwtService is registered in main.rs as a bare `Arc<JwtService>`
    // via `.app_data(jwt_service.clone())` (not wrapped in
    // `web::Data::new(...)`), so the `web::Data<Arc<JwtService>>`
    // extractor would 500 with "Requested application data is not
    // configured correctly" if used as a handler param. Match the
    // existing middleware pattern (`crates/bunyip-domain/src/middleware/auth.rs:160`)
    // and read it out of `app_data` directly.
    let jwt_service = req
        .app_data::<Arc<crate::services::JwtService>>()
        .cloned()
        .ok_or_else(|| AppError::internal("JwtService not configured"))?;

    // Authentication is gated on a server-validated OP session, NOT on the
    // stateless hub access_token. logout revokes the op_sessions row, so a
    // surviving/replayed access_token cookie can no longer mint a code.
    let op_session_cookie = req.cookie(crate::middleware::auth::AuthCookies::OP_SESSION_COOKIE);
    let op_session = match &op_session_cookie {
        Some(c) => provider.load_op_session(c.value()).await?,
        None => None,
    };
    // When `op_session` is missing we get one more silent-SSO chance before
    // bouncing the user to /login. `try_silent_sso` walks two fallbacks in
    // order:
    //   1. Hub `access_token` cookie still valid (HS256, 15-min Max-Age) -
    //      verify and mint an op_session directly. Covers users who were
    //      just in bunyip-web (Bunyip launcher click path).
    //   2. Access token gone, `refresh_token` cookie (30 days) still valid -
    //      run the same rotation `/v1/auth/refresh` does, set the rotated
    //      access + refresh cookies on the response, mint op_session. Covers
    //      DMARC-21 cleanly: a returning user whose browser auto-expired the
    //      15-min access_token but still has a live refresh_token gets
    //      silent SSO without ever seeing the bunyip login form.
    //
    // The helper returns `Some((session, cookies))` where `cookies` carries
    // every Set-Cookie the response needs to apply (op_session always, plus
    // rotated access + refresh + clear_stale on the refresh path). Falls
    // back to the existing /login redirect when no cookie input lets us
    // recover identity (logged-out user, browser cleared cookies, etc.).
    //
    // Security posture is identical to `/v1/auth/login -> create_op_session`
    // and `/v1/auth/refresh -> rotate`. Logout clears all three cookies via
    // AuthCookies::clear and revokes the op_session row + the refresh_token
    // family synchronously, so a logged-out user has nothing the silent path
    // can consume. Family-reuse detection on `refresh_tokens()` still fires.
    let silent_cookies: Vec<actix_web::cookie::Cookie<'static>>;
    let session = match op_session {
        Some(s) => {
            silent_cookies = Vec::new();
            s
        }
        None => match try_silent_sso(&req, provider, &jwt_service, &auth_service, &config).await? {
            Some((s, cookies)) => {
                silent_cookies = cookies;
                s
            }
            None => {
                let authorize_url = format!("{}{}", provider.issuer(), req.uri());
                // Distinguish the two failure modes: "no cookie at all" (first
                // visit, freshly logged out, browser expired the 7-day MaxAge)
                // vs. "cookie present but DB row gone" (user logged out
                // elsewhere, op_sessions cleanup ran, sid was forged). The
                // second case is the one that needs the cookie cleared:
                // without that, every subsequent request keeps sending the
                // stale sid and runs through this same branch indefinitely.
                let stale_cookie_present = op_session_cookie.is_some();
                tracing::info!(
                    client_id = %query.0.client_id,
                    redirect_uri = %query.0.redirect_uri,
                    has_op_session_cookie = stale_cookie_present,
                    has_access_token = req.cookie("access_token").is_some(),
                    "authorize: no active OP session, redirecting to login{}",
                    if stale_cookie_present { " (and clearing stale op_session cookie)" } else { "" },
                );
                // Use web_origin (single absolute URL of bunyip-web) rather than
                // cors_origin (which is now a comma-list once multiple RPs are
                // registered; concatenating that onto `/login` produces garbage).
                let login_url = format!(
                    "{}/login?redirect={}&checked=1",
                    config.web_origin.trim_end_matches('/'),
                    urlencoding::encode(&authorize_url),
                );
                let mut response = HttpResponse::Found();
                response.insert_header(("Location", login_url));
                // Aggressively clear a stale op_session cookie so the next
                // request lands on the clean "no cookie" branch instead of
                // repeating "load_op_session -> None -> redirect" forever.
                // Both `access_token` and `refresh_token` cookies are left
                // intact: they may still authenticate the hub session, and
                // `/login` needs them to know who the user is when offering
                // the re-login form.
                if stale_cookie_present {
                    let secure = config.is_production();
                    // BUNYIP-266: clear at the configured cookie_domain so a
                    // stale domain-scoped sid from a pre-host-only deploy is
                    // also removed; `clear_op_session_only` already emits a
                    // no-domain clear in parallel. We hand it the underlying
                    // `cookie_domain` (not the host-only-helper) so the clear
                    // covers the worst-case stale cookie shape regardless of
                    // the current `BUNYIP_COOKIE_SHARED_DOMAIN` setting.
                    let cookie_domain = config.cookie_domain.as_deref();
                    for clear_cookie in crate::middleware::auth::AuthCookies::clear_op_session_only(
                        secure,
                        cookie_domain,
                    ) {
                        response.cookie(clear_cookie);
                    }
                }
                return Ok(response.finish());
            }
        },
    };

    let q = &query.0;

    // Basic parameter validation
    if q.response_type != "code" {
        return Ok(oidc_error(
            "unsupported_response_type",
            "only response_type=code is supported",
        ));
    }
    if q.code_challenge_method != "S256" {
        return Ok(oidc_error(
            "invalid_request",
            "code_challenge_method must be S256",
        ));
    }
    if q.code_challenge.is_empty() {
        return Ok(oidc_error("invalid_request", "code_challenge is required"));
    }
    if q.state.is_empty() {
        return Ok(oidc_error("invalid_request", "state is required"));
    }
    if q.nonce.is_empty() {
        return Ok(oidc_error("invalid_request", "nonce is required"));
    }
    if !q.scope.split_whitespace().any(|s| s == "openid") {
        return Ok(oidc_error("invalid_scope", "scope must include openid"));
    }

    // Parse client_id
    let client_id = Uuid::parse_str(&q.client_id)
        .map_err(|_| AppError::bad_request("invalid client_id UUID"))?;

    // Load client
    let client = provider
        .load_client(client_id)
        .await?
        .ok_or_else(|| AppError::bad_request("unknown client_id"))?;

    // Validate redirect_uri. Non-loopback clients require an exact match;
    // bare-loopback registrations (RFC 8252) permit a varying port but the
    // request URI's *parsed* host must still be the loopback host.
    if !client
        .redirect_uris
        .iter()
        .any(|u| redirect_uri_matches(u, &q.redirect_uri))
    {
        return Ok(oidc_error("invalid_request", "redirect_uri not registered"));
    }

    // Validate scopes
    let requested_scopes: Vec<String> = q
        .scope
        .split_whitespace()
        .filter(|s| client.allowed_scopes.iter().any(|a| a.as_str() == *s))
        .map(|s| s.to_string())
        .collect();

    // Refuse to issue a code when none of the requested scopes survive the
    // intersection with the client's allowed set (RFC 6749 §4.1.2.1). Issuing
    // a code for an empty scope grant would mint a token with no scope.
    if requested_scopes.is_empty() {
        return Ok(oidc_error(
            "invalid_scope",
            "none of the requested scopes are permitted for this client",
        ));
    }

    // BUNYIP-140 JIT path: replace the old "grant every allowed_scope"
    // behaviour with a baseline-only auto-grant. Scopes that disclose
    // user-profile data (`profile`, `phone`) are no longer auto-granted;
    // they require the explicit consent screen rendered below.
    //
    // The baseline list intentionally hardcodes the no-consent set: openid
    // (mandatory per OIDC), email (verified mailbox, no PII beyond the
    // address), offline_access (refresh tokens; client must already be
    // configured for them via allowed_grant_types). Any scope outside this
    // set must reach `granted_scopes` only through `/oauth2/consent`.
    const JIT_BASELINE_SCOPES: &[&str] = &["openid", "email", "offline_access"];
    if !provider.has_entitlement(session.user_id, client_id).await? {
        let baseline: Vec<String> = client
            .allowed_scopes
            .iter()
            .filter(|s| JIT_BASELINE_SCOPES.contains(&s.as_str()))
            .cloned()
            .collect();
        provider
            .grant_entitlement(session.user_id, client_id, &baseline)
            .await?;
    }

    // BUNYIP-140 consent gate: any requested scope that isn't already in
    // `granted_scopes` triggers the consent screen. Returns the user to
    // bunyip-web's consent page with the original authorize parameters so
    // Allow can resume the dance.
    let granted = provider
        .get_granted_scopes(session.user_id, client_id)
        .await?;
    let granted_set: std::collections::HashSet<&str> = granted.iter().map(String::as_str).collect();
    let missing: Vec<&str> = requested_scopes
        .iter()
        .map(String::as_str)
        .filter(|s| !granted_set.contains(s))
        .collect();
    // BUNYIP-234: log every decision the consent gate makes so the consent
    // loop ("Allow does nothing, page just refreshes") can be diagnosed from
    // the trace. Pair with the `consent_grant` log emitted by
    // /v1/users/me/consents to triangulate (a) identity drift between the
    // consent write and this read (different user_id -> different rows),
    // (b) persistence visibility (write committed but read sees an older
    // snapshot), or (c) scope-name mismatch in the union.
    tracing::info!(
        target: "consent_gate",
        user_id = %session.user_id,
        client_id = %client_id,
        requested_scopes = ?requested_scopes,
        granted_scopes = ?granted,
        missing_scopes = ?missing,
        "BUNYIP-234: authorize consent-gate evaluation"
    );
    if !missing.is_empty() {
        // Hand control to bunyip-web. The consent page reads every authorize
        // parameter back from the URL so a successful Allow can issue a
        // fresh /oauth2/authorize redirect with the same state / nonce /
        // code_challenge.
        let consent_url = format!(
            "{}/oauth2/consent?client_id={}&missing={}&continue={}",
            config.web_origin.trim_end_matches('/'),
            urlencoding::encode(&q.client_id),
            urlencoding::encode(&missing.join(" ")),
            urlencoding::encode(&format!("{}{}", provider.issuer(), req.uri())),
        );
        let mut response = HttpResponse::Found();
        response.insert_header(("Location", consent_url));
        for c in &silent_cookies {
            response.cookie(c.clone());
        }
        return Ok(response.finish());
    }

    // BUNYIP-62: per-RP tenant gating. When the client has a non-null
    // `tenant_claim_name`, the user MUST have an `oauth_client_user_tenants`
    // assignment for this client. Zero assignments => `access_denied`.
    // One => auto-select. More than one => render the tenant picker;
    // on submit the same handler re-runs with `selected_tenant_id` set.
    //
    // Clients with `tenant_claim_name = NULL` (existing seeded clients
    // pre-BUNYIP-61) skip this block entirely and behave exactly as
    // before: no tenant claim, no picker, no assignment check. The
    // gate is opt-in per client.
    let selected_tenant_id = if client.tenant_claim_name.is_some() {
        let assignments = crate::repositories::OAuthClientUserTenantRepository::assignments_for(
            &provider.pool,
            client.client_id,
            session.user_id,
        )
        .await?;
        match (assignments.len(), q.selected_tenant_id) {
            (0, _) => {
                return Ok(oidc_error(
                    "access_denied",
                    "no tenant assigned for this client",
                ));
            }
            (1, _) => Some(assignments[0].tenant_id),
            (_, Some(picked)) => {
                if !assignments.iter().any(|a| a.tenant_id == picked) {
                    return Ok(oidc_error(
                        "access_denied",
                        "selected tenant is not assigned to this user",
                    ));
                }
                Some(picked)
            }
            (_, None) => {
                return Ok(render_tenant_picker(
                    q,
                    &client,
                    &assignments,
                    &silent_cookies,
                ));
            }
        }
    } else {
        None
    };

    // Reuse the existing OP session established at login; auth_time/acr/amr come
    // from that session rather than being re-minted per authorize request.
    let acr = session.acr.as_deref().unwrap_or("urn:bunyip:loa:pwd");
    let amr = session
        .amr
        .clone()
        .unwrap_or_else(|| vec!["pwd".to_string()]);

    // Issue authorization code
    let code = provider
        .issue_authorization_code(
            &client,
            session.user_id,
            session.id,
            &q.redirect_uri,
            &requested_scopes,
            &q.code_challenge,
            &q.nonce,
            session.created_at,
            acr,
            &amr,
            selected_tenant_id,
        )
        .await?;

    let redirect = format!(
        "{}?code={}&state={}",
        q.redirect_uri,
        urlencoding::encode(&code),
        urlencoding::encode(&q.state),
    );

    let mut response = HttpResponse::Found();
    response.append_header(("Location", redirect));
    // When the silent-SSO branch above ran we attach every Set-Cookie it
    // emitted (op_session always, plus rotated access + refresh on the
    // refresh-token path) to the 302 carrying the auth code. No-op when an
    // existing op_session was reused (the vec is empty).
    for cookie in silent_cookies {
        response.cookie(cookie);
    }
    Ok(response.finish())
}

/// Silent-SSO fallback for `/oauth2/authorize` when no `op_session` cookie
/// resolves. Tries two inputs in order:
///
///   1. Hub `access_token` cookie: HS256 JWT verified locally via
///      [`JwtService::verify_access_token`]. Cheap, no DB write besides the
///      new op_session row. Catches the user who was just in bunyip-web.
///   2. Hub `refresh_token` cookie: runs the same DB-tracked rotation as
///      `/v1/auth/refresh` (`AuthService::refresh_tokens`), so family-reuse
///      detection and audit logging are untouched. The rotated access +
///      refresh tokens are emitted as Set-Cookie alongside the new
///      op_session cookie so the browser is left in the same state as if
///      the user had hit `/v1/auth/refresh` themselves. Catches the
///      DMARC-21 case where the user came back days later: the 15-min
///      access_token cookie was deleted by the browser but the 30-day
///      refresh_token is still good.
///
/// Returns `Ok(None)` for every "no, fall back to /login" branch (no
/// cookie inputs, expired/forged JWTs, OP rejected the rotation).
async fn try_silent_sso(
    req: &HttpRequest,
    provider: &OidcProvider,
    jwt_service: &Arc<crate::services::JwtService>,
    auth_service: &Arc<crate::services::AuthService>,
    config: &crate::config::Config,
) -> Result<
    Option<(
        crate::services::oidc_provider::OpSession,
        Vec<actix_web::cookie::Cookie<'static>>,
    )>,
    AppError,
> {
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok());
    let ip = crate::middleware::auth::extract_client_ip(req);
    let device_info = crate::middleware::auth::extract_device_info(req);
    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();
    // BUNYIP-266: op_session cookie is host-only unless the operator
    // explicitly opted into cross-subdomain sharing. access/refresh
    // cookies continue to honour `cookie_domain` (tightening those is a
    // separate ticket).
    let op_cookie_domain = config.op_session_cookie_domain();

    // Path 1: valid access_token cookie.
    if let Some(access_token) = req.cookie("access_token") {
        if let Ok(claims) = jwt_service.verify_access_token(access_token.value()) {
            let session = provider
                .create_op_session(
                    claims.sub,
                    user_agent,
                    ip,
                    "urn:bunyip:loa:pwd",
                    &["pwd".to_string()],
                )
                .await?;
            tracing::info!(
                user_id = %claims.sub,
                sid = %session.sid,
                "authorize: silently established op_session from valid access_token cookie"
            );
            // Dual-emit so a stale host-only `bunyip_op_session` from a
            // pre-COOKIE_DOMAIN deployment is cleared and the domain-scoped
            // cookie wins; otherwise the next authorize reads the dead
            // host-only sid and bounces to /login (BUNYIP-146). Path 2 below
            // gets the same effect via `clear_stale`; this path sets no
            // access/refresh cookies, so it clears only the OP session.
            let cookies = crate::middleware::auth::AuthCookies::op_session_set(
                &session.sid,
                secure,
                op_cookie_domain,
            );
            return Ok(Some((session, cookies)));
        }
    }

    // Path 2: access_token gone or expired, fall back to refresh_token rotation.
    let Some(refresh_cookie) = req.cookie("refresh_token") else {
        return Ok(None);
    };
    // Verify locally first so we have user_id without needing AuthService to
    // expose it post-rotation. A forged refresh_token short-circuits here
    // without any DB writes; the in-process call below verifies independently.
    let refresh_claims = match jwt_service.verify_refresh_token(refresh_cookie.value()) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let rotated = match auth_service
        .refresh_tokens(refresh_cookie.value().to_string(), device_info, ip)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            // Family-reuse detection / revoked / DB miss. Log at warn and
            // fall through to /login so the user re-authenticates cleanly.
            tracing::warn!(
                user_id = %refresh_claims.sub,
                error = %e,
                "authorize: refresh_token rotation rejected, falling back to /login"
            );
            return Ok(None);
        }
    };
    let session = provider
        .create_op_session(
            refresh_claims.sub,
            user_agent,
            ip,
            "urn:bunyip:loa:pwd",
            &["pwd".to_string()],
        )
        .await?;
    tracing::info!(
        user_id = %refresh_claims.sub,
        sid = %session.sid,
        "authorize: silently established op_session from rotated refresh_token"
    );
    let mut cookies = Vec::with_capacity(5);
    // Clear hostname-scoped stragglers from a deployment where COOKIE_DOMAIN
    // was unset and then set; mirrors `/v1/auth/refresh`'s response shape.
    cookies.extend(crate::middleware::auth::AuthCookies::clear_stale(secure));
    cookies.push(crate::middleware::auth::AuthCookies::access_token(
        &rotated.access_token,
        secure,
        cookie_domain,
    ));
    cookies.push(crate::middleware::auth::AuthCookies::refresh_token(
        &rotated.refresh_token,
        secure,
        true,
        cookie_domain,
    ));
    cookies.push(crate::middleware::auth::AuthCookies::op_session(
        &session.sid,
        secure,
        op_cookie_domain,
    ));
    Ok(Some((session, cookies)))
}

// ── Token endpoint ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    // authorization_code fields
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    // refresh_token fields
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    // client auth (also comes via Basic auth header)
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// POST /oauth2/token
pub async fn token(
    req: HttpRequest,
    provider: web::Data<Option<Arc<OidcProvider>>>,
    pool: web::Data<sqlx::PgPool>,
    form: web::Form<TokenRequest>,
) -> Result<HttpResponse, AppError> {
    let provider = require_provider!(provider);

    // BUNYIP-264: per-IP rate limit before any client / credential work.
    // The token endpoint is the canonical brute-force surface for
    // `client_secret_basic`; cap requests well above legitimate refresh
    // cycles but tight enough to make secret-guessing infeasible.
    let ip_key = crate::middleware::auth::extract_client_ip(&req)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into());
    crate::repositories::RateLimitRepository::check_rate_limit(
        &pool,
        &ip_key,
        &crate::models::RateLimitConfig::OAUTH_TOKEN,
    )
    .await?;

    let body = &form.0;

    // Extract client credentials (Basic auth header or form params)
    let (client_id_str, client_secret_opt) = extract_client_credentials(
        &req,
        body.client_id.as_deref(),
        body.client_secret.as_deref(),
    )?;
    let client_id = Uuid::parse_str(&client_id_str)
        .map_err(|_| AppError::OidcInvalidClient("invalid client_id format".into()))?;

    let client = provider
        .load_client(client_id)
        .await?
        .ok_or_else(|| AppError::OidcInvalidClient("unknown client".into()))?;

    // Authenticate the client
    authenticate_client(&client, client_secret_opt.as_deref())?;

    // BUNYIP-254: enforce per-client `allowed_grant_types`. The schema
    // already carries the list; the runtime previously ignored it, so a
    // client registered code-only (e.g. lets-chat per migration
    // `20260618032217_register_lets_chat_oidc_client.sql`) could still
    // use the `refresh_token` grant. RFC 6749 §5.2 names
    // `unauthorized_client` as the error code for this exact case.
    if !client
        .allowed_grant_types
        .iter()
        .any(|g| g == &body.grant_type)
    {
        return Ok(oidc_error(
            "unauthorized_client",
            &format!(
                "client {} is not registered for grant_type={}",
                client.client_id, body.grant_type
            ),
        ));
    }

    let ip = extract_ip(&req);
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match body.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(
                provider,
                &pool,
                &req,
                body,
                &client,
                ip,
                user_agent.as_deref(),
            )
            .await
        }
        "refresh_token" => {
            handle_refresh_grant(
                provider,
                &pool,
                &req,
                body,
                &client,
                ip,
                user_agent.as_deref(),
            )
            .await
        }
        other => Ok(oidc_error(
            "unsupported_grant_type",
            &format!("unsupported grant_type: {other}"),
        )),
    }
}

async fn handle_authorization_code_grant(
    provider: &OidcProvider,
    pool: &sqlx::PgPool,
    _req: &HttpRequest,
    body: &TokenRequest,
    client: &OAuthClient,
    ip: Option<std::net::IpAddr>,
    user_agent: Option<&str>,
) -> Result<HttpResponse, AppError> {
    let code = body.code.as_deref().ok_or_else(|| {
        AppError::OidcInvalidRequest("code is required for authorization_code grant".into())
    })?;
    let redirect_uri = body
        .redirect_uri
        .as_deref()
        .ok_or_else(|| AppError::OidcInvalidRequest("redirect_uri is required".into()))?;
    let code_verifier = body
        .code_verifier
        .as_deref()
        .ok_or_else(|| AppError::OidcInvalidRequest("code_verifier is required (PKCE)".into()))?;

    let code_row = provider
        .consume_authorization_code(code, client.client_id, redirect_uri, code_verifier)
        .await?;

    // Load user
    let user = UserRepository::find_by_id(pool, code_row.user_id)
        .await?
        .ok_or_else(|| AppError::OidcInvalidGrant("user not found".into()))?;

    // Re-check entitlement
    if !provider.has_entitlement(user.id, client.client_id).await? {
        return Ok(oidc_error(
            "access_denied",
            "user not entitled to this client",
        ));
    }

    // Mint tokens. BUNYIP-63: pass `selected_tenant_id` so the at+jwt
    // and id_token carry the per-client tenant claim. The refresh row
    // takes the same value so the next rotation mints the same
    // tenant.
    let (access_token, at_exp) = provider.mint_access_token(
        &user,
        client,
        &code_row.scope,
        code_row.auth_time,
        code_row.acr.as_deref().unwrap_or("urn:bunyip:loa:pwd"),
        &code_row.amr.clone().unwrap_or_default(),
        code_row.selected_tenant_id,
    )?;

    let id_token = provider.mint_id_token(
        &user,
        client,
        &code_row.scope,
        &code_row.nonce,
        code_row.auth_time,
        &access_token,
        code_row.selected_tenant_id,
    )?;

    let (raw_refresh, _) = provider
        .issue_refresh_token(
            client,
            user.id,
            code_row.op_session_id,
            &code_row.scope,
            // BUNYIP-257: persist the truthful acr/amr on the family so
            // every future rotation in this family carries them forward
            // instead of defaulting to hardcoded pwd/[pwd].
            code_row.acr.as_deref().unwrap_or("urn:bunyip:loa:pwd"),
            &code_row
                .amr
                .clone()
                .unwrap_or_else(|| vec!["pwd".to_string()]),
            ip,
            user_agent,
            code_row.selected_tenant_id,
        )
        .await?;

    let expires_in = (at_exp - chrono::Utc::now()).num_seconds();

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token: Some(raw_refresh),
        scope: code_row.scope.join(" "),
        id_token: Some(id_token),
    }))
}

async fn handle_refresh_grant(
    provider: &OidcProvider,
    pool: &sqlx::PgPool,
    _req: &HttpRequest,
    body: &TokenRequest,
    client: &OAuthClient,
    ip: Option<std::net::IpAddr>,
    user_agent: Option<&str>,
) -> Result<HttpResponse, AppError> {
    let raw_refresh = body
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::OidcInvalidRequest("refresh_token is required".into()))?;

    let requested_scope: Option<Vec<String>> = body
        .scope
        .as_ref()
        .map(|s| s.split_whitespace().map(String::from).collect());

    let rotated = provider
        .rotate_refresh_token(
            raw_refresh,
            client.client_id,
            requested_scope.as_deref(),
            ip,
            user_agent,
        )
        .await?;

    // Load user
    let user = UserRepository::find_by_id(pool, rotated.user_id)
        .await?
        .ok_or_else(|| AppError::OidcInvalidGrant("user not found".into()))?;

    // Re-check entitlement at every rotation
    if !provider.has_entitlement(user.id, client.client_id).await? {
        return Ok(oidc_error(
            "access_denied",
            "user not entitled to this client",
        ));
    }

    // BUNYIP-200: re-validate the tenant assignment at every rotation,
    // mirroring the has_entitlement re-check above. The refresh-token family
    // carries the `selected_tenant_id` the user picked at the original
    // /authorize (BUNYIP-63), but an admin may have since unassigned that
    // tenant. For a tenant-scoped client (`tenant_claim_name IS NOT NULL`),
    // the carried tenant MUST still be among the user's current assignments;
    // otherwise the rotation would keep minting an at+jwt with a stale tenant
    // claim. Reject with invalid_grant so the client is forced back through
    // /authorize, where the picker re-runs against live assignments.
    if rotated.client.tenant_claim_name.is_some() {
        if let Some(selected) = rotated.selected_tenant_id {
            let assignments =
                crate::repositories::OAuthClientUserTenantRepository::assignments_for(
                    pool,
                    rotated.client.client_id,
                    user.id,
                )
                .await?;
            if !assignments.iter().any(|a| a.tenant_id == selected) {
                return Err(AppError::OidcInvalidGrant(
                    "selected tenant is no longer assigned to this user".into(),
                ));
            }
        }
    }

    let (access_token, at_exp) = provider.mint_access_token(
        &user,
        &rotated.client,
        &rotated.scope,
        chrono::Utc::now(), // auth_time not re-established on refresh
        // BUNYIP-257: read the persisted acr/amr from the rotation
        // result instead of stamping the hardcoded pwd defaults. The
        // family carries the truthful values forward so the rotated
        // at+jwt reports the authentication-method-reference set that
        // matches OIDC Core §3.1.3.7.
        &rotated.acr,
        &rotated.amr,
        rotated.selected_tenant_id,
    )?;

    let expires_in = (at_exp - chrono::Utc::now()).num_seconds();

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token: Some(rotated.raw_refresh),
        scope: rotated.scope.join(" "),
        id_token: None, // not re-issued on refresh
    }))
}

// ── Userinfo endpoint ─────────────────────────────────────────────────────────

/// GET /oauth2/userinfo
///
/// Accepts an `Authorization: Bearer <at+jwt>` token.
/// Returns the standard OIDC userinfo claims for the subject.
pub async fn userinfo(
    req: HttpRequest,
    provider: web::Data<Option<Arc<OidcProvider>>>,
    pool: web::Data<sqlx::PgPool>,
) -> Result<HttpResponse, AppError> {
    let provider = require_provider!(provider);

    // BUNYIP-264: per-IP rate limit; silent-SSO + RP profile hydrations
    // call userinfo regularly so 240/min covers multi-app browsers.
    let ip_key = crate::middleware::auth::extract_client_ip(&req)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into());
    crate::repositories::RateLimitRepository::check_rate_limit(
        &pool,
        &ip_key,
        &crate::models::RateLimitConfig::OAUTH_USERINFO,
    )
    .await?;

    let token_str = extract_bearer_token(&req)
        .ok_or_else(|| AppError::OidcInvalidToken("missing Bearer token".into()))?;

    let at_claims = provider.verify_at_jwt_claims(&token_str)?;
    let user_id = Uuid::parse_str(&at_claims.sub)
        .map_err(|_| AppError::OidcInvalidToken("invalid sub in access token".into()))?;

    let user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or_else(|| AppError::OidcInvalidToken("user not found".into()))?;

    // BUNYIP-140: extend the userinfo response with `profile` and `phone`
    // standard OIDC claims when (a) the access token's scope set covers them
    // AND (b) the corresponding column is non-NULL. NULL columns serialize
    // as ABSENT keys (not empty strings) so a verifying RP can treat
    // "claim absent" as "user has not filled it in yet" and fall back to
    // their own onboarding prompt. The scope check is against the at+jwt's
    // own `scope` claim - the granted-scopes record on bunyip is the source
    // of truth at authorize time, not at userinfo time.
    let token_scopes: std::collections::HashSet<&str> =
        at_claims.scope.split_whitespace().collect();
    // `sub` is always returned; email / membership claims are gated on the
    // `email` scope, mirroring the id_token in `mint_id_token` so userinfo
    // never discloses more than the granted scopes (RFC 6749 / OIDC Core).
    let mut body = serde_json::json!({
        "sub": user.id.to_string(),
    });
    if token_scopes.contains("email") {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("email".into(), serde_json::json!(user.email));
            obj.insert(
                "email_verified".into(),
                serde_json::json!(user.email_verified),
            );
            obj.insert(
                "membership_status".into(),
                serde_json::json!(user.membership_status),
            );
            obj.insert(
                "has_member_access".into(),
                serde_json::json!(
                    crate::services::jwt::AccessTokenClaims::has_member_access_static(
                        &user.role,
                        user.lifetime_member,
                        user.trial_ends_at.map(|t| t.timestamp()),
                        &user.membership_status,
                    )
                ),
            );
        }
    }
    if token_scopes.contains("profile") {
        if let Some(obj) = body.as_object_mut() {
            if let Some(v) = user.first_name.as_deref().filter(|s| !s.is_empty()) {
                obj.insert("given_name".into(), serde_json::Value::String(v.into()));
            }
            if let Some(v) = user.last_name.as_deref().filter(|s| !s.is_empty()) {
                obj.insert("family_name".into(), serde_json::Value::String(v.into()));
            }
        }
    }
    if token_scopes.contains("phone") {
        if let Some(obj) = body.as_object_mut() {
            if let Some(v) = user.phone.as_deref().filter(|s| !s.is_empty()) {
                obj.insert("phone_number".into(), serde_json::Value::String(v.into()));
            }
        }
    }
    Ok(HttpResponse::Ok().json(body))
}

// ── Revocation endpoint ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
    // Client credentials may also arrive via the HTTP Basic auth header.
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// POST /oauth2/revoke (RFC 7009)
///
/// Revokes a refresh token and its entire rotation family. The endpoint does
/// not maintain an access-token blocklist: access tokens are short-lived
/// stateless JWTs and are left to expire. Returns 200 regardless of whether
/// the token was found (RFC 7009 §2.2). The client is authenticated first
/// (RFC 7009 §2.1) and may only revoke its own tokens.
pub async fn revoke(
    req: HttpRequest,
    provider: web::Data<Option<Arc<OidcProvider>>>,
    form: web::Form<RevokeRequest>,
) -> Result<HttpResponse, AppError> {
    let provider = require_provider!(provider);

    // BUNYIP-264: per-IP rate limit. Legitimate logout calls /oauth2/revoke
    // once per session; sustained traffic is abuse.
    let ip_key = crate::middleware::auth::extract_client_ip(&req)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into());
    crate::repositories::RateLimitRepository::check_rate_limit(
        &provider.pool,
        &ip_key,
        &crate::models::RateLimitConfig::OAUTH_REVOKE,
    )
    .await?;

    // RFC 7009 §2.1: authenticate the client before acting on any token.
    let (client_id_str, client_secret_opt) = extract_client_credentials(
        &req,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )?;
    let client_id = Uuid::parse_str(&client_id_str)
        .map_err(|_| AppError::OidcInvalidClient("invalid client_id format".into()))?;
    let client = provider
        .load_client(client_id)
        .await?
        .ok_or_else(|| AppError::OidcInvalidClient("unknown client".into()))?;
    authenticate_client(&client, client_secret_opt.as_deref())?;

    // RFC 7009 §2.2: respond 200 regardless of whether the token was found.
    let _ = do_revoke(provider, client.client_id, &form.token).await;
    Ok(HttpResponse::Ok().finish())
}

async fn do_revoke(
    provider: &OidcProvider,
    client_id: Uuid,
    raw_token: &str,
) -> Result<(), AppError> {
    let token_hash = sha256_bytes(raw_token.as_bytes());

    // Look up the family only when the token belongs to the authenticating
    // client, so a client cannot revoke another client's tokens (RFC 7009
    // §2.1). Runtime query (not the `query!` macro) so the added client_id
    // predicate needs no `.sqlx/` offline-cache regeneration.
    let family_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT family_id FROM refresh_tokens_v2 WHERE token_hash = $1 AND client_id = $2",
    )
    .bind(token_hash)
    .bind(client_id)
    .fetch_optional(&provider.pool)
    .await?;

    if let Some(family_id) = family_id {
        sqlx::query(
            "UPDATE refresh_token_families SET revoked_at = NOW(), revoke_reason = 'client_revocation' WHERE id = $1",
        )
        .bind(family_id)
        .execute(&provider.pool)
        .await?;
    }

    Ok(())
}

// ── RP-Initiated Logout ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LogoutQuery {
    /// BUNYIP-260 (OIDC RP-Initiated Logout 1.0 §3): the id_token the OP
    /// previously issued to the calling RP. When provided, the OP uses
    /// it to identify the calling client and scopes
    /// `post_logout_redirect_uri` to that client's allowlist only.
    /// `Option` to keep legacy callers compiling; the runtime guards in
    /// `logout` reject the request when it's missing AND a
    /// `post_logout_redirect_uri` is provided (the cross-RP open
    /// redirect surface). Bare `/oauth2/logout` with no redirect is
    /// still accepted so the legacy "just sign me out" flow keeps
    /// working.
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// GET /oauth2/logout
pub async fn logout(
    provider: web::Data<Option<Arc<OidcProvider>>>,
    query: web::Query<LogoutQuery>,
    user: OptionalUser,
    config: web::Data<crate::config::Config>,
    http_client: web::Data<reqwest::Client>,
) -> Result<HttpResponse, AppError> {
    // Clone the Arc so we can move it into the background task.
    let provider_arc: Arc<OidcProvider> = match provider.as_ref().as_ref() {
        Some(p) => Arc::clone(p),
        None => return Ok(HttpResponse::NotFound().finish()),
    };

    // BUNYIP-260 (OIDC RP-Initiated Logout 1.0 §3 + audit finding):
    // `post_logout_redirect_uri` is honoured ONLY when it belongs to the
    // client the `id_token_hint` was issued to. The previous lookup
    // matched the URI against ANY client's allowlist, which let RP-A
    // bounce a victim mid-logout to RP-A's registered URL with
    // attacker-chosen `state` while the victim thought they were leaving
    // RP-B. Now: no hint -> no redirect; hint present + URI not in that
    // client's allowlist -> no redirect. Bare /oauth2/logout (no
    // redirect, no hint) still works as a "just sign me out" call.
    let redirect = match &query.post_logout_redirect_uri {
        Some(uri) if !uri.is_empty() => {
            let hint_client_id: Option<Uuid> = match query.id_token_hint.as_deref() {
                Some(hint) if !hint.is_empty() => provider_arc
                    .verify_id_token_client(hint)
                    .await
                    .map_err(|e| {
                        tracing::warn!(
                            error = %e,
                            "logout: id_token_hint verification failed; ignoring post_logout_redirect_uri"
                        );
                    })
                    .ok(),
                _ => None,
            };
            let allowed = if let Some(client_id) = hint_client_id {
                let registered: Option<i32> = sqlx::query_scalar(
                    "SELECT 1 FROM oauth_clients \
                     WHERE client_id = $1 \
                       AND disabled_at IS NULL \
                       AND $2 = ANY(post_logout_redirect_uris) LIMIT 1",
                )
                .bind(client_id)
                .bind(uri)
                .fetch_optional(&provider_arc.pool)
                .await?;
                registered.is_some()
            } else {
                // BUNYIP-260: no verified id_token_hint -> no redirect.
                // Cross-RP open-redirect surface closed.
                tracing::warn!(
                    %uri,
                    "logout: post_logout_redirect_uri supplied without a verified \
                     id_token_hint; ignoring (cross-RP open-redirect defense)"
                );
                false
            };
            if allowed {
                match &query.state {
                    Some(state) if !state.is_empty() => {
                        let sep = if uri.contains('?') { '&' } else { '?' };
                        format!("{uri}{sep}state={}", urlencoding::encode(state))
                    }
                    _ => uri.clone(),
                }
            } else {
                "/".to_string()
            }
        }
        _ => "/".to_string(),
    };

    if let Some(claims) = user.0 {
        let user_id = claims.sub; // already Uuid
        match provider_arc.revoke_sessions_for_backchannel(user_id).await {
            Ok(targets) if !targets.is_empty() => {
                let provider_arc = Arc::clone(&provider_arc);
                // Reuse the single app-state reqwest client (built once at
                // startup) rather than rebuilding one per logout (BUNYIP-74).
                let http = http_client.get_ref().clone();
                tokio::spawn(async move {
                    for (client_id, uri, sid) in targets {
                        match provider_arc.mint_logout_token(user_id, &sid, client_id) {
                            Ok(token) => {
                                if let Err(e) = http
                                    .post(&uri)
                                    .form(&[("logout_token", &token)])
                                    .send()
                                    .await
                                {
                                    tracing::warn!(
                                        %uri, %client_id, error = %e,
                                        "Backchannel logout delivery failed"
                                    );
                                } else {
                                    tracing::info!(
                                        %uri, %client_id,
                                        "Backchannel logout delivered"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    %client_id, error = %e,
                                    "Failed to mint logout token"
                                );
                            }
                        }
                    }
                });
            }
            Ok(_) => {} // no clients with backchannel URIs
            Err(e) => {
                tracing::warn!(error = %e, "Failed to revoke sessions for backchannel logout");
            }
        }
    }

    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();
    let mut response = HttpResponse::Found();
    response.append_header(("Location", redirect));
    for cookie in crate::middleware::auth::AuthCookies::clear(secure, cookie_domain) {
        response.cookie(cookie);
    }
    Ok(response.finish())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Extract (client_id, client_secret) from either HTTP Basic auth or the form
/// body's `client_id` / `client_secret` fields. Shared by the token and
/// revocation endpoints.
fn extract_client_credentials(
    req: &HttpRequest,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Result<(String, Option<String>), AppError> {
    // Try HTTP Basic auth first
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                    if let Ok(cred_str) = String::from_utf8(decoded) {
                        if let Some((id, secret)) = cred_str.split_once(':') {
                            return Ok((
                                urlencoding::decode(id).unwrap_or_default().into_owned(),
                                Some(urlencoding::decode(secret).unwrap_or_default().into_owned()),
                            ));
                        }
                    }
                }
            }
        }
    }

    // Fall back to form body
    let client_id = form_client_id
        .ok_or_else(|| AppError::OidcInvalidClient("client_id is required".into()))?
        .to_string();
    Ok((client_id, form_client_secret.map(|s| s.to_string())))
}

/// Verify the client authenticates per its registered method.
///
/// BUNYIP-254: previously this returned Ok for any `client_type == "public"`
/// regardless of the registered `token_endpoint_auth_method`. A confidential
/// client mis-registered as public would bypass secret verification. Branch
/// explicitly on the registered method so the schema and runtime stay in
/// lockstep:
///
/// - `client_secret_basic`: a verified Basic-auth secret is required. The
///   client_type column must NOT be public (a public row with
///   `client_secret_basic` is a registration bug and is refused).
/// - `none`: no secret is allowed and `client_type` must be `public`.
///   Confidential clients cannot register as `none`. PKCE handles
///   replay protection on this branch (enforced separately at
///   `/oauth2/authorize`).
/// - `private_key_jwt`: the schema accepts this value but the runtime
///   does not yet implement JWT client assertion verification. Refuse
///   rather than silently fall through; tracked as a follow-up.
fn authenticate_client(
    client: &OAuthClient,
    provided_secret: Option<&str>,
) -> Result<(), AppError> {
    match client.token_endpoint_auth_method.as_str() {
        "none" => {
            if client.client_type != "public" {
                return Err(AppError::OidcInvalidClient(
                    "client misregistered: token_endpoint_auth_method=none requires \
                     client_type=public"
                        .into(),
                ));
            }
            if provided_secret.is_some() {
                return Err(AppError::OidcInvalidClient(
                    "public client must not present a client_secret".into(),
                ));
            }
            Ok(())
        }
        "client_secret_basic" => {
            if client.client_type == "public" {
                return Err(AppError::OidcInvalidClient(
                    "client misregistered: token_endpoint_auth_method=client_secret_basic \
                     requires client_type=confidential"
                        .into(),
                ));
            }
            let expected_hash = client.client_secret_hash.as_deref().ok_or_else(|| {
                AppError::OidcInvalidClient("client has no secret configured".into())
            })?;
            let secret = provided_secret.ok_or_else(|| {
                AppError::OidcInvalidClient("client_secret required for confidential client".into())
            })?;
            use argon2::{Argon2, PasswordHash, PasswordVerifier};
            let parsed = PasswordHash::new(expected_hash)
                .map_err(|_| AppError::OidcInvalidClient("malformed client secret hash".into()))?;
            Argon2::default()
                .verify_password(secret.as_bytes(), &parsed)
                .map_err(|_| AppError::OidcInvalidClient("invalid client_secret".into()))
        }
        "private_key_jwt" => {
            // BUNYIP-254: schema allows this value, but the runtime
            // does not implement JWT client assertion verification.
            // Refuse rather than fall through (which would otherwise
            // either accept any caller or 500). A follow-up ticket
            // implements `private_key_jwt`; until then registrations
            // with this method cannot authenticate.
            Err(AppError::OidcInvalidClient(
                "token_endpoint_auth_method=private_key_jwt is not yet implemented".into(),
            ))
        }
        other => Err(AppError::OidcInvalidClient(format!(
            "unsupported token_endpoint_auth_method: {other}"
        ))),
    }
}

/// Extract `Authorization: Bearer <token>` from the request.
fn extract_bearer_token(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").map(|t| t.to_string()))
}

/// Extract the client IP from the request (X-Forwarded-For or peer addr).
fn extract_ip(req: &HttpRequest) -> Option<std::net::IpAddr> {
    req.headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| req.peer_addr().map(|addr| addr.ip()))
}

/// Does a request `redirect_uri` match a single registered redirect?
///
/// Normal clients require a byte-for-byte exact match. A bare-loopback
/// registration (`http://127.0.0.1` or `http://localhost`, per RFC 8252)
/// permits any port and path, but the request URI is parsed and its host must
/// resolve to the loopback host. This rejects the string-prefix bypasses
/// `http://127.0.0.1:1@evil.com` (host `evil.com`, loopback smuggled into the
/// userinfo) and `http://127.0.0.1.evil.com` (host is a subdomain of
/// `evil.com`), both of which `starts_with("http://127.0.0.1:")` accepted.
fn redirect_uri_matches(registered: &str, requested: &str) -> bool {
    if registered == "http://127.0.0.1" || registered == "http://localhost" {
        is_loopback_redirect(requested)
    } else {
        registered == requested
    }
}

/// True iff `requested` is an `http` URL whose *parsed* host is a loopback
/// host (`127.0.0.1`, `::1`, or `localhost`) with no userinfo component.
fn is_loopback_redirect(requested: &str) -> bool {
    let Ok(url) = url::Url::parse(requested) else {
        return false;
    };
    if url.scheme() != "http" {
        return false;
    }
    // Any userinfo (`user[:pass]@`) is a red flag: RFC 8252 loopback redirects
    // carry none, and it is the vector that smuggles `127.0.0.1:1` in front of
    // the real host (`...@evil.com`).
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::new(127, 0, 0, 1),
        Some(url::Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    }
}

#[cfg(test)]
mod redirect_uri_tests {
    use super::*;

    // Bare-loopback registration that the attack targets.
    const LOOPBACK: &str = "http://127.0.0.1";
    const LOCALHOST: &str = "http://localhost";

    #[test]
    fn userinfo_at_bypass_rejected() {
        // host parses to `evil.com`; `127.0.0.1:1` is the userinfo.
        assert!(!redirect_uri_matches(
            LOOPBACK,
            "http://127.0.0.1:1@evil.com/cb"
        ));
        assert!(!redirect_uri_matches(
            LOCALHOST,
            "http://localhost:1@evil.com/cb"
        ));
    }

    #[test]
    fn subdomain_suffix_bypass_rejected() {
        // host is `127.0.0.1.evil.com`, a domain, not the loopback IP.
        assert!(!redirect_uri_matches(
            LOOPBACK,
            "http://127.0.0.1.evil.com/cb"
        ));
    }

    #[test]
    fn genuine_loopback_with_varying_port_allowed() {
        assert!(redirect_uri_matches(LOOPBACK, "http://127.0.0.1:54321/cb"));
        assert!(redirect_uri_matches(LOCALHOST, "http://localhost:8080/cb"));
        // IPv6 loopback and the bare host (no port) are also genuine.
        assert!(redirect_uri_matches(LOOPBACK, "http://[::1]:9000/cb"));
        assert!(redirect_uri_matches(LOOPBACK, "http://127.0.0.1/cb"));
    }

    #[test]
    fn non_http_scheme_rejected() {
        assert!(!redirect_uri_matches(
            LOOPBACK,
            "https://127.0.0.1:1@evil.com/cb"
        ));
    }

    #[test]
    fn non_loopback_client_is_exact_match() {
        let reg = "https://app.example.com/callback";
        assert!(redirect_uri_matches(
            reg,
            "https://app.example.com/callback"
        ));
        // A loopback-looking request must NOT satisfy a normal registration.
        assert!(!redirect_uri_matches(reg, "http://127.0.0.1:54321/cb"));
        // Any deviation fails the exact match.
        assert!(!redirect_uri_matches(
            reg,
            "https://app.example.com/callback2"
        ));
    }
}
