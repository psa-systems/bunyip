//! `start_login` and `complete_login`: the two halves of the OIDC code
//! flow as seen from a browser SPA. Plus the password-direct
//! `password_login` + `mfa_verify` first-party shortcut.
//!
//! Lifted from mokosh-clients's `modules/oidc/flow.rs` with the
//! `BUNYIP_OIDC_*` env prefix substituted and `current_access_token`
//! sourced from `crate::stores::tokens`. See
//! `docs/bunyip/03-auth-pages.md` and `docs/bunyip/09-out-of-scope.md`
//! for the future "shared OIDC client crate" pickup.

use chrono::{Duration, Utc};
use gloo_net::http::Request;
use serde::Deserialize;
use web_sys::RequestCredentials;

use crate::stores::config::OidcConfig;
use crate::stores::tokens::{current_access_token, Tokens};

use super::pkce::{generate_code_verifier, random_opaque, s256_challenge};
use super::storage::{save_pending, take_pending, PendingFlow};

#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("config: {0}")]
    Config(String),
    #[error("storage: {0}")]
    Storage(String),
    #[error("network: {0}")]
    Network(String),
    #[error("token endpoint: {error} ({description})")]
    TokenEndpoint { error: String, description: String },
    #[error("state mismatch (possible CSRF)")]
    StateMismatch,
    #[error("redirect failed: {0}")]
    Redirect(String),
}

/// Begin the login flow. Generates PKCE + state + nonce, persists them
/// in `sessionStorage`, then navigates the browser to the authorize
/// endpoint. This function does not return on success: the page is
/// replaced.
pub fn start_login(cfg: &OidcConfig, return_to: impl Into<String>) -> Result<(), FlowError> {
    let verifier = generate_code_verifier();
    let challenge = s256_challenge(&verifier);
    let state = random_opaque();
    let nonce = random_opaque();
    let return_to = return_to.into();
    let redirect_uri = cfg
        .resolve_redirect_uri()
        .map_err(|e| FlowError::Config(e.to_string()))?;

    save_pending(&PendingFlow {
        code_verifier: verifier,
        state: state.clone(),
        nonce: nonce.clone(),
        return_to: return_to.clone(),
    })
    .map_err(FlowError::Storage)?;

    // Build the authorize URL.
    let issuer = cfg.issuer_trimmed();
    let mut url = format!("{issuer}/oauth2/authorize");
    url.push('?');
    let q: [(&str, &str); 8] = [
        ("response_type", "code"),
        ("client_id", &cfg.client_id),
        ("redirect_uri", &redirect_uri),
        ("scope", &cfg.scopes),
        ("state", &state),
        ("nonce", &nonce),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ];
    for (i, (k, v)) in q.iter().enumerate() {
        if i > 0 {
            url.push('&');
        }
        url.push_str(k);
        url.push('=');
        url.push_str(&urlencode(v));
    }

    let win = web_sys::window().ok_or_else(|| FlowError::Redirect("no window".into()))?;
    win.location()
        .set_href(&url)
        .map_err(|_| FlowError::Redirect("set_href failed".into()))
}

/// Begin an OIDC code+PKCE flow against the configured issuer but with
/// a different `client_id` + `redirect_uri` than the hub's own. Powers
/// the app launcher: each tile is a (client_id, redirect_uri) pair, and
/// clicking it kicks off a fresh flow that lands the user on the target
/// app. No `PendingFlow` is stored locally; the target app owns the
/// callback half of the dance.
pub fn start_login_for(
    cfg: &OidcConfig,
    client_id: &str,
    redirect_uri: &str,
) -> Result<(), FlowError> {
    let verifier = generate_code_verifier();
    let challenge = s256_challenge(&verifier);
    let state = random_opaque();
    let nonce = random_opaque();

    let issuer = cfg.issuer_trimmed();
    let mut url = format!("{issuer}/oauth2/authorize");
    url.push('?');
    let q: [(&str, &str); 8] = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", &cfg.scopes),
        ("state", &state),
        ("nonce", &nonce),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ];
    for (i, (k, v)) in q.iter().enumerate() {
        if i > 0 {
            url.push('&');
        }
        url.push_str(k);
        url.push('=');
        url.push_str(&urlencode(v));
    }

    let win = web_sys::window().ok_or_else(|| FlowError::Redirect("no window".into()))?;
    win.location()
        .set_href(&url)
        .map_err(|_| FlowError::Redirect("set_href failed".into()))
}

/// Snapshot of `?code=...&state=...` taken before the Dioxus router
/// mounts. Dioxus 0.7 calls `history.replaceState()` during router
/// initialization to normalize the URL to its declared route shape (no
/// query params), which would erase the OAuth response before
/// `AuthCallbackPage` ever reads it. Capture once from `main()` before
/// `dioxus::launch(App)` so the snapshot survives.
thread_local! {
    static INITIAL_SEARCH: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

pub fn snapshot_initial_search() {
    let s = web_sys::window()
        .and_then(|w| w.location().search().ok())
        .unwrap_or_default();
    INITIAL_SEARCH.with(|cell| *cell.borrow_mut() = Some(s));
}

pub fn current_search() -> String {
    INITIAL_SEARCH
        .with(|cell| cell.borrow().clone())
        .filter(|s| !s.is_empty())
        .or_else(|| web_sys::window().and_then(|w| w.location().search().ok()))
        .unwrap_or_default()
}

/// Handle the callback URL. Returns (tokens, return_to).
pub async fn complete_login(cfg: &OidcConfig) -> Result<(Tokens, String), FlowError> {
    let search = current_search();
    let params = web_sys::UrlSearchParams::new_with_str(&search)
        .map_err(|_| FlowError::Redirect("UrlSearchParams".into()))?;
    let code = params.get("code").ok_or_else(|| FlowError::TokenEndpoint {
        error: "invalid_request".into(),
        description: "missing code".into(),
    })?;
    let state = params
        .get("state")
        .ok_or_else(|| FlowError::TokenEndpoint {
            error: "invalid_request".into(),
            description: "missing state".into(),
        })?;

    if let Some(err) = params.get("error") {
        return Err(FlowError::TokenEndpoint {
            error: err,
            description: params.get("error_description").unwrap_or_default(),
        });
    }

    let pending = take_pending().map_err(FlowError::Storage)?;
    if pending.state != state {
        return Err(FlowError::StateMismatch);
    }

    let redirect_uri = cfg
        .resolve_redirect_uri()
        .map_err(|e| FlowError::Config(e.to_string()))?;

    let body = form_encode(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", &redirect_uri),
        ("code_verifier", &pending.code_verifier),
        ("client_id", &cfg.client_id),
    ]);
    let url = format!("{}/oauth2/token", cfg.issuer_trimmed());
    let resp = Request::post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .body(body)
        .map_err(|e| FlowError::Network(e.to_string()))?
        .send()
        .await
        .map_err(|e| FlowError::Network(e.to_string()))?;

    if !resp.ok() {
        let body: ErrorBody = resp
            .json()
            .await
            .unwrap_or_else(|_| ErrorBody::generic("token_endpoint_failed"));
        return Err(FlowError::TokenEndpoint {
            error: body.error,
            description: body.error_description.unwrap_or_default(),
        });
    }

    let body: TokenBody = resp
        .json()
        .await
        .map_err(|e| FlowError::Network(format!("token body: {e}")))?;

    let id_token = body.id_token.ok_or_else(|| FlowError::TokenEndpoint {
        error: "invalid_response".into(),
        description: "id_token missing from authorization_code response".into(),
    })?;

    let tokens = Tokens {
        access_token: body.access_token,
        id_token,
        refresh_token: body.refresh_token,
        expires_at: Utc::now() + Duration::seconds(body.expires_in.max(0)),
        scope: body.scope.unwrap_or_default(),
    };
    Ok((tokens, pending.return_to))
}

/// Exchange a refresh token for a fresh pair via `/oauth2/token`.
pub async fn refresh_tokens(
    cfg: &OidcConfig,
    refresh_token: &str,
    prior_id_token: &str,
) -> Result<Tokens, FlowError> {
    let body = form_encode(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", &cfg.client_id),
    ]);
    let url = format!("{}/oauth2/token", cfg.issuer_trimmed());
    let resp = Request::post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .body(body)
        .map_err(|e| FlowError::Network(e.to_string()))?
        .send()
        .await
        .map_err(|e| FlowError::Network(e.to_string()))?;

    if !resp.ok() {
        let body: ErrorBody = resp
            .json()
            .await
            .unwrap_or_else(|_| ErrorBody::generic("token_endpoint_failed"));
        return Err(FlowError::TokenEndpoint {
            error: body.error,
            description: body.error_description.unwrap_or_default(),
        });
    }

    let body: TokenBody = resp
        .json()
        .await
        .map_err(|e| FlowError::Network(format!("token body: {e}")))?;

    Ok(Tokens {
        access_token: body.access_token,
        id_token: body.id_token.unwrap_or_else(|| prior_id_token.to_string()),
        refresh_token: body.refresh_token,
        expires_at: Utc::now() + Duration::seconds(body.expires_in.max(0)),
        scope: body.scope.unwrap_or_default(),
    })
}

/// RFC 7009 token revocation. Best-effort: spec requires 200 even for
/// unknown tokens. Used by the logout flow.
pub async fn revoke_refresh_token(cfg: &OidcConfig, refresh_token: &str) -> Result<(), FlowError> {
    let body = form_encode(&[
        ("token", refresh_token),
        ("token_type_hint", "refresh_token"),
        ("client_id", &cfg.client_id),
    ]);
    let url = format!("{}/oauth2/revoke", cfg.issuer_trimmed());
    let _ = Request::post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .map_err(|e| FlowError::Network(e.to_string()))?
        .send()
        .await
        .map_err(|e| FlowError::Network(e.to_string()))?;
    Ok(())
}

/// Direct password login against `/v1/auth/login`. Returns `Success`
/// (tokens already minted, no MFA) or `MfaRequired` (carry the
/// challenge to `/v1/auth/mfa/verify`).
#[derive(Debug)]
pub enum LoginOutcome {
    Success(Tokens),
    MfaRequired { challenge: String, expires_in: i64 },
}

pub async fn password_login(
    cfg: &OidcConfig,
    email: &str,
    password: &str,
    trust_token: Option<&str>,
) -> Result<LoginOutcome, FlowError> {
    let url = format!("{}/v1/auth/login", cfg.issuer_trimmed());
    // mokosh-server's LoginRequest types `client_id` as
    // `Option<uuid::Uuid>`. Serde fails the whole request with
    // 422 Unprocessable Content when the field is present but holds
    // the empty string (`""` is neither a valid UUID nor null). The
    // SPA carries `cfg.client_id = ""` whenever the image was built
    // without `BUNYIP_OIDC_CLIENT_ID` (the common case for
    // staging-style deploys that mint a session cookie but do not
    // also want tokens minted for a specific RP). Omit the field in
    // that case so the request body deserialises as
    // `client_id: None` server-side; only attach a value when it is
    // actually a non-empty UUID string.
    let mut body = serde_json::json!({
        "email": email,
        "password": password,
        "scope": cfg.scopes,
        "trust_token": trust_token,
    });
    if !cfg.client_id.is_empty() {
        body["client_id"] = serde_json::Value::String(cfg.client_id.clone());
    }
    // `credentials: include` so the browser accepts the Set-Cookie on
    // the OP session that mokosh-server sets in this response. Without
    // it, the cross-origin Set-Cookie is silently dropped and the
    // launcher's later top-level navigation to /oauth2/authorize finds
    // no OP session and bounces the user back to /login. See
    // docs/bunyip/06-app-launcher.md + 07-sso-redirect-bridge.md.
    let resp = Request::post(&url)
        .credentials(RequestCredentials::Include)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&body)
        .map_err(|e| FlowError::Network(e.to_string()))?
        .send()
        .await
        .map_err(|e| FlowError::Network(e.to_string()))?;

    if !resp.ok() {
        let status = resp.status();
        let raw = resp.text().await.unwrap_or_default();
        let parsed: Option<ErrorBody> = serde_json::from_str(&raw).ok();
        let (err, desc) = match parsed {
            Some(b) => (b.error, b.error_description.unwrap_or_default()),
            None => (
                "login_failed".to_string(),
                if status == 401 || status == 403 {
                    "Invalid email or password".to_string()
                } else {
                    format!("HTTP {status}")
                },
            ),
        };
        return Err(FlowError::TokenEndpoint {
            error: err,
            description: desc,
        });
    }

    let body: LoginBody = resp
        .json()
        .await
        .map_err(|e| FlowError::Network(format!("login body: {e}")))?;

    if body.mfa_required.unwrap_or(false) {
        let challenge = body.challenge.ok_or_else(|| FlowError::TokenEndpoint {
            error: "invalid_response".into(),
            description: "mfa_required=true but no challenge".into(),
        })?;
        return Ok(LoginOutcome::MfaRequired {
            challenge,
            expires_in: body.expires_in.unwrap_or(0),
        });
    }

    let bundle = body.tokens.ok_or_else(|| FlowError::TokenEndpoint {
        error: "invalid_response".into(),
        description: "server did not return tokens (missing client_id?)".into(),
    })?;

    Ok(LoginOutcome::Success(Tokens {
        access_token: bundle.access_token,
        id_token: bundle.id_token,
        refresh_token: Some(bundle.refresh_token),
        expires_at: Utc::now() + Duration::seconds(bundle.expires_in.max(0)),
        scope: bundle.scope,
    }))
}

pub struct MfaVerifyOk {
    pub tokens: Tokens,
    pub trust_token: Option<String>,
}

pub async fn mfa_verify(
    cfg: &OidcConfig,
    challenge: &str,
    code: &str,
    remember_device: bool,
) -> Result<MfaVerifyOk, FlowError> {
    let url = format!("{}/v1/auth/mfa/verify", cfg.issuer_trimmed());
    let body = serde_json::json!({
        "challenge": challenge,
        "code": code,
        "remember_device": remember_device,
    });
    // `credentials: include` so the OP session cookie set on the
    // successful verify lands in the browser. Same reason as
    // password_login above.
    let resp = Request::post(&url)
        .credentials(RequestCredentials::Include)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&body)
        .map_err(|e| FlowError::Network(e.to_string()))?
        .send()
        .await
        .map_err(|e| FlowError::Network(e.to_string()))?;
    if !resp.ok() {
        let status = resp.status();
        let raw = resp.text().await.unwrap_or_default();
        let parsed: Option<ErrorBody> = serde_json::from_str(&raw).ok();
        let (err, desc) = match parsed {
            Some(b) => (b.error, b.error_description.unwrap_or_default()),
            None => ("mfa_verify_failed".into(), format!("HTTP {status}")),
        };
        return Err(FlowError::TokenEndpoint {
            error: err,
            description: desc,
        });
    }
    let body: LoginBody = resp
        .json()
        .await
        .map_err(|e| FlowError::Network(format!("verify body: {e}")))?;
    let bundle = body.tokens.ok_or_else(|| FlowError::TokenEndpoint {
        error: "invalid_response".into(),
        description: "verify did not return tokens".into(),
    })?;
    Ok(MfaVerifyOk {
        tokens: Tokens {
            access_token: bundle.access_token,
            id_token: bundle.id_token,
            refresh_token: Some(bundle.refresh_token),
            expires_at: Utc::now() + Duration::seconds(bundle.expires_in.max(0)),
            scope: bundle.scope,
        },
        trust_token: body.trust_token,
    })
}

// --- Authed issuer-targeted helpers (used by the account / admin
// pages in phases 04 / 05). Keep here so the rest of the SPA can
// import a stable shape; mokosh-clients's tree is the reference
// implementation. ----------------------------------------------------

pub async fn issuer_get_authed<T: serde::de::DeserializeOwned>(
    cfg: &OidcConfig,
    path: &str,
) -> Result<T, FlowError> {
    let token = current_access_token().ok_or_else(|| FlowError::Network("not signed in".into()))?;
    let url = format!("{}{path}", cfg.issuer_trimmed());
    let resp = Request::get(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| FlowError::Network(e.to_string()))?;
    if !resp.ok() {
        return Err(FlowError::Network(format!("HTTP {}", resp.status())));
    }
    resp.json::<T>()
        .await
        .map_err(|e| FlowError::Network(format!("body: {e}")))
}

pub async fn issuer_post_authed<T: serde::de::DeserializeOwned, B: serde::Serialize>(
    cfg: &OidcConfig,
    path: &str,
    body: &B,
) -> Result<T, FlowError> {
    let token = current_access_token().ok_or_else(|| FlowError::Network("not signed in".into()))?;
    let url = format!("{}{path}", cfg.issuer_trimmed());
    let resp = Request::post(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(body)
        .map_err(|e| FlowError::Network(e.to_string()))?
        .send()
        .await
        .map_err(|e| FlowError::Network(e.to_string()))?;
    if !resp.ok() {
        let raw = resp.text().await.unwrap_or_default();
        return Err(FlowError::Network(raw));
    }
    resp.json::<T>()
        .await
        .map_err(|e| FlowError::Network(format!("body: {e}")))
}

/// Issuer-authed POST with empty body. Returns Ok(()) on any 2xx;
/// the body is discarded. Used for endpoints that return 204
/// (e.g. `/v1/auth/sessions/{id}/revoke`).
pub async fn issuer_post_authed_empty(cfg: &OidcConfig, path: &str) -> Result<(), FlowError> {
    let token = current_access_token().ok_or_else(|| FlowError::Network("not signed in".into()))?;
    let url = format!("{}{path}", cfg.issuer_trimmed());
    let resp = Request::post(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Length", "0")
        .send()
        .await
        .map_err(|e| FlowError::Network(e.to_string()))?;
    if !resp.ok() {
        return Err(FlowError::Network(format!("HTTP {}", resp.status())));
    }
    Ok(())
}

pub async fn issuer_get<T: serde::de::DeserializeOwned>(
    cfg: &OidcConfig,
    path: &str,
) -> Result<T, FlowError> {
    let url = format!("{}{path}", cfg.issuer_trimmed());
    let resp = Request::get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| FlowError::Network(e.to_string()))?;
    if !resp.ok() {
        let raw = resp.text().await.unwrap_or_default();
        return Err(FlowError::Network(raw));
    }
    resp.json::<T>()
        .await
        .map_err(|e| FlowError::Network(format!("body: {e}")))
}

pub async fn issuer_post<T: serde::de::DeserializeOwned, B: serde::Serialize>(
    cfg: &OidcConfig,
    path: &str,
    body: &B,
) -> Result<T, FlowError> {
    let url = format!("{}{path}", cfg.issuer_trimmed());
    let resp = Request::post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(body)
        .map_err(|e| FlowError::Network(e.to_string()))?
        .send()
        .await
        .map_err(|e| FlowError::Network(e.to_string()))?;
    if !resp.ok() {
        let raw = resp.text().await.unwrap_or_default();
        return Err(FlowError::Network(raw));
    }
    resp.json::<T>()
        .await
        .map_err(|e| FlowError::Network(format!("body: {e}")))
}

// --- Wire shapes -----------------------------------------------------

#[derive(Deserialize)]
struct LoginBody {
    #[serde(default)]
    tokens: Option<LoginTokenBundle>,
    #[serde(default)]
    trust_token: Option<String>,
    #[serde(default)]
    mfa_required: Option<bool>,
    #[serde(default)]
    challenge: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

#[derive(Deserialize)]
struct LoginTokenBundle {
    access_token: String,
    id_token: String,
    refresh_token: String,
    expires_in: i64,
    scope: String,
}

#[derive(Deserialize)]
struct TokenBody {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: i64,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}
impl ErrorBody {
    fn generic(s: &str) -> Self {
        Self {
            error: s.to_string(),
            error_description: None,
        }
    }
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn urlencode(s: &str) -> String {
    let encoded = js_sys::encode_uri_component(s);
    let s: String = encoded.into();
    s.replace("%20", "+")
}
