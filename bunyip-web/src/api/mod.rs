//! Typed API client for the Mokosh-server identity backend.
//!
//! Every call hits the absolute mokosh-server URL configured at build
//! time via `BUNYIP_OIDC_ISSUER`. Bearer auth on every authed call:
//! the access_token lives in memory (`stores::tokens::CURRENT_ACCESS_TOKEN`)
//! and is mirrored to localStorage under `bunyip.tokens` for refresh
//! on reload.
//!
//! We deliberately do NOT set `credentials: 'include'` on the fetch:
//! mokosh-server's CORS is `allow_origin(Any)` and incompatible with
//! credentials. The Bearer-token-on-fetch model is what crosses
//! origins.

pub mod admin;
pub mod apps;
pub mod auth;
pub mod billing;
pub mod feedback;
pub mod me;
pub mod orgs;
pub mod tenants;
pub mod types;

use gloo_net::http::{Request, RequestBuilder};
use serde::de::DeserializeOwned;
use serde::Serialize;
use web_sys::RequestCredentials;

use crate::stores::config::OidcConfig;
use crate::stores::tokens::current_access_token;

/// Resolve a relative path (e.g. `/v1/auth/me`) against the configured
/// mokosh-server issuer URL.
pub fn issuer_url(path: &str) -> String {
    let issuer = OidcConfig::from_env().issuer_trimmed().to_string();
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!("{issuer}{path}")
    }
}

fn base_builder(method: &str, path: &str) -> RequestBuilder {
    let url = issuer_url(path);
    let b = match method {
        "GET" => Request::get(&url),
        "POST" => Request::post(&url),
        "PUT" => Request::put(&url),
        "PATCH" => Request::patch(&url),
        "DELETE" => Request::delete(&url),
        _ => Request::get(&url),
    };
    // `credentials: include` so the cross-origin OP session cookie
    // mokosh-server sets on /v1/auth/login (and clears on
    // /v1/auth/logout, /v1/auth/mfa/verify) actually lands in the
    // browser. mokosh-server's CORS layer matches with
    // `allow_credentials(true) + AllowOrigin::mirror_request()` so the
    // Set-Cookie + Allow-Origin pair satisfy the browser's
    // credentialed-CORS rules. Bearer-token-on-fetch still authorises
    // the request; the cookie just tags along where it is meaningful.
    b.credentials(RequestCredentials::Include)
        .header("Accept", "application/json")
}

fn authed(builder: RequestBuilder) -> Result<RequestBuilder, ApiError> {
    let token = current_access_token().ok_or(ApiError::NotAuthenticated)?;
    Ok(builder.header("Authorization", &format!("Bearer {token}")))
}

/// Backwards-compat shim for the DELETE / PATCH callers that built
/// their own RequestBuilder against the migrate branch's same-origin
/// helper. New code should use the typed helpers below; orgs.rs and
/// feedback.rs will move off this once their endpoints are rewired
/// in phases 04 / 05.
pub fn request(method: &str, path: &str) -> RequestBuilder {
    let b = base_builder(method, path);
    // Best-effort auth: silently omit the header if there is no
    // token yet. The callers always check `resp.ok()` and surface
    // 401 as an error.
    if let Some(token) = current_access_token() {
        b.header("Authorization", &format!("Bearer {token}"))
    } else {
        b
    }
}

#[derive(Debug, Clone)]
pub enum ApiError {
    Network(String),
    NotAuthenticated,
    Status { status: u16, message: String },
    Decode(String),
}

impl ApiError {
    /// Bucket an `ApiError` into an `ErrorVariant` for `ErrorCard`.
    /// 404 means the surface exists but the endpoint isn't wired yet
    /// (ComingSoon); 5xx + network blips are transient (Retryable);
    /// everything else is terminal (HardError).
    pub fn variant(&self) -> crate::components::error_card::ErrorVariant {
        use crate::components::error_card::ErrorVariant;
        match self {
            ApiError::Status { status: 404, .. } => ErrorVariant::ComingSoon,
            ApiError::Status { status, .. } if *status >= 500 => ErrorVariant::Retryable,
            ApiError::Network(_) => ErrorVariant::Retryable,
            _ => ErrorVariant::HardError,
        }
    }

    pub fn user_message(&self) -> String {
        match self {
            ApiError::Network(_) => "Network error - check your connection.".into(),
            ApiError::NotAuthenticated => "You are signed out.".into(),
            ApiError::Status { status: 401, .. } => {
                "Your session expired. Please sign in again.".into()
            }
            ApiError::Status {
                status: 409,
                message,
            } => message.clone(),
            ApiError::Status {
                status: 400,
                message,
            } => message.clone(),
            ApiError::Status { message, .. } => message.clone(),
            ApiError::Decode(_) => "Server returned an unexpected response.".into(),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
    /// Field-level errors emitted by `mokosh-auth-http` (e.g. password
    /// policy reject on signup-by-token returns
    /// `{ "error": "invalid_request", "details": { "password": "..." } }`).
    /// Surfaced to the user when present.
    #[serde(default)]
    details: Option<ErrorDetails>,
}

#[derive(Debug, serde::Deserialize)]
struct ErrorDetails {
    #[serde(default)]
    password: Option<String>,
}

pub async fn post_json<T: Serialize, R: DeserializeOwned>(
    path: &str,
    body: &T,
) -> Result<R, ApiError> {
    let resp = base_builder("POST", path)
        .json(body)
        .map_err(|e| ApiError::Decode(e.to_string()))?
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    handle_response(resp).await
}

pub async fn get_json<R: DeserializeOwned>(path: &str) -> Result<R, ApiError> {
    let resp = base_builder("GET", path)
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    handle_response(resp).await
}

pub async fn get_authed<R: DeserializeOwned>(path: &str) -> Result<R, ApiError> {
    let resp = authed(base_builder("GET", path))?
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    // If the access token went stale (background refresh loop missed
    // expiry due to tab suspend / system sleep / clock skew), attempt
    // a single refresh + retry transparently before surfacing 401 to
    // the user. authed() picks up the rotated token via
    // current_access_token() after force_refresh saved it.
    if resp.status() == 401
        && crate::stores::auth::try_refresh_access_token()
            .await
            .is_some()
    {
        let retry = authed(base_builder("GET", path))?
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        return handle_response(retry).await;
    }
    handle_response(resp).await
}

pub async fn post_authed<T: Serialize, R: DeserializeOwned>(
    path: &str,
    body: &T,
) -> Result<R, ApiError> {
    let resp = authed(base_builder("POST", path))?
        .json(body)
        .map_err(|e| ApiError::Decode(e.to_string()))?
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    if resp.status() == 401
        && crate::stores::auth::try_refresh_access_token()
            .await
            .is_some()
    {
        let retry = authed(base_builder("POST", path))?
            .json(body)
            .map_err(|e| ApiError::Decode(e.to_string()))?
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        return handle_response(retry).await;
    }
    handle_response(resp).await
}

pub async fn put_authed<T: Serialize, R: DeserializeOwned>(
    path: &str,
    body: &T,
) -> Result<R, ApiError> {
    let resp = authed(base_builder("PUT", path))?
        .json(body)
        .map_err(|e| ApiError::Decode(e.to_string()))?
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    handle_response(resp).await
}

pub async fn post_empty(path: &str) -> Result<(), ApiError> {
    let resp = base_builder("POST", path)
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(error_from_response(resp).await)
    }
}

pub async fn post_authed_empty<T: Serialize>(path: &str, body: &T) -> Result<(), ApiError> {
    let resp = authed(base_builder("POST", path))?
        .json(body)
        .map_err(|e| ApiError::Decode(e.to_string()))?
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(error_from_response(resp).await)
    }
}

/// POST a JSON body and discard the success response body.
pub async fn post_json_empty<T: Serialize>(path: &str, body: &T) -> Result<(), ApiError> {
    let resp = base_builder("POST", path)
        .json(body)
        .map_err(|e| ApiError::Decode(e.to_string()))?
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(error_from_response(resp).await)
    }
}

async fn handle_response<R: DeserializeOwned>(
    resp: gloo_net::http::Response,
) -> Result<R, ApiError> {
    if resp.ok() {
        resp.json::<R>()
            .await
            .map_err(|e| ApiError::Decode(e.to_string()))
    } else {
        Err(error_from_response(resp).await)
    }
}

pub async fn error_from_response_pub(resp: gloo_net::http::Response) -> ApiError {
    error_from_response(resp).await
}

async fn error_from_response(resp: gloo_net::http::Response) -> ApiError {
    let status = resp.status();
    // mokosh-server's error envelope is `{ "error": "code",
    // "error_description": "human text" }`. The migrate-branch's
    // bunyip-api used `{ "error": { "code": ..., "message": ... } }`;
    // we now talk to mokosh-server so accept the new shape.
    let message = match resp.json::<ErrorBody>().await {
        Ok(b) => b
            .details
            .as_ref()
            .and_then(|d| d.password.clone())
            .or(b.error_description)
            .or(b.error)
            .unwrap_or_else(|| format!("Request failed ({status})")),
        Err(_) => format!("Request failed ({status})"),
    };
    ApiError::Status { status, message }
}
