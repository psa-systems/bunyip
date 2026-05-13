//! Typed API client for `bunyip-api`.
//!
//! All calls go through the same-origin dev proxy (`/v1/...`) declared in
//! `Dioxus.toml`. Cookies travel automatically when `credentials = "same-origin"`.

pub mod auth;
pub mod billing;
pub mod feedback;
pub mod me;
pub mod orgs;
pub mod types;

use gloo_net::http::{Request, RequestBuilder};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// One place to set common request behavior (credentials, content-type).
pub fn request(method: &str, path: &str) -> RequestBuilder {
    let url = path.to_string();
    let b = match method {
        "GET" => Request::get(&url),
        "POST" => Request::post(&url),
        "PUT" => Request::put(&url),
        "PATCH" => Request::patch(&url),
        "DELETE" => Request::delete(&url),
        _ => Request::get(&url),
    };
    b.credentials(web_sys::RequestCredentials::SameOrigin)
}

#[derive(Debug, Clone)]
pub enum ApiError {
    Network(String),
    Status { status: u16, message: String },
    Decode(String),
}

impl ApiError {
    pub fn user_message(&self) -> String {
        match self {
            ApiError::Network(_) => "Network error - check your connection.".into(),
            ApiError::Status { status: 401, .. } => "Email or password didn't match.".into(),
            ApiError::Status { status: 409, message } => message.clone(),
            ApiError::Status { status: 400, message } => message.clone(),
            ApiError::Status { message, .. } => message.clone(),
            ApiError::Decode(_) => "Server returned an unexpected response.".into(),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct ErrorBody {
    error: ErrorBodyInner,
}

#[derive(Debug, serde::Deserialize)]
struct ErrorBodyInner {
    #[allow(dead_code)]
    code: String,
    message: String,
}

pub async fn post_json<T: Serialize, R: DeserializeOwned>(
    path: &str,
    body: &T,
) -> Result<R, ApiError> {
    let resp = request("POST", path)
        .json(body)
        .map_err(|e| ApiError::Decode(e.to_string()))?
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    handle_response(resp).await
}

pub async fn get_json<R: DeserializeOwned>(path: &str) -> Result<R, ApiError> {
    let resp = request("GET", path)
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    handle_response(resp).await
}

pub async fn post_empty(path: &str) -> Result<(), ApiError> {
    let resp = request("POST", path)
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
    let resp = request("POST", path)
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

async fn handle_response<R: DeserializeOwned>(resp: gloo_net::http::Response) -> Result<R, ApiError> {
    if resp.ok() {
        resp.json::<R>().await.map_err(|e| ApiError::Decode(e.to_string()))
    } else {
        Err(error_from_response(resp).await)
    }
}

pub async fn error_from_response_pub(resp: gloo_net::http::Response) -> ApiError {
    error_from_response(resp).await
}

async fn error_from_response(resp: gloo_net::http::Response) -> ApiError {
    let status = resp.status();
    let message = match resp.json::<ErrorBody>().await {
        Ok(b) => b.error.message,
        Err(_) => format!("Request failed ({status})"),
    };
    ApiError::Status { status, message }
}
