//! Auth requests against mokosh-server.
//!
//! `password_login` is the single most-used entry point; it lives in
//! `crate::modules::oidc::flow` because it produces a `Tokens` bundle
//! that the AuthContext consumes. The helpers in THIS file are the
//! thinner POST-and-go shapes: signup, password-reset start, signup
//! complete via token. They all return `()` (or echo a small response
//! struct).

use serde::{Deserialize, Serialize};

use super::{post_json, post_json_empty, ApiError};

#[derive(Debug, Serialize)]
pub struct SignupStartRequest {
    pub email: String,
}

/// POST `/v1/auth/signup`. Always 200; the response copy is
/// enumeration-resistant (same regardless of whether the email is
/// already in use). The bunyip SPA shows "We've sent a confirmation
/// link if that email is registerable."
pub async fn signup_start(email: String) -> Result<(), ApiError> {
    post_json_empty("/v1/auth/signup", &SignupStartRequest { email }).await
}

#[derive(Debug, Deserialize)]
pub struct SignupTokenPreview {
    pub email: String,
}

/// GET `/v1/auth/signup/by-token/{token}` - preview the token. 404
/// when the token is unknown / expired / used.
pub async fn signup_preview(token: &str) -> Result<SignupTokenPreview, ApiError> {
    super::get_json(&format!("/v1/auth/signup/by-token/{token}")).await
}

#[derive(Debug, Serialize)]
pub struct SignupCompleteRequest {
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
}

/// POST `/v1/auth/signup/by-token/{token}/complete`. Creates the user
/// + the personal tenant + the owner membership in one SERIALIZABLE
/// tx; future logins go through `password_login` like anyone else.
pub async fn signup_complete(
    token: &str,
    req: &SignupCompleteRequest,
) -> Result<serde_json::Value, ApiError> {
    post_json(
        &format!("/v1/auth/signup/by-token/{token}/complete"),
        req,
    )
    .await
}

#[derive(Debug, Serialize)]
struct ForgotPasswordRequest {
    email: String,
}

/// POST `/v1/auth/password-reset`. Enumeration-resistant; always 200.
pub async fn forgot_password(email: String) -> Result<(), ApiError> {
    post_json_empty(
        "/v1/auth/password-reset",
        &ForgotPasswordRequest { email },
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct ResetPreview {
    pub email: String,
}

/// GET `/v1/auth/password-reset/by-token/{token}`. 404 when bad.
pub async fn reset_preview(token: &str) -> Result<ResetPreview, ApiError> {
    super::get_json(&format!("/v1/auth/password-reset/by-token/{token}")).await
}

#[derive(Debug, Serialize)]
pub struct ResetCompleteRequest {
    pub password: String,
    pub password_confirmation: String,
}

/// POST `/v1/auth/password-reset/by-token/{token}/complete`. Boots
/// every active session for the user on success.
pub async fn reset_complete(
    token: &str,
    req: &ResetCompleteRequest,
) -> Result<serde_json::Value, ApiError> {
    post_json(
        &format!("/v1/auth/password-reset/by-token/{token}/complete"),
        req,
    )
    .await
}

/// POST `/v1/auth/logout` (best-effort). The cookie-based session
/// revoke does nothing on cross-origin fetches without credentials,
/// but the endpoint still cleans up internal bookkeeping when reachable.
pub async fn logout() -> Result<(), ApiError> {
    super::post_authed_empty("/v1/auth/logout", &serde_json::json!({})).await
}
