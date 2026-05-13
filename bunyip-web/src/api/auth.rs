use serde::{Deserialize, Serialize};

use super::types::User;
use super::{post_empty, post_json, post_json_empty, ApiError};

#[derive(Debug, Serialize)]
pub struct SignupRequest {
    pub email: String,
    pub name: String,
    pub password: String,
    pub org_name: String,
}

#[derive(Debug, Deserialize)]
pub struct SignupResponse {
    pub user: User,
    pub verification_link: String,
}

pub async fn signup(req: &SignupRequest) -> Result<SignupResponse, ApiError> {
    post_json("/v1/auth/signup", req).await
}

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub user: User,
    pub requires_mfa: bool,
}

pub async fn login(req: &LoginRequest) -> Result<LoginResponse, ApiError> {
    post_json("/v1/auth/login", req).await
}

pub async fn logout() -> Result<(), ApiError> {
    post_empty("/v1/auth/logout").await
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

pub async fn verify_email(token: String) -> Result<(), ApiError> {
    post_json_empty("/v1/auth/verify-email", &VerifyEmailRequest { token }).await
}

#[derive(Debug, Serialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

pub async fn totp_verify(code: String) -> Result<User, ApiError> {
    post_json("/v1/auth/totp/verify", &TotpVerifyRequest { code }).await
}

#[derive(Debug, Serialize)]
pub struct MagicLinkRequest {
    pub email: String,
}

pub async fn magic_link_request(email: String) -> Result<(), ApiError> {
    post_json_empty("/v1/auth/magic-link/request", &MagicLinkRequest { email }).await
}

#[derive(Debug, Serialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

pub async fn forgot_password(email: String) -> Result<(), ApiError> {
    post_json_empty("/v1/auth/forgot-password", &ForgotPasswordRequest { email }).await
}
