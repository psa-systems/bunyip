//! Mock auth endpoints. All state lives in `bunyip-mocks::MockStore` and resets
//! on container restart. Real implementations move to Mokosh Server post-MVP -
//! see `For AI/bunyip-feature-sso-port-notes.md`.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use bunyip_mocks::{AuditLog, User};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tower_cookies::{cookie::time::Duration as CookieDuration, cookie::SameSite, Cookie, Cookies};
use tracing::info;
use uuid::Uuid;
use validator::Validate;

use crate::errors::AppError;
use crate::state::AppState;

pub const SESSION_COOKIE: &str = "bunyip_session";
const CHALLENGE_COOKIE: &str = "bunyip_2fa_challenge";
const TRUSTED_DEVICE_COOKIE: &str = "bunyip_trusted_device";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/signup", post(signup))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/refresh", post(refresh))
        .route("/v1/auth/verify-email", post(verify_email))
        .route("/v1/auth/resend-verification", post(resend_verification))
        .route("/v1/auth/forgot-password", post(forgot_password))
        .route("/v1/auth/reset-password", post(reset_password))
        .route("/v1/auth/magic-link/request", post(magic_link_request))
        .route("/v1/auth/magic-link/consume", get(magic_link_consume))
        .route("/v1/auth/totp/setup", post(totp_setup))
        .route("/v1/auth/totp/verify-setup", post(totp_verify_setup))
        .route("/v1/auth/totp/disable", post(totp_disable))
        .route("/v1/auth/totp/verify", post(totp_verify))
        .route("/v1/auth/totp/recovery-codes/regenerate", post(totp_regenerate_codes))
        .route("/v1/auth/trusted-devices", get(list_trusted_devices).post(trust_device))
        .route("/v1/auth/trusted-devices/{id}", delete(revoke_trusted_device))
}

// --- Helpers ---

pub fn current_user_id(cookies: &Cookies) -> Option<Uuid> {
    cookies
        .get(SESSION_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok())
}

fn session_cookie(user_id: String) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, user_id))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::days(30))
        .build()
}

fn challenge_cookie(user_id: String) -> Cookie<'static> {
    Cookie::build((CHALLENGE_COOKIE, user_id))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::minutes(10))
        .build()
}

fn audit(action: &str, actor: Option<Uuid>, target: Option<&str>) -> AuditLog {
    AuditLog {
        id: Uuid::new_v4(),
        actor_user_id: actor,
        org_id: None,
        action: action.to_string(),
        target: target.map(|s| s.to_string()),
        ip: None,
        user_agent: None,
        is_admin_action: false,
        ts: Utc::now(),
    }
}

fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

// --- Signup ---

#[derive(Debug, Deserialize, Validate)]
pub struct SignupRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 2, max = 200))]
    pub name: String,
    #[validate(length(min = 1))]
    pub password: String,
    #[validate(length(min = 2, max = 100))]
    pub org_name: String,
}

#[derive(Debug, Serialize)]
pub struct SignupResponse {
    pub user: User,
    pub verification_link: String,
}

async fn signup(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(body): Json<SignupRequest>,
) -> Result<(StatusCode, Json<SignupResponse>), AppError> {
    body.validate().map_err(|e| AppError::BadRequest(e.to_string()))?;

    let mut store = state.store.write();
    if store.email_taken(&body.email) {
        return Err(AppError::Conflict("email already in use".into()));
    }

    let user = store.create_user(body.email.clone(), body.name.clone(), false);

    let base_slug = slugify(&body.org_name);
    let mut slug = base_slug.clone();
    let mut suffix = 1;
    while store.org_by_slug(&slug).is_some() {
        suffix += 1;
        slug = format!("{base_slug}-{suffix}");
    }
    let _org = store.create_org(slug, body.org_name.clone(), user.id);

    store.log_audit(audit("auth.signup", Some(user.id), Some(&body.email)));

    // Mock "verification email": print a clickable link to dev logs. The token
    // is the user_id - good enough for the demo loop, but never use this shape
    // for real signups.
    let verification_link = format!(
        "{}/verify-email?token={}",
        state.config.public_base_url, user.id
    );
    info!(email = %body.email, link = %verification_link, "mock verification email sent");

    cookies.add(session_cookie(user.id.to_string()));

    Ok((
        StatusCode::CREATED,
        Json(SignupResponse {
            user,
            verification_link,
        }),
    ))
}

// --- Login ---

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user: User,
    pub requires_mfa: bool,
}

async fn login(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let expected = state.config.mock_password.clone();
    if expected.is_empty() || body.password != expected {
        return Err(AppError::Unauthorized);
    }
    let user = state
        .store
        .read()
        .find_user_by_email(&body.email)
        .ok_or(AppError::Unauthorized)?;

    let mut store = state.store.write();
    if user.mfa_enabled && !device_is_trusted(&cookies, user.id) {
        cookies.add(challenge_cookie(user.id.to_string()));
        store.log_audit(audit("auth.login.mfa_required", Some(user.id), Some(&user.email)));
        return Ok(Json(LoginResponse {
            user,
            requires_mfa: true,
        }));
    }

    cookies.add(session_cookie(user.id.to_string()));
    store.log_audit(audit("auth.login.success", Some(user.id), Some(&user.email)));
    Ok(Json(LoginResponse {
        user,
        requires_mfa: false,
    }))
}

fn device_is_trusted(_cookies: &Cookies, _user_id: Uuid) -> bool {
    // MVP placeholder. Phase 3c will check `bunyip_trusted_device` against
    // the user's trusted-devices list in the mock store.
    false
}

async fn logout(State(state): State<AppState>, cookies: Cookies) -> StatusCode {
    if let Some(uid) = current_user_id(&cookies) {
        state.store.write().log_audit(audit("auth.logout", Some(uid), None));
    }
    cookies.remove(Cookie::build(SESSION_COOKIE).path("/").build());
    cookies.remove(Cookie::build(CHALLENGE_COOKIE).path("/").build());
    StatusCode::NO_CONTENT
}

async fn refresh(cookies: Cookies) -> StatusCode {
    if cookies.get(SESSION_COOKIE).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::UNAUTHORIZED
    }
}

// --- Email verification ---

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

async fn verify_email(
    State(state): State<AppState>,
    Json(body): Json<VerifyEmailRequest>,
) -> Result<StatusCode, AppError> {
    let user_id = Uuid::parse_str(&body.token).map_err(|_| AppError::BadRequest("invalid token".into()))?;
    let mut store = state.store.write();
    if !store.verify_user_email(user_id) {
        return Err(AppError::NotFound);
    }
    store.log_audit(audit("auth.email.verified", Some(user_id), None));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

async fn resend_verification(
    State(state): State<AppState>,
    Json(body): Json<ResendVerificationRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user = state
        .store
        .read()
        .find_user_by_email(&body.email)
        .ok_or(AppError::NotFound)?;
    let link = format!(
        "{}/verify-email?token={}",
        state.config.public_base_url, user.id
    );
    info!(email = %body.email, link = %link, "mock verification email resent");
    Ok(Json(serde_json::json!({ "verification_link": link })))
}

// --- Password reset (mock) ---

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

async fn forgot_password(
    State(state): State<AppState>,
    Json(body): Json<ForgotPasswordRequest>,
) -> Json<serde_json::Value> {
    if let Some(user) = state.store.read().find_user_by_email(&body.email) {
        let link = format!(
            "{}/reset-password?token={}",
            state.config.public_base_url, user.id
        );
        info!(email = %body.email, link = %link, "mock password reset email sent");
    }
    // Always return success; don't reveal account existence.
    Json(serde_json::json!({ "status": "sent" }))
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    #[allow(dead_code)]
    pub password: String,
}

async fn reset_password(
    State(state): State<AppState>,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<StatusCode, AppError> {
    let user_id = Uuid::parse_str(&body.token).map_err(|_| AppError::BadRequest("invalid token".into()))?;
    let mut store = state.store.write();
    if store.find_user(user_id).is_none() {
        return Err(AppError::NotFound);
    }
    store.log_audit(audit("auth.password.reset", Some(user_id), None));
    Ok(StatusCode::NO_CONTENT)
}

// --- Magic link (mock) ---

#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
}

async fn magic_link_request(
    State(state): State<AppState>,
    Json(body): Json<MagicLinkRequest>,
) -> Json<serde_json::Value> {
    if let Some(user) = state.store.read().find_user_by_email(&body.email) {
        let link = format!(
            "{}/v1/auth/magic-link/consume?token={}",
            state.config.public_base_url, user.id
        );
        info!(email = %body.email, link = %link, "mock magic-link email sent");
    }
    Json(serde_json::json!({ "status": "sent" }))
}

#[derive(Debug, Deserialize)]
pub struct MagicLinkConsumeQuery {
    pub token: String,
}

async fn magic_link_consume(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(q): Query<MagicLinkConsumeQuery>,
) -> Result<axum::response::Redirect, AppError> {
    let user_id = Uuid::parse_str(&q.token).map_err(|_| AppError::BadRequest("invalid token".into()))?;
    let user = state
        .store
        .read()
        .find_user(user_id)
        .ok_or(AppError::NotFound)?;
    cookies.add(session_cookie(user.id.to_string()));
    state.store.write().log_audit(audit("auth.magic_link.consumed", Some(user.id), None));
    Ok(axum::response::Redirect::to("/dashboard"))
}

// --- TOTP (mock) ---

#[derive(Debug, Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub otpauth_url: String,
}

async fn totp_setup(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Json<TotpSetupResponse>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let user = state.store.read().find_user(uid).ok_or(AppError::Unauthorized)?;
    // A hard-coded mock secret (base32-ish). Real implementation moves to
    // Mokosh Server.
    let secret = "JBSWY3DPEHPK3PXP".to_string();
    let otpauth_url = format!(
        "otpauth://totp/Bunyip:{}?secret={}&issuer=Bunyip",
        user.email, secret
    );
    Ok(Json(TotpSetupResponse { secret, otpauth_url }))
}

#[derive(Debug, Deserialize)]
pub struct TotpVerifySetupRequest {
    pub code: String,
}

async fn totp_verify_setup(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(body): Json<TotpVerifySetupRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    if !is_valid_mock_totp(&state.config.mock_totp_code, &body.code) {
        return Err(AppError::Unauthorized);
    }
    let mut store = state.store.write();
    if let Some(user) = store.users.iter_mut().find(|u| u.id == uid) {
        user.mfa_enabled = true;
    }
    let recovery_codes: Vec<String> = (1..=10)
        .map(|i| format!("bunyip-mock-{i:02}-{}", &uid.to_string()[..6]))
        .collect();
    store.log_audit(audit("auth.totp.enabled", Some(uid), None));
    Ok(Json(serde_json::json!({ "recovery_codes": recovery_codes })))
}

async fn totp_disable(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<StatusCode, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    if let Some(user) = store.users.iter_mut().find(|u| u.id == uid) {
        user.mfa_enabled = false;
    }
    store.log_audit(audit("auth.totp.disabled", Some(uid), None));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

async fn totp_verify(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(body): Json<TotpVerifyRequest>,
) -> Result<Json<User>, AppError> {
    let challenge = cookies
        .get(CHALLENGE_COOKIE)
        .ok_or(AppError::Unauthorized)?;
    let user_id = Uuid::parse_str(challenge.value()).map_err(|_| AppError::Unauthorized)?;
    if !is_valid_mock_totp(&state.config.mock_totp_code, &body.code) {
        return Err(AppError::Unauthorized);
    }
    let user = state.store.read().find_user(user_id).ok_or(AppError::Unauthorized)?;
    cookies.remove(Cookie::build(CHALLENGE_COOKIE).path("/").build());
    cookies.add(session_cookie(user.id.to_string()));
    state.store.write().log_audit(audit("auth.totp.verified", Some(user.id), None));
    Ok(Json(user))
}

fn is_valid_mock_totp(expected: &str, code: &str) -> bool {
    if code == expected {
        return true;
    }
    // Dev convenience: accept any 6-digit code so the demo doesn't require a
    // real authenticator app.
    code.len() == 6 && code.chars().all(|c| c.is_ascii_digit())
}

async fn totp_regenerate_codes(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Json<serde_json::Value>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    state.store.write().log_audit(audit("auth.totp.recovery_codes.regenerate", Some(uid), None));
    let recovery_codes: Vec<String> = (1..=10)
        .map(|i| format!("bunyip-mock-{i:02}-{}", &uid.to_string()[..6]))
        .collect();
    Ok(Json(serde_json::json!({ "recovery_codes": recovery_codes })))
}

// --- Trusted devices (placeholder until Phase 3c) ---

async fn list_trusted_devices() -> Json<Vec<serde_json::Value>> {
    Json(vec![])
}

async fn trust_device(cookies: Cookies) -> StatusCode {
    cookies.add(
        Cookie::build((TRUSTED_DEVICE_COOKIE, "yes"))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(CookieDuration::days(30))
            .build(),
    );
    StatusCode::NO_CONTENT
}

async fn revoke_trusted_device() -> StatusCode {
    StatusCode::NO_CONTENT
}
