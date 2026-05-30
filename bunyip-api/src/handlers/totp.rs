//! Two-factor authentication handlers

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::errors::AppError;
use crate::middleware::{extract_client_ip, extract_device_info, AuthCookies, AuthenticatedUser};
use crate::models::{AuditAction, CreateAuditLog, RateLimitConfig};
use crate::repositories::{AuditLogRepository, RateLimitRepository, UserRepository};
use crate::responses::{get_request_id, success};
use crate::services::{AuthService, PasswordService, TotpService};

/// Check rate limit and return RateLimited error if exceeded
async fn check_rate_limit(
    pool: &PgPool,
    key: &str,
    config: &RateLimitConfig,
) -> Result<(), AppError> {
    let (_count, exceeded) = RateLimitRepository::check_and_increment(pool, key, config).await?;
    if exceeded {
        let retry_after = RateLimitRepository::get_retry_after(pool, key, config).await?;
        return Err(AppError::RateLimited { retry_after });
    }
    Ok(())
}

// --- Request/Response types ---

#[derive(Debug, Deserialize)]
pub struct ConfirmSetupRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct Verify2FARequest {
    pub challenge_token: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordConfirmRequest {
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SetupResponse {
    pub otpauth_uri: String,
    pub secret: String,
}

#[derive(Debug, Serialize)]
pub struct RecoveryCodesResponse {
    pub codes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TwoFactorStatusResponse {
    pub enabled: bool,
    pub recovery_codes_remaining: i64,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    user: crate::models::UserResponse,
    expires_in: i64,
}

// --- Handlers ---

/// POST /v1/auth/2fa/setup
/// Begin 2FA setup (authenticated)
pub async fn setup_2fa(
    req: HttpRequest,
    user: AuthenticatedUser,
    totp_service: web::Data<Arc<TotpService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let info = totp_service.begin_setup(user.0.sub, &user.0.email).await?;

    Ok(success(
        SetupResponse {
            otpauth_uri: info.otpauth_uri,
            secret: info.secret,
        },
        request_id,
    ))
}

/// POST /v1/auth/2fa/confirm
/// Confirm 2FA setup with TOTP code (authenticated)
pub async fn confirm_2fa(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    user: AuthenticatedUser,
    totp_service: web::Data<Arc<TotpService>>,
    body: web::Json<ConfirmSetupRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    let codes = totp_service.confirm_setup(user.0.sub, &body.code).await?;

    // Audit log
    let ip = ip_address.map(ipnetwork::IpNetwork::from);
    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::TwoFactorEnabled)
            .with_actor(user.0.sub, &user.0.email, &user.0.role)
            .with_ip(ip),
    )
    .await?;

    Ok(success(RecoveryCodesResponse { codes }, request_id))
}

/// POST /v1/auth/2fa/verify
/// Verify 2FA code to complete login (NO auth required — uses challenge token)
pub async fn verify_2fa(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    totp_service: web::Data<Arc<TotpService>>,
    body: web::Json<Verify2FARequest>,
    config: web::Data<crate::config::Config>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);
    let device_info = extract_device_info(&req);

    // Rate limit by IP
    let ip_key = ip_address.map(|ip| ip.to_string()).unwrap_or_default();
    check_rate_limit(
        &pool,
        &format!("2fa_verify:{}", ip_key),
        &RateLimitConfig::LOGIN,
    )
    .await?;

    // Verify challenge token to get user_id
    let jwt_service = req
        .app_data::<Arc<crate::services::JwtService>>()
        .ok_or(AppError::internal("JWT service not available"))?;
    let claims = jwt_service.verify_2fa_challenge_token(&body.challenge_token)?;
    let user_id = claims.sub;

    // Try TOTP code first, then recovery code
    // Strip spaces so users can enter TOTP as "XXX XXX"
    let code = body.code.trim().replace(' ', "");
    let code = code.as_str();
    let is_recovery = code.contains('-') || code.len() > 6;

    let verified = if is_recovery {
        totp_service.verify_recovery_code(user_id, code).await?
    } else {
        totp_service.verify_code(user_id, code).await?
    };

    if !verified {
        return Err(AppError::validation("code", "Invalid verification code"));
    }

    // Audit the verification
    let ip = ip_address.map(ipnetwork::IpNetwork::from);
    let user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or(AppError::InvalidCredentials)?;

    if is_recovery {
        AuditLogRepository::create(
            &pool,
            CreateAuditLog::new(AuditAction::TwoFactorRecoveryCodeUsed)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;
    } else {
        AuditLogRepository::create(
            &pool,
            CreateAuditLog::new(AuditAction::TwoFactorVerified)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;
    }

    // Complete login
    let (tokens, user_response) = auth_service
        .complete_2fa_login(&body.challenge_token, device_info, ip_address)
        .await?;

    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();

    let response = AuthResponse {
        user: user_response,
        expires_in: tokens.expires_in,
    };

    let mut resp = HttpResponse::Ok();
    for cookie in AuthCookies::clear_stale(secure) {
        resp.cookie(cookie);
    }
    Ok(resp
        .cookie(AuthCookies::access_token(
            &tokens.access_token,
            secure,
            cookie_domain,
        ))
        .cookie(AuthCookies::refresh_token(
            &tokens.refresh_token,
            secure,
            true,
            cookie_domain,
        ))
        .json(crate::responses::ApiResponse {
            success: true,
            data: Some(response),
            meta: crate::responses::ResponseMeta::new(request_id),
        }))
}

/// DELETE /v1/auth/2fa
/// Disable 2FA (authenticated, requires password, blocked for admins)
pub async fn disable_2fa(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    user: AuthenticatedUser,
    totp_service: web::Data<Arc<TotpService>>,
    body: web::Json<PasswordConfirmRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    // Block admins from disabling 2FA
    if user.0.role == "admin" {
        return Err(AppError::Forbidden);
    }

    // Verify password
    let db_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    let password_hash = db_user.password_hash.as_ref().ok_or(AppError::validation(
        "password",
        "No password set for this account",
    ))?;

    let password_service = PasswordService::new();
    if !password_service.verify(&body.password, password_hash)? {
        return Err(AppError::validation("password", "Invalid password"));
    }

    totp_service.disable(user.0.sub).await?;

    // Audit log
    let ip = ip_address.map(ipnetwork::IpNetwork::from);
    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::TwoFactorDisabled)
            .with_actor(user.0.sub, &user.0.email, &user.0.role)
            .with_ip(ip),
    )
    .await?;

    Ok(crate::responses::success_no_data(request_id))
}

/// POST /v1/auth/2fa/recovery-codes
/// Regenerate recovery codes (authenticated, requires password)
pub async fn regenerate_recovery_codes(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    user: AuthenticatedUser,
    totp_service: web::Data<Arc<TotpService>>,
    body: web::Json<PasswordConfirmRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    // Verify password
    let db_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    let password_hash = db_user.password_hash.as_ref().ok_or(AppError::validation(
        "password",
        "No password set for this account",
    ))?;

    let password_service = PasswordService::new();
    if !password_service.verify(&body.password, password_hash)? {
        return Err(AppError::validation("password", "Invalid password"));
    }

    let codes = totp_service.regenerate_recovery_codes(user.0.sub).await?;

    // Audit log
    let ip = ip_address.map(ipnetwork::IpNetwork::from);
    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::TwoFactorRecoveryCodesRegenerated)
            .with_actor(user.0.sub, &user.0.email, &user.0.role)
            .with_ip(ip),
    )
    .await?;

    Ok(success(RecoveryCodesResponse { codes }, request_id))
}

/// GET /v1/auth/2fa/status
/// Get 2FA status (authenticated)
pub async fn get_2fa_status(
    req: HttpRequest,
    user: AuthenticatedUser,
    totp_service: web::Data<Arc<TotpService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let enabled = totp_service.is_enabled(user.0.sub).await?;
    let recovery_codes_remaining = if enabled {
        totp_service.recovery_codes_remaining(user.0.sub).await?
    } else {
        0
    };

    Ok(success(
        TwoFactorStatusResponse {
            enabled,
            recovery_codes_remaining,
        },
        request_id,
    ))
}
