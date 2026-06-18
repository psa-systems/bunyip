//! User handlers
//!
//! This module contains HTTP handlers for user management endpoints.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;
use tokio;

use crate::errors::AppError;
use crate::middleware::{extract_client_ip, AuthCookies, AuthenticatedUser};
use crate::models::{
    AuditAction, CreateAuditLog, SubscriptionTier, TrustedDeviceInfo, UserResponse,
};
use crate::repositories::{
    AuditLogRepository, TokenRepository, TrustedDeviceRepository, UserRepository,
};
use crate::responses::{get_request_id, success, success_no_data};
use crate::services::{AuthService, EmailService, PasswordService, StripeService, TotpService};
use crate::validation::validate_email;

/// Request body for deleting account
#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
    pub totp_code: Option<String>,
}

/// Request body for changing password
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
    /// Fresh TOTP/recovery code, required when the account has 2FA (BUNYIP-138).
    #[serde(default)]
    pub totp_code: Option<String>,
}

/// Request body for requesting email change
#[derive(Debug, Deserialize)]
pub struct RequestEmailChangeBody {
    pub new_email: String,
    pub current_password: Option<String>,
    /// Fresh TOTP/recovery code, required when the account has 2FA (BUNYIP-138).
    #[serde(default)]
    pub totp_code: Option<String>,
}

/// Request body for confirming email change
#[derive(Debug, Deserialize)]
pub struct ConfirmEmailChangeBody {
    pub token: String,
}

/// Request body for confirming email verification
#[derive(Debug, Deserialize)]
pub struct ConfirmEmailVerificationBody {
    pub token: String,
}

/// GET /v1/users/me
/// Get current user profile
pub async fn get_current_user(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Get fresh user data from database
    let user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    Ok(success(UserResponse::from(user), request_id))
}

/// BUNYIP-139 (slice A of BUNYIP-103): request body for `PUT /v1/users/me/profile`.
/// Each `Option<String>` reads as: present + non-empty after trim -> write the
/// value; present + empty / whitespace-only -> clear to NULL; absent -> leave
/// the column unchanged. Length is bounded at 64 chars per column to match
/// the DB CHECK constraint and return a clean 400 instead of a 500.
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
}

const PROFILE_FIELD_MAX_LEN: usize = 64;

fn normalize_profile_field(
    field: &str,
    raw: &Option<String>,
) -> Result<Option<Option<String>>, AppError> {
    // None at the JSON level = "leave the column unchanged" (outer None).
    // Some + empty after trim = "clear to NULL" (Some(None)).
    // Some + non-empty after trim = "write the trimmed value" (Some(Some)).
    match raw {
        None => Ok(None),
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(Some(None))
            } else if trimmed.chars().count() > PROFILE_FIELD_MAX_LEN {
                Err(AppError::validation(
                    field,
                    format!("{field} must be {PROFILE_FIELD_MAX_LEN} characters or fewer"),
                ))
            } else {
                Ok(Some(Some(trimmed.to_string())))
            }
        }
    }
}

/// PUT /v1/users/me/profile (BUNYIP-139)
///
/// Persist the optional first_name / last_name / phone columns. Fields absent
/// from the request body are left unchanged; fields present + empty are
/// cleared to NULL. Over-length input returns 400, not 500.
///
/// No OIDC claim emission yet - that lands in BUNYIP-140 alongside the
/// `profile` + `phone` scope plumbing.
pub async fn update_current_user_profile(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    body: web::Json<UpdateProfileRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let first_name = normalize_profile_field("first_name", &body.first_name)?;
    let last_name = normalize_profile_field("last_name", &body.last_name)?;
    let phone = normalize_profile_field("phone", &body.phone)?;

    let current = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    let next_first = first_name.unwrap_or(current.first_name.clone());
    let next_last = last_name.unwrap_or(current.last_name.clone());
    let next_phone = phone.unwrap_or(current.phone.clone());

    let updated = UserRepository::update_profile(
        &pool,
        user.0.sub,
        next_first.as_deref(),
        next_last.as_deref(),
        next_phone.as_deref(),
    )
    .await?;

    Ok(success(UserResponse::from(updated), request_id))
}

/// PUT /v1/users/me/password
/// Change current user's password
pub async fn change_password(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    email_service: web::Data<Arc<EmailService>>,
    totp_service: web::Data<Arc<TotpService>>,
    body: web::Json<ChangePasswordRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    // Sensitive op: require a fresh TOTP code when 2FA is on (BUNYIP-138).
    crate::handlers::require_totp_if_enabled(
        &pool,
        &totp_service,
        user.0.sub,
        body.totp_code.as_deref(),
    )
    .await?;

    auth_service
        .change_password(
            user.0.sub,
            body.current_password.clone(),
            body.new_password.clone(),
            ip_address,
        )
        .await?;

    // Send password changed notification email (in background, don't wait)
    let email = user.0.email.clone();
    let email_svc = email_service.get_ref().clone();
    tokio::spawn(async move {
        if let Err(e) = email_svc.send_password_changed(&email).await {
            tracing::error!(error = %e, email = %email, "Failed to send password changed email");
        }
    });

    Ok(success_no_data(request_id))
}

/// GET /v1/users/me/sessions
/// List active sessions for current user.
///
/// The `current` flag marks the session the presented refresh-token cookie
/// belongs to, so the UI can label and protect it (BUNYIP-137). The stored
/// `token_hash` is never returned.
pub async fn list_sessions(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Hash the caller's refresh-token cookie (if present) to match it to its
    // stored row without exposing any hashes to the client.
    let current_hash = req
        .cookie("refresh_token")
        .map(|c| auth_service.hash_token(c.value()));

    let tokens = TokenRepository::find_user_refresh_tokens(&pool, user.0.sub).await?;

    // Map to response format (hide sensitive fields)
    let sessions: Vec<_> = tokens
        .into_iter()
        .map(|t| {
            let current = current_hash.as_deref() == Some(t.token_hash.as_str());
            serde_json::json!({
                "id": t.id,
                "device_info": t.device_info,
                "ip_address": t.ip_address.map(|ip| ip.ip().to_string()),
                "created_at": t.created_at,
                "last_used_at": t.last_used_at,
                "current": current,
            })
        })
        .collect();

    Ok(success(
        serde_json::json!({ "sessions": sessions }),
        request_id,
    ))
}

/// DELETE /v1/users/me/sessions/{session_id}
/// Revoke a specific session
pub async fn revoke_session(
    req: HttpRequest,
    user: AuthenticatedUser,
    path: web::Path<uuid::Uuid>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let session_id = path.into_inner();

    // Find the token and verify it belongs to the user
    let token = TokenRepository::find_refresh_token_by_id(&pool, session_id)
        .await?
        .ok_or(AppError::not_found("Session"))?;

    if token.user_id != user.0.sub {
        return Err(AppError::Forbidden);
    }

    // Revoke the token
    TokenRepository::revoke_refresh_token(&pool, session_id).await?;

    Ok(success_no_data(request_id))
}

/// POST /v1/users/me/sessions/revoke-others
/// Revoke every active session for the current user except the one the
/// presented refresh-token cookie belongs to ("log out all other devices",
/// BUNYIP-137).
pub async fn revoke_other_sessions(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let current_hash = match req
        .cookie("refresh_token")
        .map(|c| auth_service.hash_token(c.value()))
    {
        Some(h) => h,
        None => return Err(AppError::Unauthorized),
    };

    let sessions = TokenRepository::find_user_refresh_tokens(&pool, user.0.sub).await?;
    let keep_id = sessions
        .iter()
        .find(|t| t.token_hash == current_hash)
        .map(|t| t.id);

    // If the current session cannot be located among active rows (e.g. it was
    // just rotated), fall back to a nil keep-id, which revokes every session.
    // The caller is then logged out on their next refresh and re-authenticates.
    let keep = keep_id.unwrap_or_else(uuid::Uuid::nil);
    let revoked =
        TokenRepository::revoke_other_user_refresh_tokens(pool.get_ref(), user.0.sub, keep).await?;

    Ok(success(
        serde_json::json!({ "revoked": revoked }),
        request_id,
    ))
}

/// POST /v1/users/me/email
/// Request email change
pub async fn request_email_change(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    email_service: web::Data<Arc<EmailService>>,
    totp_service: web::Data<Arc<TotpService>>,
    body: web::Json<RequestEmailChangeBody>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    // Validate email format
    validate_email(&body.new_email)?;

    // Sensitive op: require a fresh TOTP code when 2FA is on (BUNYIP-138).
    crate::handlers::require_totp_if_enabled(
        &pool,
        &totp_service,
        user.0.sub,
        body.totp_code.as_deref(),
    )
    .await?;

    let (_old_email, token) = auth_service
        .request_email_change(
            user.0.sub,
            body.new_email.clone(),
            body.current_password.clone(),
            ip_address,
        )
        .await?;

    match token {
        Some(token) => {
            // Verified user: send verification email to new address
            let new_email = body.new_email.clone();
            let email_svc = email_service.get_ref().clone();
            tokio::spawn(async move {
                if let Err(e) = email_svc.send_email_change_verify(&new_email, &token).await {
                    tracing::error!(error = %e, email = %new_email, "Failed to send email change verification");
                }
            });

            Ok(success(
                serde_json::json!({ "message": "Verification email sent to your new address. Please check your inbox.", "requires_relogin": false }),
                request_id,
            ))
        }
        None => {
            // Unverified user: email changed immediately, sessions revoked
            Ok(success(
                serde_json::json!({ "message": "Email address updated successfully. Please log in with your new email.", "requires_relogin": true }),
                request_id,
            ))
        }
    }
}

/// POST /v1/users/me/email/confirm
/// Confirm email change (token-based, no auth required)
pub async fn confirm_email_change(
    req: HttpRequest,
    auth_service: web::Data<Arc<AuthService>>,
    email_service: web::Data<Arc<EmailService>>,
    body: web::Json<ConfirmEmailChangeBody>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    let (old_email, new_email) = auth_service
        .confirm_email_change(body.token.clone(), ip_address)
        .await?;

    // Send notification to old email (fire and forget)
    let email_svc = email_service.get_ref().clone();
    tokio::spawn(async move {
        if let Err(e) = email_svc
            .send_email_change_notification(&old_email, &new_email)
            .await
        {
            tracing::error!(error = %e, email = %old_email, "Failed to send email change notification");
        }
    });

    Ok(success(
        serde_json::json!({ "message": "Email address updated successfully. Please log in with your new email." }),
        request_id,
    ))
}

/// POST /v1/users/me/email/verify
/// Request email verification (auth required, 2FA must be enabled)
pub async fn request_email_verification(
    req: HttpRequest,
    user: AuthenticatedUser,
    auth_service: web::Data<Arc<AuthService>>,
    email_service: web::Data<Arc<EmailService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    let token = auth_service
        .request_email_verification(user.0.sub, ip_address)
        .await?;

    // Send verification email (fire and forget)
    let email = user.0.email.clone();
    let email_svc = email_service.get_ref().clone();
    tokio::spawn(async move {
        if let Err(e) = email_svc.send_email_verify(&email, &token).await {
            tracing::error!(error = %e, email = %email, "Failed to send email verification");
        }
    });

    Ok(success(
        serde_json::json!({ "message": "Verification email sent. Please check your inbox." }),
        request_id,
    ))
}

/// POST /v1/users/me/email/verify/confirm
/// Confirm email verification (token-based, no auth required)
pub async fn confirm_email_verification(
    req: HttpRequest,
    auth_service: web::Data<Arc<AuthService>>,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    body: web::Json<ConfirmEmailVerificationBody>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    let (user_id, email, tier) = auth_service
        .confirm_email_verification(body.token.clone(), ip_address)
        .await?;

    tracing::info!(email = %email, subscription_tier = %tier.as_str(), "Email verified successfully");

    // Create $0 Stripe subscription for lifetime members so they receive invoices
    if tier == SubscriptionTier::Lifetime {
        if let Some(free_price_id) = stripe.free_price_id() {
            let user = UserRepository::find_by_id(&pool, user_id)
                .await?
                .ok_or(AppError::not_found("User"))?;
            let customer_id = match user.stripe_customer_id {
                Some(id) => id,
                None => {
                    let id = stripe.create_customer(&email, user_id).await?;
                    UserRepository::update_stripe_customer_id(pool.get_ref(), user_id, &id).await?;
                    id
                }
            };
            if let Err(e) = stripe
                .create_free_subscription(&customer_id, &free_price_id)
                .await
            {
                tracing::error!(error = %e, user_id = %user_id, "Failed to create $0 subscription for lifetime member");
            }
        }
    }

    Ok(success(
        serde_json::json!({
            "message": "Email verified successfully.",
            "subscription_tier": tier.as_str(),
        }),
        request_id,
    ))
}

/// DELETE /v1/users/me
/// Delete current user's account (soft delete)
pub async fn delete_account(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    config: web::Data<crate::config::Config>,
    totp_service: web::Data<Arc<TotpService>>,
    stripe_service: web::Data<Arc<StripeService>>,
    oidc_provider: web::Data<Option<Arc<bunyip_oidc::services::oidc_provider::OidcProvider>>>,
    body: web::Json<DeleteAccountRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    // Look up the full user record
    let db_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    // Verify password
    let password_hash = db_user.password_hash.as_ref().ok_or(AppError::validation(
        "password",
        "No password set for this account",
    ))?;

    let password_service = PasswordService::new();
    if !password_service.verify(&body.password, password_hash)? {
        return Err(AppError::validation("password", "Invalid password"));
    }

    // If 2FA is enabled, require and verify TOTP code
    if db_user.two_factor_enabled {
        let totp_code = body.totp_code.as_deref().ok_or_else(|| {
            AppError::validation("totp_code", "Two-factor authentication code is required")
        })?;

        if totp_code.is_empty() {
            return Err(AppError::validation(
                "totp_code",
                "Two-factor authentication code is required",
            ));
        }

        let valid = totp_service.verify_code(user.0.sub, totp_code).await?;
        if !valid {
            return Err(AppError::validation(
                "totp_code",
                "Invalid two-factor authentication code",
            ));
        }
    }

    // Cancel active Stripe subscription if one exists
    if let Some(customer_id) = &db_user.stripe_customer_id {
        if let Ok(Some(sub)) = stripe_service.get_customer_subscription(customer_id).await {
            if sub.status == "active" || sub.status == "past_due" {
                if let Err(e) = stripe_service.cancel_subscription(&sub.id, false).await {
                    tracing::error!(
                        error = %e,
                        user_id = %user.0.sub,
                        subscription_id = %sub.id,
                        "Failed to cancel Stripe subscription during account deletion"
                    );
                }
            }
        }
    }

    // Soft-delete the user
    UserRepository::soft_delete(&pool, user.0.sub).await?;

    // Revoke all refresh tokens
    TokenRepository::revoke_all_user_refresh_tokens(pool.get_ref(), user.0.sub).await?;

    // Revoke OIDC OP sessions so SSO into downstream clients dies with the
    // account (as logout_all does); otherwise a live op_session keeps minting
    // codes for a user who just deleted themselves.
    crate::handlers::auth::revoke_op_sessions(&oidc_provider, user.0.sub).await;

    // Audit log
    let ip = ip_address.map(ipnetwork::IpNetwork::from);
    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::UserAccountDeleted)
            .with_actor(user.0.sub, &user.0.email, &user.0.role)
            .with_resource("user", user.0.sub)
            .with_ip(ip),
    )
    .await?;

    tracing::info!(
        user_id = %user.0.sub,
        user_email = %user.0.email,
        "User deleted their own account"
    );

    if let Some(provider) = oidc_provider.as_ref().as_ref().cloned() {
        let deleted_user_id = user.0.sub;
        tokio::spawn(crate::handlers::admin::dispatch_lifecycle_event(
            provider,
            deleted_user_id,
            "user.deleted",
        ));
    }

    // Clear auth cookies and return success
    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();

    let mut response = HttpResponse::Ok().json(crate::responses::ApiResponse::<()> {
        success: true,
        data: None,
        meta: crate::responses::ResponseMeta::new(request_id),
    });

    for cookie in AuthCookies::clear(secure, cookie_domain) {
        response.add_cookie(&cookie).ok();
    }

    Ok(response)
}

/// GET /v1/users/me/trusted-devices
/// List the caller's active trusted devices (BUNYIP-138).
pub async fn list_trusted_devices(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let devices = TrustedDeviceRepository::find_user_devices(&pool, user.0.sub).await?;
    let out: Vec<TrustedDeviceInfo> = devices.into_iter().map(Into::into).collect();
    Ok(success(serde_json::json!({ "devices": out }), request_id))
}

/// POST /v1/users/me/trusted-devices/{id}/revoke
/// Revoke a single trusted device. Only the caller's own devices may be
/// revoked; revoking re-arms the TOTP prompt on that device.
pub async fn revoke_trusted_device(
    req: HttpRequest,
    user: AuthenticatedUser,
    path: web::Path<uuid::Uuid>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let id = path.into_inner();

    let device = TrustedDeviceRepository::find_by_id(&pool, id)
        .await?
        .ok_or_else(|| AppError::not_found("Trusted device"))?;

    // Ownership guard: return 404 (not 403) for a foreign id so it is not
    // confirmed to exist.
    if device.user_id != user.0.sub {
        return Err(AppError::not_found("Trusted device"));
    }

    TrustedDeviceRepository::revoke(&pool, id).await?;
    Ok(success_no_data(request_id))
}
