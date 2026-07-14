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
    Application, AuditAction, CreateAuditLog, SubscriptionTier, TrustedDeviceInfo, UserResponse,
};
use crate::repositories::{
    AccountDeleteDispatchFailureRepository, ApplicationRepository, AuditLogRepository,
    TokenRepository, TrustedDeviceRepository, UserRepository,
};
use crate::responses::{get_request_id, paginated, success, success_no_data};
use crate::services::{
    AuthService, EmailService, PasswordService, StripeService, TierGrantTrigger, TotpService,
    WebhookService,
};
use crate::validation::validate_email;
use bunyip_domain::services::{BunyipEvent, EventBus};
use uuid::Uuid;

/// Request body for deleting account
#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
    pub totp_code: Option<String>,
}

/// Query for `DELETE /v1/users/me`. `?purge=1` opts into a HARD delete of the
/// row instead of the default soft delete, honoured ONLY on non-production
/// deployments that also set `BUNYIP_E2E_BOOTSTRAP_ALLOW=true` (see
/// `Config::e2e_purge_enabled`). Used by the e2e suite so disposable test
/// accounts do not accumulate; ignored everywhere else (BUNYIP-246).
#[derive(Debug, Deserialize)]
pub struct DeleteAccountQuery {
    #[serde(default)]
    pub purge: Option<String>,
}

impl DeleteAccountQuery {
    /// True when the caller asked to purge (`?purge=1|true|yes`).
    fn wants_purge(&self) -> bool {
        matches!(
            self.purge.as_deref().map(str::trim),
            Some("1") | Some("true") | Some("yes")
        )
    }
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
    /// BUNYIP-366: opt-out toggle for the new-login-location email alert. Absent
    /// leaves it unchanged; `true`/`false` sets it. Unlike the text fields there
    /// is no "clear" state (the column is NOT NULL).
    #[serde(default)]
    pub login_location_alerts: Option<bool>,
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

/// BUNYIP-140: request body for `POST /v1/users/me/consents`. The web UI
/// (bunyip-web's consent screen) sends the client_id from the in-flight
/// authorize round-trip plus the set of newly-granted scopes (the missing
/// set the authorize handler bounced on).
#[derive(Debug, Deserialize)]
pub struct GrantConsentRequest {
    pub client_id: uuid::Uuid,
    pub scopes: Vec<String>,
}

/// POST /v1/users/me/consents (BUNYIP-140)
///
/// Persist the user's OIDC scope consents for `client_id`. The new scopes
/// are unioned into `user_application_access.granted_scopes`; existing
/// scopes are preserved. The signed-in session cookie authenticates the
/// caller; the (user, client) pair is the consent's primary key.
///
/// Empty `scopes` is allowed and a no-op (returns 200). The handler does
/// not validate that the scopes are in `client.allowed_scopes` because the
/// authorize handler already filters that on the next round-trip; storing
/// a stale scope here is harmless.
pub async fn grant_consent(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    oidc_provider: web::Data<
        Option<std::sync::Arc<bunyip_oidc::services::oidc_provider::OidcProvider>>,
    >,
    body: web::Json<GrantConsentRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let provider = oidc_provider
        .as_ref()
        .as_ref()
        .ok_or_else(|| AppError::not_found("OIDC provider not configured"))?;
    let _ = &pool; // pool unused; provider owns its own pool. Kept for symmetry with sibling handlers.

    // BUNYIP-261: server-side intersect body.scopes with the client's
    // registered `allowed_scopes`. The previous handler accepted any
    // scope string in the request body, so a crafted POST (or an
    // attacker-controlled child app that bounced the user through
    // bunyip-web's consent screen with `?missing=admin.god`) could
    // permanently grant a scope the client was never registered for.
    // Load the client and refuse the request if the intersection with
    // its `allowed_scopes` is empty; otherwise persist only the safe
    // subset. Unknown / disabled client_id falls through to a 400.
    let client = provider
        .load_client(body.client_id)
        .await?
        .ok_or_else(|| AppError::validation("client_id", "unknown or disabled client"))?;
    let allowed: std::collections::HashSet<&str> =
        client.allowed_scopes.iter().map(|s| s.as_str()).collect();
    let safe_scopes: Vec<String> = body
        .scopes
        .iter()
        .filter(|s| allowed.contains(s.as_str()))
        .cloned()
        .collect();
    if safe_scopes.is_empty() && !body.scopes.is_empty() {
        // The caller asked for SOME scopes; every one of them was outside
        // the client's allowlist. Refuse rather than silently writing an
        // empty grant - the caller's intent was wrong, not a legitimate
        // "deny all" pass.
        return Err(AppError::validation(
            "scopes",
            "no requested scope is in this client's allowed_scopes",
        ));
    }

    // BUNYIP-234: log the (user_id, client_id, scopes) the write is keyed
    // on so the consent-loop investigation can correlate the write here
    // with the read that the next /oauth2/authorize call performs via
    // `provider.get_granted_scopes`. If the two don't match a row, the
    // loop is identity-mismatch (user_id drift between access_token and
    // op_session); if they DO match but the read sees a different scope
    // set, it's a persistence / visibility issue.
    tracing::info!(
        target: "consent_grant",
        user_id = %user.0.sub,
        client_id = %body.client_id,
        requested = ?body.scopes,
        granted = ?safe_scopes,
        "BUNYIP-234 / BUNYIP-261: persisting filtered consent grant"
    );
    provider
        .add_scopes_to_grant(user.0.sub, body.client_id, &safe_scopes)
        .await
        .map_err(|e| AppError::internal(format!("consent persist failed: {e}")))?;
    Ok(success_no_data(request_id))
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
    auth_service: web::Data<Arc<AuthService>>,
    stripe: web::Data<Arc<StripeService>>,
    body: web::Json<UpdateProfileRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    let first_name = normalize_profile_field("first_name", &body.first_name)?;
    let last_name = normalize_profile_field("last_name", &body.last_name)?;
    let phone = normalize_profile_field("phone", &body.phone)?;

    let current = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    let next_first = first_name.unwrap_or(current.first_name.clone());
    let next_last = last_name.unwrap_or(current.last_name.clone());
    let next_phone = phone.unwrap_or(current.phone.clone());

    // BUNYIP-366: apply the login-location-alert opt-out first, and only when the
    // client actually sent it, so the profile UPDATE below returns the row with
    // the new value.
    if let Some(enabled) = body.login_location_alerts {
        UserRepository::set_login_location_alerts(&pool, user.0.sub, enabled).await?;
    }

    let updated = UserRepository::update_profile(
        &pool,
        user.0.sub,
        next_first.as_deref(),
        next_last.as_deref(),
        next_phone.as_deref(),
    )
    .await?;

    // BUNYIP-221: if the name save just closed the dual-condition gate (email
    // already verified, both names now present), grant the initial tier. The
    // helper is idempotent and a no-op when the gate was already closed by a
    // prior verify or by an admin grant.
    let granted = auth_service
        .maybe_grant_initial_tier(user.0.sub, ip_address, TierGrantTrigger::ProfileCompleted)
        .await
        .unwrap_or_else(|e| {
            // A grant failure must NOT fail the profile update; the user has
            // successfully saved their name. Log and move on; the next call
            // (e.g. a later verify, an admin retry) can re-try the grant.
            tracing::error!(
                error = %e,
                user_id = %user.0.sub,
                "Failed to grant initial tier after profile completion"
            );
            None
        });

    // Mirror the lifetime $0-subscription side-effect that `confirm_email_verification`
    // does so the side that closes the gate produces the same end state.
    if granted == Some(SubscriptionTier::Lifetime) {
        maybe_create_lifetime_subscription(&pool, &stripe, user.0.sub).await;
    }

    Ok(success(UserResponse::from(updated), request_id))
}

/// BUNYIP-221: create the $0 Stripe subscription for a freshly-granted
/// Lifetime member so they keep receiving invoices. Mirror of the inline
/// block in `confirm_email_verification`; lifted out so both grant call
/// sites stay in sync. Best-effort: a failure logs but does not propagate
/// (the user is already a lifetime member at the DB level).
async fn maybe_create_lifetime_subscription(pool: &PgPool, stripe: &StripeService, user_id: Uuid) {
    let Some(free_price_id) = stripe.free_price_id() else {
        return;
    };
    let user = match UserRepository::find_by_id(pool, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::warn!(user_id = %user_id, "User vanished before lifetime sub creation");
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, user_id = %user_id, "Failed to re-read user for lifetime sub");
            return;
        }
    };
    let customer_id = match user.stripe_customer_id {
        Some(id) => id,
        None => match stripe.create_customer(&user.email, user_id).await {
            Ok(id) => {
                if let Err(e) = UserRepository::update_stripe_customer_id(pool, user_id, &id).await
                {
                    tracing::error!(error = %e, user_id = %user_id, "Failed to persist stripe customer id");
                    return;
                }
                id
            }
            Err(e) => {
                tracing::error!(error = %e, user_id = %user_id, "Failed to create Stripe customer for lifetime member");
                return;
            }
        },
    };
    if let Err(e) = stripe
        .create_free_subscription(&customer_id, &free_price_id)
        .await
    {
        tracing::error!(error = %e, user_id = %user_id, "Failed to create $0 subscription for lifetime member");
    }
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
/// Offset-pagination query for the session / trusted-device lists (BUNYIP-177).
/// `page` is 1-indexed (default 1); `per_page` defaults to 20 and is clamped to
/// 1..=100, matching the rest of the API's paginated endpoints.
#[derive(Debug, serde::Deserialize)]
pub struct PageQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
}

pub async fn list_sessions(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    query: web::Query<PageQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    // i64 so a crafted large ?page= cannot overflow the offset (a negative
    // OFFSET would 500). per_page is already clamped to 1..=100 (BUNYIP-177).
    let offset = (page as i64 - 1) * per_page as i64;

    // Hash the caller's refresh-token cookie (if present) to match it to its
    // stored row without exposing any hashes to the client.
    let current_hash = req
        .cookie("refresh_token")
        .map(|c| auth_service.hash_token(c.value()));

    let tokens =
        TokenRepository::find_user_refresh_tokens_paginated(&pool, user.0.sub, per_page, offset)
            .await?;
    let total = TokenRepository::count_user_refresh_tokens(&pool, user.0.sub).await?;

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

    Ok(paginated(sessions, total, page, per_page, request_id))
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

    match &tier {
        Some(t) => {
            tracing::info!(email = %email, subscription_tier = %t.as_str(), "Email verified, initial tier granted")
        }
        None => {
            tracing::info!(email = %email, "Email verified; tier grant pending name save (BUNYIP-221)")
        }
    }

    // Create $0 Stripe subscription for lifetime members so they receive
    // invoices. Only fires when the verify itself was the side that closed
    // the BUNYIP-221 dual gate AND the grant landed on Lifetime; the same
    // side-effect fires from `update_current_user_profile` when the name
    // save is the closer instead.
    if tier == Some(SubscriptionTier::Lifetime) {
        maybe_create_lifetime_subscription(pool.get_ref(), stripe.get_ref(), user_id).await;
    }

    Ok(success(
        serde_json::json!({
            "message": "Email verified successfully.",
            // Empty string when the gate is still open on the name side; the
            // bunyip-web verify-email page falls through to a neutral message
            // in that case (handlers/auth_pages.rs::verify_email).
            "subscription_tier": tier.as_ref().map(|t| t.as_str()).unwrap_or(""),
        }),
        request_id,
    ))
}

/// BUNYIP-211: fan the `account_deleted` webhook out to every active app that
/// has a `webhook_url` (mokosh and any other connected PSA app), retrying each
/// and recording the per-app outcome. Called from a spawned task after the
/// soft delete commits, and reused as the loop body has the same shape as the
/// single-app admin replay.
pub(crate) async fn fan_out_account_deleted(
    pool: &PgPool,
    webhook_service: &WebhookService,
    user_id: Uuid,
) {
    let apps = match ApplicationRepository::list_active(pool).await {
        Ok(apps) => apps,
        Err(e) => {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                "account_deleted fan-out: failed to list applications; downstream apps not notified"
            );
            return;
        }
    };

    for app in apps {
        // Skip apps with no webhook endpoint: nothing to deliver, not a failure.
        if app.webhook_url.as_deref().is_none_or(str::is_empty) {
            continue;
        }
        let outcome = webhook_service
            .dispatch_account_deleted(&app, user_id)
            .await;
        record_account_delete_dispatch(pool, user_id, &app, &outcome).await;
    }
}

/// BUNYIP-211: persist the outcome of a single app's `account_deleted` dispatch.
/// Always writes an audit row (per-app status); on exhaustion also writes a
/// replayable `account_delete_dispatch_failures` row. Shared by the delete
/// fan-out and the admin replay so the two paths cannot record differently.
pub(crate) async fn record_account_delete_dispatch(
    pool: &PgPool,
    user_id: Uuid,
    app: &Application,
    outcome: &Result<(), String>,
) {
    let (status, error) = match outcome {
        Ok(()) => ("delivered", None),
        Err(e) => ("failed", Some(e.as_str())),
    };

    let audit = CreateAuditLog::new(AuditAction::AccountDeleteWebhookDispatched)
        .with_resource("application", app.id)
        .with_metadata(serde_json::json!({
            "user_id": user_id,
            "app_slug": app.slug,
            "status": status,
            "error": error,
        }))
        .with_severity(if outcome.is_ok() {
            crate::models::AuditSeverity::Info
        } else {
            crate::models::AuditSeverity::Error
        });
    if let Err(e) = AuditLogRepository::create(pool, audit).await {
        tracing::error!(error = %e, user_id = %user_id, app_slug = %app.slug, "failed to write account-delete dispatch audit row");
    }

    if let Err(err) = outcome {
        if let Err(e) =
            AccountDeleteDispatchFailureRepository::record(pool, user_id, &app.slug, err).await
        {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                app_slug = %app.slug,
                "failed to persist account-delete dispatch failure; downstream purge may be silently lost"
            );
        }
    }
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
    webhook_service: web::Data<Arc<WebhookService>>,
    event_bus: web::Data<Arc<EventBus>>,
    oidc_provider: web::Data<Option<Arc<bunyip_oidc::services::oidc_provider::OidcProvider>>>,
    query: web::Query<DeleteAccountQuery>,
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

    // BUNYIP-246: non-production e2e hard purge. After the same ownership proof
    // the soft-delete path requires (password, and TOTP when enabled), an
    // opted-in `?purge` physically removes the row so disposable e2e accounts do
    // not accumulate on staging. Gated to a non-production environment +
    // BUNYIP_E2E_BOOTSTRAP_ALLOW, so production always falls through to the soft
    // delete below regardless of the flag. Disposable accounts have no Stripe
    // customer, OIDC sessions, or connected apps, so this skips the downstream
    // cascade and just revokes tokens and clears cookies (writing the usual
    // post-delete audit row would FK-violate against the row we just removed).
    if query.wants_purge() && config.e2e_purge_enabled() {
        UserRepository::hard_delete(&pool, user.0.sub).await?;
        TokenRepository::revoke_all_user_refresh_tokens(pool.get_ref(), user.0.sub).await?;
        crate::handlers::auth::revoke_op_sessions(&oidc_provider, user.0.sub).await;

        tracing::info!(
            user_id = %user.0.sub,
            user_email = %user.0.email,
            "Hard-purged e2e account (non-production)"
        );

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
        return Ok(response);
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

    // BUNYIP-211: publish the terminal event on the in-process bus so any local
    // subscriber (audit log tail, SSE) observes the delete, then cascade the
    // purge to every connected app. The fan-out runs in a spawned task with its
    // own retry + failure capture so a slow/unreachable downstream cannot block
    // (or fail) the user's delete, which is already committed.
    event_bus.publish(BunyipEvent::AccountDeleted {
        user_id: user.0.sub,
    });
    {
        let pool = pool.get_ref().clone();
        let webhook_service = webhook_service.get_ref().clone();
        let deleted_user_id = user.0.sub;
        tokio::spawn(async move {
            fan_out_account_deleted(&pool, &webhook_service, deleted_user_id).await;
        });
    }

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
    app_pool: web::Data<crate::db::AppPool>,
    query: web::Query<PageQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    // i64 so a crafted large ?page= cannot overflow the offset (a negative
    // OFFSET would 500). per_page is already clamped to 1..=100 (BUNYIP-177).
    let offset = (page as i64 - 1) * per_page as i64;

    // BUNYIP-344: read the caller's own devices under per-user RLS. Both queries
    // share one `begin_with_user` transaction so the `app.current_user_id` GUC
    // (which the `user_isolation` policy on trusted_devices keys off) is set for
    // both. The `WHERE user_id = $1` filters below are kept as defence in depth;
    // on the NOBYPASSRLS `bunyip_app` role the policy alone would already scope
    // the rows.
    let mut tx = crate::db::begin_with_user(app_pool.pool(), user.0.sub).await?;
    let devices = TrustedDeviceRepository::find_user_devices_paginated(
        &mut *tx, user.0.sub, per_page, offset,
    )
    .await?;
    let total = TrustedDeviceRepository::count_user_devices(&mut *tx, user.0.sub).await?;
    tx.commit().await?;
    let out: Vec<TrustedDeviceInfo> = devices.into_iter().map(Into::into).collect();
    Ok(paginated(out, total, page, per_page, request_id))
}

/// POST /v1/users/me/trusted-devices/{id}/revoke
/// Revoke a single trusted device. Only the caller's own devices may be
/// revoked; revoking re-arms the TOTP prompt on that device.
pub async fn revoke_trusted_device(
    req: HttpRequest,
    user: AuthenticatedUser,
    path: web::Path<uuid::Uuid>,
    app_pool: web::Data<crate::db::AppPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let id = path.into_inner();

    // BUNYIP-344: look up and revoke under per-user RLS. Both queries share one
    // `begin_with_user` transaction, so on the NOBYPASSRLS role a device owned
    // by another user is invisible (lookup returns None -> 404) and the revoke
    // UPDATE can only touch the caller's own row. The in-Rust ownership check
    // below is kept as defence in depth.
    let mut tx = crate::db::begin_with_user(app_pool.pool(), user.0.sub).await?;
    let device = TrustedDeviceRepository::find_by_id(&mut *tx, id)
        .await?
        .ok_or_else(|| AppError::not_found("Trusted device"))?;

    // Ownership guard: return 404 (not 403) for a foreign id so it is not
    // confirmed to exist.
    if device.user_id != user.0.sub {
        return Err(AppError::not_found("Trusted device"));
    }

    TrustedDeviceRepository::revoke(&mut *tx, id).await?;
    tx.commit().await?;
    Ok(success_no_data(request_id))
}
