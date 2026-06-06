//! Authentication handlers
//!
//! This module contains HTTP handlers for authentication endpoints.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::errors::AppError;
use crate::middleware::{
    extract_client_ip, extract_device_info, AuthCookies, AuthenticatedUser, OptionalUser,
};
use crate::models::{CreateUser, RateLimitConfig, UserResponse, UserRole};
use crate::repositories::{RateLimitRepository, UserRepository};
use crate::responses::{get_request_id, success};
use crate::services::{AcceptInviteResult, AuthService, LoginResult, PasswordService};

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

/// Injected OIDC provider (present only when bunyip-api runs as the OP).
pub type OidcProviderData =
    web::Data<Option<Arc<bunyip_oidc::services::oidc_provider::OidcProvider>>>;

/// Establish a server-side OP session for a freshly-authenticated user and
/// return the `bunyip_op_session` cookie to set on the login response.
///
/// `/oauth2/authorize` gates on this session (not the stateless access_token),
/// so it must be created at every login path. Returns `None` when the OP
/// provider is not configured (non-OP deploys), or if session creation fails -
/// callers simply skip setting the cookie in that case.
pub(crate) async fn establish_op_session(
    provider: &OidcProviderData,
    req: &HttpRequest,
    user_id: uuid::Uuid,
    secure: bool,
    cookie_domain: Option<&str>,
) -> Option<actix_web::cookie::Cookie<'static>> {
    let provider = provider.as_ref().as_ref()?;
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok());
    let ip = extract_client_ip(req);
    match provider
        .create_op_session(
            user_id,
            user_agent,
            ip,
            "urn:bunyip:loa:pwd",
            &["pwd".to_string()],
        )
        .await
    {
        Ok(session) => Some(AuthCookies::op_session(&session.sid, secure, cookie_domain)),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to establish OP session at login");
            None
        }
    }
}

/// Revoke all of a user's OP sessions and fan out back-channel logout tokens.
///
/// The DB revoke is awaited SYNCHRONOUSLY so an immediately-subsequent
/// `/oauth2/authorize` sees no active session (the BUNYIP-53 race). Only the
/// back-channel HTTP delivery to registered clients (e.g. DMARC) is spawned.
/// No-op when the OP provider is not configured.
pub(crate) async fn revoke_op_sessions(provider: &OidcProviderData, user_id: uuid::Uuid) {
    let Some(provider_arc) = provider.as_ref().as_ref().cloned() else {
        return;
    };
    match provider_arc.revoke_sessions_for_backchannel(user_id).await {
        Ok(targets) => {
            tokio::spawn(async move {
                let http = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .unwrap_or_default();
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
                                tracing::info!(%uri, %client_id, "Backchannel logout delivered");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(%client_id, error = %e, "Failed to mint logout token");
                        }
                    }
                }
            });
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to revoke sessions for backchannel logout");
        }
    }
}

/// Request body for user registration
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    /// Stripe Customer ID created by POST /v1/billing/setup-intent before this request.
    pub stripe_customer_id: Option<String>,
    /// Payment method ID returned by stripe.confirmSetup() on the frontend.
    pub payment_method_id: Option<String>,
}

/// Request body for login
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub remember: bool,
}

/// Request body for magic link request
#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
}

/// Request body for magic link verification
#[derive(Debug, Deserialize)]
pub struct VerifyMagicLinkRequest {
    pub token: String,
}

/// Request body for password reset request
#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

/// Request body for password reset confirmation
#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirmRequest {
    pub token: String,
    pub new_password: String,
}

/// Request body for initial admin setup
#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub email: String,
    pub password: String,
}

/// Response for setup status check
#[derive(Debug, Serialize)]
pub struct SetupStatusResponse {
    pub setup_required: bool,
    pub email_enabled: bool,
    pub stripe_enabled: bool,
}

/// Response for successful authentication
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub expires_in: i64,
}

/// POST /v1/auth/register
/// Register a new user and log them in
pub async fn register(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    email_service: web::Data<Arc<crate::services::EmailService>>,
    body: web::Json<RegisterRequest>,
    config: web::Data<crate::config::Config>,
    oidc_provider: OidcProviderData,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);
    let device_info = extract_device_info(&req);

    // Rate limit by IP address
    let ip_key = ip_address.map(|ip| ip.to_string()).unwrap_or_default();
    check_rate_limit(&pool, &ip_key, &RateLimitConfig::REGISTRATION).await?;

    // Validate email format
    crate::validation::validate_email(&body.email)?;

    auth_service
        .register(body.email.clone(), body.password.clone(), ip_address)
        .await?;

    // Generate tokens so the user is logged in immediately
    // (newly registered users never have 2FA, so this always returns Success)
    let result = auth_service
        .login(
            body.email.clone(),
            body.password.clone(),
            device_info,
            ip_address,
        )
        .await?;

    let (tokens, user) = match result {
        LoginResult::Success(tokens, user) => (tokens, user),
        LoginResult::TwoFactorRequired { .. } => {
            // Should never happen for a brand-new registration
            return Err(AppError::internal(
                "Unexpected 2FA challenge during registration",
            ));
        }
    };

    // Store Stripe customer and payment method if card authorization was completed
    if let (Some(customer_id), Some(payment_method_id)) =
        (&body.stripe_customer_id, &body.payment_method_id)
    {
        UserRepository::update_stripe_registration_info(
            &pool,
            user.id,
            customer_id,
            payment_method_id,
        )
        .await?;
    }

    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();

    let op_cookie =
        establish_op_session(&oidc_provider, &req, user.id, secure, cookie_domain).await;

    // Send welcome email (in background, don't wait)
    let email = body.email.clone();
    let email_svc = email_service.get_ref().clone();
    tokio::spawn(async move {
        if let Err(e) = email_svc.send_account_created(&email).await {
            tracing::error!(error = %e, email = %email, "Failed to send account created email");
        }
    });

    let response = AuthResponse {
        user,
        expires_in: tokens.expires_in,
    };

    let mut resp = HttpResponse::Created();
    for cookie in AuthCookies::clear_stale(secure) {
        resp.cookie(cookie);
    }
    resp.cookie(AuthCookies::access_token(
        &tokens.access_token,
        secure,
        cookie_domain,
    ))
    .cookie(AuthCookies::refresh_token(
        &tokens.refresh_token,
        secure,
        false,
        cookie_domain,
    ));
    if let Some(op) = op_cookie {
        resp.cookie(op);
    }
    Ok(resp.json(crate::responses::ApiResponse {
        success: true,
        data: Some(response),
        meta: crate::responses::ResponseMeta::new(request_id),
    }))
}

/// POST /v1/auth/login
/// Login with email and password
pub async fn login(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    body: web::Json<LoginRequest>,
    config: web::Data<crate::config::Config>,
    oidc_provider: OidcProviderData,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);
    let device_info = extract_device_info(&req);

    // Rate limit by email
    check_rate_limit(&pool, &body.email.to_lowercase(), &RateLimitConfig::LOGIN).await?;

    let result = auth_service
        .login(
            body.email.clone(),
            body.password.clone(),
            device_info,
            ip_address,
        )
        .await?;

    match result {
        LoginResult::TwoFactorRequired { challenge_token } => Ok(success(
            serde_json::json!({ "requires_2fa": true, "challenge_token": challenge_token }),
            request_id,
        )),
        LoginResult::Success(tokens, user) => {
            let secure = config.is_production();
            let cookie_domain = config.cookie_domain.as_deref();

            let op_cookie =
                establish_op_session(&oidc_provider, &req, user.id, secure, cookie_domain).await;

            let response = AuthResponse {
                user,
                expires_in: tokens.expires_in,
            };

            let mut resp = HttpResponse::Ok();
            // Clear stale hostname-scoped cookies before setting domain-scoped ones
            for cookie in AuthCookies::clear_stale(secure) {
                resp.cookie(cookie);
            }
            resp.cookie(AuthCookies::access_token(
                &tokens.access_token,
                secure,
                cookie_domain,
            ))
            .cookie(AuthCookies::refresh_token(
                &tokens.refresh_token,
                secure,
                body.remember,
                cookie_domain,
            ));
            if let Some(op) = op_cookie {
                resp.cookie(op);
            }
            Ok(resp.json(crate::responses::ApiResponse {
                success: true,
                data: Some(response),
                meta: crate::responses::ResponseMeta::new(request_id),
            }))
        }
    }
}

/// POST /v1/auth/magic-link
/// Request a magic link for passwordless login
pub async fn request_magic_link(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    email_service: web::Data<Arc<crate::services::EmailService>>,
    body: web::Json<MagicLinkRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    // Rate limit by email
    check_rate_limit(
        &pool,
        &body.email.to_lowercase(),
        &RateLimitConfig::MAGIC_LINK,
    )
    .await?;

    // Validate email format
    crate::validation::validate_email(&body.email)?;

    // Generate magic link token
    let token = auth_service
        .request_magic_link(body.email.clone(), ip_address)
        .await?;

    // Send email (in background, don't wait)
    let email = body.email.clone();
    let email_svc = email_service.get_ref().clone();
    tokio::spawn(async move {
        if let Err(e) = email_svc.send_magic_link(&email, &token).await {
            tracing::error!(error = %e, email = %email, "Failed to send magic link email");
        }
    });

    // Always return success (don't reveal if email exists)
    Ok(
        HttpResponse::Accepted().json(crate::responses::ApiResponse::<()> {
            success: true,
            data: None,
            meta: crate::responses::ResponseMeta::new(request_id),
        }),
    )
}

/// POST /v1/auth/magic-link/verify
/// Verify a magic link and login
pub async fn verify_magic_link(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    email_service: web::Data<Arc<crate::services::EmailService>>,
    body: web::Json<VerifyMagicLinkRequest>,
    config: web::Data<crate::config::Config>,
    oidc_provider: OidcProviderData,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);
    let device_info = extract_device_info(&req);

    // Rate limit by IP address
    let ip_key = ip_address.map(|ip| ip.to_string()).unwrap_or_default();
    check_rate_limit(&pool, &ip_key, &RateLimitConfig::LOGIN).await?;

    let result = auth_service
        .verify_magic_link(body.token.clone(), device_info, ip_address)
        .await?;

    match result {
        crate::services::MagicLinkResult::TwoFactorRequired {
            challenge_token,
            is_new_user,
        } => {
            // Still send welcome email for new users
            if is_new_user {
                let email_svc = email_service.get_ref().clone();
                // We don't have the email easily here, but new users with 2FA is rare
                // (they'd need to have set up 2FA via magic link account creation then somehow enabled it)
                let _ = email_svc; // no-op for this edge case
            }
            Ok(success(
                serde_json::json!({ "requires_2fa": true, "challenge_token": challenge_token }),
                request_id,
            ))
        }
        crate::services::MagicLinkResult::Success(tokens, user, is_new_user) => {
            // Send account created email for new users (in background, don't wait)
            if is_new_user {
                let email = user.email.clone();
                let email_svc = email_service.get_ref().clone();
                tokio::spawn(async move {
                    if let Err(e) = email_svc.send_account_created(&email).await {
                        tracing::error!(error = %e, email = %email, "Failed to send account created email");
                    }
                });
            }

            let secure = config.is_production();
            let cookie_domain = config.cookie_domain.as_deref();

            let op_cookie =
                establish_op_session(&oidc_provider, &req, user.id, secure, cookie_domain).await;

            let response = AuthResponse {
                user,
                expires_in: tokens.expires_in,
            };

            let mut resp = HttpResponse::Ok();
            for cookie in AuthCookies::clear_stale(secure) {
                resp.cookie(cookie);
            }
            resp.cookie(AuthCookies::access_token(
                &tokens.access_token,
                secure,
                cookie_domain,
            ))
            .cookie(AuthCookies::refresh_token(
                &tokens.refresh_token,
                secure,
                true,
                cookie_domain,
            ));
            if let Some(op) = op_cookie {
                resp.cookie(op);
            }
            Ok(resp.json(crate::responses::ApiResponse {
                success: true,
                data: Some(response),
                meta: crate::responses::ResponseMeta::new(request_id),
            }))
        }
    }
}

/// Request body for accepting an admin invite
#[derive(Debug, Deserialize)]
pub struct AcceptInviteRequest {
    pub token: String,
    pub password: Option<String>,
}

/// POST /v1/auth/invite/accept
/// Accept an admin invite
pub async fn accept_admin_invite(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    body: web::Json<AcceptInviteRequest>,
    config: web::Data<crate::config::Config>,
    oidc_provider: OidcProviderData,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);
    let device_info = extract_device_info(&req);

    // Rate limit by IP address
    let ip_key = ip_address.map(|ip| ip.to_string()).unwrap_or_default();
    check_rate_limit(&pool, &ip_key, &RateLimitConfig::LOGIN).await?;

    let result = auth_service
        .accept_admin_invite(
            body.token.clone(),
            body.password.clone(),
            device_info,
            ip_address,
        )
        .await?;

    match result {
        AcceptInviteResult::PasswordRequired { email } => Ok(success(
            serde_json::json!({ "needs_password": true, "email": email }),
            request_id,
        )),
        AcceptInviteResult::Success(tokens, user) => {
            let secure = config.is_production();
            let cookie_domain = config.cookie_domain.as_deref();

            let op_cookie =
                establish_op_session(&oidc_provider, &req, user.id, secure, cookie_domain).await;

            let response = AuthResponse {
                user,
                expires_in: tokens.expires_in,
            };

            let mut resp = HttpResponse::Ok();
            for cookie in AuthCookies::clear_stale(secure) {
                resp.cookie(cookie);
            }
            resp.cookie(AuthCookies::access_token(
                &tokens.access_token,
                secure,
                cookie_domain,
            ))
            .cookie(AuthCookies::refresh_token(
                &tokens.refresh_token,
                secure,
                true,
                cookie_domain,
            ));
            if let Some(op) = op_cookie {
                resp.cookie(op);
            }
            Ok(resp.json(crate::responses::ApiResponse {
                success: true,
                data: Some(response),
                meta: crate::responses::ResponseMeta::new(request_id),
            }))
        }
    }
}

/// POST /v1/auth/refresh
/// Refresh access token using refresh token
pub async fn refresh_token(
    req: HttpRequest,
    auth_service: web::Data<Arc<AuthService>>,
    config: web::Data<crate::config::Config>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);
    let device_info = extract_device_info(&req);

    // Get refresh token from cookie
    let refresh_token = match req.cookie("refresh_token") {
        Some(c) => c.value().to_string(),
        None => {
            tracing::warn!(
                request_id = %request_id,
                ip = ?ip_address,
                "token_refresh: no refresh_token cookie present"
            );
            return Err(AppError::Unauthorized);
        }
    };

    let tokens = match auth_service
        .refresh_tokens(refresh_token, device_info, ip_address)
        .await
    {
        Ok(tokens) => {
            tracing::info!(
                request_id = %request_id,
                "token_refresh: success"
            );
            tokens
        }
        Err(e) => {
            tracing::warn!(
                request_id = %request_id,
                error = %e,
                ip = ?extract_client_ip(&req),
                "token_refresh: failed"
            );
            return Err(e);
        }
    };

    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();

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
            data: Some(serde_json::json!({ "expires_in": tokens.expires_in })),
            meta: crate::responses::ResponseMeta::new(request_id),
        }))
}

/// POST /v1/auth/logout
/// Logout current session
pub async fn logout(
    req: HttpRequest,
    user: AuthenticatedUser,
    auth_service: web::Data<Arc<AuthService>>,
    config: web::Data<crate::config::Config>,
    oidc_provider: web::Data<Option<Arc<bunyip_oidc::services::oidc_provider::OidcProvider>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    // Get refresh token from cookie
    if let Some(refresh_token) = req.cookie("refresh_token").map(|c| c.value().to_string()) {
        auth_service
            .logout(refresh_token, user.0.sub, ip_address)
            .await?;
    }

    // Revoke OIDC op-sessions (synchronously) and fan out back-channel logout
    // tokens so an immediately-subsequent /oauth2/authorize finds no session.
    revoke_op_sessions(&oidc_provider, user.0.sub).await;

    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();

    // Clear cookies
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

/// GET /v1/auth/logout?url=<url>
///
/// SSO logout endpoint for child apps and the bunyip-web BFF. Clears
/// the auth cookies on `.{cookie_domain}` and 302s the browser to
/// `url`, which becomes the user's final landing page (no bounce
/// through `/login`). Pre-fix, this redirected to
/// `{web_origin}/login?redirect={url}&checked=1`, which forced every
/// logout to land on the bunyip login form even when the caller
/// explicitly wanted "log me out and send me home"; child apps
/// (mokosh-clients) end up back on a Bunyip login screen instead of
/// their own landing page. The new semantics match what the param
/// name `url` already implies, and matches the OIDC RP-initiated
/// logout pattern (`post_logout_redirect_uri`).
///
/// `url` is still validated against `cookie_domain` (or, when
/// unset, the parsed host of `web_origin`) so logouts can only
/// redirect to the bunyip apex or one of its subdomains; anything
/// else is rejected with 422.
pub async fn logout_redirect(
    req: HttpRequest,
    query: web::Query<RedirectQuery>,
    optional_user: OptionalUser,
    auth_service: web::Data<Arc<AuthService>>,
    config: web::Data<crate::config::Config>,
    oidc_provider: OidcProviderData,
) -> Result<HttpResponse, AppError> {
    let target_url = &query.url;

    // Validate the redirect URL is on an allowed domain
    let allowed = match url::Url::parse(target_url) {
        Ok(parsed) => {
            if let Some(host) = parsed.host_str() {
                // web_origin is a single absolute URL (cors_origin is now a
                // comma-list and Url::parse would fail on it).
                let web_domain = url::Url::parse(&config.web_origin)
                    .ok()
                    .and_then(|u| u.host_str().map(|h| h.to_string()));

                let base_domain = config
                    .cookie_domain
                    .as_deref()
                    .map(|d| d.trim_start_matches('.'))
                    .or(web_domain.as_deref());

                match base_domain {
                    Some(domain) => host == domain || host.ends_with(&format!(".{domain}")),
                    None => false,
                }
            } else {
                false
            }
        }
        Err(_) => false,
    };

    if !allowed {
        return Err(AppError::validation("url", "Invalid redirect URL"));
    }

    // If authenticated, revoke the refresh token and OP sessions.
    if let Some(user) = &optional_user.0 {
        if let Some(refresh_token) = req.cookie("refresh_token").map(|c| c.value().to_string()) {
            let ip_address = extract_client_ip(&req);
            auth_service
                .logout(refresh_token, user.sub, ip_address)
                .await
                .ok();
        }
        revoke_op_sessions(&oidc_provider, user.sub).await;
    }

    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();
    let clear_cookies = AuthCookies::clear(secure, cookie_domain);

    let mut builder = HttpResponse::Found();
    for cookie in clear_cookies {
        builder.cookie(cookie);
    }

    Ok(builder
        .insert_header(("Location", target_url.as_str()))
        .finish())
}

/// POST /v1/auth/logout-all
/// Logout from all sessions
pub async fn logout_all(
    req: HttpRequest,
    user: AuthenticatedUser,
    auth_service: web::Data<Arc<AuthService>>,
    config: web::Data<crate::config::Config>,
    oidc_provider: OidcProviderData,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    auth_service.logout_all(user.0.sub, ip_address).await?;
    revoke_op_sessions(&oidc_provider, user.0.sub).await;

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

/// POST /v1/auth/password-reset
/// Request a password reset
pub async fn request_password_reset(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    email_service: web::Data<Arc<crate::services::EmailService>>,
    body: web::Json<PasswordResetRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    // Rate limit by email
    check_rate_limit(
        &pool,
        &body.email.to_lowercase(),
        &RateLimitConfig::PASSWORD_RESET,
    )
    .await?;

    // Validate email format
    crate::validation::validate_email(&body.email)?;

    // Request password reset
    if let Some(token) = auth_service
        .request_password_reset(body.email.clone(), ip_address)
        .await?
    {
        // Send email
        let email = body.email.clone();
        let email_svc = email_service.get_ref().clone();
        tokio::spawn(async move {
            if let Err(e) = email_svc.send_password_reset(&email, &token).await {
                tracing::error!(error = %e, email = %email, "Failed to send password reset email");
            }
        });
    }

    // Always return success (don't reveal if email exists)
    Ok(
        HttpResponse::Accepted().json(crate::responses::ApiResponse::<()> {
            success: true,
            data: None,
            meta: crate::responses::ResponseMeta::new(request_id),
        }),
    )
}

/// POST /v1/auth/password-reset/confirm
/// Complete password reset with token
pub async fn confirm_password_reset(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    email_service: web::Data<Arc<crate::services::EmailService>>,
    body: web::Json<PasswordResetConfirmRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    // Rate limit by IP address
    let ip_key = ip_address.map(|ip| ip.to_string()).unwrap_or_default();
    check_rate_limit(&pool, &ip_key, &RateLimitConfig::LOGIN).await?;

    let email = auth_service
        .complete_password_reset(body.token.clone(), body.new_password.clone(), ip_address)
        .await?;

    // Send password changed notification email (in background, don't wait)
    let email_svc = email_service.get_ref().clone();
    tokio::spawn(async move {
        if let Err(e) = email_svc.send_password_changed(&email).await {
            tracing::error!(error = %e, email = %email, "Failed to send password changed email");
        }
    });

    Ok(crate::responses::success_no_data(request_id))
}

/// GET /v1/auth/password-reset/verify
/// Verify a password reset token (without using it)
pub async fn verify_password_reset_token(
    req: HttpRequest,
    auth_service: web::Data<Arc<AuthService>>,
    query: web::Query<VerifyMagicLinkRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Just verify the token is valid
    auth_service.verify_reset_token(query.token.clone()).await?;

    Ok(success(serde_json::json!({ "valid": true }), request_id))
}

/// Query params for redirect endpoint
#[derive(Debug, Deserialize)]
pub struct RedirectQuery {
    pub url: String,
}

/// GET /v1/auth/redirect?url=<url>
/// Check authentication and redirect to the target URL if valid.
/// If not authenticated, redirects to the login page with ?redirect=<url>.
/// Also refreshes the access token cookie if expired but refresh token is valid.
pub async fn auth_redirect(
    req: HttpRequest,
    query: web::Query<RedirectQuery>,
    optional_user: OptionalUser,
    auth_service: web::Data<Arc<AuthService>>,
    config: web::Data<crate::config::Config>,
) -> Result<HttpResponse, AppError> {
    let target_url = &query.url;

    tracing::info!(
        target_url = %target_url,
        has_access_token = req.cookie("access_token").is_some(),
        has_refresh_token = req.cookie("refresh_token").is_some(),
        user_authenticated = optional_user.0.is_some(),
        cookie_domain = ?config.cookie_domain,
        cors_origin = %config.cors_origin,
        "auth_redirect: request received"
    );

    // Validate the redirect URL is on an allowed domain
    let allowed = match url::Url::parse(target_url) {
        Ok(parsed) => {
            if let Some(host) = parsed.host_str() {
                // Extract base domain from CORS origin for comparison
                let cors_domain = url::Url::parse(&config.cors_origin)
                    .ok()
                    .and_then(|u| u.host_str().map(|h| h.to_string()));

                // Also allow cookie_domain subdomains
                let base_domain = config
                    .cookie_domain
                    .as_deref()
                    .map(|d| d.trim_start_matches('.'))
                    .or(cors_domain.as_deref());

                match base_domain {
                    Some(domain) => host == domain || host.ends_with(&format!(".{domain}")),
                    None => false,
                }
            } else {
                false
            }
        }
        Err(_) => false,
    };

    tracing::info!(allowed = allowed, "auth_redirect: URL validation result");

    if !allowed {
        return Err(AppError::validation("url", "Invalid redirect URL"));
    }

    let login_url = format!(
        "{}/login?redirect={}&checked=1",
        config.web_origin.trim_end_matches('/'),
        urlencoding::encode(target_url)
    );

    // If access token is valid, redirect immediately
    if optional_user.0.is_some() {
        tracing::info!(location = %target_url, "auth_redirect: user authenticated, redirecting to target");
        return Ok(HttpResponse::Found()
            .insert_header(("Location", target_url.as_str()))
            .finish());
    }

    // Access token missing/expired — try refresh token
    let refresh_token = req.cookie("refresh_token").map(|c| c.value().to_string());

    if let Some(ref refresh_token) = refresh_token {
        tracing::info!("auth_redirect: attempting token refresh");
        let ip_address = extract_client_ip(&req);
        let device_info = extract_device_info(&req);

        match auth_service
            .refresh_tokens(refresh_token.clone(), device_info, ip_address)
            .await
        {
            Ok(tokens) => {
                tracing::info!(location = %target_url, "auth_redirect: refresh succeeded, redirecting to target");
                let secure = config.is_production();
                let cookie_domain = config.cookie_domain.as_deref();

                let mut resp = HttpResponse::Found();
                for cookie in AuthCookies::clear_stale(secure) {
                    resp.cookie(cookie);
                }
                return Ok(resp
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
                    .insert_header(("Location", target_url.as_str()))
                    .finish());
            }
            Err(e) => {
                tracing::warn!(error = %e, "auth_redirect: refresh token failed");
            }
        }
    } else {
        tracing::info!("auth_redirect: no refresh token cookie found");
    }

    // Not authenticated — redirect to login
    tracing::info!(location = %login_url, "auth_redirect: not authenticated, redirecting to login");
    Ok(HttpResponse::Found()
        .insert_header(("Location", login_url.as_str()))
        .finish())
}

/// GET /v1/auth/setup/status
/// Check whether initial admin setup is required
pub async fn setup_status(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    config: web::Data<crate::config::Config>,
    stripe_service: web::Data<Arc<crate::services::StripeService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let admin_emails = UserRepository::find_admin_emails(&pool).await?;

    Ok(HttpResponse::Ok().json(crate::responses::ApiResponse {
        success: true,
        data: Some(SetupStatusResponse {
            setup_required: admin_emails.is_empty(),
            email_enabled: config.email.enabled,
            stripe_enabled: stripe_service.is_configured(),
        }),
        meta: crate::responses::ResponseMeta::new(request_id),
    }))
}

/// POST /v1/auth/setup
/// Create the initial admin user (only works when no admins exist)
pub async fn setup_admin(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    body: web::Json<SetupRequest>,
    config: web::Data<crate::config::Config>,
    oidc_provider: OidcProviderData,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);
    let device_info = extract_device_info(&req);

    // Only allow setup when no admin users exist
    let admin_emails = UserRepository::find_admin_emails(&pool).await?;
    if !admin_emails.is_empty() {
        return Err(AppError::Forbidden);
    }

    // Validate email format
    crate::validation::validate_email(&body.email)?;

    // Validate and hash password
    let password_service = PasswordService::new();
    password_service.validate_strength(&body.password)?;
    password_service.validate_not_contains_email(&body.password, &body.email)?;
    let password_hash = password_service.hash(&body.password)?;

    // Create the admin user
    let user = UserRepository::create(
        &pool,
        CreateUser {
            email: body.email.clone(),
            password_hash: Some(password_hash),
            role: UserRole::Admin,
        },
    )
    .await?;

    tracing::info!(email = %user.email, "Initial admin user created via setup");

    // Log them in immediately
    let result = auth_service
        .login(
            body.email.clone(),
            body.password.clone(),
            device_info,
            ip_address,
        )
        .await?;

    let (tokens, user) = match result {
        LoginResult::Success(tokens, user) => (tokens, user),
        LoginResult::TwoFactorRequired { .. } => {
            return Err(AppError::internal("Unexpected 2FA challenge during setup"));
        }
    };

    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();

    let op_cookie =
        establish_op_session(&oidc_provider, &req, user.id, secure, cookie_domain).await;

    let response = AuthResponse {
        user,
        expires_in: tokens.expires_in,
    };

    let mut resp = HttpResponse::Created();
    for cookie in AuthCookies::clear_stale(secure) {
        resp.cookie(cookie);
    }
    resp.cookie(AuthCookies::access_token(
        &tokens.access_token,
        secure,
        cookie_domain,
    ))
    .cookie(AuthCookies::refresh_token(
        &tokens.refresh_token,
        secure,
        false,
        cookie_domain,
    ));
    if let Some(op) = op_cookie {
        resp.cookie(op);
    }
    Ok(resp.json(crate::responses::ApiResponse {
        success: true,
        data: Some(response),
        meta: crate::responses::ResponseMeta::new(request_id),
    }))
}

// ── /v1/auth/memberships ────────────────────────────────────────────────────
//
// Synthetic single-tenant stub. Bunyip's M1 scope (per
// `dev-docs/milestone-1-handoff.md`) is "one user = one account"; the
// real organisations + memberships domain is the phase-04 multi-tenant
// work and has no tables yet. Until that ships, the mokosh-clients SPA
// (`src/hooks/auth.rs:240+`) hits this endpoint to populate its tenant
// switcher and brand label, so a missing endpoint shows up as a
// `memberships load failed: HTTP 404` warning and an empty brand area.
//
// This handler returns one synthetic membership derived from the
// authenticated bunyip user. `tenant_id` is the all-zeros-with-1
// default tenant UUID (`Uuid::from_u128(1)`), which matches
// mokosh-server's `OIDC_DEFAULT_TENANT_ID` fallback: every user
// JIT-provisioned from a bunyip at+jwt lands in that mokosh tenant, so
// the SPA sees a tenant id that lines up with the data scope its PSA
// API calls run against. When the real phase-04 work lands, this
// handler is replaced by a real-row query against an `org_memberships`
// table; the response shape stays as-is.

#[derive(Debug, Serialize)]
struct MembershipView {
    tenant_id: String,
    tenant_name: String,
    tenant_kind: String,
    role: String,
    status: String,
    is_active: bool,
}

#[derive(Debug, Serialize)]
struct MembershipsResponse {
    memberships: Vec<MembershipView>,
    active_tenant_id: String,
}

/// GET /v1/auth/memberships
///
/// Lists the tenants the authenticated user is a member of. Today
/// returns a synthetic single-tenant response (see module comment); the
/// real implementation lands with the phase-04 multi-tenant work.
///
/// Response shape (raw JSON, not wrapped in `ApiResponse` because the
/// mokosh-clients SPA decodes the body directly):
/// ```json
/// {
///   "memberships": [
///     {
///       "tenant_id":   "00000000-0000-0000-0000-000000000001",
///       "tenant_name": "<user.email>",
///       "tenant_kind": "personal",
///       "role":        "owner",
///       "status":      "active",
///       "is_active":   true
///     }
///   ],
///   "active_tenant_id": "00000000-0000-0000-0000-000000000001"
/// }
/// ```
/// Synthesise the response payload for the current synthetic stub.
/// Extracted so the unit test below can exercise the shape without
/// going through the actix extractor machinery.
///
/// The default tenant UUID matches mokosh-server's
/// `OIDC_DEFAULT_TENANT_ID` fallback (see mokosh-server's
/// `auth/middleware.rs::default_bunyip_tenant_id`). Bunyip-issued
/// at+jwt tokens currently carry no tenant claim, so every JIT-
/// provisioned user lands in this tenant in mokosh; the SPA needs to
/// see the same id here for its `active_membership()` lookup to match.
fn synthesise_memberships_response(email: &str) -> MembershipsResponse {
    let default_tenant_id = uuid::Uuid::from_u128(1).to_string();
    MembershipsResponse {
        memberships: vec![MembershipView {
            tenant_id: default_tenant_id.clone(),
            tenant_name: email.to_string(),
            tenant_kind: "personal".to_string(),
            role: "owner".to_string(),
            status: "active".to_string(),
            is_active: true,
        }],
        active_tenant_id: default_tenant_id,
    }
}

pub async fn get_memberships(
    _req: HttpRequest,
    user: AuthenticatedUser,
) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(synthesise_memberships_response(&user.0.email)))
}

#[cfg(test)]
mod memberships_tests {
    use super::*;

    #[test]
    fn synthesise_memberships_response_matches_spa_shape() {
        let resp = synthesise_memberships_response("alice@example.com");
        let json = serde_json::to_value(&resp).expect("serialise");

        // Top-level fields that mokosh-clients SPA's `Body` struct
        // decodes (src/hooks/auth.rs around line 252).
        assert!(json["memberships"].is_array());
        assert_eq!(json["memberships"].as_array().unwrap().len(), 1);
        assert_eq!(
            json["active_tenant_id"].as_str(),
            Some("00000000-0000-0000-0000-000000000001"),
            "active_tenant_id must match mokosh-server's default_bunyip_tenant_id"
        );

        // Per-row fields that mokosh-clients SPA's `MembershipView`
        // struct decodes (src/hooks/auth.rs around line 13).
        let row = &json["memberships"][0];
        assert_eq!(
            row["tenant_id"].as_str(),
            Some("00000000-0000-0000-0000-000000000001"),
        );
        assert_eq!(row["tenant_name"].as_str(), Some("alice@example.com"));
        assert_eq!(row["tenant_kind"].as_str(), Some("personal"));
        assert_eq!(row["role"].as_str(), Some("owner"));
        assert_eq!(row["status"].as_str(), Some("active"));
        assert_eq!(row["is_active"].as_bool(), Some(true));
    }
}
