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
use crate::models::{RateLimitConfig, UserResponse};
use crate::repositories::UserRepository;
use crate::responses::{get_request_id, success};
use crate::services::{AcceptInviteResult, AuthService, LoginResult};

use super::check_rate_limit;

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
///
/// BUNYIP-257: `acr` and `amr` are passed in by the caller so the persisted
/// op_session row reflects the ACTUAL authentication method (password,
/// magic-link, MFA, trusted-device, ...) instead of a hardcoded `pwd`
/// fallback. Every downstream consumer (the /authorize at+jwt mint, the
/// silent-SSO refresh-token path's family seed, the back-channel logout
/// fan-out) inherits the truthful value.
///
/// BUNYIP-266: `op_session_cookie_domain` is sourced from
/// `Config::op_session_cookie_domain()`, NOT `Config::cookie_domain`. Without
/// the explicit `BUNYIP_COOKIE_SHARED_DOMAIN=true` opt-in this resolves to
/// `None`, so the session cookie is host-scoped and never sent to sibling
/// subdomains regardless of how `COOKIE_DOMAIN` is set.
pub(crate) async fn establish_op_session(
    provider: &OidcProviderData,
    req: &HttpRequest,
    user_id: uuid::Uuid,
    secure: bool,
    op_session_cookie_domain: Option<&str>,
    acr: &str,
    amr: &[String],
) -> Option<actix_web::cookie::Cookie<'static>> {
    let provider = provider.as_ref().as_ref()?;
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok());
    let ip = extract_client_ip(req);

    // BUNYIP-255: drop any pre-existing op_session sid the browser
    // carries BEFORE minting the new one. A pre-login sid planted by a
    // sibling-subdomain XSS (or a stale cookie from an unrelated
    // browser session) would otherwise stay live and shadow the new
    // session, classic session-fixation surface. Best-effort: a revoke
    // failure here does not block the new login - the new sid wins
    // anyway because `op_session_set`'s dual-emit clear takes care of
    // the browser-side stale state.
    if let Some(stale) = req.cookie(AuthCookies::OP_SESSION_COOKIE) {
        if let Err(e) = provider.revoke_op_session_by_sid(stale.value()).await {
            tracing::debug!(error = %e, "Pre-login op_session revoke failed (best-effort)");
        }
    }

    match provider
        .create_op_session(user_id, user_agent, ip, acr, amr)
        .await
    {
        Ok(session) => Some(AuthCookies::op_session(
            &session.sid,
            secure,
            op_session_cookie_domain,
        )),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to establish OP session at login");
            None
        }
    }
}

/// BUNYIP-257: ACR for a password-only login (no second factor).
pub(crate) const ACR_PASSWORD: &str = "urn:bunyip:loa:pwd";

/// BUNYIP-257: ACR after a TOTP-verified login (second factor satisfied).
pub(crate) const ACR_MFA: &str = "urn:bunyip:loa:mfa";

/// BUNYIP-257: ACR for a magic-link login (one-time-password channel).
pub(crate) const ACR_OTP: &str = "urn:bunyip:loa:otp";

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
    /// BUNYIP-377: honeypot. A hidden field a human leaves empty; a non-empty
    /// value marks an automated submit. Named innocuously so browser autofill
    /// ignores it.
    #[serde(default)]
    pub contact_channel: Option<String>,
    /// BUNYIP-377: the signup timing-challenge token the form was rendered with
    /// (from `GET /v1/auth/register-challenge`).
    #[serde(default)]
    pub signup_token: Option<String>,
}

/// Request body for login
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub remember: bool,
    /// BUNYIP-373: opaque, client-generated stable device identifier. Feeds the
    /// suspicious-login gate's "new device" signal. Optional: absent = the gate
    /// falls back to the country signal only.
    #[serde(default)]
    pub device_id: Option<String>,
}

#[cfg(test)]
mod request_shape_tests {
    use super::LoginRequest;

    /// BUNYIP-506: the wire-compatibility rule is asymmetric by direction.
    /// Response models in bunyip-web default every non-essential field, but a
    /// request body keeps its required inputs required, so a malformed request
    /// still fails (actix turns this deserialize error into a 400) instead of
    /// authenticating against an empty password.
    #[test]
    fn login_request_without_a_password_is_rejected() {
        let e = serde_json::from_value::<LoginRequest>(serde_json::json!({
            "email": "ada@example.com",
        }))
        .expect_err("a login body with no password must be rejected");
        assert!(
            e.to_string().contains("password"),
            "expected the missing required input to be named: {e}"
        );
    }
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
    /// BUNYIP-373: same client-generated device id as the login path.
    #[serde(default)]
    pub device_id: Option<String>,
}

/// BUNYIP-373: request body to complete a login withheld pending email
/// approval. The challenge token was returned by `/login` or `/magic-link/verify`
/// as `challenge_token`; `code` is the 6-digit value from the approval email.
#[derive(Debug, Deserialize)]
pub struct VerifyLoginApprovalRequest {
    pub challenge_token: String,
    pub code: String,
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

/// Response for the feature-flags probe (`GET /v1/auth/setup/status`).
///
/// BUNYIP-290: this used to carry `setup_required` for the removed first-admin
/// wizard. The endpoint now only advertises which optional integrations are
/// wired, which the web UI reads to hide unavailable actions.
#[derive(Debug, Serialize)]
pub struct SetupStatusResponse {
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

    // Rate limit by IP address. BUNYIP-426 F7: the cap applies in EVERY
    // environment (skipping it below production once left `/v1/auth/register`
    // unthrottled on the publicly reachable dev-sso stack). BUNYIP-601: the cap
    // no longer branches on the environment in code. There is one preset, and a
    // non-production instance that needs a looser budget (the deployed-instance
    // e2e suite self-provisions disposable accounts from one CI egress IP and
    // would trip the 3/hour production cap: BUNYIP-150 / 196 / 197) sets
    // `RATE_LIMIT_REGISTRATION_MAX_REQUESTS`, resolved by `check_rate_limit` via
    // the const -> env -> persisted chain.
    let ip_key = ip_address.map(|ip| ip.to_string()).unwrap_or_default();
    check_rate_limit(&pool, &ip_key, &RateLimitConfig::REGISTRATION).await?;

    // BUNYIP-377: bot guard (honeypot + submit timing). Opt-in via
    // SIGNUP_BOT_GUARD_ENABLED, off until every register form carries the hidden
    // fields. Rejects uniformly so no individual check is an oracle for bots.
    if config.signup_bot_guard_enabled {
        auth_service.verify_signup_not_bot(
            body.contact_channel.as_deref(),
            body.signup_token.as_deref(),
        )?;
    }

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
            None,
            None,
            // BUNYIP-381: a fresh registration is not "remember me" (1-day refresh).
            false,
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
        LoginResult::ApprovalRequired { .. } => {
            // BUNYIP-373: a brand-new account has no baseline country/device to
            // deviate from, so the suspicious-login gate never fires here.
            return Err(AppError::internal(
                "Unexpected login-approval challenge during registration",
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

    let secure = config.cookies_secure(&req);
    let cookie_domain = config.cookie_domain.as_deref();

    let op_cookie = establish_op_session(
        &oidc_provider,
        &req,
        user.id,
        secure,
        config.op_session_cookie_domain(),
        ACR_PASSWORD,
        &["pwd".to_string()],
    )
    .await;

    // BUNYIP-296: await the welcome inline before returning so the
    // /onboarding page's auto-fired POST /v1/users/me/email/verify cannot
    // race the welcome onto the SMTP wire. Best-effort: a mail failure
    // still logs and continues, because the register itself has already
    // committed and the user's dashboard access does not depend on the
    // welcome. BUNYIP-265 rule holds: do not log the raw email address.
    // Password signup: the address is not verified yet (the onboarding page
    // fires the verify step), so the email keeps its "verify your email" prompt.
    if let Err(e) = email_service.send_account_created(&body.email, false).await {
        tracing::error!(error = %e, "Failed to send account created email");
    }

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

/// GET /v1/auth/register-challenge
/// BUNYIP-377: issue a short-lived signup timing-challenge token for a freshly
/// rendered register form. Unauthenticated; the token is just a signed
/// timestamp, so minting one is harmless and needs no rate limit. The register
/// handler verifies it (when SIGNUP_BOT_GUARD_ENABLED is on).
pub async fn register_challenge(
    req: HttpRequest,
    auth_service: web::Data<Arc<AuthService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let token = auth_service.create_signup_challenge()?;
    Ok(success(serde_json::json!({ "token": token }), request_id))
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

    // BUNYIP-255: multi-keyed login rate limit. The previous per-email
    // window alone left credential spraying ("one password across many
    // victim emails") under the radar - each victim had a fresh budget,
    // so an attacker with one common password could try it against
    // hundreds of accounts in a minute without ever tripping the cap.
    // Layer per-IP and per-IP-per-email caps so the aggregate guessing
    // budget from any one source IP is bounded independently of which
    // email it targets. The existing per-email cap stays in place as
    // the per-account fallback.
    let ip_key = ip_address
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into());
    let email_key = body.email.to_lowercase();
    check_rate_limit(
        &pool,
        &format!("login_ip:{ip_key}"),
        &RateLimitConfig::LOGIN,
    )
    .await?;
    check_rate_limit(
        &pool,
        &format!("login_ip_email:{ip_key}:{email_key}"),
        &RateLimitConfig::LOGIN,
    )
    .await?;
    check_rate_limit(&pool, &email_key, &RateLimitConfig::LOGIN).await?;

    // Trusted-device cookie (BUNYIP-138): if present and valid, a subscriber
    // skips the 2FA prompt. Forwarded verbatim by the web BFF.
    let trusted_device_token = req
        .cookie(AuthCookies::TRUSTED_DEVICE_COOKIE)
        .map(|c| c.value().to_string());

    let result = auth_service
        .login(
            body.email.clone(),
            body.password.clone(),
            device_info,
            ip_address,
            trusted_device_token,
            body.device_id.clone(),
            body.remember,
        )
        .await?;

    match result {
        LoginResult::TwoFactorRequired { challenge_token } => Ok(success(
            serde_json::json!({ "requires_2fa": true, "challenge_token": challenge_token }),
            request_id,
        )),
        // BUNYIP-373: suspicious login - an approval code was emailed. Same
        // challenge-token handshake as 2FA; the client re-submits with the code
        // to POST /auth/login-approval/verify.
        LoginResult::ApprovalRequired { challenge_token } => Ok(success(
            serde_json::json!({ "requires_approval": true, "challenge_token": challenge_token }),
            request_id,
        )),
        LoginResult::Success(tokens, user) => {
            let secure = config.cookies_secure(&req);
            let cookie_domain = config.cookie_domain.as_deref();

            let op_cookie = establish_op_session(
                &oidc_provider,
                &req,
                user.id,
                secure,
                config.op_session_cookie_domain(),
                ACR_PASSWORD,
                &["pwd".to_string()],
            )
            .await;

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
            // BUNYIP-265: drop raw email (PII + enumeration).
            tracing::error!(error = %e, "Failed to send magic link email");
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
        .verify_magic_link(
            body.token.clone(),
            device_info,
            ip_address,
            body.device_id.clone(),
        )
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
        // BUNYIP-373: suspicious magic-link login - approval code emailed. Same
        // handshake as the password path.
        crate::services::MagicLinkResult::ApprovalRequired { challenge_token } => Ok(success(
            serde_json::json!({ "requires_approval": true, "challenge_token": challenge_token }),
            request_id,
        )),
        crate::services::MagicLinkResult::Success(tokens, user, is_new_user) => {
            // BUNYIP-296: welcome email for a magic-link-created account is
            // awaited inline to match the register path. Magic-link signup
            // verifies the email as part of the flow itself so no verify
            // message follows, meaning the ordering-race concern does not
            // apply here; the inline await is stylistic uniformity so both
            // signup paths behave identically. BUNYIP-265 rule holds: do
            // not log the raw email address.
            if is_new_user {
                // Magic-link signup already verified the address (above), so
                // pass true to suppress the email's "verify your email" prompt.
                if let Err(e) = email_service.send_account_created(&user.email, true).await {
                    tracing::error!(error = %e, "Failed to send account created email");
                }
            }

            let secure = config.cookies_secure(&req);
            let cookie_domain = config.cookie_domain.as_deref();

            let op_cookie = establish_op_session(
                &oidc_provider,
                &req,
                user.id,
                secure,
                config.op_session_cookie_domain(),
                ACR_OTP,
                &["otp".to_string()],
            )
            .await;

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

/// POST /v1/auth/login-approval/verify
/// BUNYIP-373: complete a login that was withheld pending email approval (NO
/// auth required - it is gated by the challenge token). Verifies the emailed
/// code and, on success, sets the same session cookies a normal login would.
pub async fn verify_login_approval(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    body: web::Json<VerifyLoginApprovalRequest>,
    config: web::Data<crate::config::Config>,
    oidc_provider: OidcProviderData,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);
    let device_info = extract_device_info(&req);

    // Rate limit by IP. The per-challenge attempt counter (bounded, single-use,
    // 15-minute TTL) is the primary brute-force guard on the 6-digit code; this
    // is defense-in-depth against a spray across many challenge tokens from one
    // source IP.
    let ip_key = ip_address.map(|ip| ip.to_string()).unwrap_or_default();
    check_rate_limit(
        &pool,
        &format!("login_approval_verify:{ip_key}"),
        &RateLimitConfig::LOGIN,
    )
    .await?;

    let (tokens, user) = auth_service
        .complete_login_approval(&body.challenge_token, &body.code, device_info, ip_address)
        .await?;

    let secure = config.cookies_secure(&req);
    let cookie_domain = config.cookie_domain.as_deref();

    // The approval proves control of the account's email on top of the primary
    // factor. v1 gates password + magic-link; report the password ACR as the
    // common single-factor assurance (a follow-up can thread the exact origin
    // through the challenge if the distinction ever matters).
    let op_cookie = establish_op_session(
        &oidc_provider,
        &req,
        user.id,
        secure,
        config.op_session_cookie_domain(),
        ACR_PASSWORD,
        &["pwd".to_string()],
    )
    .await;

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
            let secure = config.cookies_secure(&req);
            let cookie_domain = config.cookie_domain.as_deref();

            let op_cookie = establish_op_session(
                &oidc_provider,
                &req,
                user.id,
                secure,
                config.op_session_cookie_domain(),
                ACR_PASSWORD,
                &["pwd".to_string()],
            )
            .await;

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

    let secure = config.cookies_secure(&req);
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
///
/// BUNYIP-323: uses `OptionalUser`, NOT `AuthenticatedUser`. A logout must
/// succeed even when the caller's access_token is expired, missing, or
/// invalid, so the browser's cookies are guaranteed to be cleared regardless
/// of the session's state. Previously the handler required a valid
/// `AuthenticatedUser` extractor: the extractor 401'd before the handler
/// ran on any stale token, no clearing cookies were emitted, and the user
/// stayed effectively signed in from the browser's perspective (David hit
/// this trying to re-register with a corrected email).
///
/// With a valid user (the common case) we still revoke the refresh token in
/// the DB and fan out OIDC op-session revocations + back-channel logout
/// tokens, matching the pre-BUNYIP-323 semantics. Without a valid user we
/// skip those steps but still emit the `AuthCookies::clear` set so the
/// browser purges its cookies; the residual DB state (an expired refresh
/// token or an unreachable op_session) is either already unusable or gets
/// GC'd on its own schedule.
pub async fn logout(
    req: HttpRequest,
    optional_user: OptionalUser,
    auth_service: web::Data<Arc<AuthService>>,
    config: web::Data<crate::config::Config>,
    oidc_provider: web::Data<Option<Arc<bunyip_oidc::services::oidc_provider::OidcProvider>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    if let Some(user) = optional_user.0.as_ref() {
        // Only try to revoke the refresh token when we know whose it is.
        // Without a valid access_token we cannot bind the refresh_token to a
        // user_id for the audit log; leave the row and let TTL clean it up.
        if let Some(refresh_token) = req.cookie("refresh_token").map(|c| c.value().to_string()) {
            // Best-effort: DB errors here must not block cookie clearing.
            // A refresh token that fails to revoke (e.g. already-revoked, DB
            // hiccup) is not a reason to leave the browser signed in.
            if let Err(e) = auth_service
                .logout(refresh_token, user.sub, ip_address)
                .await
            {
                tracing::warn!(
                    error = %e,
                    user_id = %user.sub,
                    "logout: refresh-token revoke failed; still clearing cookies"
                );
            }
        }

        // Revoke OIDC op-sessions (synchronously) and fan out back-channel
        // logout tokens so an immediately-subsequent /oauth2/authorize finds
        // no session.
        revoke_op_sessions(&oidc_provider, user.sub).await;
    }

    let secure = config.cookies_secure(&req);
    let cookie_domain = config.cookie_domain.as_deref();

    // Clear cookies unconditionally. This is the whole point of the endpoint
    // from the browser's perspective: emit clearing `Set-Cookie` headers for
    // access_token, refresh_token, and the OP session cookie so the next
    // request from this browser carries none of them.
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

    let secure = config.cookies_secure(&req);
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

    let secure = config.cookies_secure(&req);
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
        // BUNYIP-397: the reset email names the country the request came from
        // when the IP resolves (best-effort; None for local IPs or no GeoIP DB).
        let country = auth_service.country_name_for_ip(ip_address);
        // Send email
        let email = body.email.clone();
        let email_svc = email_service.get_ref().clone();
        tokio::spawn(async move {
            if let Err(e) = email_svc
                .send_password_reset(&email, &token, country.as_deref())
                .await
            {
                // BUNYIP-265: drop raw email (PII + enumeration).
                tracing::error!(error = %e, "Failed to send password reset email");
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
            // BUNYIP-265: drop raw email (PII + enumeration).
            tracing::error!(error = %e, "Failed to send password changed email");
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

    // BUNYIP-265: log only the URL's path; the query string can carry
    // OIDC `state` / `code` / `return_to` values that have request-level
    // sensitivity and do not belong in log files.
    let target_path = url::Url::parse(target_url)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| target_url.split('?').next().unwrap_or("").to_string());
    tracing::debug!(
        target_path = %target_path,
        has_access_token = req.cookie("access_token").is_some(),
        has_refresh_token = req.cookie("refresh_token").is_some(),
        user_authenticated = optional_user.0.is_some(),
        cookie_domain = ?config.cookie_domain,
        web_origin = %config.web_origin,
        "auth_redirect: request received"
    );

    // Validate the redirect URL is on an allowed domain. Validate against
    // web_origin (a single absolute URL) like logout_redirect does; cors_origin
    // is a comma-list that Url::parse cannot handle, which 422'd every redirect
    // whenever COOKIE_DOMAIN was unset.
    let allowed = match url::Url::parse(target_url) {
        Ok(parsed) => {
            if let Some(host) = parsed.host_str() {
                let web_domain = url::Url::parse(&config.web_origin)
                    .ok()
                    .and_then(|u| u.host_str().map(|h| h.to_string()));

                // Also allow cookie_domain subdomains
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

    tracing::debug!(allowed = allowed, "auth_redirect: URL validation result");

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
        tracing::debug!(location = %target_url, "auth_redirect: user authenticated, redirecting to target");
        return Ok(HttpResponse::Found()
            .insert_header(("Location", target_url.as_str()))
            .finish());
    }

    // Access token missing/expired — try refresh token
    let refresh_token = req.cookie("refresh_token").map(|c| c.value().to_string());

    if let Some(ref refresh_token) = refresh_token {
        tracing::debug!("auth_redirect: attempting token refresh");
        let ip_address = extract_client_ip(&req);
        let device_info = extract_device_info(&req);

        match auth_service
            .refresh_tokens(refresh_token.clone(), device_info, ip_address)
            .await
        {
            Ok(tokens) => {
                tracing::debug!(location = %target_url, "auth_redirect: refresh succeeded, redirecting to target");
                let secure = config.cookies_secure(&req);
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
        tracing::debug!("auth_redirect: no refresh token cookie found");
    }

    // Not authenticated — redirect to login
    tracing::debug!(location = %login_url, "auth_redirect: not authenticated, redirecting to login");
    Ok(HttpResponse::Found()
        .insert_header(("Location", login_url.as_str()))
        .finish())
}

/// GET /v1/auth/setup/status
/// Feature-flags probe: reports which optional integrations are wired
/// (email, Stripe) so the web UI can hide unavailable actions. BUNYIP-290
/// dropped the first-admin `setup_required` flag along with the setup wizard.
pub async fn setup_status(
    req: HttpRequest,
    config: web::Data<crate::config::Config>,
    stripe_service: web::Data<Arc<crate::services::StripeService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    Ok(HttpResponse::Ok().json(crate::responses::ApiResponse {
        success: true,
        data: Some(SetupStatusResponse {
            email_enabled: config.email.enabled,
            stripe_enabled: stripe_service.is_configured(),
        }),
        meta: crate::responses::ResponseMeta::new(request_id),
    }))
}

// ── /v1/auth/memberships ────────────────────────────────────────────────────
//
// Synthetic single-tenant stub. Bunyip's M1 scope (per
// `docs/dev-docs/CHANGELOG.md`) is "one user = one account"; the
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
