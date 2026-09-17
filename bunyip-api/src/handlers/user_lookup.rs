//! Machine-authed user directory lookup: `GET /v1/users/lookup?email=...`.
//!
//! Purpose. Mokosh-server's PMS-1208 grant-invitation flow needs to
//! know whether an email address resolves to a Bunyip identity BEFORE
//! it creates a pending invitation on its side, because in the SaaS
//! deployment the grantee eventually signs in through Bunyip and a
//! grant to an unknown-to-Bunyip address is a UX dead end. Mokosh's
//! handler calls this endpoint with the invitee's address; a 200 with
//! the user id is what lets the invitation go through, a 404 is what
//! refuses it with copy pointing the owner at "ask them to sign up
//! first."
//!
//! Wire shape. `GET /v1/users/lookup?email={address}`; response is
//! `{"user_id": "<uuid>", "email": "<address>"}` on match, 404 on
//! either an unknown address or a soft-deleted user. The email in the
//! response is the CANONICAL stored form so a caller with a mixed-
//! case address gets the row's own casing back.
//!
//! Machine auth. Same shape as `POST /v1/mailer/send` (BUNYIP-602):
//! HTTP Basic client_id:client_secret, verified through
//! `machine_client::load_machine_client` +
//! `verify_machine_client`. The endpoint is in
//! `rate_limit_floor::EXEMPT_PATHS` because the suite's apps share
//! egress and a per-IP floor would let one app throttle another; the
//! per-app throughput cap is `RateLimitConfig::USER_LOOKUP`.
//!
//! Refuse-before-Argon2. `MAILER_AUTH_FAILURES` is the shared per-IP
//! failure-only bucket the mailer relay already uses; this endpoint
//! consults the SAME bucket rather than declaring its own, because
//! the property being bounded is "an unauthenticated flood against
//! any machine-authed endpoint on this host" and splitting the
//! bucket per-endpoint would double the budget an attacker can spend.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use bunyip_domain::repositories::UserRepository;
use bunyip_oidc::machine_client;

use crate::errors::AppError;
use crate::middleware::extract_client_ip;
use crate::models::RateLimitConfig;
use crate::repositories::{RateLimitConfigRepository, RateLimitRepository};
use crate::responses::{get_request_id, success};

#[derive(Debug, Deserialize)]
pub struct UserLookupQuery {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct UserLookupResponse {
    pub user_id: String,
    pub email: String,
    /// PMS-1208 finding 7: whether this bunyip identity has verified
    /// their email address. Mokosh's grant-invitation flow reads this
    /// so the owner is told at invite-create time when the invitee is
    /// registered on bunyip but not yet verified. The mokosh middleware
    /// refuses to JIT-provision an unverified grantee into someone
    /// else's tenant (deliberate: placeholder path exists only for
    /// first-sight owners bunyip is in the middle of verifying), so
    /// without this field the owner sends an invitation, the grantee
    /// accepts, and the switch fails at placement with a generic 403.
    /// Surfacing it here lets that refusal land where the owner can
    /// act on it.
    pub email_verified: bool,
}

async fn auth_failures_at_cap(pool: &PgPool, ip_key: &str) -> Result<bool, AppError> {
    let config =
        RateLimitConfigRepository::effective(pool, &RateLimitConfig::MAILER_AUTH_FAILURES).await?;
    let (count, _) = RateLimitRepository::check(pool, ip_key, &config).await?;
    Ok(count >= config.max_requests)
}

async fn record_auth_failure(pool: &PgPool, ip_key: Option<&str>) {
    let Some(ip_key) = ip_key else { return };
    if let Err(e) = RateLimitRepository::check_and_increment(
        pool,
        ip_key,
        &RateLimitConfig::MAILER_AUTH_FAILURES,
    )
    .await
    {
        tracing::error!(
            error = %e,
            "user-lookup endpoint could not record a failed client authentication"
        );
    }
}

/// GET /v1/users/lookup?email={address}
pub async fn user_lookup(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    query: web::Query<UserLookupQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_key = extract_client_ip(&req).map(|ip| ip.to_string());

    if let Some(ip) = ip_key.as_deref() {
        if auth_failures_at_cap(&pool, ip).await? {
            let retry_after = match RateLimitRepository::get_retry_after(
                &pool,
                ip,
                &RateLimitConfig::MAILER_AUTH_FAILURES,
            )
            .await
            {
                Ok(secs) => secs,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "user-lookup could not read the failure window; reporting the full window"
                    );
                    RateLimitConfig::MAILER_AUTH_FAILURES.window_seconds.max(0) as u64
                }
            };
            tracing::error!(
                category = "rate_limit",
                client = %ip,
                action = RateLimitConfig::MAILER_AUTH_FAILURES.action,
                "user-lookup: too many failed client authentications from this address"
            );
            return Err(AppError::RateLimited { retry_after });
        }
    }

    let Some((client_id, secret)) = machine_client::basic_credentials(&req) else {
        record_auth_failure(&pool, ip_key.as_deref()).await;
        return Err(AppError::OidcInvalidClient(
            "HTTP Basic client credentials are required".into(),
        ));
    };

    let client = match machine_client::load_machine_client(&pool, &client_id).await {
        Ok(c) => c,
        Err(e) => {
            record_auth_failure(&pool, ip_key.as_deref()).await;
            tracing::warn!(
                ip = ip_key.as_deref().unwrap_or("unknown"),
                client_id = %client_id,
                error = %e,
                "user-lookup rejected: unknown or disabled client"
            );
            return Err(e);
        }
    };

    if let Err(e) = machine_client::verify_machine_client(&client, &secret).await {
        record_auth_failure(&pool, ip_key.as_deref()).await;
        tracing::warn!(
            ip = ip_key.as_deref().unwrap_or("unknown"),
            client_id = %client.client_id,
            client = %client.name,
            error = %e,
            "user-lookup rejected: client authentication failed"
        );
        return Err(e);
    }

    // Per-app throughput cap. `USER_LOOKUP` (60/min per client_id)
    // matches the mailer send cap: a calling app should not need
    // more than one lookup per second of steady state.
    super::check_rate_limit(
        &pool,
        &client.client_id.to_string(),
        &RateLimitConfig::USER_LOOKUP,
    )
    .await?;

    let email = query.email.trim();
    if email.is_empty() {
        return Err(AppError::BadRequest(
            "email query parameter is required".to_string(),
        ));
    }

    let user = UserRepository::find_by_email(&pool, email).await?;
    let user = user.ok_or_else(|| AppError::NotFound {
        resource: "user".to_string(),
    })?;

    Ok(success(
        UserLookupResponse {
            user_id: user.id.to_string(),
            email: user.email,
            email_verified: user.email_verified,
        },
        request_id,
    ))
}
