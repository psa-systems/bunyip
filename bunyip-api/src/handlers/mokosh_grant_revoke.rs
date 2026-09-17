//! Machine-authed revocation of a specific mokosh grant.
//! `DELETE /v1/mokosh-grants/{id}`.
//!
//! Why this exists. `DELETE /v1/grants/{id}` is the OWNER path: the
//! grantor holds a bunyip at+jwt and revokes their own grant. Mokosh-
//! server's MAPPS-875 owner surface has no bunyip bearer available
//! (its SPA holds a mokosh-audience token), so it acts as a machine
//! caller here, presenting the same `oauth_clients` machine credential
//! the sibling list / register endpoints use and naming the owner it
//! acts on behalf of.
//!
//! Wire shape.
//! - Auth: HTTP Basic client_id:client_secret (`machine_client`).
//! - Body: `{ owner_bunyip_user_id }`. Required. The revoke query
//!   binds the caller-as-owner into the WHERE clause, so a machine
//!   client cannot revoke a grant it does not own by construction
//!   even though the endpoint carries no owner-issued bearer.
//! - Response: 204 on the first revoke; 204 on idempotent replay
//!   (the second call finds `revoked_at IS NOT NULL` and the query
//!   moves no row, which mirrors the user-authed handler). A
//!   different owner or unknown id: 404.
//!
//! Side effect. The user-authed revoke path fires the
//! `mokosh_grant_changed` webhook so mokosh-server's mirror flips the
//! grant to revoked within the 30-second BUNYIP-674 stale window;
//! this endpoint fires the SAME webhook for the same reason (a
//! grantee holding a still-valid at+jwt must lose access within the
//! window).
//!
//! Refuse-before-Argon2 and rate-limit sharing follow the sibling
//! machine endpoints. Feature gate: `orgs_enabled` off answers 404.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use bunyip_domain::errors::AppError;
use bunyip_domain::repositories::{ApplicationRepository, MokoshGrantRepository};
use bunyip_domain::services::WebhookService;
use bunyip_oidc::machine_client;

use crate::config::TierConfig;
use crate::middleware::extract_client_ip;
use crate::models::RateLimitConfig;
use crate::repositories::{RateLimitConfigRepository, RateLimitRepository};
use crate::responses::get_request_id;

const MOKOSH_APP_SLUG: &str = "mokosh";

#[derive(Debug, Deserialize)]
pub struct RevokeGrantRequest {
    pub owner_bunyip_user_id: Uuid,
}

fn orgs_enabled(tier_config: &Arc<RwLock<TierConfig>>) -> bool {
    tier_config
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .orgs_enabled
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
            "mokosh-grant-revoke endpoint could not record a failed client authentication"
        );
    }
}

/// DELETE /v1/mokosh-grants/{id}
pub async fn revoke_grant(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    webhook: web::Data<Arc<WebhookService>>,
    path: web::Path<Uuid>,
    body: web::Json<RevokeGrantRequest>,
) -> Result<HttpResponse, AppError> {
    let _request_id = get_request_id(&req);
    if !orgs_enabled(tier_config.get_ref()) {
        return Err(AppError::not_found("Mokosh grant"));
    }

    // Refuse-before-Argon2 (shared per-IP failure bucket).
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
                        "mokosh-grant-revoke could not read the failure window; reporting the full window"
                    );
                    RateLimitConfig::MAILER_AUTH_FAILURES.window_seconds.max(0) as u64
                }
            };
            tracing::error!(
                category = "rate_limit",
                client = %ip,
                action = RateLimitConfig::MAILER_AUTH_FAILURES.action,
                "mokosh-grant-revoke: too many failed client authentications from this address"
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
                "mokosh-grant-revoke rejected: unknown or disabled client"
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
            "mokosh-grant-revoke rejected: client authentication failed"
        );
        return Err(e);
    }

    super::check_rate_limit(
        &pool,
        &client.client_id.to_string(),
        &RateLimitConfig::USER_LOOKUP,
    )
    .await?;

    let grant_id = path.into_inner();
    let owner = body.owner_bunyip_user_id;

    // The repository's `revoke` returns None when the id is unknown,
    // when the caller is not the owner, OR when the grant is already
    // revoked. The user-authed handler distinguishes idempotent replay
    // (204) from foreign-caller / unknown-id (404) with a pre-read.
    // Mirror that shape: read first, decide, then move.
    let existing = MokoshGrantRepository::find_by_id(pool.get_ref(), grant_id).await?;
    let existing = match existing {
        Some(g) if g.owner_bunyip_user_id == owner => g,
        _ => return Err(AppError::not_found("Mokosh grant")),
    };
    if existing.revoked_at.is_some() {
        // Idempotent replay: the grant is already revoked. Do not re-fire
        // the webhook; the mirror was moved on the first revoke, and a
        // spurious re-fire would show up in the mokosh audit log as
        // a second revoke event for the same grant.
        return Ok(HttpResponse::NoContent().finish());
    }

    let revoked = MokoshGrantRepository::revoke(pool.get_ref(), grant_id, owner).await?;
    if let Some(grant) = revoked {
        // BUNYIP-674: same fire-and-forget webhook the user-authed
        // revoke path uses. See handlers::mokosh_grants::notify_grant_changed.
        match ApplicationRepository::find_by_slug(pool.get_ref(), MOKOSH_APP_SLUG).await {
            Ok(Some(app)) => {
                webhook.notify_mokosh_grant_changed(&app, &grant).await;
            }
            Ok(None) => {
                tracing::warn!(
                    grant_id = %grant.id,
                    "No `mokosh` application row registered; skipping mokosh_grant_changed webhook"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    grant_id = %grant.id,
                    "Failed to load `mokosh` application row for the mokosh_grant_changed webhook"
                );
            }
        }
    }

    Ok(HttpResponse::NoContent().finish())
}
