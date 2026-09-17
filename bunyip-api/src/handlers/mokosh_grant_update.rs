//! Machine-authed in-place role change on a mokosh grant.
//! `PATCH /v1/mokosh-grants/{id}`.
//!
//! BUNYIP-748. The owner-authed sibling `PATCH /v1/grants/{id}`
//! (`handlers::mokosh_grants::update_grant_role`) reads the owner
//! from the at+jwt sub; this endpoint's caller is mokosh-server
//! acting on behalf of an owner it has already authenticated, so the
//! owner id rides in the body the same way the sibling MAPPS-875
//! list/revoke machine endpoints receive it.
//!
//! Wire shape.
//! - Auth: HTTP Basic client_id:client_secret (the `machine_client` /
//!   mailer relay / user-lookup pattern).
//! - Body: `{ owner_bunyip_user_id, role }`. Owner binds the WHERE
//!   the same way the machine-authed revoke does. Role is validated
//!   against the PMS-1162 vocabulary; a value outside the closed set
//!   is 400 naming what was rejected.
//! - Response: 200 with the updated grant on success. 404 for
//!   unknown-id / foreign-owner / already-revoked (mirrors the user-
//!   authed handler's posture; the sibling revoke behaves identically).
//!
//! Fires the same `mokosh_grant_changed` webhook the user-authed
//! variant does, so mokosh's mirror flips within the BUNYIP-674
//! stale window even when the change came in through the machine
//! path.
//!
//! Refuse-before-Argon2 and rate-limit sharing follow the sibling
//! machine endpoints (`MAILER_AUTH_FAILURES` per-IP failure bucket,
//! `USER_LOOKUP` per-app throughput). Floor exemption is the
//! `/v1/mokosh-grants/*` wildcard MAPPS-875 added; no new entry
//! needed. Feature gate: `orgs_enabled` off returns 404.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use bunyip_domain::errors::AppError;
use bunyip_domain::repositories::ApplicationRepository;
use bunyip_domain::services::{MokoshGrantsService, WebhookService};
use bunyip_oidc::machine_client;

use crate::config::TierConfig;
use crate::middleware::extract_client_ip;
use crate::models::RateLimitConfig;
use crate::repositories::{RateLimitConfigRepository, RateLimitRepository};
use crate::responses::{get_request_id, success};

const MOKOSH_APP_SLUG: &str = "mokosh";

#[derive(Debug, Deserialize)]
pub struct UpdateGrantRoleRequest {
    pub owner_bunyip_user_id: Uuid,
    pub role: String,
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
            "mokosh-grant-update endpoint could not record a failed client authentication"
        );
    }
}

/// PATCH /v1/mokosh-grants/{id}
pub async fn update_grant_role(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    webhook: web::Data<Arc<WebhookService>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateGrantRoleRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    if !orgs_enabled(tier_config.get_ref()) {
        return Err(AppError::not_found("Mokosh grant"));
    }

    // Refuse-before-Argon2 (shared per-IP failure bucket, sibling
    // machine endpoints).
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
                        "mokosh-grant-update could not read the failure window; reporting the full window"
                    );
                    RateLimitConfig::MAILER_AUTH_FAILURES.window_seconds.max(0) as u64
                }
            };
            tracing::error!(
                category = "rate_limit",
                client = %ip,
                action = RateLimitConfig::MAILER_AUTH_FAILURES.action,
                "mokosh-grant-update: too many failed client authentications from this address"
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
                "mokosh-grant-update rejected: unknown or disabled client"
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
            "mokosh-grant-update rejected: client authentication failed"
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
    let new_role = body.role.trim();

    // Delegate to the same service the user-authed handler uses so
    // the vocabulary check, the enumeration-resistant 404, and the
    // update SQL all live in one place. Callers upstream see the
    // same shape either way.
    let grant = MokoshGrantsService::update_grant_role(
        pool.get_ref(),
        // The `orgs_enabled` gate ran at the top of this handler;
        // we know it's true or we would have returned 404 already.
        // Pass `true` unconditionally here so the service does not
        // read the tier config a second time.
        true,
        owner,
        grant_id,
        new_role,
    )
    .await?;

    // Fire the same webhook as the user-authed handler. The mokosh
    // receiver's `mokosh_grant_changed` handler upserts the mirror
    // with the new role, so grantees see the change within the
    // BUNYIP-674 30-second stale window regardless of which
    // endpoint the caller reached.
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

    Ok(success(grant, request_id))
}
