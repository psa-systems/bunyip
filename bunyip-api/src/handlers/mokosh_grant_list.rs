//! Machine-authed listing of a bunyip user's ACTIVE outgoing mokosh
//! grants. `GET /v1/mokosh-grants?owner_bunyip_user_id={sub}`.
//!
//! Why this exists. `GET /v1/grants?role=owner` is the OWNER path: the
//! grantor is present as a user, holds an at+jwt for bunyip, and reads
//! their own outbox. Mokosh-server's MAPPS-875 owner surface, in
//! contrast, has no bunyip bearer available: the SPA authenticates
//! against MOKOSH's audience, and mokosh's own audience is not what
//! bunyip accepts. Mokosh acts as a machine caller here, presenting
//! its `oauth_clients` machine credential (same client used for
//! `/v1/users/lookup` and `POST /v1/mokosh-grants`) and naming the
//! owner it acts on behalf of in a query parameter that must match
//! the value bunyip's own owner-path handler would have read from the
//! at+jwt sub. There is no impersonation-shape concern because the
//! response is ALREADY scoped to grants that owner issued: reading
//! them says nothing about anyone else's row.
//!
//! Wire shape.
//! - Auth: HTTP Basic client_id:client_secret (the `machine_client` /
//!   mailer relay / user-lookup pattern).
//! - Query: `owner_bunyip_user_id=<uuid>`. Required. Non-UUID -> 400.
//! - Response: 200 with `{ data: [{ grant_id, grantee_bunyip_user_id,
//!   mokosh_account_id, role, granted_at, revoked_at }...], meta }`.
//!   Revoked rows are excluded (mirror of the user-authed handler's
//!   `list_active_by_owner` shape). An empty list is not a distinct
//!   error case.
//!
//! Refuse-before-Argon2. Shares the failure-only per-IP bucket
//! `RateLimitConfig::MAILER_AUTH_FAILURES` with the sibling machine
//! endpoints for the same reason those share it: the property being
//! bounded is "an unauthenticated flood against any machine-authed
//! endpoint on this host", and splitting the bucket per-endpoint
//! doubles the attacker budget.
//!
//! Feature gate. `orgs_enabled` off answers 404 like the sibling
//! grant routes, matching BUNYIP-493's "off means invisible" rule.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use bunyip_domain::errors::AppError;
use bunyip_oidc::machine_client;

use crate::config::TierConfig;
use crate::middleware::extract_client_ip;
use crate::models::RateLimitConfig;
use crate::repositories::{RateLimitConfigRepository, RateLimitRepository};
use crate::responses::{get_request_id, success};

#[derive(Debug, Deserialize)]
pub struct ListGrantsQuery {
    pub owner_bunyip_user_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct GrantView {
    pub grant_id: Uuid,
    pub grantee_bunyip_user_id: Uuid,
    pub mokosh_account_id: String,
    pub role: String,
    pub granted_at: chrono::DateTime<chrono::Utc>,
    /// MAPPS-875 v2: grantee identity fields for the mokosh owner
    /// outbox. The owner already knows the address (they typed it on
    /// the invite modal, and it stays visible on the pending row
    /// until accepted), so exposing it here discloses nothing new
    /// while giving the SPA a real display name for the active
    /// grants list. Omitted (null on the wire) when the grantee row
    /// has since been soft-deleted or when the join failed for any
    /// other reason; the SPA falls back to its own default label.
    pub grantee_email: Option<String>,
    pub grantee_name: Option<String>,
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
            "mokosh-grant-list endpoint could not record a failed client authentication"
        );
    }
}

/// GET /v1/mokosh-grants?owner_bunyip_user_id={sub}
pub async fn list_owner_grants(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    query: web::Query<ListGrantsQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
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
                        "mokosh-grant-list could not read the failure window; reporting the full window"
                    );
                    RateLimitConfig::MAILER_AUTH_FAILURES.window_seconds.max(0) as u64
                }
            };
            tracing::error!(
                category = "rate_limit",
                client = %ip,
                action = RateLimitConfig::MAILER_AUTH_FAILURES.action,
                "mokosh-grant-list: too many failed client authentications from this address"
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
                "mokosh-grant-list rejected: unknown or disabled client"
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
            "mokosh-grant-list rejected: client authentication failed"
        );
        return Err(e);
    }

    // Per-app throughput cap: reuse `USER_LOOKUP` for the same
    // reason the sibling register endpoint reuses it - one call per
    // owner opening their outbox, matching the register cadence and
    // the lookup cadence.
    super::check_rate_limit(
        &pool,
        &client.client_id.to_string(),
        &RateLimitConfig::USER_LOOKUP,
    )
    .await?;

    let owner = query.owner_bunyip_user_id;

    // MAPPS-875 v2: read grants + join the grantee's `users` row for
    // email + name so the SPA can render "Revoke access for
    // <person>". The user-authed sibling handler at
    // `handlers::mokosh_grants::list_grants` still uses the
    // repository shape (`MokoshGrantRepository::list_active_by_owner`)
    // because its response is the raw `MokoshAccountGrant` and the
    // owner already knows themselves; the machine-authed path needs
    // enriched rows because its caller is mokosh-server rendering a
    // stranger. LEFT JOIN so a soft-deleted grantee row does not
    // filter the grant out (the row still exists, it just can't be
    // switched into any more; owner needs to be able to revoke it).
    // Filter `role IS NOT NULL AND revoked_at IS NULL` mirrors the
    // repository's active predicate exactly.
    // Named row struct keeps clippy::type_complexity quiet and reads
    // as documentation for the join shape.
    #[derive(sqlx::FromRow)]
    struct GrantJoinRow {
        id: Uuid,
        grantee_bunyip_user_id: Uuid,
        mokosh_account_id: String,
        role: String,
        granted_at: chrono::DateTime<chrono::Utc>,
        email: Option<String>,
        first_name: Option<String>,
        last_name: Option<String>,
    }

    let rows: Vec<GrantJoinRow> = sqlx::query_as(
        r#"
        SELECT g.id,
               g.grantee_bunyip_user_id,
               g.mokosh_account_id,
               g.role,
               g.granted_at,
               u.email,
               u.first_name,
               u.last_name
        FROM mokosh_account_grants g
        LEFT JOIN users u ON u.id = g.grantee_bunyip_user_id
        WHERE g.owner_bunyip_user_id = $1
          AND g.revoked_at IS NULL
        ORDER BY g.granted_at ASC
        "#,
    )
    .bind(owner)
    .fetch_all(pool.get_ref())
    .await
    .map_err(bunyip_domain::errors::AppError::from)?;

    let views: Vec<GrantView> = rows
        .into_iter()
        .map(|row| {
            let name = compose_name(row.first_name.as_deref(), row.last_name.as_deref());
            GrantView {
                grant_id: row.id,
                grantee_bunyip_user_id: row.grantee_bunyip_user_id,
                mokosh_account_id: row.mokosh_account_id,
                role: row.role,
                granted_at: row.granted_at,
                grantee_email: row.email,
                grantee_name: name,
            }
        })
        .collect();

    Ok(success(views, request_id))
}

/// Compose a display name from the two optional halves. Empty halves
/// collapse (`" X"` never appears); both empty returns `None` so the
/// SPA falls back to the email.
fn compose_name(first: Option<&str>, last: Option<&str>) -> Option<String> {
    let f = first.map(str::trim).filter(|s| !s.is_empty());
    let l = last.map(str::trim).filter(|s| !s.is_empty());
    match (f, l) {
        (Some(a), Some(b)) => Some(format!("{a} {b}")),
        (Some(a), None) => Some(a.to_string()),
        (None, Some(b)) => Some(b.to_string()),
        (None, None) => None,
    }
}
