//! Machine-authed registration of a grant that was created on the
//! consuming resource server. `POST /v1/mokosh-grants`.
//!
//! Why this exists. `POST /v1/grants` is the OWNER path: the grantor
//! is present as a user, holds an at+jwt for bunyip, and grants
//! someone else access to their Mokosh account. Mokosh-server's
//! PMS-1208 invitation flow, in contrast, has no owner request in
//! flight when the invitation is accepted: the grantee clicked a
//! link in an email. That flow needs to end with a row in bunyip's
//! `mokosh_account_grants` so the later `POST /v1/grants/{id}/access-token`
//! mint call has something to look up, but the only party doing the
//! work at accept-time is mokosh-server, and it authenticates against
//! bunyip as a CALLING APP rather than as a user.
//!
//! Wire shape.
//! - Auth: HTTP Basic client_id:client_secret over TLS, verified through
//!   `machine_client::load_machine_client` + `verify_machine_client`
//!   (the mailer relay / user-lookup pattern). The registration must
//!   list `client_credentials` in `allowed_grant_types`, which is what
//!   makes this a whitelisted machine endpoint.
//! - Body: `{ grant_id, owner_bunyip_user_id, grantee_bunyip_user_id,
//!            mokosh_account_id, role }`. `grant_id` is the id BOTH
//!   servers use for the same grant. Mokosh's mirror row (`id`) and
//!   bunyip's own row (`id`) share this uuid by construction, so the
//!   SPA can send it to bunyip's mint endpoint without a translation
//!   step.
//! - Response: 200 with `{ grant_id, granted_at, revoked_at }`. The
//!   200 rather than 201 is deliberate: mokosh may retry a network-
//!   dropped accept, and the second call would find the row present.
//!   Idempotency by (owner, grantee, mokosh_account) is what the
//!   partial UNIQUE index in migration 20260915000060 already
//!   guarantees; naming the id in `ON CONFLICT` on the primary key is
//!   how the retry stays a no-op when the caller sends the same id
//!   twice, and reports a 409 when the caller sends a different id
//!   for a triple that is already active.
//!
//! Refuse-before-Argon2. The endpoint shares the failure-only per-IP
//! bucket `RateLimitConfig::MAILER_AUTH_FAILURES` with `/v1/mailer/send`
//! and `/v1/users/lookup` for the same reason those two share it: the
//! property being bounded is "an unauthenticated flood against any
//! machine-authed endpoint on this host", and splitting the bucket
//! per-endpoint would double the budget an attacker can spend.
//!
//! Feature gate. `orgs_enabled` off answers 404 like the other grant
//! routes, matching BUNYIP-493's "off means invisible" rule.

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
pub struct RegisterGrantRequest {
    /// The grant id BOTH servers use. Mokosh sends its invitation id
    /// here so mokosh's mirror `mokosh_bunyip_grants.bunyip_grant_id`
    /// and bunyip's own `mokosh_account_grants.id` are the SAME uuid
    /// by construction, and no translation step is needed later at
    /// mint time.
    pub grant_id: Uuid,
    pub owner_bunyip_user_id: Uuid,
    pub grantee_bunyip_user_id: Uuid,
    /// The Mokosh tenant slug the grantee is being given access to.
    pub mokosh_account_id: String,
    /// PMS-1162 role vocabulary. The CHECK constraint on the column
    /// refuses anything outside admin/manager/technician/finance/read_only,
    /// so a typo returns 400 without pre-validation here.
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterGrantResponse {
    pub grant_id: Uuid,
    pub granted_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
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
            "mokosh-grant-register endpoint could not record a failed client authentication"
        );
    }
}

/// POST /v1/mokosh-grants
pub async fn register_grant(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    body: web::Json<RegisterGrantRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    if !orgs_enabled(tier_config.get_ref()) {
        return Err(AppError::not_found("Mokosh grant"));
    }

    // Refuse-before-Argon2: share the same per-IP failure bucket the
    // other machine endpoints on this host use. See module doc.
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
                        "mokosh-grant-register could not read the failure window; reporting the full window"
                    );
                    RateLimitConfig::MAILER_AUTH_FAILURES.window_seconds.max(0) as u64
                }
            };
            tracing::error!(
                category = "rate_limit",
                client = %ip,
                action = RateLimitConfig::MAILER_AUTH_FAILURES.action,
                "mokosh-grant-register: too many failed client authentications from this address"
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
                "mokosh-grant-register rejected: unknown or disabled client"
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
            "mokosh-grant-register rejected: client authentication failed"
        );
        return Err(e);
    }

    // Per-app throughput cap: reuse `USER_LOOKUP`. Same caller shape
    // and same rough steady-state rate (one call per invitation
    // accept), so a separate preset would fragment the operator
    // surface for no functional gain.
    super::check_rate_limit(
        &pool,
        &client.client_id.to_string(),
        &RateLimitConfig::USER_LOOKUP,
    )
    .await?;

    let RegisterGrantRequest {
        grant_id,
        owner_bunyip_user_id,
        grantee_bunyip_user_id,
        mokosh_account_id,
        role,
    } = body.into_inner();

    // Idempotent upsert keyed on the id mokosh chose so a retry of the
    // same accept lands a no-op with the same response. A different
    // caller-supplied id for the same (owner, grantee, account) triple
    // still trips the partial UNIQUE index below and returns 409 via
    // the sqlx error mapping in `bunyip-domain::repositories::mokosh_grant`.
    //
    // `role` is validated by the CHECK constraint on the column
    // (admin/manager/technician/finance/read_only); an unknown role
    // therefore returns 400 from the database rather than silently
    // storing. Same for the FK to `users(id)` on both sides: an id
    // that does not resolve to a bunyip user returns 400.
    //
    // `ON CONFLICT (id) DO UPDATE` on the primary key covers the retry
    // path. `ON CONFLICT` on the partial UNIQUE (owner, grantee,
    // account) WHERE revoked_at IS NULL cannot be composed with the
    // primary key one, so a same-triple-different-id lands as 23505
    // and 409.
    let row: (
        Uuid,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = sqlx::query_as(
        "INSERT INTO mokosh_account_grants \
             (id, owner_bunyip_user_id, grantee_bunyip_user_id, mokosh_account_id, role) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO UPDATE SET \
                 role = EXCLUDED.role, \
                 owner_bunyip_user_id = EXCLUDED.owner_bunyip_user_id, \
                 grantee_bunyip_user_id = EXCLUDED.grantee_bunyip_user_id, \
                 mokosh_account_id = EXCLUDED.mokosh_account_id \
             RETURNING id, granted_at, revoked_at",
    )
    .bind(grant_id)
    .bind(owner_bunyip_user_id)
    .bind(grantee_bunyip_user_id)
    .bind(&mokosh_account_id)
    .bind(&role)
    .fetch_one(pool.get_ref())
    .await
    .map_err(bunyip_domain::repositories::map_mokosh_grant_error)?;

    Ok(success(
        RegisterGrantResponse {
            grant_id: row.0,
            granted_at: row.1,
            revoked_at: row.2,
        },
        request_id,
    ))
}
