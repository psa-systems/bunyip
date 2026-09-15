//! BUNYIP-673 [BUNYIP-626 child 2]: HTTP handlers for `/v1/grants/*`.
//!
//! Every handler resolves the `orgs_enabled` flag ONCE from the process-
//! wide `Arc<RwLock<TierConfig>>` and passes the boolean into the
//! service. Flag-off returns 404 matching BUNYIP-493's invisibility
//! rule.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use bunyip_domain::errors::AppError;
use bunyip_domain::middleware::AuthenticatedUser;
use bunyip_domain::models::{CreateGrantRequest, MokoshAccountGrant};
use bunyip_domain::repositories::ApplicationRepository;
use bunyip_domain::services::{MokoshGrantsService, WebhookService};

use crate::config::TierConfig;
use crate::responses::{created, get_request_id, success};

/// BUNYIP-674: the `applications.slug` we look the Mokosh app row up
/// under. Kept as a constant so a rename in the seed data means one
/// edit here; the notify path degrades silently (a warn log) when no
/// row matches, so a fresh Bunyip that has not registered Mokosh yet
/// still serves grants and lets the operator wire the webhook up
/// after the fact.
const MOKOSH_APP_SLUG: &str = "mokosh";

/// Fire the `mokosh_grant_changed` webhook if a Mokosh application row
/// exists with a webhook URL. `warn` and continue on absence or
/// database error: the grant state is already committed, so a missing
/// webhook must not fail the caller. Mokosh's 30s cache is the
/// backstop when a delivery drops.
async fn notify_grant_changed(
    pool: &sqlx::PgPool,
    webhook: &Arc<WebhookService>,
    grant: &MokoshAccountGrant,
) {
    match ApplicationRepository::find_by_slug(pool, MOKOSH_APP_SLUG).await {
        Ok(Some(app)) => {
            webhook.notify_mokosh_grant_changed(&app, grant).await;
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

fn orgs_enabled(tier_config: &Arc<RwLock<TierConfig>>) -> bool {
    tier_config
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .orgs_enabled
}

/// `POST /v1/grants` - the caller (grantor) creates a grant.
pub async fn create_grant(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    webhook: web::Data<Arc<WebhookService>>,
    body: web::Json<CreateGrantRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let grant =
        MokoshGrantsService::create_grant(pool.get_ref(), flag, user.0.sub, body.into_inner())
            .await?;
    // BUNYIP-674: fire-and-forget the `mokosh_grant_changed` webhook
    // so the Mokosh receiver invalidates its 30s grant cache within
    // one round-trip rather than waiting for TTL expiry.
    notify_grant_changed(pool.get_ref(), webhook.get_ref(), &grant).await;
    Ok(created(grant, request_id))
}

#[derive(Debug, Deserialize)]
pub struct ListGrantsQuery {
    /// `owner` (the caller's issued grants, default) or `grantee` (grants
    /// the caller has received). Kept as a single param so the wire
    /// stays symmetric with what the parent ticket asked for; a caller
    /// wanting both makes two requests.
    #[serde(default)]
    pub role: Option<String>,
}

/// `GET /v1/grants?role=owner|grantee`.
pub async fn list_grants(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    query: web::Query<ListGrantsQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let mode = query.role.as_deref().unwrap_or("owner");
    let grants = match mode {
        "owner" => MokoshGrantsService::list_own(pool.get_ref(), flag, user.0.sub).await?,
        "grantee" => MokoshGrantsService::list_received(pool.get_ref(), flag, user.0.sub).await?,
        _ => {
            return Err(AppError::validation(
                "role",
                "role must be 'owner' or 'grantee'",
            ))
        }
    };
    Ok(success(grants, request_id))
}

/// `DELETE /v1/grants/{id}` - revoke a grant. The caller must be the
/// grant's owner; a foreign delete is 403 not 404 so the audit log has a
/// row naming who tried.
pub async fn revoke_grant(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    webhook: web::Data<Arc<WebhookService>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let grant =
        MokoshGrantsService::revoke_grant(pool.get_ref(), flag, user.0.sub, path.into_inner())
            .await?;
    // BUNYIP-674: same fire-and-forget on the revoke side; the payload
    // carries `state: "revoked"` and a NULL `role` so the Mokosh
    // receiver flips its cached row to revoked.
    notify_grant_changed(pool.get_ref(), webhook.get_ref(), &grant).await;
    Ok(success(grant, request_id))
}
