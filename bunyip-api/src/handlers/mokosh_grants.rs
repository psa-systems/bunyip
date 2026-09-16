//! BUNYIP-673 [BUNYIP-626 child 2]: HTTP handlers for `/v1/grants/*`.
//!
//! Every handler resolves the `orgs_enabled` flag ONCE from the process-
//! wide `Arc<RwLock<TierConfig>>` and passes the boolean into the
//! service. Flag-off returns 404 matching BUNYIP-493's invisibility
//! rule.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use bunyip_domain::errors::AppError;
use bunyip_domain::middleware::AuthenticatedUser;
use bunyip_domain::models::{CreateGrantRequest, MokoshAccountGrant};
use bunyip_domain::repositories::{ApplicationRepository, MokoshGrantRepository, UserRepository};
use bunyip_domain::services::{MokoshGrantsService, WebhookService};
use bunyip_oidc::services::oidc_provider::{GrantClaimSet, OidcProvider};

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

/// Body for `POST /v1/grants/{id}/access-token`.
#[derive(Debug, Deserialize)]
pub struct MintGrantTokenRequest {
    /// The target OAuth client's `client_id` (Uuid, the same shape
    /// `oauth_clients.client_id` holds). The consuming Mokosh app
    /// already knows this - it is the id the SPA authenticates against
    /// at `/authorize`. Named in the body rather than looked up from a
    /// bunyip-side registry because Bunyip serves many resource
    /// servers and the caller has always known which one they intend
    /// to sign into; a bunyip-managed lookup would either need a
    /// hardcoded slug (fragile) or a new env var (an operator surface
    /// this request does not need).
    pub client_id: Uuid,
}

/// Body for `POST /v1/grants/{id}/access-token`.
#[derive(Debug, Serialize)]
pub struct MintGrantTokenResponse {
    pub access_token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub mokosh_account_id: String,
    pub role: String,
}

/// `POST /v1/grants/{id}/access-token` - the grantee mints an at+jwt
/// scoped to the granted Mokosh account.
///
/// Every failure returns 404 rather than 403 for a caller who is not
/// the grantee, matching the sibling `revoke_grant` posture where a
/// foreign caller cannot enumerate grants they do not own. Both
/// "unknown id" and "wrong caller" therefore look identical from the
/// outside; the audit trail on the row identifies who actually tried.
pub async fn mint_grant_token(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    provider: web::Data<Arc<OidcProvider>>,
    path: web::Path<Uuid>,
    body: web::Json<MintGrantTokenRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    if !flag {
        return Err(AppError::not_found("Mokosh grant"));
    }

    let grant_id = path.into_inner();
    let grant = MokoshGrantRepository::find_by_id(pool.get_ref(), grant_id)
        .await?
        .ok_or_else(|| AppError::not_found("Mokosh grant"))?;

    if grant.grantee_bunyip_user_id != user.0.sub {
        // Wrong caller: 404, not 403. See the module-level note - a
        // caller who is not the grantee cannot enumerate grants they
        // do not own.
        return Err(AppError::not_found("Mokosh grant"));
    }
    if grant.revoked_at.is_some() {
        return Err(AppError::not_found("Mokosh grant"));
    }

    // Target client. The provider's own `load_client` gives us
    // `first_party`, `tenant_claim_name`, `disabled_at`, and the TTL /
    // audience the mint reads. A client that is not registered, is
    // disabled, is third-party, or has no tenant claim configured is
    // refused: the grant flow only makes sense against a resource
    // server with tenant-claim support (Mokosh today; other siblings
    // later).
    //
    // The precondition is `tenant_claim_name IS NOT NULL`, not
    // `first_party = TRUE`. Two orthogonal signals: `first_party` is
    // a UX property BUNYIP-406 uses to name the app on the consent
    // screen; `tenant_claim_name` is the CAPABILITY - which
    // registration axis on the client controls tenant scoping. A
    // grant token is issued to any registered client that opted
    // into tenant-scoped claims, whether or not it happens to be
    // marked first-party. This unblocks the BUNYIP-406 / BUNYIP-626
    // contradiction that shipped an unreachable endpoint.
    let client = provider
        .load_client(body.client_id)
        .await?
        .ok_or_else(|| AppError::bad_request("Unknown client_id"))?;
    if client.disabled_at.is_some() {
        return Err(AppError::bad_request("Client is disabled"));
    }
    if client.tenant_claim_name.is_none() {
        return Err(AppError::bad_request(
            "Client is not configured with a tenant_claim_name",
        ));
    }

    // Grantee user. The grant table's FK to `users(id)` guarantees the
    // row exists at grant-creation time; a delete-user path between
    // create and mint would tombstone the row and this lookup would
    // 404 back to the caller with a clean shape.
    let grantee = UserRepository::find_by_id(pool.get_ref(), user.0.sub)
        .await?
        .ok_or_else(|| AppError::not_found("User"))?;

    let grant_set = GrantClaimSet {
        grant_id: grant.id,
        role: grant.role.clone(),
        mokosh_account_id: grant.mokosh_account_id.clone(),
    };
    // Scope: `openid` alone. A grant token is deliberately narrow -
    // the caller is exercising a granted role on ONE resource server,
    // not consenting to a broader scope set the way an authorize flow
    // would negotiate. A future ticket may widen this to include the
    // client's registered mokosh:* scopes, but the minimal one gets
    // the flow working without inheriting scope from the grantor's
    // last authorize session.
    let scope = vec!["openid".to_string()];
    let now = chrono::Utc::now();
    let (access_token, exp) = provider.mint_grant_access_token(
        &grantee,
        &client,
        &scope,
        now,
        // acr / amr mirror the values a fresh cookie-authenticated
        // session would produce: silver LoA and `pwd` because the
        // grantee is signed in with a password (grants cannot be
        // minted from an unauthenticated flow). MFA-elevated ACR is
        // a future refinement.
        "urn:mace:incommon:iap:silver",
        &["pwd".to_string()],
        &grant_set,
    )?;

    Ok(success(
        MintGrantTokenResponse {
            access_token,
            expires_at: exp,
            mokosh_account_id: grant.mokosh_account_id,
            role: grant.role,
        },
        request_id,
    ))
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
