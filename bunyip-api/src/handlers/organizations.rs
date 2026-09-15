//! BUNYIP-672 [BUNYIP-626 child 1]: HTTP handlers for `/v1/organization/*`.
//!
//! All routes gate on `tier_config.orgs_enabled` at the service layer;
//! the flag is read once here from the process-wide `Arc<RwLock<...>>`
//! (the same value `GET /v1/auth/setup/status` reads) and passed into
//! each call, so the service never touches actix state and the handler
//! never reads a lock more than once per request.
//!
//! Flag-off returns 404 with no body detail, matching BUNYIP-493's
//! "off means INVISIBLE" rule and hiding the shape of the feature from
//! a caller who is not entitled to see it.

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use bunyip_domain::errors::AppError;
use bunyip_domain::middleware::AuthenticatedUser;
use bunyip_domain::models::{
    AddTeamMemberRequest, CreateOrganizationRequest, CreateTeamRequest, UpdateOrganizationRequest,
    UpdateTeamMemberRoleRequest, UpdateTeamRequest,
};
use bunyip_domain::services::{OrgBillingService, OrganizationsService, TeamsService};

use crate::config::TierConfig;
use crate::org_billing_provider::StripeOrgBillingProvider;
use crate::responses::{created, get_request_id, success};

fn orgs_enabled(tier_config: &Arc<RwLock<TierConfig>>) -> bool {
    tier_config
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .orgs_enabled
}

pub async fn create_organization(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    body: web::Json<CreateOrganizationRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let org = OrganizationsService::create(pool.get_ref(), flag, user.0.sub, &body.name).await?;
    Ok(created(org, request_id))
}

pub async fn get_own_organization(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let org = OrganizationsService::get_own(pool.get_ref(), flag, user.0.sub)
        .await?
        .ok_or_else(|| AppError::not_found("Organization"))?;
    Ok(success(org, request_id))
}

pub async fn update_own_organization(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    body: web::Json<UpdateOrganizationRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let org =
        OrganizationsService::update_own(pool.get_ref(), flag, user.0.sub, &body.name).await?;
    Ok(success(org, request_id))
}

pub async fn list_teams(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let teams = TeamsService::list(pool.get_ref(), flag, user.0.sub).await?;
    Ok(success(teams, request_id))
}

pub async fn create_team(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    body: web::Json<CreateTeamRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let team = TeamsService::create(
        pool.get_ref(),
        flag,
        user.0.sub,
        &body.name,
        body.description.as_deref(),
    )
    .await?;
    Ok(created(team, request_id))
}

pub async fn get_team(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let team = TeamsService::get(pool.get_ref(), flag, user.0.sub, path.into_inner()).await?;
    Ok(success(team, request_id))
}

pub async fn update_team(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateTeamRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let team = TeamsService::update(
        pool.get_ref(),
        flag,
        user.0.sub,
        path.into_inner(),
        &body.name,
        body.description.as_deref(),
    )
    .await?;
    Ok(success(team, request_id))
}

pub async fn delete_team(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    TeamsService::delete(pool.get_ref(), flag, user.0.sub, path.into_inner()).await?;
    Ok(success(serde_json::json!({ "deleted": true }), request_id))
}

pub async fn list_team_members(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let members =
        TeamsService::list_members(pool.get_ref(), flag, user.0.sub, path.into_inner()).await?;
    Ok(success(members, request_id))
}

pub async fn add_team_member(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    provider: web::Data<Arc<StripeOrgBillingProvider>>,
    path: web::Path<Uuid>,
    body: web::Json<AddTeamMemberRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let team_id = path.into_inner();
    let member = TeamsService::add_member(
        pool.get_ref(),
        flag,
        user.0.sub,
        team_id,
        body.bunyip_user_id,
        &body.role,
    )
    .await?;
    // BUNYIP-693: the org owner's Stripe subscription bills per seat, so
    // adding a member updates the quantity. `sync_seat_count_for_team`
    // no-ops when the org has no subscription and logs-without-propagating
    // on a Stripe hiccup so the membership write survives.
    OrgBillingService::sync_seat_count_for_team(
        pool.get_ref(),
        provider.get_ref().as_ref(),
        team_id,
    )
    .await?;
    Ok(created(member, request_id))
}

pub async fn update_team_member_role(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<(Uuid, Uuid)>,
    body: web::Json<UpdateTeamMemberRoleRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let (team_id, bunyip_user_id) = path.into_inner();
    let member = TeamsService::update_member_role(
        pool.get_ref(),
        flag,
        user.0.sub,
        team_id,
        bunyip_user_id,
        &body.role,
    )
    .await?;
    Ok(success(member, request_id))
}

pub async fn remove_team_member(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    provider: web::Data<Arc<StripeOrgBillingProvider>>,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let (team_id, bunyip_user_id) = path.into_inner();
    TeamsService::remove_member(pool.get_ref(), flag, user.0.sub, team_id, bunyip_user_id).await?;
    // BUNYIP-693: sync down after the removal.
    OrgBillingService::sync_seat_count_for_team(
        pool.get_ref(),
        provider.get_ref().as_ref(),
        team_id,
    )
    .await?;
    Ok(success(serde_json::json!({ "removed": true }), request_id))
}
