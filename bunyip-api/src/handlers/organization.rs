//! Organization and team handlers (BUNYIP-626 child 1).
//!
//! Every handler reads the live `orgs_enabled` flag through
//! [`live_orgs_enabled`] and passes it to the service layer, which returns
//! `AppError::not_found("Organizations feature is disabled")` when the flag
//! is off. Routes stay mounted regardless of the flag; the service's refusal
//! is what turns them into 404s, matching the BUNYIP-493 pattern.

use std::sync::{Arc, RwLock};

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::TierConfig;
use crate::errors::AppError;
use crate::middleware::AuthenticatedUser;
use crate::models::organization::{Organization, Team, TeamMember};
use crate::responses::{get_request_id, success, success_no_data};
use crate::services::{OrganizationService, TeamService};

/// Live read of `orgs_enabled` from the TierConfig lock. Mirrors
/// [`super::live_free_price_id`]: a poisoned lock recovers through
/// `PoisonError::into_inner` and logs, so one unrelated panic does not kill
/// the organization surface.
pub(crate) fn live_orgs_enabled(tier_config: &std::sync::RwLock<TierConfig>) -> bool {
    match tier_config.read() {
        Ok(guard) => guard.orgs_enabled,
        Err(poison) => {
            tracing::error!(
                "TierConfig read lock was poisoned by a previous panic; recovering through poison"
            );
            poison.into_inner().orgs_enabled
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateOrganizationBody {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganizationBody {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct OrganizationBody {
    pub id: Uuid,
    pub name: String,
    pub owner_bunyip_user_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<Organization> for OrganizationBody {
    fn from(o: Organization) -> Self {
        Self {
            id: o.id,
            name: o.name,
            owner_bunyip_user_id: o.owner_bunyip_user_id,
            created_at: o.created_at,
            updated_at: o.updated_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TeamBody {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<Team> for TeamBody {
    fn from(t: Team) -> Self {
        Self {
            id: t.id,
            organization_id: t.organization_id,
            name: t.name,
            description: t.description,
            created_at: t.created_at,
            updated_at: t.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateTeamBody {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTeamBody {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TeamMemberBody {
    pub team_id: Uuid,
    pub bunyip_user_id: Uuid,
    pub role: String,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

impl From<TeamMember> for TeamMemberBody {
    fn from(m: TeamMember) -> Self {
        Self {
            team_id: m.team_id,
            bunyip_user_id: m.bunyip_user_id,
            role: m.role,
            joined_at: m.joined_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AddMemberBody {
    pub bunyip_user_id: Uuid,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRoleBody {
    pub role: String,
}

pub async fn get_my_organization(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = live_orgs_enabled(&tier_config);
    let org = OrganizationService::get_organization_by_owner(&pool, flag, user.0.sub)
        .await?
        .ok_or_else(|| AppError::not_found("Organization"))?;
    Ok(success(OrganizationBody::from(org), request_id))
}

pub async fn create_my_organization(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    body: web::Json<CreateOrganizationBody>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = live_orgs_enabled(&tier_config);
    let org = OrganizationService::create_organization(&pool, flag, user.0.sub, body.name.clone())
        .await?;
    Ok(success(OrganizationBody::from(org), request_id))
}

pub async fn update_my_organization(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    body: web::Json<UpdateOrganizationBody>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = live_orgs_enabled(&tier_config);
    let org = OrganizationService::update_organization(&pool, flag, user.0.sub, body.name.clone())
        .await?;
    Ok(success(OrganizationBody::from(org), request_id))
}

async fn caller_org_id(
    pool: &PgPool,
    flag: bool,
    owner_bunyip_user_id: Uuid,
) -> Result<Uuid, AppError> {
    OrganizationService::get_organization_by_owner(pool, flag, owner_bunyip_user_id)
        .await?
        .map(|o| o.id)
        .ok_or_else(|| AppError::not_found("Organization"))
}

pub async fn list_teams(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = live_orgs_enabled(&tier_config);
    let org_id = caller_org_id(&pool, flag, user.0.sub).await?;
    let teams = TeamService::list_teams(&pool, flag, org_id, user.0.sub).await?;
    let body: Vec<TeamBody> = teams.into_iter().map(TeamBody::from).collect();
    Ok(success(body, request_id))
}

pub async fn create_team(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    body: web::Json<CreateTeamBody>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = live_orgs_enabled(&tier_config);
    let org_id = caller_org_id(&pool, flag, user.0.sub).await?;
    let team = TeamService::create_team(
        &pool,
        flag,
        org_id,
        user.0.sub,
        body.name.clone(),
        body.description.clone(),
    )
    .await?;
    Ok(success(TeamBody::from(team), request_id))
}

pub async fn update_team(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateTeamBody>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = live_orgs_enabled(&tier_config);
    let team = TeamService::update_team(
        &pool,
        flag,
        path.into_inner(),
        user.0.sub,
        body.name.clone(),
        body.description.clone(),
    )
    .await?;
    Ok(success(TeamBody::from(team), request_id))
}

pub async fn delete_team(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = live_orgs_enabled(&tier_config);
    TeamService::delete_team(&pool, flag, path.into_inner(), user.0.sub).await?;
    Ok(success_no_data(request_id))
}

pub async fn list_team_members(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = live_orgs_enabled(&tier_config);
    let members = TeamService::list_members(&pool, flag, path.into_inner(), user.0.sub).await?;
    let body: Vec<TeamMemberBody> = members.into_iter().map(TeamMemberBody::from).collect();
    Ok(success(body, request_id))
}

pub async fn add_team_member(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<Uuid>,
    body: web::Json<AddMemberBody>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = live_orgs_enabled(&tier_config);
    let member = TeamService::add_member(
        &pool,
        flag,
        path.into_inner(),
        user.0.sub,
        body.bunyip_user_id,
        body.role.clone(),
    )
    .await?;
    Ok(success(TeamMemberBody::from(member), request_id))
}

pub async fn update_team_member_role(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<(Uuid, Uuid)>,
    body: web::Json<UpdateMemberRoleBody>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = live_orgs_enabled(&tier_config);
    let (team_id, user_id) = path.into_inner();
    let member = TeamService::update_member_role(
        &pool,
        flag,
        team_id,
        user.0.sub,
        user_id,
        body.role.clone(),
    )
    .await?;
    Ok(success(TeamMemberBody::from(member), request_id))
}

pub async fn remove_team_member(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = live_orgs_enabled(&tier_config);
    let (team_id, user_id) = path.into_inner();
    TeamService::remove_member(&pool, flag, team_id, user.0.sub, user_id).await?;
    Ok(success_no_data(request_id))
}
