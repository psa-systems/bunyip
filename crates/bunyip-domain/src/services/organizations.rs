//! BUNYIP-672 [BUNYIP-626 child 1]: organization and team services.
//!
//! Every method gates on `orgs_enabled` and returns
//! [`AppError::not_found`] when the flag is off. That matches the shape
//! the parent epic's contract asked for and mirrors BUNYIP-493's rule
//! that off means INVISIBLE (a `Forbidden` would confirm the feature
//! exists to a caller who is not entitled to see it).
//!
//! The service accepts a boolean `orgs_enabled` argument rather than
//! reading the tier config itself. Two reasons: the api-side handler
//! already holds the `Arc<RwLock<TierConfig>>` for `/v1/auth/setup/status`
//! and would otherwise resolve it twice, and a background caller (a
//! bunyip-web renderer, a test) that has already made the flag decision
//! can pass the value it decided from.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{validate_name, validate_team_member_role, Organization, Team, TeamMember};
use crate::repositories::{OrganizationRepository, TeamMemberRepository, TeamRepository};

pub struct OrganizationsService;

impl OrganizationsService {
    /// `POST /v1/organization` - create the caller's organization.
    ///
    /// A second create by the same owner is refused with 409 via the
    /// `UNIQUE(owner_bunyip_user_id)` constraint on the table.
    pub async fn create(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        name: &str,
    ) -> Result<Organization, AppError> {
        gate(orgs_enabled)?;
        let name = validate_name(name).map_err(|msg| AppError::validation("name", msg))?;
        OrganizationRepository::create(pool, owner_bunyip_user_id, &name).await
    }

    /// `GET /v1/organization` - the caller's own org, if any.
    ///
    /// Returns `Ok(None)` when the caller has no org so the handler can
    /// answer 404 without the service knowing the wire shape. The flag
    /// gate is checked first so a caller with the flag off never learns
    /// whether they would have had an org.
    pub async fn get_own(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
    ) -> Result<Option<Organization>, AppError> {
        gate(orgs_enabled)?;
        OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id).await
    }

    /// `PUT /v1/organization` - rename the caller's org.
    ///
    /// Refuses with 404 when the caller has no org (rather than 409 or
    /// 403), matching the "flag-off is 404" shape.
    pub async fn update_own(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        name: &str,
    ) -> Result<Organization, AppError> {
        gate(orgs_enabled)?;
        let name = validate_name(name).map_err(|msg| AppError::validation("name", msg))?;
        let existing = OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id)
            .await?
            .ok_or_else(|| AppError::not_found("Organization"))?;
        OrganizationRepository::update_name(pool, existing.id, &name).await
    }
}

pub struct TeamsService;

impl TeamsService {
    /// `GET /v1/organization/teams` - list the caller's org's teams.
    pub async fn list(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
    ) -> Result<Vec<Team>, AppError> {
        gate(orgs_enabled)?;
        let org = ensure_caller_org(pool, owner_bunyip_user_id).await?;
        TeamRepository::list_by_organization(pool, org.id).await
    }

    pub async fn create(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        name: &str,
        description: Option<&str>,
    ) -> Result<Team, AppError> {
        gate(orgs_enabled)?;
        let org = ensure_caller_org(pool, owner_bunyip_user_id).await?;
        let name = validate_name(name).map_err(|msg| AppError::validation("name", msg))?;
        TeamRepository::create(pool, org.id, &name, description).await
    }

    pub async fn get(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        team_id: Uuid,
    ) -> Result<Team, AppError> {
        gate(orgs_enabled)?;
        let org = ensure_caller_org(pool, owner_bunyip_user_id).await?;
        let team = TeamRepository::find_by_id(pool, team_id)
            .await?
            .ok_or_else(|| AppError::not_found("Team"))?;
        ensure_team_belongs_to_org(&team, org.id)?;
        Ok(team)
    }

    pub async fn update(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        team_id: Uuid,
        name: &str,
        description: Option<&str>,
    ) -> Result<Team, AppError> {
        gate(orgs_enabled)?;
        let team = Self::get(pool, orgs_enabled, owner_bunyip_user_id, team_id).await?;
        let name = validate_name(name).map_err(|msg| AppError::validation("name", msg))?;
        TeamRepository::update(pool, team.id, &name, description).await
    }

    pub async fn delete(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        team_id: Uuid,
    ) -> Result<(), AppError> {
        gate(orgs_enabled)?;
        let team = Self::get(pool, orgs_enabled, owner_bunyip_user_id, team_id).await?;
        let deleted = TeamRepository::delete(pool, team.id).await?;
        if !deleted {
            return Err(AppError::not_found("Team"));
        }
        Ok(())
    }

    pub async fn list_members(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        team_id: Uuid,
    ) -> Result<Vec<TeamMember>, AppError> {
        gate(orgs_enabled)?;
        let team = Self::get(pool, orgs_enabled, owner_bunyip_user_id, team_id).await?;
        TeamMemberRepository::list_by_team(pool, team.id).await
    }

    pub async fn add_member(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        team_id: Uuid,
        bunyip_user_id: Uuid,
        role: &str,
    ) -> Result<TeamMember, AppError> {
        gate(orgs_enabled)?;
        if !validate_team_member_role(role) {
            return Err(AppError::validation(
                "role",
                "role must be 'member' or 'leader'",
            ));
        }
        let team = Self::get(pool, orgs_enabled, owner_bunyip_user_id, team_id).await?;
        TeamMemberRepository::add(pool, team.id, bunyip_user_id, role).await
    }

    pub async fn update_member_role(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        team_id: Uuid,
        bunyip_user_id: Uuid,
        role: &str,
    ) -> Result<TeamMember, AppError> {
        gate(orgs_enabled)?;
        if !validate_team_member_role(role) {
            return Err(AppError::validation(
                "role",
                "role must be 'member' or 'leader'",
            ));
        }
        let team = Self::get(pool, orgs_enabled, owner_bunyip_user_id, team_id).await?;
        TeamMemberRepository::update_role(pool, team.id, bunyip_user_id, role)
            .await?
            .ok_or_else(|| AppError::not_found("Team member"))
    }

    pub async fn remove_member(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        team_id: Uuid,
        bunyip_user_id: Uuid,
    ) -> Result<(), AppError> {
        gate(orgs_enabled)?;
        let team = Self::get(pool, orgs_enabled, owner_bunyip_user_id, team_id).await?;
        let removed = TeamMemberRepository::remove(pool, team.id, bunyip_user_id).await?;
        if !removed {
            return Err(AppError::not_found("Team member"));
        }
        Ok(())
    }
}

fn gate(orgs_enabled: bool) -> Result<(), AppError> {
    if orgs_enabled {
        Ok(())
    } else {
        // Off means INVISIBLE, not inert: a 403 confirms the route exists
        // and the caller lacks entitlement; a 404 hides both facts.
        Err(AppError::not_found("Organization"))
    }
}

async fn ensure_caller_org(
    pool: &PgPool,
    owner_bunyip_user_id: Uuid,
) -> Result<Organization, AppError> {
    OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id)
        .await?
        .ok_or_else(|| AppError::not_found("Organization"))
}

fn ensure_team_belongs_to_org(team: &Team, org_id: Uuid) -> Result<(), AppError> {
    if team.organization_id == org_id {
        Ok(())
    } else {
        // Refuse cross-org access with 404, so a caller cannot probe for
        // another org's team ids by watching the response code.
        Err(AppError::not_found("Team"))
    }
}
