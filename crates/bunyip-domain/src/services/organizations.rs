//! Organization and team services, flag-gated on `TierConfig::orgs_enabled`
//! (BUNYIP-493, BUNYIP-626 child 1).
//!
//! Every method takes the live flag value from the caller. Flag-off returns
//! `AppError::not_found("Organizations feature is disabled")` so the HTTP
//! surface stays a clean 404; callers match on the error kind rather than
//! branching on the flag themselves.
//!
//! The flag is passed in rather than read from a lock here because
//! bunyip-domain has no `TierConfig` live-read dependency; the API layer owns
//! that read and the service stays composable (also simpler to unit-test).
//!
//! Uniqueness: a pre-check SELECT returns the pretty conflict message when the
//! row already exists; the backing UNIQUE constraint still refuses on a lost
//! race and the kernel maps the resulting 23505 to a generic `Conflict`.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::organization::{
    AddTeamMember, CreateOrganization, CreateTeam, Organization, Team, TeamMember,
    UpdateOrganization, UpdateTeam, TEAM_MEMBER_ROLE_MEMBER,
};
use crate::repositories::{OrganizationRepository, TeamMemberRepository, TeamRepository};

const FEATURE_DISABLED: &str = "Organizations feature is disabled";

fn feature_off<T>() -> Result<T, AppError> {
    Err(AppError::not_found(FEATURE_DISABLED))
}

pub struct OrganizationService;

impl OrganizationService {
    pub async fn create_organization(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        name: String,
    ) -> Result<Organization, AppError> {
        if !orgs_enabled {
            return feature_off();
        }
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::bad_request("Organization name is required"));
        }
        if OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id)
            .await?
            .is_some()
        {
            return Err(AppError::conflict("This user already owns an organization"));
        }
        OrganizationRepository::create(
            pool,
            CreateOrganization {
                owner_bunyip_user_id,
                name,
            },
        )
        .await
    }

    pub async fn get_organization_by_owner(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
    ) -> Result<Option<Organization>, AppError> {
        if !orgs_enabled {
            return feature_off();
        }
        OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id).await
    }

    pub async fn update_organization(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        name: String,
    ) -> Result<Organization, AppError> {
        if !orgs_enabled {
            return feature_off();
        }
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::bad_request("Organization name is required"));
        }
        let org = OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id)
            .await?
            .ok_or_else(|| AppError::not_found("Organization"))?;
        OrganizationRepository::update(pool, org.id, UpdateOrganization { name }).await
    }
}

pub struct TeamService;

impl TeamService {
    async fn authorize_org(
        pool: &PgPool,
        organization_id: Uuid,
        caller_bunyip_user_id: Uuid,
    ) -> Result<Organization, AppError> {
        let org = OrganizationRepository::find_by_id(pool, organization_id)
            .await?
            .ok_or_else(|| AppError::not_found("Organization"))?;
        if org.owner_bunyip_user_id != caller_bunyip_user_id {
            // Mirror a 404 rather than 403 so a non-owner cannot probe for the
            // existence of someone else's organization id.
            return Err(AppError::not_found("Organization"));
        }
        Ok(org)
    }

    async fn team_in_caller_org(
        pool: &PgPool,
        team_id: Uuid,
        caller_bunyip_user_id: Uuid,
    ) -> Result<Team, AppError> {
        let team = TeamRepository::find_by_id(pool, team_id)
            .await?
            .ok_or_else(|| AppError::not_found("Team"))?;
        Self::authorize_org(pool, team.organization_id, caller_bunyip_user_id).await?;
        Ok(team)
    }

    pub async fn list_teams(
        pool: &PgPool,
        orgs_enabled: bool,
        organization_id: Uuid,
        caller_bunyip_user_id: Uuid,
    ) -> Result<Vec<Team>, AppError> {
        if !orgs_enabled {
            return feature_off();
        }
        Self::authorize_org(pool, organization_id, caller_bunyip_user_id).await?;
        TeamRepository::list_by_organization(pool, organization_id).await
    }

    pub async fn create_team(
        pool: &PgPool,
        orgs_enabled: bool,
        organization_id: Uuid,
        caller_bunyip_user_id: Uuid,
        name: String,
        description: Option<String>,
    ) -> Result<Team, AppError> {
        if !orgs_enabled {
            return feature_off();
        }
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::bad_request("Team name is required"));
        }
        Self::authorize_org(pool, organization_id, caller_bunyip_user_id).await?;
        let dup = TeamRepository::list_by_organization(pool, organization_id)
            .await?
            .into_iter()
            .any(|t| t.name == name);
        if dup {
            return Err(AppError::conflict(
                "A team with this name already exists in this organization",
            ));
        }
        TeamRepository::create(
            pool,
            CreateTeam {
                organization_id,
                name,
                description,
            },
        )
        .await
    }

    pub async fn update_team(
        pool: &PgPool,
        orgs_enabled: bool,
        team_id: Uuid,
        caller_bunyip_user_id: Uuid,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<Team, AppError> {
        if !orgs_enabled {
            return feature_off();
        }
        let name = name.map(|n| n.trim().to_string());
        if let Some(ref n) = name {
            if n.is_empty() {
                return Err(AppError::bad_request("Team name cannot be empty"));
            }
        }
        let team = Self::team_in_caller_org(pool, team_id, caller_bunyip_user_id).await?;
        if let Some(ref new_name) = name {
            if new_name != &team.name {
                let dup = TeamRepository::list_by_organization(pool, team.organization_id)
                    .await?
                    .into_iter()
                    .any(|t| t.id != team.id && &t.name == new_name);
                if dup {
                    return Err(AppError::conflict(
                        "A team with this name already exists in this organization",
                    ));
                }
            }
        }
        TeamRepository::update(pool, team_id, UpdateTeam { name, description }).await
    }

    pub async fn delete_team(
        pool: &PgPool,
        orgs_enabled: bool,
        team_id: Uuid,
        caller_bunyip_user_id: Uuid,
    ) -> Result<(), AppError> {
        if !orgs_enabled {
            return feature_off();
        }
        Self::team_in_caller_org(pool, team_id, caller_bunyip_user_id).await?;
        let affected = TeamRepository::delete(pool, team_id).await?;
        if affected == 0 {
            return Err(AppError::not_found("Team"));
        }
        Ok(())
    }

    pub async fn list_members(
        pool: &PgPool,
        orgs_enabled: bool,
        team_id: Uuid,
        caller_bunyip_user_id: Uuid,
    ) -> Result<Vec<TeamMember>, AppError> {
        if !orgs_enabled {
            return feature_off();
        }
        Self::team_in_caller_org(pool, team_id, caller_bunyip_user_id).await?;
        TeamMemberRepository::list_by_team(pool, team_id).await
    }

    pub async fn add_member(
        pool: &PgPool,
        orgs_enabled: bool,
        team_id: Uuid,
        caller_bunyip_user_id: Uuid,
        bunyip_user_id: Uuid,
        role: Option<String>,
    ) -> Result<TeamMember, AppError> {
        if !orgs_enabled {
            return feature_off();
        }
        Self::team_in_caller_org(pool, team_id, caller_bunyip_user_id).await?;
        let role = role
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| TEAM_MEMBER_ROLE_MEMBER.to_string());
        let existing = TeamMemberRepository::list_by_team(pool, team_id)
            .await?
            .into_iter()
            .any(|m| m.bunyip_user_id == bunyip_user_id);
        if existing {
            return Err(AppError::conflict("User is already a member of this team"));
        }
        TeamMemberRepository::add(
            pool,
            AddTeamMember {
                team_id,
                bunyip_user_id,
                role,
            },
        )
        .await
    }

    pub async fn update_member_role(
        pool: &PgPool,
        orgs_enabled: bool,
        team_id: Uuid,
        caller_bunyip_user_id: Uuid,
        bunyip_user_id: Uuid,
        role: String,
    ) -> Result<TeamMember, AppError> {
        if !orgs_enabled {
            return feature_off();
        }
        let role = role.trim().to_string();
        if role.is_empty() {
            return Err(AppError::bad_request("Role is required"));
        }
        Self::team_in_caller_org(pool, team_id, caller_bunyip_user_id).await?;
        TeamMemberRepository::update_role(pool, team_id, bunyip_user_id, &role)
            .await?
            .ok_or_else(|| AppError::not_found("Team member"))
    }

    pub async fn remove_member(
        pool: &PgPool,
        orgs_enabled: bool,
        team_id: Uuid,
        caller_bunyip_user_id: Uuid,
        bunyip_user_id: Uuid,
    ) -> Result<(), AppError> {
        if !orgs_enabled {
            return feature_off();
        }
        Self::team_in_caller_org(pool, team_id, caller_bunyip_user_id).await?;
        let affected = TeamMemberRepository::remove(pool, team_id, bunyip_user_id).await?;
        if affected == 0 {
            return Err(AppError::not_found("Team member"));
        }
        Ok(())
    }
}
