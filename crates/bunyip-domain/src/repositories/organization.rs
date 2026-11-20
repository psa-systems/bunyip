//! Repository for organizations, teams, and team members (BUNYIP-626 child 1).
//!
//! No flag gating here; service layer refuses when `orgs_enabled` is off, so
//! the repository stays a thin data-access shim like its siblings.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::organization::{
    AddTeamMember, CreateOrganization, CreateTeam, Organization, Team, TeamMember,
    UpdateOrganization, UpdateTeam,
};

pub struct OrganizationRepository;

impl OrganizationRepository {
    pub async fn create(pool: &PgPool, data: CreateOrganization) -> Result<Organization, AppError> {
        let row = sqlx::query_as::<_, Organization>(
            "INSERT INTO organizations (owner_bunyip_user_id, name) \
             VALUES ($1, $2) RETURNING *",
        )
        .bind(data.owner_bunyip_user_id)
        .bind(&data.name)
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Organization>, AppError> {
        let row = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
        Ok(row)
    }

    pub async fn find_by_owner(
        pool: &PgPool,
        owner_bunyip_user_id: Uuid,
    ) -> Result<Option<Organization>, AppError> {
        let row = sqlx::query_as::<_, Organization>(
            "SELECT * FROM organizations WHERE owner_bunyip_user_id = $1",
        )
        .bind(owner_bunyip_user_id)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }

    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        data: UpdateOrganization,
    ) -> Result<Organization, AppError> {
        let row = sqlx::query_as::<_, Organization>(
            "UPDATE organizations SET name = $2, updated_at = NOW() \
             WHERE id = $1 RETURNING *",
        )
        .bind(id)
        .bind(&data.name)
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }
}

pub struct TeamRepository;

impl TeamRepository {
    pub async fn create(pool: &PgPool, data: CreateTeam) -> Result<Team, AppError> {
        let row = sqlx::query_as::<_, Team>(
            "INSERT INTO teams (organization_id, name, description) \
             VALUES ($1, $2, $3) RETURNING *",
        )
        .bind(data.organization_id)
        .bind(&data.name)
        .bind(data.description.as_deref())
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Team>, AppError> {
        let row = sqlx::query_as::<_, Team>("SELECT * FROM teams WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
        Ok(row)
    }

    pub async fn list_by_organization(
        pool: &PgPool,
        organization_id: Uuid,
    ) -> Result<Vec<Team>, AppError> {
        let rows = sqlx::query_as::<_, Team>(
            "SELECT * FROM teams WHERE organization_id = $1 ORDER BY name",
        )
        .bind(organization_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    pub async fn update(pool: &PgPool, id: Uuid, data: UpdateTeam) -> Result<Team, AppError> {
        // Partial update using COALESCE keeps unspecified fields untouched.
        let row = sqlx::query_as::<_, Team>(
            "UPDATE teams SET \
                 name = COALESCE($2, name), \
                 description = COALESCE($3, description), \
                 updated_at = NOW() \
             WHERE id = $1 RETURNING *",
        )
        .bind(id)
        .bind(data.name.as_deref())
        .bind(data.description.as_deref())
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM teams WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }
}

pub struct TeamMemberRepository;

impl TeamMemberRepository {
    pub async fn add(pool: &PgPool, data: AddTeamMember) -> Result<TeamMember, AppError> {
        let row = sqlx::query_as::<_, TeamMember>(
            "INSERT INTO team_members (team_id, bunyip_user_id, role) \
             VALUES ($1, $2, $3) RETURNING *",
        )
        .bind(data.team_id)
        .bind(data.bunyip_user_id)
        .bind(&data.role)
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    pub async fn list_by_team(pool: &PgPool, team_id: Uuid) -> Result<Vec<TeamMember>, AppError> {
        let rows = sqlx::query_as::<_, TeamMember>(
            "SELECT * FROM team_members WHERE team_id = $1 ORDER BY joined_at",
        )
        .bind(team_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    pub async fn update_role(
        pool: &PgPool,
        team_id: Uuid,
        bunyip_user_id: Uuid,
        role: &str,
    ) -> Result<Option<TeamMember>, AppError> {
        let row = sqlx::query_as::<_, TeamMember>(
            "UPDATE team_members SET role = $3 \
             WHERE team_id = $1 AND bunyip_user_id = $2 \
             RETURNING *",
        )
        .bind(team_id)
        .bind(bunyip_user_id)
        .bind(role)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }

    pub async fn remove(
        pool: &PgPool,
        team_id: Uuid,
        bunyip_user_id: Uuid,
    ) -> Result<u64, AppError> {
        let result =
            sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND bunyip_user_id = $2")
                .bind(team_id)
                .bind(bunyip_user_id)
                .execute(pool)
                .await?;
        Ok(result.rows_affected())
    }
}
