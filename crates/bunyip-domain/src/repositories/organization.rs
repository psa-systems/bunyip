//! BUNYIP-672: repository for organizations, teams and team_members.
//!
//! Thin SQL over the three tables migration 20260915* added. All reads
//! and writes go through the `bunyip_migrator` pool (bunyip-api has no
//! per-request pool split); the `orgs_enabled` flag is enforced by the
//! service layer above, not here, so the repository stays reusable from a
//! background task that has already decided the flag is on.

use sqlx::{Error as SqlxError, PgPool};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{Organization, Team, TeamMember};

pub struct OrganizationRepository;

impl OrganizationRepository {
    /// Insert a new organization row. A second call by the same owner
    /// fails the `UNIQUE(owner_bunyip_user_id)` constraint; the service
    /// layer maps that to a 409.
    pub async fn create(
        pool: &PgPool,
        owner_bunyip_user_id: Uuid,
        name: &str,
    ) -> Result<Organization, AppError> {
        sqlx::query_as::<_, Organization>(
            "INSERT INTO organizations (owner_bunyip_user_id, name) VALUES ($1, $2) RETURNING *",
        )
        .bind(owner_bunyip_user_id)
        .bind(name)
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Organization>, AppError> {
        sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(map_sqlx)
    }

    pub async fn find_by_owner(
        pool: &PgPool,
        owner_bunyip_user_id: Uuid,
    ) -> Result<Option<Organization>, AppError> {
        sqlx::query_as::<_, Organization>(
            "SELECT * FROM organizations WHERE owner_bunyip_user_id = $1",
        )
        .bind(owner_bunyip_user_id)
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn update_name(
        pool: &PgPool,
        id: Uuid,
        name: &str,
    ) -> Result<Organization, AppError> {
        sqlx::query_as::<_, Organization>(
            "UPDATE organizations SET name = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
        )
        .bind(name)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)
    }
}

pub struct TeamRepository;

impl TeamRepository {
    pub async fn create(
        pool: &PgPool,
        organization_id: Uuid,
        name: &str,
        description: Option<&str>,
    ) -> Result<Team, AppError> {
        sqlx::query_as::<_, Team>(
            "INSERT INTO teams (organization_id, name, description) VALUES ($1, $2, $3) RETURNING *",
        )
        .bind(organization_id)
        .bind(name)
        .bind(description)
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Team>, AppError> {
        sqlx::query_as::<_, Team>("SELECT * FROM teams WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(map_sqlx)
    }

    pub async fn list_by_organization(
        pool: &PgPool,
        organization_id: Uuid,
    ) -> Result<Vec<Team>, AppError> {
        sqlx::query_as::<_, Team>(
            "SELECT * FROM teams WHERE organization_id = $1 ORDER BY created_at ASC",
        )
        .bind(organization_id)
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        name: &str,
        description: Option<&str>,
    ) -> Result<Team, AppError> {
        sqlx::query_as::<_, Team>(
            "UPDATE teams SET name = $1, description = $2, updated_at = NOW() \
             WHERE id = $3 RETURNING *",
        )
        .bind(name)
        .bind(description)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, AppError> {
        let result = sqlx::query("DELETE FROM teams WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(map_sqlx)?;
        Ok(result.rows_affected() > 0)
    }
}

pub struct TeamMemberRepository;

impl TeamMemberRepository {
    pub async fn add(
        pool: &PgPool,
        team_id: Uuid,
        bunyip_user_id: Uuid,
        role: &str,
    ) -> Result<TeamMember, AppError> {
        sqlx::query_as::<_, TeamMember>(
            "INSERT INTO team_members (team_id, bunyip_user_id, role) \
             VALUES ($1, $2, $3) RETURNING *",
        )
        .bind(team_id)
        .bind(bunyip_user_id)
        .bind(role)
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn list_by_team(pool: &PgPool, team_id: Uuid) -> Result<Vec<TeamMember>, AppError> {
        sqlx::query_as::<_, TeamMember>(
            "SELECT * FROM team_members WHERE team_id = $1 ORDER BY joined_at ASC",
        )
        .bind(team_id)
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn update_role(
        pool: &PgPool,
        team_id: Uuid,
        bunyip_user_id: Uuid,
        role: &str,
    ) -> Result<Option<TeamMember>, AppError> {
        sqlx::query_as::<_, TeamMember>(
            "UPDATE team_members SET role = $1 \
             WHERE team_id = $2 AND bunyip_user_id = $3 RETURNING *",
        )
        .bind(role)
        .bind(team_id)
        .bind(bunyip_user_id)
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn remove(
        pool: &PgPool,
        team_id: Uuid,
        bunyip_user_id: Uuid,
    ) -> Result<bool, AppError> {
        let result =
            sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND bunyip_user_id = $2")
                .bind(team_id)
                .bind(bunyip_user_id)
                .execute(pool)
                .await
                .map_err(map_sqlx)?;
        Ok(result.rows_affected() > 0)
    }
}

/// Classify sqlx errors this module can produce so the service layer sees
/// a typed `AppError`. UNIQUE-violation is the load-bearing case:
/// `organizations` refuses a second row by the same owner, `teams` refuses
/// two teams with the same name in one org, and `team_members` refuses
/// duplicate membership. Every one maps to the same Conflict variant; the
/// service picks the wording that matches the endpoint.
fn map_sqlx(e: SqlxError) -> AppError {
    if let SqlxError::Database(db_err) = &e {
        if db_err.code().as_deref() == Some("23505") {
            return AppError::conflict(db_err.message().to_string());
        }
    }
    AppError::from(e)
}
