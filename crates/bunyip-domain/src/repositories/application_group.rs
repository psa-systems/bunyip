//! Application group repository

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{ApplicationGroup, CreateApplicationGroup, UpdateApplicationGroup};

pub struct ApplicationGroupRepository;

impl ApplicationGroupRepository {
    /// List all groups, ordered for display.
    pub async fn list(pool: &PgPool) -> Result<Vec<ApplicationGroup>, AppError> {
        let groups = sqlx::query_as::<_, ApplicationGroup>(
            r#"
            SELECT * FROM application_groups
            ORDER BY sort_order ASC, display_name ASC
            "#,
        )
        .fetch_all(pool)
        .await?;
        Ok(groups)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<ApplicationGroup>, AppError> {
        let group = sqlx::query_as::<_, ApplicationGroup>(
            r#"SELECT * FROM application_groups WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        Ok(group)
    }

    pub async fn find_by_slug(
        pool: &PgPool,
        slug: &str,
    ) -> Result<Option<ApplicationGroup>, AppError> {
        let group = sqlx::query_as::<_, ApplicationGroup>(
            r#"SELECT * FROM application_groups WHERE slug = $1"#,
        )
        .bind(slug)
        .fetch_optional(pool)
        .await?;
        Ok(group)
    }

    pub async fn create(
        pool: &PgPool,
        body: &CreateApplicationGroup,
    ) -> Result<ApplicationGroup, AppError> {
        let group = sqlx::query_as::<_, ApplicationGroup>(
            r#"
            INSERT INTO application_groups (name, slug, display_name, description, icon_url, sort_order)
            VALUES ($1, $2, $3, $4, $5, COALESCE($6, 0))
            RETURNING *
            "#,
        )
        .bind(&body.name)
        .bind(&body.slug)
        .bind(&body.display_name)
        .bind(&body.description)
        .bind(&body.icon_url)
        .bind(body.sort_order)
        .fetch_one(pool)
        .await?;
        Ok(group)
    }

    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        body: &UpdateApplicationGroup,
    ) -> Result<ApplicationGroup, AppError> {
        let group = sqlx::query_as::<_, ApplicationGroup>(
            r#"
            UPDATE application_groups
            SET name         = COALESCE($1, name),
                slug         = COALESCE($2, slug),
                display_name = COALESCE($3, display_name),
                description  = COALESCE($4, description),
                icon_url     = COALESCE($5, icon_url),
                sort_order   = COALESCE($6, sort_order),
                updated_at   = NOW()
            WHERE id = $7
            RETURNING *
            "#,
        )
        .bind(&body.name)
        .bind(&body.slug)
        .bind(&body.display_name)
        .bind(&body.description)
        .bind(&body.icon_url)
        .bind(body.sort_order)
        .bind(id)
        .fetch_one(pool)
        .await?;
        Ok(group)
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        // Members keep their rows; `applications.group_id` is ON DELETE SET NULL,
        // so removing a group simply ungroups its applications.
        sqlx::query(r#"DELETE FROM application_groups WHERE id = $1"#)
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
