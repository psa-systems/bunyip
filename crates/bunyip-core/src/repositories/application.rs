//! Application repository

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{Application, CreateApplication, UpdateApplication};

pub struct ApplicationRepository;

impl ApplicationRepository {
    /// List all active applications
    pub async fn list_active(pool: &PgPool) -> Result<Vec<Application>, AppError> {
        let apps = sqlx::query_as::<_, Application>(
            r#"
            SELECT * FROM applications
            WHERE is_active = TRUE
            ORDER BY sort_order ASC, display_name ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(apps)
    }

    /// Find application by ID
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Application>, AppError> {
        let app = sqlx::query_as::<_, Application>(
            r#"
            SELECT * FROM applications WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(app)
    }

    /// Find application by slug
    pub async fn find_by_slug(pool: &PgPool, slug: &str) -> Result<Option<Application>, AppError> {
        let app = sqlx::query_as::<_, Application>(
            r#"
            SELECT * FROM applications WHERE slug = $1
            "#,
        )
        .bind(slug)
        .fetch_optional(pool)
        .await?;

        Ok(app)
    }

    /// Find active application by slug
    pub async fn find_active_by_slug(
        pool: &PgPool,
        slug: &str,
    ) -> Result<Option<Application>, AppError> {
        let app = sqlx::query_as::<_, Application>(
            r#"
            SELECT * FROM applications WHERE slug = $1 AND is_active = TRUE
            "#,
        )
        .bind(slug)
        .fetch_optional(pool)
        .await?;

        Ok(app)
    }

    /// Toggle maintenance mode
    pub async fn set_maintenance_mode(
        pool: &PgPool,
        app_id: Uuid,
        maintenance: bool,
        message: Option<&str>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE applications
            SET maintenance_mode = $1, maintenance_message = $2, updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(maintenance)
        .bind(message)
        .bind(app_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Toggle active status
    pub async fn set_active(pool: &PgPool, app_id: Uuid, active: bool) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE applications
            SET is_active = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(active)
        .bind(app_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Update application version
    pub async fn update_version(
        pool: &PgPool,
        app_id: Uuid,
        version: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE applications
            SET version = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(version)
        .bind(app_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Update application fields (admin)
    pub async fn update(
        pool: &PgPool,
        app_id: Uuid,
        data: &UpdateApplication,
    ) -> Result<Application, AppError> {
        let app = sqlx::query_as::<_, Application>(
            r#"
            UPDATE applications
            SET display_name        = COALESCE($1, display_name),
                description         = COALESCE($2, description),
                icon_url            = COALESCE($3, icon_url),
                source_code_url     = COALESCE($4, source_code_url),
                version             = COALESCE($5, version),
                subdomain           = COALESCE($6, subdomain),
                container_name      = COALESCE($7, container_name),
                health_check_url    = COALESCE($8, health_check_url),
                is_active           = COALESCE($9, is_active),
                maintenance_mode    = COALESCE($10, maintenance_mode),
                maintenance_message = COALESCE($11, maintenance_message),
                webhook_url         = COALESCE($12, webhook_url),
                forgejo_owner       = COALESCE($13, forgejo_owner),
                forgejo_repo        = COALESCE($14, forgejo_repo),
                pinned_release_tag  = COALESCE($15, pinned_release_tag),
                oci_image_owner     = COALESCE($16, oci_image_owner),
                oci_image_name      = COALESCE($17, oci_image_name),
                pinned_image_tag    = COALESCE($18, pinned_image_tag),
                updated_at          = NOW()
            WHERE id = $19
            RETURNING *
            "#,
        )
        .bind(data.display_name.as_deref())
        .bind(data.description.as_deref())
        .bind(data.icon_url.as_deref())
        .bind(data.source_code_url.as_deref())
        .bind(data.version.as_deref())
        .bind(data.subdomain.as_deref())
        .bind(data.container_name.as_deref())
        .bind(data.health_check_url.as_deref())
        .bind(data.is_active)
        .bind(data.maintenance_mode)
        .bind(data.maintenance_message.as_deref())
        .bind(data.webhook_url.as_deref())
        .bind(data.forgejo_owner.as_deref())
        .bind(data.forgejo_repo.as_deref())
        .bind(data.pinned_release_tag.as_deref())
        .bind(data.oci_image_owner.as_deref())
        .bind(data.oci_image_name.as_deref())
        .bind(data.pinned_image_tag.as_deref())
        .bind(app_id)
        .fetch_one(pool)
        .await?;

        Ok(app)
    }

    /// Returns the previously-pinned tag for an application (for cache invalidation).
    pub async fn get_pinned_tag(pool: &PgPool, app_id: Uuid) -> Result<Option<String>, AppError> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT pinned_release_tag FROM applications WHERE id = $1")
                .bind(app_id)
                .fetch_optional(pool)
                .await?;
        Ok(row.and_then(|r| r.0))
    }

    /// Create a new application (admin)
    pub async fn create(pool: &PgPool, data: &CreateApplication) -> Result<Application, AppError> {
        let app = sqlx::query_as::<_, Application>(
            r#"
            INSERT INTO applications (name, slug, display_name, description, icon_url,
                container_name, health_check_url, subdomain, webhook_url, version, source_code_url)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#,
        )
        .bind(&data.name)
        .bind(&data.slug)
        .bind(&data.display_name)
        .bind(data.description.as_deref())
        .bind(data.icon_url.as_deref())
        .bind(&data.container_name)
        .bind(data.health_check_url.as_deref())
        .bind(data.subdomain.as_deref())
        .bind(data.webhook_url.as_deref())
        .bind(data.version.as_deref())
        .bind(data.source_code_url.as_deref())
        .fetch_one(pool)
        .await?;

        Ok(app)
    }

    /// Delete an application by ID (admin)
    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM applications WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::not_found("Application"));
        }

        Ok(())
    }

    /// Swap sort_order between two applications (admin)
    pub async fn swap_sort_order(
        pool: &PgPool,
        app_id_a: Uuid,
        app_id_b: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE applications AS a
            SET sort_order = b.sort_order, updated_at = NOW()
            FROM (
                SELECT id, sort_order FROM applications WHERE id = ANY($1)
            ) AS b
            WHERE a.id = ANY($1) AND a.id != b.id
            "#,
        )
        .bind(&[app_id_a, app_id_b][..])
        .execute(pool)
        .await?;

        Ok(())
    }

    /// List all applications (admin)
    pub async fn list_all(pool: &PgPool) -> Result<Vec<Application>, AppError> {
        let apps = sqlx::query_as::<_, Application>(
            r#"
            SELECT * FROM applications ORDER BY sort_order ASC, display_name ASC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(apps)
    }
}

#[cfg(test)]
mod tests {
    //! DB-backed integration tests. Skipped when DATABASE_URL is unset.
    use super::*;
    use crate::models::UpdateApplication;

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
    }

    #[actix_rt::test]
    async fn update_sets_oci_fields() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let slug = format!("test-oci-update-{}", uuid::Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO applications (name, slug, display_name, container_name)
            VALUES ($1, $1, $1, $1)
        "#,
        )
        .bind(&slug)
        .execute(&pool)
        .await
        .unwrap();

        let row: (uuid::Uuid,) = sqlx::query_as("SELECT id FROM applications WHERE slug = $1")
            .bind(&slug)
            .fetch_one(&pool)
            .await
            .unwrap();

        let update = UpdateApplication {
            display_name: None,
            description: None,
            icon_url: None,
            source_code_url: None,
            version: None,
            subdomain: None,
            container_name: None,
            health_check_url: None,
            is_active: None,
            maintenance_mode: None,
            maintenance_message: None,
            webhook_url: None,
            forgejo_owner: None,
            forgejo_repo: None,
            pinned_release_tag: None,
            oci_image_owner: Some("a8n".into()),
            oci_image_name: Some("rus".into()),
            pinned_image_tag: Some("v1".into()),
        };

        ApplicationRepository::update(&pool, row.0, &update)
            .await
            .unwrap();

        let reloaded = ApplicationRepository::find_by_slug(&pool, &slug)
            .await
            .unwrap()
            .expect("app exists");
        assert_eq!(reloaded.oci_image_owner.as_deref(), Some("a8n"));
        assert_eq!(reloaded.oci_image_name.as_deref(), Some("rus"));
        assert_eq!(reloaded.pinned_image_tag.as_deref(), Some("v1"));

        sqlx::query("DELETE FROM applications WHERE id = $1")
            .bind(row.0)
            .execute(&pool)
            .await
            .unwrap();
    }
}
