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

    /// List active HOSTED applications (hub launch tiles). Excludes
    /// catalog-only distribution products (is_hosted = FALSE).
    pub async fn list_active_hosted(pool: &PgPool) -> Result<Vec<Application>, AppError> {
        let apps = sqlx::query_as::<_, Application>(
            r#"
            SELECT * FROM applications
            WHERE is_active = TRUE AND is_hosted = TRUE
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

    /// Toggle whether a product requires a per-product entitlement (BUNYIP-39).
    /// FALSE keeps it open to all members; TRUE gates it behind an entitlement.
    pub async fn set_requires_entitlement(
        pool: &PgPool,
        app_id: Uuid,
        requires_entitlement: bool,
    ) -> Result<(), AppError> {
        let result = sqlx::query(
            r#"
            UPDATE applications
            SET requires_entitlement = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(requires_entitlement)
        .bind(app_id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::not_found("Application"));
        }

        Ok(())
    }

    /// Toggle maintenance mode
    pub async fn set_maintenance_mode(
        pool: &PgPool,
        app_id: Uuid,
        maintenance: bool,
        message: Option<&str>,
    ) -> Result<(), AppError> {
        let result = sqlx::query(
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

        if result.rows_affected() == 0 {
            return Err(AppError::not_found("Application"));
        }

        Ok(())
    }

    /// Toggle active status
    pub async fn set_active(pool: &PgPool, app_id: Uuid, active: bool) -> Result<(), AppError> {
        let result = sqlx::query(
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

        if result.rows_affected() == 0 {
            return Err(AppError::not_found("Application"));
        }

        Ok(())
    }

    /// Assign an application to a group, or clear it (`group_id = None`).
    ///
    /// Deliberately separate from [`Self::update`]: that method COALESCEs every
    /// field and is called with partial bodies (e.g. an is_active toggle), so
    /// it can neither clear `group_id` to NULL nor be trusted to leave it
    /// untouched. A direct `SET group_id = $1` here both sets and clears.
    pub async fn set_group(
        pool: &PgPool,
        app_id: Uuid,
        group_id: Option<Uuid>,
    ) -> Result<(), AppError> {
        let result = sqlx::query(
            r#"
            UPDATE applications
            SET group_id = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(group_id)
        .bind(app_id)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::not_found("Application"));
        }

        Ok(())
    }

    /// Update application version
    pub async fn update_version(
        pool: &PgPool,
        app_id: Uuid,
        version: &str,
    ) -> Result<(), AppError> {
        let result = sqlx::query(
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

        if result.rows_affected() == 0 {
            return Err(AppError::not_found("Application"));
        }

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
                is_hosted           = COALESCE($10, is_hosted),
                maintenance_mode    = COALESCE($11, maintenance_mode),
                maintenance_message = COALESCE($12, maintenance_message),
                webhook_url         = COALESCE($13, webhook_url),
                forgejo_owner       = COALESCE($14, forgejo_owner),
                forgejo_repo        = COALESCE($15, forgejo_repo),
                pinned_release_tag  = COALESCE($16, pinned_release_tag),
                artifact_source     = COALESCE($17, artifact_source),
                -- Empty string clears forgejo_package back to NULL (= fall back
                -- to forgejo_repo); NULL/omitted keeps the current value.
                forgejo_package     = NULLIF(COALESCE($18, forgejo_package), ''),
                oci_image_owner     = COALESCE($19, oci_image_owner),
                oci_image_name      = COALESCE($20, oci_image_name),
                pinned_image_tag    = COALESCE($21, pinned_image_tag),
                -- $23 (bound after the WHERE id param) so the existing $1..$22
                -- numbering is untouched (BUNYIP-343).
                release_notes_url   = COALESCE($23, release_notes_url),
                updated_at          = NOW()
            WHERE id = $22
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
        .bind(data.is_hosted)
        .bind(data.maintenance_mode)
        .bind(data.maintenance_message.as_deref())
        .bind(data.webhook_url.as_deref())
        .bind(data.forgejo_owner.as_deref())
        .bind(data.forgejo_repo.as_deref())
        .bind(data.pinned_release_tag.as_deref())
        .bind(data.artifact_source.as_deref())
        .bind(data.forgejo_package.as_deref())
        .bind(data.oci_image_owner.as_deref())
        .bind(data.oci_image_name.as_deref())
        .bind(data.pinned_image_tag.as_deref())
        .bind(app_id)
        .bind(data.release_notes_url.as_deref())
        .fetch_one(pool)
        .await?;

        Ok(app)
    }

    /// Create a new application (admin). Distribution coordinates (Forgejo
    /// downloads + OCI image) can be supplied at creation so a product is
    /// usable in one call; artifact_source falls back to the column default
    /// ('release') when not provided.
    pub async fn create(pool: &PgPool, data: &CreateApplication) -> Result<Application, AppError> {
        let app = sqlx::query_as::<_, Application>(
            r#"
            INSERT INTO applications (name, slug, display_name, description, icon_url,
                container_name, health_check_url, subdomain, webhook_url, version, source_code_url,
                is_hosted,
                forgejo_owner, forgejo_repo, forgejo_package, pinned_release_tag, artifact_source,
                oci_image_owner, oci_image_name, pinned_image_tag, release_notes_url)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                COALESCE($12, TRUE),
                $13, $14, $15, $16, COALESCE($17, 'release'),
                $18, $19, $20, $21)
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
        .bind(data.is_hosted)
        .bind(data.forgejo_owner.as_deref())
        .bind(data.forgejo_repo.as_deref())
        .bind(data.forgejo_package.as_deref())
        .bind(data.pinned_release_tag.as_deref())
        .bind(data.artifact_source.as_deref())
        .bind(data.oci_image_owner.as_deref())
        .bind(data.oci_image_name.as_deref())
        .bind(data.pinned_image_tag.as_deref())
        .bind(data.release_notes_url.as_deref())
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
        let result = sqlx::query(
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

        // Each id pins to the OTHER row's sort_order, so a real swap touches
        // both rows. Zero rows means one (or both) ids were missing or equal;
        // report that instead of silently succeeding.
        if result.rows_affected() == 0 {
            return Err(AppError::not_found("Application"));
        }

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

    /// BUNYIP-386: record a published image tag in the app's version history so a
    /// later pin bump does not lose it. Idempotent on (application_id, image_tag).
    pub async fn record_version(
        pool: &PgPool,
        application_id: Uuid,
        image_tag: &str,
        image_digest: Option<&str>,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO application_versions (application_id, image_tag, image_digest)
            VALUES ($1, $2, $3)
            ON CONFLICT (application_id, image_tag)
            DO UPDATE SET image_digest =
                COALESCE(application_versions.image_digest, EXCLUDED.image_digest)
            "#,
        )
        .bind(application_id)
        .bind(image_tag)
        .bind(image_digest)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// BUNYIP-386: true when `image_tag` is a recorded, non-yanked version of the
    /// application. The OCI proxy uses this as its tag allow-list so historical
    /// tags stay pullable after the pinned tag is bumped.
    pub async fn is_pullable_version(
        pool: &PgPool,
        application_id: Uuid,
        image_tag: &str,
    ) -> Result<bool, AppError> {
        let ok: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM application_versions
                WHERE application_id = $1 AND image_tag = $2 AND NOT yanked
            )
            "#,
        )
        .bind(application_id)
        .bind(image_tag)
        .fetch_one(pool)
        .await?;

        Ok(ok)
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
            release_notes_url: None,
            version: None,
            subdomain: None,
            container_name: None,
            health_check_url: None,
            is_active: None,
            is_hosted: None,
            maintenance_mode: None,
            maintenance_message: None,
            webhook_url: None,
            forgejo_owner: None,
            forgejo_repo: None,
            pinned_release_tag: None,
            artifact_source: None,
            forgejo_package: None,
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

    // BUNYIP-386: version history record/pull/yank behaviour.
    #[actix_rt::test]
    async fn version_history_roundtrip_and_yank() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let slug = format!("test-oci-versions-{}", uuid::Uuid::new_v4());
        sqlx::query(
            r#"INSERT INTO applications (name, slug, display_name, container_name)
               VALUES ($1, $1, $1, $1)"#,
        )
        .bind(&slug)
        .execute(&pool)
        .await
        .unwrap();
        let (app_id,): (uuid::Uuid,) =
            sqlx::query_as("SELECT id FROM applications WHERE slug = $1")
                .bind(&slug)
                .fetch_one(&pool)
                .await
                .unwrap();

        // Record two versions; the repeated v0.7.0 call is idempotent.
        ApplicationRepository::record_version(&pool, app_id, "v0.7.0", None)
            .await
            .unwrap();
        ApplicationRepository::record_version(&pool, app_id, "v0.8.0", None)
            .await
            .unwrap();
        ApplicationRepository::record_version(&pool, app_id, "v0.7.0", None)
            .await
            .unwrap();

        // Both recorded tags are pullable; an unrecorded one is not.
        assert!(
            ApplicationRepository::is_pullable_version(&pool, app_id, "v0.7.0")
                .await
                .unwrap()
        );
        assert!(
            ApplicationRepository::is_pullable_version(&pool, app_id, "v0.8.0")
                .await
                .unwrap()
        );
        assert!(
            !ApplicationRepository::is_pullable_version(&pool, app_id, "v9.9.9")
                .await
                .unwrap()
        );

        // A yanked version stops being pullable; others are unaffected.
        sqlx::query(
            "UPDATE application_versions SET yanked = true WHERE application_id = $1 AND image_tag = $2",
        )
        .bind(app_id)
        .bind("v0.7.0")
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            !ApplicationRepository::is_pullable_version(&pool, app_id, "v0.7.0")
                .await
                .unwrap()
        );
        assert!(
            ApplicationRepository::is_pullable_version(&pool, app_id, "v0.8.0")
                .await
                .unwrap()
        );

        // Idempotent record: exactly one v0.7.0 row.
        let (n,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM application_versions WHERE application_id = $1 AND image_tag = $2",
        )
        .bind(app_id)
        .bind("v0.7.0")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 1);

        // application_versions rows cascade-delete with the app.
        sqlx::query("DELETE FROM applications WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
