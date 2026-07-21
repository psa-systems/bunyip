//! Per-application documentation repository (BUNYIP-388).

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::application_doc::{
    ApplicationDoc, ApplicationDocSummary, CreateApplicationDoc, UpdateApplicationDoc,
};

pub struct ApplicationDocRepository;

impl ApplicationDocRepository {
    /// Public: doc-page metadata for an app identified by its slug, ordered for
    /// display. Bodies are omitted; use [`get_by_app_and_slug`] for a page.
    pub async fn list_by_app_slug(
        pool: &PgPool,
        app_slug: &str,
    ) -> Result<Vec<ApplicationDocSummary>, AppError> {
        let rows = sqlx::query_as::<_, ApplicationDocSummary>(
            r#"
            SELECT d.slug, d.title, d.sort_order
            FROM application_docs d
            JOIN applications a ON a.id = d.application_id
            WHERE a.slug = $1
            ORDER BY d.sort_order ASC, d.title ASC
            "#,
        )
        .bind(app_slug)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Public: one doc page by app slug + doc slug.
    pub async fn get_by_app_and_slug(
        pool: &PgPool,
        app_slug: &str,
        doc_slug: &str,
    ) -> Result<Option<ApplicationDoc>, AppError> {
        let row = sqlx::query_as::<_, ApplicationDoc>(
            r#"
            SELECT d.*
            FROM application_docs d
            JOIN applications a ON a.id = d.application_id
            WHERE a.slug = $1 AND d.slug = $2
            "#,
        )
        .bind(app_slug)
        .bind(doc_slug)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }

    /// Admin: all doc pages for an app by id (full rows, ordered).
    pub async fn list_by_app_id(
        pool: &PgPool,
        application_id: Uuid,
    ) -> Result<Vec<ApplicationDoc>, AppError> {
        let rows = sqlx::query_as::<_, ApplicationDoc>(
            r#"
            SELECT * FROM application_docs
            WHERE application_id = $1
            ORDER BY sort_order ASC, title ASC
            "#,
        )
        .bind(application_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Admin: one doc page by id.
    pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<ApplicationDoc>, AppError> {
        let row =
            sqlx::query_as::<_, ApplicationDoc>("SELECT * FROM application_docs WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await?;
        Ok(row)
    }

    /// Admin: create a doc page for an app.
    pub async fn create(
        pool: &PgPool,
        application_id: Uuid,
        data: &CreateApplicationDoc,
    ) -> Result<ApplicationDoc, AppError> {
        let row = sqlx::query_as::<_, ApplicationDoc>(
            r#"
            INSERT INTO application_docs (application_id, slug, title, body, sort_order)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(application_id)
        .bind(&data.slug)
        .bind(&data.title)
        .bind(&data.body)
        .bind(data.sort_order)
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    /// Admin: patch a doc page (COALESCE per field), bumping `updated_at`.
    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        data: &UpdateApplicationDoc,
    ) -> Result<ApplicationDoc, AppError> {
        let row = sqlx::query_as::<_, ApplicationDoc>(
            r#"
            UPDATE application_docs SET
                slug = COALESCE($2, slug),
                title = COALESCE($3, title),
                body = COALESCE($4, body),
                sort_order = COALESCE($5, sort_order),
                updated_at = now()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(data.slug.as_deref())
        .bind(data.title.as_deref())
        .bind(data.body.as_deref())
        .bind(data.sort_order)
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    /// Admin: delete a doc page. Returns true when a row was removed.
    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, AppError> {
        let res = sqlx::query("DELETE FROM application_docs WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }
}
