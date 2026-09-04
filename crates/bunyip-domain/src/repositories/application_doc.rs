//! Per-application documentation repository (BUNYIP-388).

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::application_doc::{
    ApplicationDoc, ApplicationDocSummary, CreateApplicationDoc, DocumentedApplication,
    UpdateApplicationDoc,
};

/// The public "which applications have documentation" query (BUNYIP-635), kept
/// as a constant so the unit test below can assert the active filter is still
/// in it: a deactivated application must drop out of the `/docs` hub, and the
/// only thing that makes it drop out is this predicate.
const DOCUMENTED_APPS_SQL: &str = r#"
    SELECT DISTINCT a.slug, a.display_name
    FROM applications a
    JOIN application_docs d ON d.application_id = a.id
    WHERE a.is_active = TRUE
    ORDER BY a.display_name ASC
    "#;

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

    /// The set of application ids that have at least one documentation page.
    /// One query for the whole catalog, so the downloads endpoint can flag
    /// `has_docs` per app without an EXISTS round-trip each.
    pub async fn app_ids_with_docs(
        pool: &PgPool,
    ) -> Result<std::collections::HashSet<Uuid>, AppError> {
        let rows: Vec<(Uuid,)> =
            sqlx::query_as("SELECT DISTINCT application_id FROM application_docs")
                .fetch_all(pool)
                .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Public: every ACTIVE application carrying at least one documentation
    /// page, for the `/docs` hub (BUNYIP-635). The join is what makes the list
    /// real data: an app with no pages never appears, and deactivating one
    /// removes it on the next read.
    pub async fn list_documented_apps(
        pool: &PgPool,
    ) -> Result<Vec<DocumentedApplication>, AppError> {
        let rows = sqlx::query_as::<_, DocumentedApplication>(DOCUMENTED_APPS_SQL)
            .fetch_all(pool)
            .await?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::DOCUMENTED_APPS_SQL;

    /// BUNYIP-635: the `/docs` hub promises that deactivating an application
    /// removes its entry. That promise is one predicate wide, so it is asserted
    /// here rather than left to a reviewer noticing its removal.
    #[test]
    fn the_documented_app_list_only_ever_returns_active_applications() {
        assert!(
            DOCUMENTED_APPS_SQL.contains("a.is_active = TRUE"),
            "a deactivated application must drop out of the public docs hub"
        );
        assert!(
            DOCUMENTED_APPS_SQL.contains("JOIN application_docs"),
            "the list is derived from published pages, never from the catalog"
        );
    }
}
