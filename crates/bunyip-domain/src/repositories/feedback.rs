//! Feedback repository

use sqlx::{PgPool, QueryBuilder};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{
    ArchivedFeedbackItem, CreateFeedback, Feedback, FeedbackAttachmentMeta, FeedbackStatus,
    RespondToFeedback,
};

pub struct FeedbackRepository;

impl FeedbackRepository {
    pub async fn create(pool: &PgPool, data: CreateFeedback) -> Result<Feedback, AppError> {
        let feedback = sqlx::query_as::<_, Feedback>(
            r#"
            INSERT INTO feedback (name, email, subject, tags, message, page_path, is_spam)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(data.name)
        .bind(data.email)
        .bind(data.subject)
        .bind(data.tags)
        .bind(data.message)
        .bind(data.page_path)
        .bind(data.is_spam)
        .fetch_one(pool)
        .await?;

        Ok(feedback)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Feedback>, AppError> {
        let feedback = sqlx::query_as::<_, Feedback>("SELECT * FROM feedback WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;

        Ok(feedback)
    }

    pub async fn list_paginated(
        pool: &PgPool,
        page: i32,
        per_page: i32,
        status: Option<&str>,
    ) -> Result<(Vec<Feedback>, i64), AppError> {
        let offset = (page - 1) * per_page;

        let mut query = QueryBuilder::new("SELECT * FROM feedback");
        let mut count_query = QueryBuilder::new("SELECT COUNT(*)::BIGINT FROM feedback");

        if let Some(status) = status {
            query.push(" WHERE status = ").push_bind(status);
            count_query.push(" WHERE status = ").push_bind(status);
        }

        query
            .push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(per_page)
            .push(" OFFSET ")
            .push_bind(offset);

        let feedback = query.build_query_as::<Feedback>().fetch_all(pool).await?;

        let total: (i64,) = count_query.build_query_as().fetch_one(pool).await?;

        Ok((feedback, total.0))
    }

    pub async fn update_status(
        pool: &PgPool,
        id: Uuid,
        status: FeedbackStatus,
    ) -> Result<Feedback, AppError> {
        let feedback = sqlx::query_as::<_, Feedback>(
            "UPDATE feedback SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
        )
        .bind(status.as_str())
        .bind(id)
        .fetch_one(pool)
        .await?;

        Ok(feedback)
    }

    pub async fn list_all(pool: &PgPool) -> Result<Vec<Feedback>, AppError> {
        let feedback = sqlx::query_as::<_, Feedback>(
            "SELECT * FROM feedback WHERE is_spam = false ORDER BY created_at DESC",
        )
        .fetch_all(pool)
        .await?;

        Ok(feedback)
    }

    pub async fn list_archived(
        pool: &PgPool,
        page: i32,
        per_page: i32,
    ) -> Result<(Vec<ArchivedFeedbackItem>, i64), AppError> {
        let offset = (page - 1) * per_page;

        let items = sqlx::query_as::<_, ArchivedFeedbackItem>(
            r#"
            SELECT
                id,
                archived_at,
                (data->>'name')::text                                                     AS name,
                (data->>'email')::text                                                    AS email,
                (data->>'subject')::text                                                  AS subject,
                ARRAY(SELECT jsonb_array_elements_text(COALESCE(data->'tags', '[]'::jsonb))) AS tags,
                LEFT(COALESCE(data->>'message', ''), 120)                                 AS message_excerpt,
                (data->>'status')::text                                                   AS original_status,
                (data->>'created_at')::timestamptz                                        AS created_at
            FROM feedback_archive
            ORDER BY archived_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(per_page)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let total: (i64,) = sqlx::query_as("SELECT COUNT(*)::BIGINT FROM feedback_archive")
            .fetch_one(pool)
            .await?;

        Ok((items, total.0))
    }

    pub async fn restore_from_archive(pool: &PgPool, id: Uuid) -> Result<Feedback, AppError> {
        let feedback = sqlx::query_as::<_, Feedback>(
            r#"
            WITH archive_data AS (
                DELETE FROM feedback_archive WHERE id = $1 RETURNING data
            )
            INSERT INTO feedback (
                id, name, email, subject, tags, message, page_path,
                status, admin_response, responded_by, responded_at,
                is_spam, created_at, updated_at
            )
            SELECT
                (data->>'id')::uuid,
                data->>'name',
                data->>'email',
                data->>'subject',
                ARRAY(SELECT jsonb_array_elements_text(COALESCE(data->'tags', '[]'::jsonb))),
                data->>'message',
                data->>'page_path',
                'reviewed',
                data->>'admin_response',
                (data->>'responded_by')::uuid,
                (data->>'responded_at')::timestamptz,
                COALESCE((data->>'is_spam')::boolean, false),
                (data->>'created_at')::timestamptz,
                NOW()
            FROM archive_data
            ON CONFLICT (id) DO UPDATE
                SET status = 'reviewed', updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_one(pool)
        .await?;

        Ok(feedback)
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM feedback WHERE id = $1 AND status = 'closed'")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::not_found("Feedback"));
        }

        Ok(())
    }

    pub async fn save_attachments(
        pool: &PgPool,
        feedback_id: Uuid,
        attachments: Vec<(String, String, Vec<u8>)>,
    ) -> Result<(), AppError> {
        for (filename, mime_type, data) in attachments {
            let size_bytes = data.len() as i32;
            sqlx::query(
                r#"
                INSERT INTO feedback_attachments (feedback_id, filename, mime_type, size_bytes, data)
                VALUES ($1, $2, $3, $4, $5)
                "#,
            )
            .bind(feedback_id)
            .bind(filename)
            .bind(mime_type)
            .bind(size_bytes)
            .bind(data)
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    pub async fn find_attachments(
        pool: &PgPool,
        feedback_id: Uuid,
    ) -> Result<Vec<FeedbackAttachmentMeta>, AppError> {
        let rows = sqlx::query_as::<_, FeedbackAttachmentMeta>(
            "SELECT id, feedback_id, filename, mime_type, size_bytes, created_at FROM feedback_attachments WHERE feedback_id = $1 ORDER BY created_at",
        )
        .bind(feedback_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    pub async fn get_attachment_data(
        pool: &PgPool,
        attachment_id: Uuid,
    ) -> Result<Option<(FeedbackAttachmentMeta, Vec<u8>)>, AppError> {
        let row = sqlx::query_as::<_, (Uuid, Uuid, String, String, i32, Vec<u8>, chrono::DateTime<chrono::Utc>)>(
            "SELECT id, feedback_id, filename, mime_type, size_bytes, data, created_at FROM feedback_attachments WHERE id = $1",
        )
        .bind(attachment_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| {
            let meta = FeedbackAttachmentMeta {
                id: r.0,
                feedback_id: r.1,
                filename: r.2,
                mime_type: r.3,
                size_bytes: r.4,
                created_at: r.6,
            };
            (meta, r.5)
        }))
    }

    pub async fn archive_and_purge_closed(pool: &PgPool) -> Result<u64, AppError> {
        let result = sqlx::query(
            r#"
            WITH to_purge AS (
                SELECT id FROM feedback
                WHERE status = 'closed'
                  AND updated_at < NOW() - INTERVAL '90 days'
            ),
            archived AS (
                INSERT INTO feedback_archive (id, data)
                SELECT f.id, row_to_json(f)::jsonb
                FROM feedback f
                JOIN to_purge tp ON f.id = tp.id
                ON CONFLICT (id) DO NOTHING
                RETURNING id
            )
            DELETE FROM feedback f
            USING archived a
            WHERE f.id = a.id
            "#,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn respond(
        pool: &PgPool,
        feedback_id: Uuid,
        data: RespondToFeedback,
    ) -> Result<Feedback, AppError> {
        let feedback = sqlx::query_as::<_, Feedback>(
            r#"
            UPDATE feedback
            SET status = $1,
                admin_response = $2,
                responded_by = $3,
                responded_at = NOW(),
                updated_at = NOW()
            WHERE id = $4
            RETURNING *
            "#,
        )
        .bind(data.status.as_str())
        .bind(data.admin_response)
        .bind(data.responded_by)
        .bind(feedback_id)
        .fetch_one(pool)
        .await?;

        Ok(feedback)
    }
}
