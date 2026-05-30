//! Admin notification repository

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{AdminNotification, CreateAdminNotification};

pub struct NotificationRepository;

impl NotificationRepository {
    /// Create a new admin notification
    pub async fn create(
        pool: &PgPool,
        data: CreateAdminNotification,
    ) -> Result<AdminNotification, AppError> {
        let notification = sqlx::query_as::<_, AdminNotification>(
            r#"
            INSERT INTO admin_notifications (type, title, message, metadata, user_id)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(data.notification_type.as_str())
        .bind(&data.title)
        .bind(&data.message)
        .bind(&data.metadata)
        .bind(data.user_id)
        .fetch_one(pool)
        .await?;

        Ok(notification)
    }

    /// List unread notifications
    pub async fn list_unread(pool: &PgPool) -> Result<Vec<AdminNotification>, AppError> {
        let notifications = sqlx::query_as::<_, AdminNotification>(
            r#"
            SELECT * FROM admin_notifications
            WHERE is_read = FALSE
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(notifications)
    }

    /// List all notifications with pagination
    pub async fn list_paginated(
        pool: &PgPool,
        page: i32,
        per_page: i32,
    ) -> Result<(Vec<AdminNotification>, i64), AppError> {
        let offset = (page - 1) * per_page;

        let notifications = sqlx::query_as::<_, AdminNotification>(
            r#"
            SELECT * FROM admin_notifications
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(per_page)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admin_notifications")
            .fetch_one(pool)
            .await?;

        Ok((notifications, total.0))
    }

    /// Mark notification as read
    pub async fn mark_as_read(
        pool: &PgPool,
        notification_id: Uuid,
        admin_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE admin_notifications
            SET is_read = TRUE, read_by = $1, read_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(admin_id)
        .bind(notification_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Mark all notifications as read
    pub async fn mark_all_as_read(pool: &PgPool, admin_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE admin_notifications
            SET is_read = TRUE, read_by = $1, read_at = NOW()
            WHERE is_read = FALSE
            "#,
        )
        .bind(admin_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Count unread notifications
    pub async fn count_unread(pool: &PgPool) -> Result<i64, AppError> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM admin_notifications WHERE is_read = FALSE")
                .fetch_one(pool)
                .await?;

        Ok(count.0)
    }

    /// Delete old notifications (cleanup)
    pub async fn delete_old(pool: &PgPool, days: i32) -> Result<u64, AppError> {
        let result = sqlx::query(
            r#"
            DELETE FROM admin_notifications
            WHERE created_at < NOW() - INTERVAL '1 day' * $1
            "#,
        )
        .bind(days)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}
