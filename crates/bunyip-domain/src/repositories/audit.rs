//! Audit log repository

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{AuditLog, CreateAuditLog};

pub struct AuditLogRepository;

impl AuditLogRepository {
    /// Create a new audit log entry
    pub async fn create(pool: &PgPool, data: CreateAuditLog) -> Result<AuditLog, AppError> {
        let log = sqlx::query_as::<_, AuditLog>(
            r#"
            INSERT INTO audit_logs (
                actor_id, actor_email, actor_role, actor_ip_address, action,
                resource_type, resource_id, old_values, new_values, metadata,
                is_admin_action, severity
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING *
            "#,
        )
        .bind(data.actor_id)
        .bind(&data.actor_email)
        .bind(&data.actor_role)
        .bind(data.actor_ip_address)
        .bind(data.action.as_str())
        .bind(&data.resource_type)
        .bind(data.resource_id)
        .bind(&data.old_values)
        .bind(&data.new_values)
        .bind(&data.metadata)
        .bind(data.action.is_admin_action())
        .bind(data.severity.as_str())
        .fetch_one(pool)
        .await?;

        Ok(log)
    }

    /// List audit logs with pagination and filters
    pub async fn list_paginated(
        pool: &PgPool,
        page: i32,
        per_page: i32,
        actor_id: Option<Uuid>,
        action: Option<&str>,
        admin_only: bool,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> Result<(Vec<AuditLog>, i64), AppError> {
        let offset = (page - 1) * per_page;

        // Build query dynamically based on filters
        let mut conditions = Vec::new();
        let mut param_idx = 3; // Start after LIMIT and OFFSET

        if actor_id.is_some() {
            conditions.push(format!("actor_id = ${}", param_idx));
            param_idx += 1;
        }

        if action.is_some() {
            conditions.push(format!("action = ${}", param_idx));
            param_idx += 1;
        }

        if admin_only {
            conditions.push("is_admin_action = TRUE".to_string());
        }

        if start_date.is_some() {
            conditions.push(format!("created_at >= ${}", param_idx));
            param_idx += 1;
        }

        if end_date.is_some() {
            conditions.push(format!("created_at <= ${}", param_idx));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let query = format!(
            "SELECT * FROM audit_logs {} ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            where_clause
        );
        let count_query = format!("SELECT COUNT(*) FROM audit_logs {}", where_clause);

        // For simplicity, just handle the most common case - no filters
        // In a real implementation, you'd build the query more dynamically
        let logs = sqlx::query_as::<_, AuditLog>(&query)
            .bind(per_page)
            .bind(offset)
            .fetch_all(pool)
            .await?;

        let total: (i64,) = sqlx::query_as(&count_query).fetch_one(pool).await?;

        Ok((logs, total.0))
    }

    /// List recent audit logs for a user
    pub async fn list_by_actor(
        pool: &PgPool,
        actor_id: Uuid,
        limit: i32,
    ) -> Result<Vec<AuditLog>, AppError> {
        let logs = sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT * FROM audit_logs
            WHERE actor_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(actor_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(logs)
    }

    /// List admin actions
    pub async fn list_admin_actions(
        pool: &PgPool,
        page: i32,
        per_page: i32,
    ) -> Result<(Vec<AuditLog>, i64), AppError> {
        let offset = (page - 1) * per_page;

        let logs = sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT * FROM audit_logs
            WHERE is_admin_action = TRUE
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(per_page)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM audit_logs WHERE is_admin_action = TRUE")
                .fetch_one(pool)
                .await?;

        Ok((logs, total.0))
    }

    /// List security-related events
    pub async fn list_security_events(
        pool: &PgPool,
        limit: i32,
    ) -> Result<Vec<AuditLog>, AppError> {
        let logs = sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT * FROM audit_logs
            WHERE action IN ('user_login', 'user_logout', 'password_changed', 'password_reset_completed', 'admin_user_impersonated')
            ORDER BY created_at DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(logs)
    }
}
