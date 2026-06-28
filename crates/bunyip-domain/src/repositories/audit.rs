//! Audit log repository

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{AuditLog, CreateAuditLog};

pub struct AuditLogRepository;

/// Push the optional admin-filter predicates onto a `QueryBuilder`, binding
/// each value so placeholders and bindings can never drift apart. Used for
/// both the page query and the count query in `list_paginated`.
fn push_audit_filters<'a>(
    qb: &mut QueryBuilder<'a, Postgres>,
    actor_id: Option<Uuid>,
    action: Option<&'a str>,
    admin_only: bool,
    start_date: Option<DateTime<Utc>>,
    end_date: Option<DateTime<Utc>>,
) {
    let mut sep = " WHERE ";
    if let Some(actor_id) = actor_id {
        qb.push(sep).push("actor_id = ").push_bind(actor_id);
        sep = " AND ";
    }
    if let Some(action) = action {
        qb.push(sep).push("action = ").push_bind(action);
        sep = " AND ";
    }
    if admin_only {
        qb.push(sep).push("is_admin_action = TRUE");
        sep = " AND ";
    }
    if let Some(start_date) = start_date {
        qb.push(sep).push("created_at >= ").push_bind(start_date);
        sep = " AND ";
    }
    if let Some(end_date) = end_date {
        qb.push(sep).push("created_at <= ").push_bind(end_date);
    }
}

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

        // Build the same filter clause on both the page query and the count
        // query via QueryBuilder so every placeholder is actually bound (the
        // previous version emitted `$3`/`$4` filters but only ever bound
        // `$1`/`$2`, so any actor/action filter 500'd at runtime).
        let mut query = QueryBuilder::new("SELECT * FROM audit_logs");
        push_audit_filters(
            &mut query, actor_id, action, admin_only, start_date, end_date,
        );
        query
            .push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(per_page)
            .push(" OFFSET ")
            .push_bind(offset);

        let mut count_query = QueryBuilder::new("SELECT COUNT(*) FROM audit_logs");
        push_audit_filters(
            &mut count_query,
            actor_id,
            action,
            admin_only,
            start_date,
            end_date,
        );

        let logs = query.build_query_as::<AuditLog>().fetch_all(pool).await?;
        let total: (i64,) = count_query.build_query_as().fetch_one(pool).await?;

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
