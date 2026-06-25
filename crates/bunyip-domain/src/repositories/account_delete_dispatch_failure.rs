//! BUNYIP-211: account-delete webhook dispatch failures.
//!
//! A row here records an `account_deleted` webhook delivery that exhausted its
//! retries against one downstream app. The upstream bunyip delete is already
//! committed (irreversible), so the row is the durable signal that this app's
//! copy of the user still needs purging. The admin replay endpoint re-fires the
//! webhook; the row stays as the audit trail of the unresolved delete.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::errors::AppError;

/// A persisted account-delete dispatch failure (`account_delete_dispatch_failures`).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AccountDeleteDispatchFailure {
    pub id: Uuid,
    pub user_id: Uuid,
    pub app_slug: String,
    pub last_error: String,
    pub attempted_at: DateTime<Utc>,
}

pub struct AccountDeleteDispatchFailureRepository;

impl AccountDeleteDispatchFailureRepository {
    /// Record an exhausted dispatch for `(user_id, app_slug)`. Each exhaustion
    /// is its own row so a later replay attempt that also fails is visible as a
    /// distinct event rather than overwriting the first.
    pub async fn record(
        pool: &PgPool,
        user_id: Uuid,
        app_slug: &str,
        last_error: &str,
    ) -> Result<AccountDeleteDispatchFailure, AppError> {
        let row = sqlx::query_as::<_, AccountDeleteDispatchFailure>(
            r#"
            INSERT INTO account_delete_dispatch_failures (user_id, app_slug, last_error)
            VALUES ($1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(app_slug)
        .bind(last_error)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }
}
