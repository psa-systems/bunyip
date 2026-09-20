//! BUNYIP-603: the shared mailer suppression list (`mailer_suppressions`).
//!
//! One row per recipient address the SMTP provider reported as a hard bounce or
//! a spam complaint. The mailer relay (BUNYIP-602) reads it before every send;
//! the bounce/complaint feedback webhook writes it. The list is shared across
//! every calling app because it protects the one sending domain's reputation.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

use crate::errors::AppError;

/// One row of the suppression list, as read back for the admin surface
/// (BUNYIP-762): the operator needs to see why and when an address was
/// suppressed, not just that it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct MailerSuppression {
    pub address: String,
    pub reason: String,
    pub detail: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Normalize a recipient address for suppression matching: trim surrounding
/// whitespace and lowercase it. Suppression is deliberately case-insensitive
/// across the whole address (the industry norm for a suppression list), so a
/// bounce reported for `User@Example.com` also suppresses `user@example.com`.
/// Every read and write goes through this so the stored key and the lookup key
/// can never disagree.
pub fn normalize_address(address: &str) -> String {
    address.trim().to_lowercase()
}

pub struct MailerSuppressionRepository;

impl MailerSuppressionRepository {
    /// Whether `address` is on the suppression list. The address is normalized
    /// here, so the caller passes the raw recipient and never has to remember to
    /// fold case itself.
    pub async fn is_suppressed(pool: &PgPool, address: &str) -> Result<bool, AppError> {
        let normalized = normalize_address(address);
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mailer_suppressions WHERE address = $1)",
        )
        .bind(&normalized)
        .fetch_one(pool)
        .await?;
        Ok(exists)
    }

    /// Record `address` as suppressed, or refresh an existing row's reason and
    /// detail. Idempotent on the address, so a provider that redelivers the same
    /// bounce (they retry) never errors and simply bumps `updated_at`.
    pub async fn upsert(
        pool: &PgPool,
        address: &str,
        reason: &str,
        detail: Option<&str>,
    ) -> Result<(), AppError> {
        let normalized = normalize_address(address);
        sqlx::query(
            r#"
            INSERT INTO mailer_suppressions (address, reason, detail)
            VALUES ($1, $2, $3)
            ON CONFLICT (address) DO UPDATE
                SET reason = EXCLUDED.reason,
                    detail = EXCLUDED.detail,
                    updated_at = NOW()
            "#,
        )
        .bind(&normalized)
        .bind(reason)
        .bind(detail)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// The total number of suppressed addresses, for the admin list's paging.
    pub async fn count(pool: &PgPool) -> Result<i64, AppError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mailer_suppressions")
            .fetch_one(pool)
            .await?;
        Ok(count)
    }

    /// Page through the suppression list, newest first, for the admin surface
    /// (BUNYIP-762).
    pub async fn list(
        pool: &PgPool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MailerSuppression>, AppError> {
        let rows = sqlx::query_as::<_, MailerSuppression>(
            "SELECT address, reason, detail, created_at, updated_at
             FROM mailer_suppressions
             ORDER BY created_at DESC
             LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Remove `address` from the suppression list so it can be mailed again
    /// (BUNYIP-762). Returns whether a row existed to delete.
    pub async fn delete(pool: &PgPool, address: &str) -> Result<bool, AppError> {
        let normalized = normalize_address(address);
        let result = sqlx::query("DELETE FROM mailer_suppressions WHERE address = $1")
            .bind(&normalized)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_folds_case_and_trims() {
        assert_eq!(normalize_address("  User@Example.COM "), "user@example.com");
        assert_eq!(normalize_address("plain@x.test"), "plain@x.test");
    }
}
