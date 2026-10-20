//! BUNYIP-933: admin-managed whitelist of principals exempt from rate
//! limits.
//!
//! A row names a `(kind, value)` pair in the same vocabulary rate-limit
//! keys use: `email:foo@bar.com`, `ip:1.2.3.4`, `user:<uuid>`. The limiter
//! checks the current request's resolved key against this table before
//! incrementing any counter; a match short-circuits to Allow with no
//! counter increment and no history record.

use chrono::{DateTime, Utc};
use sqlx::{types::Uuid, FromRow, PgPool};

use crate::errors::AppError;

/// Three principal kinds the limiter addresses. The rate-limit key prefix
/// (`email:` / `ip:` / `user:`) is identical, so matching is a split on
/// the first colon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhitelistKind {
    User,
    Email,
    Ip,
}

impl WhitelistKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Email => "email",
            Self::Ip => "ip",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "email" => Some(Self::Email),
            "ip" => Some(Self::Ip),
            _ => None,
        }
    }
}

/// One whitelist row. Columns mirror the schema in
/// `20261020000010_rate_limit_whitelist.sql`.
#[derive(Debug, Clone, FromRow)]
pub struct RateLimitWhitelistRow {
    pub id: Uuid,
    pub kind: String,
    pub value: String,
    pub reason: String,
    pub added_by: Option<Uuid>,
    pub added_at: DateTime<Utc>,
}

pub struct RateLimitWhitelistRepository;

impl RateLimitWhitelistRepository {
    /// Every whitelist row, newest first. The admin page renders this list
    /// in full (small by construction, no pagination).
    pub async fn list(pool: &PgPool) -> Result<Vec<RateLimitWhitelistRow>, AppError> {
        let rows = sqlx::query_as::<_, RateLimitWhitelistRow>(
            "SELECT id, kind, value, reason, added_by, added_at \
             FROM rate_limit_whitelist \
             ORDER BY added_at DESC",
        )
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Insert one `(kind, value)` pair. The unique index on `(kind, value)`
    /// makes a repeat insert a no-op; `ON CONFLICT DO NOTHING` keeps the
    /// endpoint idempotent (two admins pressing Add race-free).
    pub async fn insert(
        pool: &PgPool,
        kind: WhitelistKind,
        value: &str,
        reason: &str,
        added_by: Option<Uuid>,
    ) -> Result<Option<RateLimitWhitelistRow>, AppError> {
        let row = sqlx::query_as::<_, RateLimitWhitelistRow>(
            "INSERT INTO rate_limit_whitelist (kind, value, reason, added_by) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (kind, value) DO NOTHING \
             RETURNING id, kind, value, reason, added_by, added_at",
        )
        .bind(kind.as_str())
        .bind(value)
        .bind(reason)
        .bind(added_by)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }

    /// Delete one row by id. Returns `true` when a row was deleted.
    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, AppError> {
        let affected = sqlx::query("DELETE FROM rate_limit_whitelist WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected();
        Ok(affected > 0)
    }

    /// Does the current rate-limit key resolve to a whitelisted principal?
    /// `key` is the raw string passed to `check_and_increment` and follows
    /// the `kind:value` convention; a key without that shape is never
    /// whitelisted.
    ///
    /// One indexed point lookup per call. Deliberately not cached in this
    /// first cut: adding a cache means invalidating it on write across
    /// workers, which is its own follow-up.
    pub async fn is_whitelisted(pool: &PgPool, key: &str) -> Result<bool, AppError> {
        let Some((kind_str, value)) = key.split_once(':') else {
            return Ok(false);
        };
        let Some(kind) = WhitelistKind::parse(kind_str) else {
            return Ok(false);
        };
        let found: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM rate_limit_whitelist WHERE kind = $1 AND value = $2 LIMIT 1",
        )
        .bind(kind.as_str())
        .bind(value)
        .fetch_optional(pool)
        .await?;
        Ok(found.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_round_trips_through_parse() {
        for k in [WhitelistKind::User, WhitelistKind::Email, WhitelistKind::Ip] {
            assert_eq!(WhitelistKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(WhitelistKind::parse("admin"), None);
        assert_eq!(WhitelistKind::parse(""), None);
    }
}
