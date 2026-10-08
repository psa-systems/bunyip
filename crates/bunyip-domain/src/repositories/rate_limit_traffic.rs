//! Per-bucket traffic counts, feeding the admin page's sparkline.
//!
//! Each call to `RateLimitRepository::check_and_increment` upserts one row
//! here, keyed by `(action, sha256(key), bucket_start)` on a 15-minute
//! grid. The read path rolls up every row for an action in a time range
//! into one point per bucket, so the admin page gets a cheap range scan
//! rather than a scan over `rate_limits` history.
//!
//! Retention: 24 hours. The maximum window the admin page offers is 1 day,
//! so anything older is dead weight.

use chrono::{DateTime, Duration, DurationRound, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};

use crate::errors::AppError;

/// One rolled-up bucket for an action, summed across every key that hit
/// it. Returned by [`RateLimitTrafficRepository::read`].
#[derive(Debug, Clone, PartialEq, FromRow)]
pub struct TrafficPoint {
    pub bucket_start: DateTime<Utc>,
    pub count: i64,
}

/// Width of a traffic bucket. 15 minutes keeps 1 day of history at 96 rows
/// per `(action, key_hash)`, which stays well inside the ticket's "no
/// monitoring stack" budget while still showing spikes.
pub const BUCKET_WIDTH_SECS: i64 = 900;

/// Default retention in seconds. The admin page's maximum window is 1 day,
/// so anything older is useless.
pub const DEFAULT_RETENTION_SECS: i64 = 86400;

/// Rate-limit traffic repository.
pub struct RateLimitTrafficRepository;

impl RateLimitTrafficRepository {
    /// Record one request. Upserts the row for the resolved bucket;
    /// successive calls in the same bucket increment `count`.
    ///
    /// Called from `check_and_increment` on every call (over-cap or not),
    /// so the write is best-effort and the caller swallows the error so
    /// enforcement is not blocked.
    pub async fn record(
        pool: &PgPool,
        action: &str,
        key: &str,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let bucket_start = truncate_bucket(now);
        let key_hash = sha256(key);
        sqlx::query(
            r#"
            INSERT INTO rate_limit_traffic (action, key_hash, bucket_start, count)
            VALUES ($1, $2, $3, 1)
            ON CONFLICT (action, key_hash, bucket_start)
            DO UPDATE SET count = rate_limit_traffic.count + 1
            "#,
        )
        .bind(action)
        .bind(&key_hash[..])
        .bind(bucket_start)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Read the per-bucket totals for an action in `[since, now]`, newest
    /// bucket first. The admin page's sparkline consumes this directly.
    pub async fn read(
        pool: &PgPool,
        action: &str,
        since: DateTime<Utc>,
    ) -> Result<Vec<TrafficPoint>, AppError> {
        let rows = sqlx::query_as::<_, TrafficPoint>(
            r#"
            SELECT bucket_start, SUM(count)::bigint AS count
            FROM rate_limit_traffic
            WHERE action = $1 AND bucket_start >= $2
            GROUP BY bucket_start
            ORDER BY bucket_start DESC
            "#,
        )
        .bind(action)
        .bind(since)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Delete rows older than `retention_seconds`.
    pub async fn sweep(pool: &PgPool, retention_seconds: i64) -> Result<u64, AppError> {
        let horizon = Utc::now() - Duration::seconds(retention_seconds);
        let result = sqlx::query("DELETE FROM rate_limit_traffic WHERE bucket_start < $1")
            .bind(horizon)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }
}

/// Truncate `now` to the start of its 15-minute bucket. `DurationRound`'s
/// `duration_trunc` is the chrono-native way to do this and matches a SQL
/// `date_trunc('minute', ...)` approach without the extra round trip.
fn truncate_bucket(now: DateTime<Utc>) -> DateTime<Utc> {
    now.duration_trunc(Duration::seconds(BUCKET_WIDTH_SECS))
        .unwrap_or(now)
}

fn sha256(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_bucket_floors_to_a_15_minute_grid() {
        let fifteen = Duration::seconds(BUCKET_WIDTH_SECS);
        let t = "2026-10-08T10:23:45Z".parse::<DateTime<Utc>>().unwrap();
        let got = truncate_bucket(t);
        let expected = "2026-10-08T10:15:00Z".parse::<DateTime<Utc>>().unwrap();
        assert_eq!(got, expected);
        // And the start of a bucket rounds to itself.
        let edge = "2026-10-08T10:15:00Z".parse::<DateTime<Utc>>().unwrap();
        assert_eq!(truncate_bucket(edge), edge);
        // And the next bucket is 15 minutes along.
        assert_eq!(truncate_bucket(edge + fifteen), edge + fifteen);
    }

    #[test]
    fn sha256_is_deterministic_and_fixed_width() {
        let a = sha256("ap@client.example");
        let b = sha256("ap@client.example");
        let c = sha256("other@client.example");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }
}
