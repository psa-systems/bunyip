//! Persisted rate-limit configuration (BUNYIP-413).
//!
//! One optional `rate_limit_configs` row per known [`RateLimitConfig`] action.
//! Absent means "use the bootstrap default" (the compile-time const with any
//! `RATE_LIMIT_{ACTION}_*` env var applied); present overrides the cap and
//! window for that action everywhere it is enforced. The enforcement path
//! resolves the effective config through [`RateLimitConfigRepository::effective`],
//! so a change lands on the next request with no restart.
//!
//! BUNYIP-556: that resolution reads a process-wide TTL snapshot of the whole
//! table ([`RateLimitConfigCache`]), not a row per decision. The table holds at
//! most one row per action and is written only by a super admin, but the
//! rate-limit floor runs underneath every route, so the uncached read cost one
//! extra round trip on every request and six more on every login. `upsert` and
//! `delete` invalidate the snapshot in the writing process, so an admin change
//! is still live on the next request there; another api process picks it up
//! within the TTL.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::RateLimitConfig;

/// A persisted per-action override row.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct RateLimitConfigRow {
    pub action: String,
    pub max_requests: i32,
    pub window_seconds: i64,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

/// Every persisted override, indexed by action. Shared by `Arc` so a request
/// clones a pointer rather than the map.
pub type RateLimitOverrides = Arc<HashMap<String, RateLimitConfigRow>>;

/// Freshness window for the override snapshot, matching `PRICING_CACHE_TTL_SECS`.
/// It bounds only how long a SECOND api process keeps enforcing the previous
/// cap; the process that took the admin write invalidates its own snapshot.
pub const RATE_LIMIT_CONFIG_CACHE_TTL_SECS: u64 = 30;

/// Single-slot TTL cache for the whole `rate_limit_configs` table (BUNYIP-556).
///
/// Shaped on `PricingCache`: a TTL slot with an explicit [`invalidate`] for the
/// admin write path. One `list` refreshes every action at once, so the snapshot
/// is always internally consistent.
///
/// [`invalidate`]: RateLimitConfigCache::invalidate
pub struct RateLimitConfigCache {
    ttl: Duration,
    slot: RwLock<Option<(Instant, RateLimitOverrides)>>,
}

impl RateLimitConfigCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            slot: RwLock::new(None),
        }
    }

    /// The fresh snapshot, otherwise the result of `load`.
    ///
    /// The read lock is never held across the await: a rare concurrent double
    /// load is cheaper than serializing every request behind one query.
    ///
    /// A load failure NEVER silently reverts the platform to its bootstrap
    /// caps, which would be a security-relevant change of behaviour: with a
    /// previous snapshot it logs at `error` and serves that one (stale, but the
    /// caps the admin actually set), and with no snapshot at all it propagates
    /// the error to the caller, which is the same failure the counter query
    /// beside it would raise anyway.
    pub async fn get_or_load<F, Fut>(&self, load: F) -> Result<RateLimitOverrides, AppError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<RateLimitConfigRow>, AppError>>,
    {
        if let Some((at, hit)) = self.slot.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if at.elapsed() < self.ttl {
                return Ok(hit.clone());
            }
        }
        match load().await {
            Ok(rows) => {
                let fresh: RateLimitOverrides = Arc::new(
                    rows.into_iter()
                        .map(|row| (row.action.clone(), row))
                        .collect(),
                );
                *self.slot.write().unwrap_or_else(|e| e.into_inner()) =
                    Some((Instant::now(), fresh.clone()));
                Ok(fresh)
            }
            Err(e) => {
                let stale = self
                    .slot
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|(_, v)| v.clone());
                match stale {
                    Some(v) => {
                        tracing::error!(
                            error = %e,
                            overrides = v.len(),
                            "rate-limit config refresh failed; serving the last good snapshot"
                        );
                        Ok(v)
                    }
                    None => Err(e),
                }
            }
        }
    }

    /// Drop the snapshot so the next resolution re-reads the table. Called on
    /// every write, so an admin change is enforced on the next request in this
    /// process with no TTL wait.
    pub fn invalidate(&self) {
        *self.slot.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// The one snapshot every enforcement site shares. It is process-wide rather
/// than held on app state because `bunyip-oci` and `bunyip-oidc` enforce limits
/// through these same associated functions, which take only a pool.
fn cache() -> &'static RateLimitConfigCache {
    static CACHE: OnceLock<RateLimitConfigCache> = OnceLock::new();
    CACHE.get_or_init(|| {
        RateLimitConfigCache::new(Duration::from_secs(RATE_LIMIT_CONFIG_CACHE_TTL_SECS))
    })
}

pub struct RateLimitConfigRepository;

impl RateLimitConfigRepository {
    /// Every persisted override, action-ordered.
    pub async fn list(pool: &PgPool) -> Result<Vec<RateLimitConfigRow>, AppError> {
        let rows = sqlx::query_as::<_, RateLimitConfigRow>(
            r#"
            SELECT action, max_requests, window_seconds, updated_at, updated_by
            FROM rate_limit_configs
            ORDER BY action
            "#,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// The persisted override for `action`, if any.
    pub async fn get(pool: &PgPool, action: &str) -> Result<Option<RateLimitConfigRow>, AppError> {
        let row = sqlx::query_as::<_, RateLimitConfigRow>(
            r#"
            SELECT action, max_requests, window_seconds, updated_at, updated_by
            FROM rate_limit_configs
            WHERE action = $1
            "#,
        )
        .bind(action)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }

    /// Create or update the override for `action`. `updated_by` is the acting
    /// super admin. Returns the stored row.
    pub async fn upsert(
        pool: &PgPool,
        action: &str,
        max_requests: i32,
        window_seconds: i64,
        updated_by: Option<Uuid>,
    ) -> Result<RateLimitConfigRow, AppError> {
        let row = sqlx::query_as::<_, RateLimitConfigRow>(
            r#"
            INSERT INTO rate_limit_configs (action, max_requests, window_seconds, updated_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (action) DO UPDATE
                SET max_requests = EXCLUDED.max_requests,
                    window_seconds = EXCLUDED.window_seconds,
                    updated_at = NOW(),
                    updated_by = EXCLUDED.updated_by
            RETURNING action, max_requests, window_seconds, updated_at, updated_by
            "#,
        )
        .bind(action)
        .bind(max_requests)
        .bind(window_seconds)
        .bind(updated_by)
        .fetch_one(pool)
        .await?;
        cache().invalidate();
        Ok(row)
    }

    /// Drop the override for `action`, reverting it to the bootstrap default.
    /// Returns true when a row was actually removed.
    pub async fn delete(pool: &PgPool, action: &str) -> Result<bool, AppError> {
        let result = sqlx::query("DELETE FROM rate_limit_configs WHERE action = $1")
            .bind(action)
            .execute(pool)
            .await?;
        cache().invalidate();
        Ok(result.rows_affected() > 0)
    }

    /// The cached snapshot of every persisted override (BUNYIP-556), reloaded
    /// at most once per TTL and on every write.
    pub async fn overrides(pool: &PgPool) -> Result<RateLimitOverrides, AppError> {
        cache().get_or_load(|| Self::list(pool)).await
    }

    /// The config actually enforced for `base`: the bootstrap default (const +
    /// env) with the persisted row's cap/window applied when one exists. Every
    /// enforcement entry point resolves through here, so an override takes
    /// effect at every call site for that action.
    ///
    /// Reads the cached snapshot, never a per-decision `SELECT`: the const to
    /// env to persisted precedence is unchanged, only where the persisted layer
    /// is read from.
    pub async fn effective(
        pool: &PgPool,
        base: &RateLimitConfig,
    ) -> Result<RateLimitConfig, AppError> {
        let base = base.with_env_defaults();
        match Self::overrides(pool).await?.get(base.action) {
            Some(row) => Ok(base.with_overrides(Some(row.max_requests), Some(row.window_seconds))),
            None => Ok(base),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn row(action: &str, max_requests: i32, window_seconds: i64) -> RateLimitConfigRow {
        RateLimitConfigRow {
            action: action.to_string(),
            max_requests,
            window_seconds,
            updated_at: DateTime::from_timestamp(1_000, 0).unwrap(),
            updated_by: None,
        }
    }

    /// The whole point of BUNYIP-556: N rate-limit decisions inside one TTL
    /// window read the table ONCE, not N times.
    #[tokio::test]
    async fn ten_decisions_load_the_table_once() {
        let cache = RateLimitConfigCache::new(Duration::from_secs(30));
        let loads = AtomicUsize::new(0);

        for _ in 0..10 {
            let snapshot = cache
                .get_or_load(|| async {
                    loads.fetch_add(1, Ordering::Relaxed);
                    Ok(vec![row("login", 2, 120)])
                })
                .await
                .unwrap();
            assert_eq!(snapshot.get("login").unwrap().max_requests, 2);
        }

        assert_eq!(loads.load(Ordering::Relaxed), 1);
    }

    /// An expired snapshot is re-read, so an override written by another api
    /// process lands within the TTL with no restart.
    #[tokio::test]
    async fn an_expired_snapshot_is_reloaded() {
        let cache = RateLimitConfigCache::new(Duration::from_secs(0));
        let loads = AtomicUsize::new(0);

        for _ in 0..3 {
            cache
                .get_or_load(|| async {
                    loads.fetch_add(1, Ordering::Relaxed);
                    Ok(Vec::new())
                })
                .await
                .unwrap();
        }

        assert_eq!(loads.load(Ordering::Relaxed), 3);
    }

    /// An admin write invalidates the snapshot, so the new cap is enforced on
    /// the next request in this process rather than after the TTL.
    #[tokio::test]
    async fn an_invalidated_snapshot_is_reloaded_at_once() {
        let cache = RateLimitConfigCache::new(Duration::from_secs(30));

        let first = cache
            .get_or_load(|| async { Ok(vec![row("login", 5, 60)]) })
            .await
            .unwrap();
        assert_eq!(first.get("login").unwrap().max_requests, 5);

        cache.invalidate();

        let second = cache
            .get_or_load(|| async { Ok(vec![row("login", 2, 60)]) })
            .await
            .unwrap();
        assert_eq!(second.get("login").unwrap().max_requests, 2);
    }

    /// A failed refresh serves the last good snapshot. Silently reverting to the
    /// bootstrap caps would be a security-relevant change of behaviour, so the
    /// admin-set override survives the outage (and the failure is logged at
    /// `error` by `get_or_load`).
    #[tokio::test]
    async fn a_failed_refresh_serves_the_last_good_snapshot() {
        let cache = RateLimitConfigCache::new(Duration::from_secs(0));

        cache
            .get_or_load(|| async { Ok(vec![row("login", 2, 120)]) })
            .await
            .unwrap();

        let served = cache
            .get_or_load(|| async { Err(AppError::internal("rate_limit_configs unreadable")) })
            .await
            .expect("a failed refresh must not fail the decision when a snapshot exists");
        assert_eq!(served.get("login").unwrap().max_requests, 2);
    }

    /// With nothing cached yet there is no last good snapshot to serve, so the
    /// error propagates rather than becoming a silent bootstrap default.
    #[tokio::test]
    async fn a_failed_first_load_propagates() {
        let cache = RateLimitConfigCache::new(Duration::from_secs(30));
        assert!(cache
            .get_or_load(|| async { Err(AppError::internal("rate_limit_configs unreadable")) })
            .await
            .is_err());
    }

    fn body_of(name: &str) -> String {
        let src = include_str!("rate_limit_config.rs");
        let start = src
            .find(name)
            .unwrap_or_else(|| panic!("{name} still exists"));
        let rest = &src[start..];
        let end = rest.find("\n    }").expect("function body ends");
        rest[..end].to_string()
    }

    /// Regression guard (BUNYIP-556): the enforcement path resolves from the
    /// cached snapshot. A reinstated per-decision `Self::get` would put one
    /// extra query back under every request and six back on every login.
    #[test]
    fn effective_never_reads_a_row_per_decision() {
        let body = body_of("pub async fn effective(");
        assert!(
            body.contains("Self::overrides("),
            "effective must resolve from the cached snapshot"
        );
        assert!(
            !body.contains("Self::get("),
            "effective must not SELECT one rate_limit_configs row per decision"
        );
    }

    /// Both writes drop the snapshot, so an admin change never waits out the
    /// TTL in the process that took the write.
    #[test]
    fn every_write_invalidates_the_snapshot() {
        for name in ["pub async fn upsert(", "pub async fn delete("] {
            assert!(
                body_of(name).contains("cache().invalidate()"),
                "{name} must invalidate the cached snapshot"
            );
        }
    }
}
