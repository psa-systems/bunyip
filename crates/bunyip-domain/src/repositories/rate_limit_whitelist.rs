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
use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

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

/// The set of whitelisted `(kind, value)` pairs, shared by `Arc` so a lookup
/// clones a pointer rather than the set.
pub type WhitelistSet = Arc<HashSet<(String, String)>>;

/// Freshness window for the whitelist snapshot, matching
/// `RATE_LIMIT_CONFIG_CACHE_TTL_SECS`. It bounds only how long a SECOND api
/// process keeps enforcing the previous snapshot; the process that took the
/// admin write invalidates its own snapshot.
pub const RATE_LIMIT_WHITELIST_CACHE_TTL_SECS: u64 = 30;

/// Single-slot TTL cache for the whole `rate_limit_whitelist` table
/// (BUNYIP-962).
///
/// Shaped on `RateLimitConfigCache`: a TTL slot with an explicit
/// [`invalidate`] for the admin write path. One `list` refreshes the whole
/// set at once, so the snapshot is always internally consistent.
///
/// [`invalidate`]: WhitelistCache::invalidate
pub struct WhitelistCache {
    ttl: Duration,
    slot: RwLock<Option<(Instant, WhitelistSet)>>,
}

impl WhitelistCache {
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
    /// A load failure NEVER silently treats every principal as whitelisted:
    /// with a previous snapshot it logs at `error` and serves that one
    /// (stale, but the set the admin actually set), and with no snapshot at
    /// all it propagates the error to the caller, which is the same failure
    /// the point lookup beside it would raise anyway.
    pub async fn get_or_load<F, Fut>(&self, load: F) -> Result<WhitelistSet, AppError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<RateLimitWhitelistRow>, AppError>>,
    {
        if let Some((at, hit)) = self.slot.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if at.elapsed() < self.ttl {
                return Ok(hit.clone());
            }
        }
        match load().await {
            Ok(rows) => {
                let fresh: WhitelistSet =
                    Arc::new(rows.into_iter().map(|row| (row.kind, row.value)).collect());
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
                            entries = v.len(),
                            "rate-limit whitelist refresh failed; serving the last good snapshot"
                        );
                        Ok(v)
                    }
                    None => Err(e),
                }
            }
        }
    }

    /// Drop the snapshot so the next lookup re-reads the table. Called on
    /// every write, so an admin change is enforced on the next request in
    /// this process with no TTL wait.
    pub fn invalidate(&self) {
        *self.slot.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// The one snapshot every enforcement site shares. It is process-wide rather
/// than held on app state because `bunyip-oci` and `bunyip-oidc` enforce
/// limits through these same associated functions, which take only a pool.
fn cache() -> &'static WhitelistCache {
    static CACHE: OnceLock<WhitelistCache> = OnceLock::new();
    CACHE.get_or_init(|| {
        WhitelistCache::new(Duration::from_secs(RATE_LIMIT_WHITELIST_CACHE_TTL_SECS))
    })
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
        cache().invalidate();
        Ok(row)
    }

    /// Delete one row by id. Returns `true` when a row was deleted.
    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, AppError> {
        let affected = sqlx::query("DELETE FROM rate_limit_whitelist WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected();
        cache().invalidate();
        Ok(affected > 0)
    }

    /// Does the current rate-limit key resolve to a whitelisted principal?
    /// `key` is the raw string passed to `check_and_increment` and follows
    /// the `kind:value` convention; a key without that shape is never
    /// whitelisted.
    ///
    /// BUNYIP-962: reads the cached snapshot (`WhitelistCache`, TTL
    /// [`RATE_LIMIT_WHITELIST_CACHE_TTL_SECS`]) rather than issuing a
    /// per-call `SELECT`, mirroring `RateLimitConfigCache` (BUNYIP-556).
    pub async fn is_whitelisted(pool: &PgPool, key: &str) -> Result<bool, AppError> {
        let Some((kind_str, value)) = key.split_once(':') else {
            return Ok(false);
        };
        let Some(kind) = WhitelistKind::parse(kind_str) else {
            return Ok(false);
        };
        let set = cache().get_or_load(|| Self::list(pool)).await?;
        Ok(set.contains(&(kind.as_str().to_string(), value.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn kind_round_trips_through_parse() {
        for k in [WhitelistKind::User, WhitelistKind::Email, WhitelistKind::Ip] {
            assert_eq!(WhitelistKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(WhitelistKind::parse("admin"), None);
        assert_eq!(WhitelistKind::parse(""), None);
    }

    fn row(kind: &str, value: &str) -> RateLimitWhitelistRow {
        RateLimitWhitelistRow {
            id: Uuid::new_v4(),
            kind: kind.to_string(),
            value: value.to_string(),
            reason: "test".to_string(),
            added_by: None,
            added_at: DateTime::from_timestamp(1_000, 0).unwrap(),
        }
    }

    /// The whole point of BUNYIP-962: N whitelist lookups inside one TTL
    /// window read the table ONCE, not N times.
    #[tokio::test]
    async fn ten_lookups_load_the_table_once() {
        let cache = WhitelistCache::new(Duration::from_secs(30));
        let loads = AtomicUsize::new(0);

        for _ in 0..10 {
            let set = cache
                .get_or_load(|| async {
                    loads.fetch_add(1, Ordering::Relaxed);
                    Ok(vec![row("ip", "1.2.3.4")])
                })
                .await
                .unwrap();
            assert!(set.contains(&("ip".to_string(), "1.2.3.4".to_string())));
        }

        assert_eq!(loads.load(Ordering::Relaxed), 1);
    }

    /// An expired snapshot is re-read, so a whitelist entry written by another
    /// api process lands within the TTL with no restart.
    #[tokio::test]
    async fn an_expired_snapshot_is_reloaded() {
        let cache = WhitelistCache::new(Duration::from_secs(0));
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

    /// An admin write invalidates the snapshot, so the new entry is enforced
    /// on the next request in this process rather than after the TTL.
    #[tokio::test]
    async fn an_invalidated_snapshot_is_reloaded_at_once() {
        let cache = WhitelistCache::new(Duration::from_secs(30));

        let first = cache
            .get_or_load(|| async { Ok(vec![row("ip", "1.1.1.1")]) })
            .await
            .unwrap();
        assert!(first.contains(&("ip".to_string(), "1.1.1.1".to_string())));

        cache.invalidate();

        let second = cache
            .get_or_load(|| async { Ok(vec![row("ip", "2.2.2.2")]) })
            .await
            .unwrap();
        assert!(!second.contains(&("ip".to_string(), "1.1.1.1".to_string())));
        assert!(second.contains(&("ip".to_string(), "2.2.2.2".to_string())));
    }

    /// A failed refresh serves the last good snapshot. Silently treating
    /// every principal as not-whitelisted would drop admin-granted exemptions
    /// during an outage, so the previous set survives (and the failure is
    /// logged at `error` by `get_or_load`).
    #[tokio::test]
    async fn a_failed_refresh_serves_the_last_good_snapshot() {
        let cache = WhitelistCache::new(Duration::from_secs(0));

        cache
            .get_or_load(|| async { Ok(vec![row("ip", "9.9.9.9")]) })
            .await
            .unwrap();

        let served = cache
            .get_or_load(|| async { Err(AppError::internal("rate_limit_whitelist unreadable")) })
            .await
            .expect("a failed refresh must not fail the lookup when a snapshot exists");
        assert!(served.contains(&("ip".to_string(), "9.9.9.9".to_string())));
    }

    /// With nothing cached yet there is no last good snapshot to serve, so the
    /// error propagates rather than becoming a silent empty whitelist.
    #[tokio::test]
    async fn a_failed_first_load_propagates() {
        let cache = WhitelistCache::new(Duration::from_secs(30));
        assert!(cache
            .get_or_load(|| async { Err(AppError::internal("rate_limit_whitelist unreadable")) })
            .await
            .is_err());
    }

    fn body_of(name: &str) -> String {
        let src = include_str!("rate_limit_whitelist.rs");
        let start = src
            .find(name)
            .unwrap_or_else(|| panic!("{name} still exists"));
        let rest = &src[start..];
        let end = rest.find("\n    }").expect("function body ends");
        rest[..end].to_string()
    }

    /// Regression guard (BUNYIP-962): `is_whitelisted` resolves from the
    /// cached snapshot. A reinstated per-call `SELECT` would put the query
    /// back on every non-exempt request.
    #[test]
    fn is_whitelisted_never_reads_a_row_per_call() {
        let body = body_of("pub async fn is_whitelisted(");
        assert!(
            body.contains("cache().get_or_load("),
            "is_whitelisted must resolve from the cached snapshot"
        );
        assert!(
            !body.to_lowercase().contains("select"),
            "is_whitelisted must not SELECT a row per call"
        );
    }

    /// Both writes drop the snapshot, so an admin change never waits out the
    /// TTL in the process that took the write.
    #[test]
    fn every_write_invalidates_the_snapshot() {
        for name in ["pub async fn insert(", "pub async fn delete("] {
            assert!(
                body_of(name).contains("cache().invalidate()"),
                "{name} must invalidate the cached snapshot"
            );
        }
    }
}
