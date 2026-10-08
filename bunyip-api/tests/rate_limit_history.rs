//! Rate-limit history is written on the under-cap to over-cap boundary and
//! swept at 24 hours.
//!
//! Env-gated like `rls_isolation.rs`: it needs a throwaway Postgres to
//! migrate. Set `BUNYIP_TEST_DATABASE_URL` (or reuse `RLS_TEST_DATABASE_URL`)
//! to a database this test may migrate; unset skips the test.

use bunyip_domain::models::RateLimitConfig;
use bunyip_domain::repositories::{RateLimitHistoryRepository, RateLimitRepository};
use chrono::{Duration, Utc};
use sqlx::postgres::PgPoolOptions;

async fn setup() -> Option<sqlx::PgPool> {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"))
        .ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    // Clean slate: these tests assert row counts and the table is
    // process-global.
    sqlx::query("TRUNCATE rate_limits, rate_limit_history")
        .execute(&pool)
        .await
        .expect("truncate");
    Some(pool)
}

/// A burst of over-cap requests produces one history row, not one per
/// request. The write is gated on the first crossing of the cap, so later
/// over-cap counts increment `rate_limits.count` without inflating the
/// history table.
#[tokio::test]
async fn a_burst_over_the_cap_writes_one_history_row() {
    let Some(pool) = setup().await else {
        eprintln!("test database unset; skipping");
        return;
    };

    let config = RateLimitConfig::LOGIN;
    let key = "burst@example.com";

    // Fire enough requests to cross the cap plus five more over-cap. The
    // history row is written on the first over-cap request; subsequent
    // over-cap requests only increment `rate_limits.count`.
    let total = config.max_requests + 5;
    for _ in 0..total {
        RateLimitRepository::check_and_increment(&pool, key, &config)
            .await
            .expect("check_and_increment");
    }

    let rows = RateLimitHistoryRepository::list(&pool, Utc::now() - Duration::hours(1), 100)
        .await
        .expect("list history");
    let for_key: Vec<_> = rows
        .into_iter()
        .filter(|r| r.key == key && r.action == config.action)
        .collect();
    assert_eq!(
        for_key.len(),
        1,
        "one throttle event, one history row, got {for_key:?}"
    );
    let row = &for_key[0];
    assert!(
        (row.expires_at - row.fired_at).num_seconds() == config.window_seconds,
        "expires_at = fired_at + window_seconds: {row:?} window={}",
        config.window_seconds
    );
}

/// A row older than the retention floor is swept; a fresh row is kept.
#[tokio::test]
async fn the_sweep_deletes_only_rows_past_retention() {
    let Some(pool) = setup().await else {
        eprintln!("test database unset; skipping");
        return;
    };

    let now = Utc::now();
    // One row two days old (past the 24h floor), one row one hour old.
    sqlx::query(
        "INSERT INTO rate_limit_history (action, key, fired_at, expires_at) \
         VALUES ('login', 'old@example.com', $1, $2), \
                ('login', 'new@example.com', $3, $4)",
    )
    .bind(now - Duration::days(2))
    .bind(now - Duration::days(2) + Duration::seconds(300))
    .bind(now - Duration::hours(1))
    .bind(now - Duration::hours(1) + Duration::seconds(300))
    .execute(&pool)
    .await
    .expect("seed history");

    let deleted = RateLimitHistoryRepository::sweep(&pool, 86400)
        .await
        .expect("sweep");
    assert_eq!(deleted, 1, "only the two-day-old row is past retention");

    let survivors = RateLimitHistoryRepository::list(&pool, now - Duration::days(7), 10)
        .await
        .expect("list");
    let keys: Vec<_> = survivors.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(keys, vec!["new@example.com"], "only the recent row remains");
}
