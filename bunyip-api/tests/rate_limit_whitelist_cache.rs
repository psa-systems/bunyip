//! BUNYIP-962: `is_whitelisted` reads a process-wide cached snapshot of
//! `rate_limit_whitelist` rather than issuing a `SELECT` per call.
//!
//! Env-gated like `rls_isolation.rs`: it needs a throwaway Postgres to
//! migrate. Set `BUNYIP_TEST_DATABASE_URL` (or reuse `RLS_TEST_DATABASE_URL`)
//! to a database this test may migrate; unset skips the test.

use bunyip_domain::models::RateLimitConfig;
use bunyip_domain::repositories::{
    RateLimitRepository, RateLimitWhitelistRepository, WhitelistKind,
};
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
    bunyip_api::db::ensure_app_role_shell(&pool)
        .await
        .expect("ensure bunyip_app role shell");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    sqlx::query("TRUNCATE rate_limits, rate_limit_whitelist")
        .execute(&pool)
        .await
        .expect("truncate");
    Some(pool)
}

/// AC1: once the cache is warm, a whitelisted principal's `check_and_increment`
/// call (which runs `is_whitelisted` first, unconditionally) issues no
/// `rate_limit_whitelist` query at all. Proven here by closing every
/// connection in the pool after the warming call: if the second call needed a
/// query, it would fail against the closed pool instead of returning the
/// cached hit.
#[tokio::test]
async fn is_whitelisted_hits_the_cache_with_no_db_round_trip_once_warm() {
    let Some(pool) = setup().await else {
        eprintln!("test database unset; skipping");
        return;
    };

    RateLimitWhitelistRepository::insert(&pool, WhitelistKind::Ip, "203.0.113.9", "test", None)
        .await
        .expect("insert whitelist row");

    // Warms the cache: the first lookup for this key must read the table.
    let (count, exceeded) =
        RateLimitRepository::check_and_increment(&pool, "ip:203.0.113.9", &RateLimitConfig::LOGIN)
            .await
            .expect("first call warms the cache");
    assert_eq!(
        (count, exceeded),
        (0, false),
        "a whitelisted key short-circuits"
    );

    // Close every connection. Any further query against this pool now fails,
    // so a second is_whitelisted call that still needs a query would error.
    pool.close().await;
    assert!(pool.is_closed());

    let (count, exceeded) =
        RateLimitRepository::check_and_increment(&pool, "ip:203.0.113.9", &RateLimitConfig::LOGIN)
            .await
            .expect("second call must be served from the warm cache, not a query");
    assert_eq!(
        (count, exceeded),
        (0, false),
        "the cached hit still short-circuits with the pool closed"
    );
}
