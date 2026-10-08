//! Rate-limit traffic is recorded on every call, aggregates per 15-minute
//! bucket per `(action, key_hash)`, and sweeps at 24 hours.
//!
//! Env-gated like `rls_isolation.rs`: it needs a throwaway Postgres to
//! migrate. Set `BUNYIP_TEST_DATABASE_URL` (or reuse `RLS_TEST_DATABASE_URL`)
//! to a database this test may migrate; unset skips the test.

use bunyip_domain::models::RateLimitConfig;
use bunyip_domain::repositories::{RateLimitRepository, RateLimitTrafficRepository};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
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
    sqlx::query("TRUNCATE rate_limits, rate_limit_history, rate_limit_traffic")
        .execute(&pool)
        .await
        .expect("truncate");
    Some(pool)
}

fn sha256(key: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().to_vec()
}

/// Every request recorded in the same 15-minute bucket collapses into one
/// row with an incrementing count; a row that straddles two buckets lands
/// in two rows. The read path then sums across keys per bucket.
#[tokio::test]
async fn traffic_aggregates_per_15_minute_bucket_and_rolls_up_on_read() {
    let Some(pool) = setup().await else {
        eprintln!("test database unset; skipping");
        return;
    };

    let action = "login";
    let key_a = "alice@example.com";
    let key_b = "bob@example.com";

    // One bucket at 10:00, three requests from Alice.
    let bucket_a = "2026-10-08T10:00:00Z"
        .parse::<chrono::DateTime<Utc>>()
        .unwrap();
    // Pick a time inside the bucket.
    let inside_a = bucket_a + Duration::seconds(300);
    for _ in 0..3 {
        RateLimitTrafficRepository::record(&pool, action, key_a, inside_a)
            .await
            .expect("record alice bucket_a");
    }
    // Same bucket, two from Bob.
    for _ in 0..2 {
        RateLimitTrafficRepository::record(&pool, action, key_b, inside_a)
            .await
            .expect("record bob bucket_a");
    }
    // Next bucket at 10:15, four from Alice.
    let bucket_b = bucket_a + Duration::seconds(900);
    let inside_b = bucket_b + Duration::seconds(60);
    for _ in 0..4 {
        RateLimitTrafficRepository::record(&pool, action, key_a, inside_b)
            .await
            .expect("record alice bucket_b");
    }

    // The per-row shape is one row per (action, key_hash, bucket_start);
    // assert the two Alice rows carry 3 and 4.
    let alice_hash = sha256(key_a);
    let alice_rows: Vec<(chrono::DateTime<Utc>, i32)> = sqlx::query_as(
        "SELECT bucket_start, count FROM rate_limit_traffic \
         WHERE action = $1 AND key_hash = $2 ORDER BY bucket_start",
    )
    .bind(action)
    .bind(&alice_hash)
    .fetch_all(&pool)
    .await
    .expect("fetch alice rows");
    assert_eq!(alice_rows.len(), 2);
    assert_eq!(alice_rows[0], (bucket_a, 3));
    assert_eq!(alice_rows[1], (bucket_b, 4));

    // The read path sums across keys per bucket. Bucket A rolls up to 5
    // (3 Alice + 2 Bob), bucket B to 4 (Alice only).
    let points = RateLimitTrafficRepository::read(&pool, action, bucket_a)
        .await
        .expect("read");
    assert_eq!(points.len(), 2, "two buckets covered");
    // Newest first.
    assert_eq!(points[0].bucket_start, bucket_b);
    assert_eq!(points[0].count, 4);
    assert_eq!(points[1].bucket_start, bucket_a);
    assert_eq!(points[1].count, 5);
}

/// `check_and_increment` records traffic on every call, over-cap or not.
/// Two under-cap calls land one row with count=2. BUNYIP-898 detached the
/// write into `tokio::spawn`, so it lands some scheduler ticks after the
/// awaited call returns; poll instead of asserting immediately.
#[tokio::test]
async fn check_and_increment_records_traffic_on_every_call() {
    let Some(pool) = setup().await else {
        eprintln!("test database unset; skipping");
        return;
    };

    let config = RateLimitConfig::LOGIN;
    let key = "trafficked@example.com";

    for _ in 0..2 {
        RateLimitRepository::check_and_increment(&pool, key, &config)
            .await
            .expect("check");
    }

    let key_hash = sha256(key);
    let count = wait_for_traffic_count(&pool, config.action, &key_hash, 2).await;
    assert_eq!(count, 2);
}

/// Polls `rate_limit_traffic` for up to a second, since the write that
/// populates it is now a detached `tokio::spawn` task rather than part of
/// the awaited `check_and_increment` call.
async fn wait_for_traffic_count(
    pool: &sqlx::PgPool,
    action: &str,
    key_hash: &[u8],
    want: i32,
) -> i32 {
    for _ in 0..100 {
        let count: Option<i32> = sqlx::query_scalar(
            "SELECT count FROM rate_limit_traffic WHERE action = $1 AND key_hash = $2",
        )
        .bind(action)
        .bind(key_hash)
        .fetch_optional(pool)
        .await
        .expect("fetch traffic count");
        if count == Some(want) {
            return count.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("rate_limit_traffic row for action={action} never reached count={want}");
}

/// A row older than retention is swept; a fresh one is kept.
#[tokio::test]
async fn traffic_sweep_deletes_only_rows_past_retention() {
    let Some(pool) = setup().await else {
        eprintln!("test database unset; skipping");
        return;
    };

    let now = Utc::now();
    let old_hash = sha256("old");
    let fresh_hash = sha256("fresh");
    sqlx::query(
        "INSERT INTO rate_limit_traffic (action, key_hash, bucket_start, count) \
         VALUES ('login', $1, $2, 5), ('login', $3, $4, 7)",
    )
    .bind(&old_hash)
    .bind(now - Duration::days(2))
    .bind(&fresh_hash)
    .bind(now - Duration::hours(1))
    .execute(&pool)
    .await
    .expect("seed traffic");

    let deleted = RateLimitTrafficRepository::sweep(&pool, 86400)
        .await
        .expect("sweep");
    assert_eq!(deleted, 1);

    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rate_limit_traffic")
        .fetch_one(&pool)
        .await
        .expect("count remaining");
    assert_eq!(remaining, 1);
}
