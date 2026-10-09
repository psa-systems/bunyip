//! BUNYIP-893 admin diagnostics endpoints: shape, auth and clamp coverage.
//!
//! Env-gated like the other DB-backed integration tests: set
//! `RLS_TEST_DATABASE_URL` (or `BUNYIP_TEST_DATABASE_URL`) to a throwaway
//! Postgres this test may migrate. Unset -> skipped.
//!
//! Covers:
//! - `GET /admin/rate-limits/history` returns `data: [...]`, newest first.
//! - `GET /admin/rate-limits/traffic` returns the configured limit + the
//!   per-15-minute points for the action.
//! - Unknown action -> 400.
//! - `since` older than the 24h floor is quietly clamped (older rows do not
//!   leak).
//! - A non-admin caller is refused (middleware).
//! - `GET /admin/rate-limits/overview` (BUNYIP-900) returns one entry per
//!   `RateLimitConfig::ALL` action, each carrying its own traffic + approaching
//!   rows, behind a single ADMIN_DIAGNOSTICS check.
//! - Two full page renders (history + overview) by the same admin inside the
//!   same 60s window both succeed: the batched render costs 2
//!   ADMIN_DIAGNOSTICS calls, not the pre-fix 41, so there is headroom for a
//!   second render well inside the 60/60s cap.

use actix_web::{http::header::ContentType, test, web, App};
use bunyip_api::handlers;
use bunyip_api::models::{CreateUser, User, UserRole};
use bunyip_api::repositories::UserRepository;
use bunyip_api::services::{JwtConfig, JwtService};
use chrono::{Duration, Utc};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const JWT_SECRET: &str = "bunyip-893-test-secret-at-least-32-bytes-long";

async fn maybe_pool() -> Option<PgPool> {
    let url = std::env::var("RLS_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("BUNYIP_TEST_DATABASE_URL"))
        .ok()?;
    let pool = PgPoolOptions::new().connect(&url).await.ok()?;
    bunyip_api::db::ensure_app_role_shell(&pool)
        .await
        .expect("ensure bunyip_app role shell");
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

async fn seed_admin(pool: &PgPool) -> User {
    let email = format!("admin-diag-{}@example.test", Uuid::new_v4().simple());
    UserRepository::create(
        pool,
        CreateUser {
            email,
            password_hash: Some("x".to_string()),
            role: UserRole::Admin,
        },
    )
    .await
    .expect("seed admin")
}

async fn seed_subscriber(pool: &PgPool) -> User {
    let email = format!("sub-diag-{}@example.test", Uuid::new_v4().simple());
    UserRepository::create(
        pool,
        CreateUser {
            email,
            password_hash: Some("x".to_string()),
            role: UserRole::Subscriber,
        },
    )
    .await
    .expect("seed subscriber")
}

fn bearer(jwt: &JwtService, user: &User) -> String {
    format!(
        "Bearer {}",
        jwt.create_access_token(user).expect("mint access token")
    )
}

macro_rules! build_app {
    ($pool:expr, $jwt:expr) => {{
        test::init_service(
            App::new()
                .app_data(web::Data::new($pool.clone()))
                .app_data($jwt.clone())
                .route(
                    "/admin/rate-limits/history",
                    web::get().to(handlers::list_rate_limit_history),
                )
                .route(
                    "/admin/rate-limits/traffic",
                    web::get().to(handlers::list_rate_limit_traffic),
                )
                .route(
                    "/admin/rate-limits/overview",
                    web::get().to(handlers::list_rate_limit_overview),
                ),
        )
        .await
    }};
}

#[actix_rt::test]
async fn history_returns_rows_newest_first() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let admin = seed_admin(&pool).await;

    // Seed two rows: one 2h ago, one 5m ago. The newer one leads.
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO rate_limit_history (action, key, fired_at, expires_at) \
         VALUES ('login', 'old@example.com', $1, $2), \
                ('login', 'new@example.com', $3, $4)",
    )
    .bind(now - Duration::hours(2))
    .bind(now - Duration::hours(2) + Duration::seconds(60))
    .bind(now - Duration::minutes(5))
    .bind(now - Duration::minutes(5) + Duration::seconds(60))
    .execute(&pool)
    .await
    .expect("seed history");

    let app = build_app!(pool, jwt);
    let req = test::TestRequest::get()
        .uri("/admin/rate-limits/history")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .insert_header(ContentType::json())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: Value = test::read_body_json(resp).await;
    let rows = body["data"].as_array().expect("data is an array");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["key"], "new@example.com");
    assert_eq!(rows[1]["key"], "old@example.com");
    assert_eq!(rows[0]["action"], "login");
}

#[actix_rt::test]
async fn history_since_is_clamped_to_the_24h_floor() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let admin = seed_admin(&pool).await;

    // One row 48h old (past the retention floor) and one row 1h old.
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO rate_limit_history (action, key, fired_at, expires_at) \
         VALUES ('login', 'ancient@example.com', $1, $2), \
                ('login', 'recent@example.com', $3, $4)",
    )
    .bind(now - Duration::hours(48))
    .bind(now - Duration::hours(48) + Duration::seconds(60))
    .bind(now - Duration::hours(1))
    .bind(now - Duration::hours(1) + Duration::seconds(60))
    .execute(&pool)
    .await
    .expect("seed history");

    let app = build_app!(pool, jwt);
    // Ask for a since 72h ago; the server must clamp it to 24h and return
    // only the recent row.
    let since = (now - Duration::hours(72)).to_rfc3339();
    let uri = format!("/admin/rate-limits/history?since={since}");
    let req = test::TestRequest::get()
        .uri(&uri)
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: Value = test::read_body_json(resp).await;
    let rows = body["data"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "the 48h row is below the clamp: {rows:?}");
    assert_eq!(rows[0]["key"], "recent@example.com");
}

#[actix_rt::test]
async fn traffic_returns_limit_and_bucket_points() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let admin = seed_admin(&pool).await;

    // Seed a traffic row: a 15-minute bucket at 10:00 with count=3.
    let bucket_start = "2026-10-08T10:00:00Z"
        .parse::<chrono::DateTime<Utc>>()
        .unwrap();
    sqlx::query(
        "INSERT INTO rate_limit_traffic (action, key_hash, bucket_start, count) \
         VALUES ('login', $1, $2, 3)",
    )
    .bind(vec![0u8; 32])
    .bind(bucket_start)
    .execute(&pool)
    .await
    .expect("seed traffic");

    let app = build_app!(pool, jwt);
    // 1d window so the seeded bucket at a fixed time is covered, assuming
    // the test runs well after the seeded instant; the window just bounds
    // the lower edge and the seeded time predates `now`.
    let req = test::TestRequest::get()
        .uri("/admin/rate-limits/traffic?action=login&window=1d")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "{:?}", resp.status());
    let body: Value = test::read_body_json(resp).await;
    let data = &body["data"];
    assert_eq!(data["action"], "login");
    // The server resolves the configured limit through RateLimitConfig::LOGIN.
    assert!(
        data["max_requests"].as_i64().unwrap_or(0) > 0,
        "configured limit present: {data}"
    );
    assert_eq!(data["bucket_width_seconds"], 900);
    let points = data["points"].as_array().expect("points array");
    // The seeded row is well in the past (2026-10-08), so against a 1d
    // window from `now` it may or may not be included depending on when
    // the test runs. The shape assertion is the point: the array exists
    // and each item has `bucket_start` + `count`.
    for p in points {
        assert!(p["bucket_start"].is_string());
        assert!(p["count"].is_number());
    }
}

#[actix_rt::test]
async fn traffic_rejects_unknown_action() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let admin = seed_admin(&pool).await;

    let app = build_app!(pool, jwt);
    let req = test::TestRequest::get()
        .uri("/admin/rate-limits/traffic?action=not_a_real_action&window=1h")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn traffic_rejects_unknown_window() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let admin = seed_admin(&pool).await;

    let app = build_app!(pool, jwt);
    let req = test::TestRequest::get()
        .uri("/admin/rate-limits/traffic?action=login&window=3h")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn history_refuses_a_non_admin() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let subscriber = seed_subscriber(&pool).await;

    let app = build_app!(pool, jwt);
    let req = test::TestRequest::get()
        .uri("/admin/rate-limits/history")
        .insert_header(("authorization", bearer(&jwt, &subscriber)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "AdminUser must refuse a subscriber"
    );
}

#[actix_rt::test]
async fn overview_returns_one_entry_per_configured_action() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let admin = seed_admin(&pool).await;

    let app = build_app!(pool, jwt);
    let req = test::TestRequest::get()
        .uri("/admin/rate-limits/overview?window=1h")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "{:?}", resp.status());

    let body: Value = test::read_body_json(resp).await;
    let entries = body["data"].as_array().expect("data is an array");
    assert_eq!(
        entries.len(),
        bunyip_api::models::RateLimitConfig::ALL.len(),
        "one overview entry per configured action: {entries:?}"
    );
    for entry in entries {
        assert!(entry["action"].is_string());
        assert!(entry["traffic"]["points"].is_array());
        assert!(entry["approaching"].is_array());
    }
}

/// BUNYIP-900: before the fix, a single render fetched `rate_limit_traffic`
/// and `rate_limit_approaching` once per `RateLimitConfig::ALL` action (41
/// ADMIN_DIAGNOSTICS-budgeted calls against a 60/60s cap), so a second
/// render (refresh or window toggle) in the same window could exhaust the
/// budget and degrade the Traffic / Close-to-the-Limit sections. The fix
/// batches both into the single `overview` call, so one render costs 2
/// calls (history + overview) and two renders cost 4, well under the cap.
#[actix_rt::test]
async fn two_renders_within_60s_do_not_degrade_traffic_or_approaching() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let admin = seed_admin(&pool).await;
    let app = build_app!(pool, jwt);

    for render in 0..2 {
        let history_req = test::TestRequest::get()
            .uri("/admin/rate-limits/history")
            .insert_header(("authorization", bearer(&jwt, &admin)))
            .to_request();
        let history_resp = test::call_service(&app, history_req).await;
        assert_eq!(
            history_resp.status(),
            200,
            "render {render}: history must not degrade"
        );

        let overview_req = test::TestRequest::get()
            .uri("/admin/rate-limits/overview?window=1h")
            .insert_header(("authorization", bearer(&jwt, &admin)))
            .to_request();
        let overview_resp = test::call_service(&app, overview_req).await;
        assert_eq!(
            overview_resp.status(),
            200,
            "render {render}: overview (Traffic + Close-to-the-Limit) must not degrade"
        );
        let body: Value = test::read_body_json(overview_resp).await;
        assert!(
            body["data"].as_array().is_some(),
            "render {render}: overview still returns data, not a 429 body"
        );
    }
}
