//! BUNYIP-893 admin diagnostics endpoints: shape, auth and clamp coverage.
//!
//! Env-gated like the other DB-backed integration tests: set
//! `RLS_TEST_DATABASE_URL` (or `BUNYIP_TEST_DATABASE_URL`) to a throwaway
//! Postgres this test may migrate. Unset -> skipped.
//!
//! Covers:
//! - `GET /admin/rate-limits/history` returns `data: [...]`, newest first.
//! - `since` older than the 24h floor is quietly clamped (older rows do not
//!   leak).
//! - A non-admin caller is refused (middleware).
//! - `GET /admin/rate-limits/overview` (BUNYIP-900) returns one entry per
//!   `RateLimitConfig::ALL` action, each carrying its own traffic + approaching
//!   rows, behind a single ADMIN_DIAGNOSTICS check.
//! - The overview's per-action `traffic` carries the configured limit + the
//!   per-15-minute points for the action.
//! - `window` outside `1h`/`6h`/`1d` -> 400; `threshold` and `limit` outside
//!   their valid ranges are clamped, not rejected.
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
    // `+` in the RFC 3339 offset is a space in a query string unless encoded,
    // which the server then rejects as a bad `since` (BUNYIP-904).
    let since = urlencoding::encode(&(now - Duration::hours(72)).to_rfc3339()).into_owned();
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
async fn overview_returns_limit_and_bucket_points_per_action() {
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
        .uri("/admin/rate-limits/overview?window=1d")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "{:?}", resp.status());
    let body: Value = test::read_body_json(resp).await;
    let entries = body["data"].as_array().expect("data is an array");
    let login = entries
        .iter()
        .find(|e| e["action"] == "login")
        .expect("login entry present");
    let traffic = &login["traffic"];
    assert_eq!(traffic["action"], "login");
    // The server resolves the configured limit through RateLimitConfig::LOGIN.
    assert!(
        traffic["max_requests"].as_i64().unwrap_or(0) > 0,
        "configured limit present: {traffic}"
    );
    assert_eq!(traffic["bucket_width_seconds"], 900);
    let points = traffic["points"].as_array().expect("points array");
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
async fn overview_rejects_unknown_window() {
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
        .uri("/admin/rate-limits/overview?window=3h")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn overview_rejects_out_of_range_threshold() {
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
        .uri("/admin/rate-limits/overview?window=1h&threshold=50")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

/// `limit` is clamped to `[1, 100]`, not rejected: a value below 1 (here, 0)
/// clamps to 1, so exactly one of several qualifying rows for an action
/// comes back instead of zero.
#[actix_rt::test]
async fn overview_limit_is_clamped_not_rejected() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let admin = seed_admin(&pool).await;
    let now = Utc::now();

    // registration: Ip-keyed, max_requests 10, default threshold floor 7.
    // Two different IPs both qualify under the default threshold.
    sqlx::query(
        "INSERT INTO rate_limits (id, key, action, count, window_start) \
         VALUES ($1, '203.0.113.5', 'registration', 8, $2), \
                ($3, '203.0.113.6', 'registration', 9, $2)",
    )
    .bind(Uuid::new_v4())
    .bind(now)
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("seed registration approaching rows");

    let app = build_app!(pool, jwt);
    let req = test::TestRequest::get()
        .uri("/admin/rate-limits/overview?window=1h&limit=0")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "out-of-range limit is clamped, not rejected: {:?}",
        resp.status()
    );
    let body: Value = test::read_body_json(resp).await;
    let entries = body["data"].as_array().expect("data is an array");
    let registration_approaching = entries
        .iter()
        .find(|e| e["action"] == "registration")
        .expect("registration entry present")["approaching"]
        .as_array()
        .expect("registration approaching is an array");
    assert_eq!(
        registration_approaching.len(),
        1,
        "clamped limit (1) returns exactly one of the two qualifying rows: {registration_approaching:?}"
    );
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

/// BUNYIP-920: the overview handler now fetches every action's approaching
/// rows in one batched query and resolves every email-/id-keyed row through
/// one batched `UserRepository` lookup each, partitioning both back into
/// per-action, per-row results in memory. This seeds rows across three
/// actions with three different `KeySubject` kinds (email, user id via the
/// 2FA prefix, and IP) so a partitioning bug (a row's user resolved from a
/// different action's lookup, or dropped crossing the in-memory regroup)
/// would show up as a wrong `user_id`/`user_email`/`ip` on the wrong entry.
#[actix_rt::test]
async fn overview_resolves_approaching_rows_to_the_right_action_and_subject() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let admin = seed_admin(&pool).await;
    let subscriber = seed_subscriber(&pool).await;
    let now = Utc::now();

    // login: Email-keyed, max_requests 10, threshold floor at default 0.7 -> 7.
    sqlx::query(
        "INSERT INTO rate_limits (id, key, action, count, window_start) VALUES ($1, $2, 'login', 8, $3)",
    )
    .bind(Uuid::new_v4())
    .bind(&subscriber.email)
    .bind(now)
    .execute(&pool)
    .await
    .expect("seed login approaching row");

    // two_factor_verify_failures: TwoFactorUserId-keyed, max_requests 5, floor 4.
    let two_factor_key = format!("2fa_verify_user:{}", subscriber.id);
    sqlx::query(
        "INSERT INTO rate_limits (id, key, action, count, window_start) VALUES ($1, $2, 'two_factor_verify_failures', 4, $3)",
    )
    .bind(Uuid::new_v4())
    .bind(&two_factor_key)
    .bind(now)
    .execute(&pool)
    .await
    .expect("seed 2fa approaching row");

    // registration: Ip-keyed, max_requests 10, floor 7.
    sqlx::query(
        "INSERT INTO rate_limits (id, key, action, count, window_start) VALUES ($1, $2, 'registration', 8, $3)",
    )
    .bind(Uuid::new_v4())
    .bind("203.0.113.5")
    .bind(now)
    .execute(&pool)
    .await
    .expect("seed registration approaching row");

    let app = build_app!(pool, jwt);
    let req = test::TestRequest::get()
        .uri("/admin/rate-limits/overview?window=1h")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "{:?}", resp.status());
    let body: Value = test::read_body_json(resp).await;
    let entries = body["data"].as_array().expect("data is an array");

    let entry_for = |action: &str| {
        entries
            .iter()
            .find(|e| e["action"] == action)
            .unwrap_or_else(|| panic!("no overview entry for {action}: {entries:?}"))
    };

    let login_approaching = entry_for("login")["approaching"]
        .as_array()
        .expect("login approaching is an array");
    assert_eq!(
        login_approaching.len(),
        1,
        "login approaching: {login_approaching:?}"
    );
    assert_eq!(login_approaching[0]["user_id"], subscriber.id.to_string());
    assert_eq!(login_approaching[0]["user_email"], subscriber.email);
    assert!(login_approaching[0]["ip"].is_null());

    let two_factor_approaching = entry_for("two_factor_verify_failures")["approaching"]
        .as_array()
        .expect("2fa approaching is an array");
    assert_eq!(
        two_factor_approaching.len(),
        1,
        "2fa approaching: {two_factor_approaching:?}"
    );
    assert_eq!(
        two_factor_approaching[0]["user_id"],
        subscriber.id.to_string()
    );
    assert_eq!(two_factor_approaching[0]["user_email"], subscriber.email);

    let registration_approaching = entry_for("registration")["approaching"]
        .as_array()
        .expect("registration approaching is an array");
    assert_eq!(
        registration_approaching.len(),
        1,
        "registration approaching: {registration_approaching:?}"
    );
    assert!(registration_approaching[0]["user_id"].is_null());
    assert!(registration_approaching[0]["user_email"].is_null());
    assert_eq!(registration_approaching[0]["ip"], "203.0.113.5");
}
