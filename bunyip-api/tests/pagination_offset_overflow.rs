//! BUNYIP-995: `GET /v1/admin/invites` and `GET /v1/admin/feedback` compute
//! their SQL `OFFSET` as `(page - 1) * per_page` in `i32` before any
//! widening. A `page` near `i32::MAX` overflows that multiply: a debug build
//! panics (`attempt to multiply with overflow`), a release build wraps to an
//! arbitrary value that Postgres then rejects as a negative `OFFSET`,
//! surfacing as an unhandled 500. The fix computes the offset in `i64` via
//! `saturating_mul` (BUNYIP-946 F14's precedent) before it ever reaches SQL.
//!
//! Env-gated like `support_tickets.rs`: needs a throwaway Postgres to
//! migrate. Set `BUNYIP_TEST_DATABASE_URL` (or reuse `RLS_TEST_DATABASE_URL`)
//! to a database this test may migrate; unset skips the test.

use actix_web::{test, web, App};
use bunyip_api::config::AutoBanConfig;
use bunyip_api::middleware::AutoBanService;
use bunyip_api::models::{CreateUser, UserRole};
use bunyip_api::repositories::UserRepository;
use bunyip_api::services::{JwtConfig, JwtService};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

const JWT_SECRET: &str = "bunyip-995-test-secret-at-least-32-bytes-long";

async fn test_pool(purpose: &str) -> Option<sqlx::PgPool> {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"));
    let Ok(url) = url else {
        eprintln!("BUNYIP_TEST_DATABASE_URL / RLS_TEST_DATABASE_URL unset; skipping {purpose}");
        return None;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to test database");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

async fn bearer_for_fresh_admin(pool: &sqlx::PgPool, jwt: &JwtService) -> String {
    let email = format!("bunyip-995-{}@example.test", Uuid::new_v4().simple());
    let admin = UserRepository::create(
        pool,
        CreateUser {
            email,
            password_hash: Some("x".to_string()),
            role: UserRole::Admin,
        },
    )
    .await
    .expect("seed admin");
    format!(
        "Bearer {}",
        jwt.create_access_token(&admin).expect("mint access token")
    )
}

/// `page=2147483647` on the admin invites list (`InviteRepository::list_filtered`,
/// BUNYIP-995 AC1) must return a normal, empty paginated page, not a panic or
/// a 500 from Postgres rejecting a wrapped-negative `OFFSET`.
#[actix_rt::test]
async fn admin_invites_list_tolerates_a_page_value_that_would_overflow_i32() {
    let Some(pool) = test_pool("the admin invites overflow-page test").await else {
        return;
    };

    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let auto_ban = Arc::new(AutoBanService::new(
        AutoBanConfig {
            enabled: true,
            threshold: 5,
            window_secs: 3600,
            ban_duration_secs: 86400,
        },
        pool.clone(),
    ));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(jwt.clone())
            .app_data(web::Data::from(auto_ban.clone()))
            .service(web::scope("/v1").configure(bunyip_api::routes::admin::configure)),
    )
    .await;

    let bearer = bearer_for_fresh_admin(&pool, &jwt).await;

    // (page - 1) * per_page with page = i32::MAX, per_page = 100 overflows
    // i32::MAX by construction: this is the exact repro from the issue.
    let req = test::TestRequest::get()
        .uri("/v1/admin/invites?page=2147483647&per_page=100")
        .insert_header(("authorization", bearer))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "an out-of-range page must still return a normal paginated response"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    let items = body["data"]["items"]
        .as_array()
        .expect("items array present");
    assert!(
        items.is_empty(),
        "a page this far past the end must be empty, not an error"
    );
}

/// Same check for the feedback list endpoint backing `list_paginated_filtered`
/// (BUNYIP-995 AC2).
#[actix_rt::test]
async fn admin_feedback_list_tolerates_a_page_value_that_would_overflow_i32() {
    let Some(pool) = test_pool("the admin feedback overflow-page test").await else {
        return;
    };

    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let auto_ban = Arc::new(AutoBanService::new(
        AutoBanConfig {
            enabled: true,
            threshold: 5,
            window_secs: 3600,
            ban_duration_secs: 86400,
        },
        pool.clone(),
    ));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(jwt.clone())
            .app_data(web::Data::from(auto_ban.clone()))
            .service(web::scope("/v1").configure(bunyip_api::routes::admin::configure)),
    )
    .await;

    let bearer = bearer_for_fresh_admin(&pool, &jwt).await;

    let req = test::TestRequest::get()
        .uri("/v1/admin/feedback?page=2147483647&per_page=100")
        .insert_header(("authorization", bearer))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        200,
        "an out-of-range page must still return a normal paginated response"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    let items = body["data"]["items"]
        .as_array()
        .expect("items array present");
    assert!(
        items.is_empty(),
        "a page this far past the end must be empty, not an error"
    );
}
