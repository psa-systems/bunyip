//! BUNYIP-413 super-admin gate integration test.
//!
//! Proves at the HTTP layer that the rate-limit and IP-ban MANAGEMENT endpoints
//! are restricted to the super admin (the first setup account) while the
//! existing read endpoints stay open to any admin, and that a rate limit created
//! through the API is persisted.
//!
//! Env-gated the same way the other DB-backed integration tests are: with
//! `RLS_TEST_DATABASE_URL` unset it skips and stays green (bunyip CI has no
//! Postgres service). The URL must point at a throwaway, already-migrated
//! database:
//!
//! ```sh
//! RLS_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_413_test \
//!   cargo test -p bunyip-api --test super_admin_gate -- --nocapture
//! ```

use actix_web::{test, web, App};
use bunyip_api::config::AutoBanConfig;
use bunyip_api::middleware::AutoBanService;
use bunyip_api::models::{CreateUser, User, UserRole};
use bunyip_api::repositories::{RateLimitConfigRepository, UserRepository};
use bunyip_api::services::{JwtConfig, JwtService};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const JWT_SECRET: &str = "bunyip-413-test-secret-at-least-32-bytes-long";

async fn maybe_pool() -> Option<PgPool> {
    let url = std::env::var("RLS_TEST_DATABASE_URL").ok()?;
    PgPoolOptions::new().connect(&url).await.ok()
}

/// Seed an admin, optionally flagged as the super admin.
async fn seed_admin(pool: &PgPool, super_admin: bool) -> User {
    let email = format!("gate-{}@example.test", Uuid::new_v4().simple());
    let user = UserRepository::create(
        pool,
        CreateUser {
            email,
            password_hash: Some("x".to_string()),
            role: UserRole::Admin,
        },
    )
    .await
    .expect("seed admin");
    if super_admin {
        UserRepository::set_super_admin(pool, user.id, true)
            .await
            .expect("flag super admin")
    } else {
        user
    }
}

fn bearer(jwt: &JwtService, user: &User) -> String {
    format!(
        "Bearer {}",
        jwt.create_access_token(user).expect("mint access token")
    )
}

/// An ordinary admin may READ the limit configuration but may not change it or
/// ban an IP; the super admin may do both, and a saved limit is persisted.
#[actix_rt::test]
async fn management_endpoints_are_super_admin_only() {
    let Some(pool) = maybe_pool().await else {
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

    let admin = seed_admin(&pool, false).await;
    let super_admin = seed_admin(&pool, true).await;

    // Start from the bootstrap default for this action.
    RateLimitConfigRepository::delete(&pool, "login")
        .await
        .unwrap();

    // Reading the configuration is open to any admin.
    let req = test::TestRequest::get()
        .uri("/v1/admin/rate-limit-configs")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), 200);

    // Writing it is not.
    let req = test::TestRequest::put()
        .uri("/v1/admin/rate-limit-configs/login")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .set_json(serde_json::json!({ "max_requests": 9, "window_seconds": 90 }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        403,
        "an ordinary admin must not change a rate limit"
    );
    assert!(
        RateLimitConfigRepository::get(&pool, "login")
            .await
            .unwrap()
            .is_none(),
        "the refused write must not have persisted anything"
    );

    // Neither is banning an IP by hand.
    let req = test::TestRequest::post()
        .uri("/v1/admin/ip-bans")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .set_json(serde_json::json!({ "ip": "203.0.113.44", "reason": "test" }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        403,
        "an ordinary admin must not ban an IP"
    );
    assert!(
        !auto_ban.is_banned(&"203.0.113.44".parse().unwrap()).await,
        "the refused ban must not have taken effect"
    );

    // The super admin can do both, and the limit is persisted.
    let req = test::TestRequest::put()
        .uri("/v1/admin/rate-limit-configs/login")
        .insert_header(("authorization", bearer(&jwt, &super_admin)))
        .set_json(serde_json::json!({ "max_requests": 9, "window_seconds": 90 }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), 200);
    let stored = RateLimitConfigRepository::get(&pool, "login")
        .await
        .unwrap()
        .expect("the created rate limit is persisted");
    assert_eq!((stored.max_requests, stored.window_seconds), (9, 90));
    assert_eq!(stored.updated_by, Some(super_admin.id));

    let req = test::TestRequest::post()
        .uri("/v1/admin/ip-bans")
        .insert_header(("authorization", bearer(&jwt, &super_admin)))
        .set_json(serde_json::json!({ "ip": "203.0.113.44", "reason": "test" }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), 200);
    assert!(
        auto_ban.is_banned(&"203.0.113.44".parse().unwrap()).await,
        "the ban is effective on the next request"
    );

    // Deleting the override reverts the action to its bootstrap default, and is
    // likewise refused to an ordinary admin.
    let req = test::TestRequest::delete()
        .uri("/v1/admin/rate-limit-configs/login")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), 403);
    let req = test::TestRequest::delete()
        .uri("/v1/admin/rate-limit-configs/login")
        .insert_header(("authorization", bearer(&jwt, &super_admin)))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), 200);
    assert!(RateLimitConfigRepository::get(&pool, "login")
        .await
        .unwrap()
        .is_none());

    // Cleanup.
    auto_ban
        .unban(&"203.0.113.44".parse().unwrap())
        .await
        .unwrap();
    for id in [admin.id, super_admin.id] {
        // The audited writes above reference the actor, so drop those rows first.
        sqlx::query("DELETE FROM audit_logs WHERE actor_id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
