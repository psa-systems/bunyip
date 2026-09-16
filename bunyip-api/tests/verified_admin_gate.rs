//! BUNYIP-732 verified-admin-gate integration test.
//!
//! Proves at the HTTP layer that `VerifiedAdminUser` (used on the actions
//! BUNYIP-619 gated in bunyip-web) refuses an admin who is not
//! verification-complete with a 403 naming verification as the reason, accepts
//! one who is, and that plain `AdminUser` (the BUNYIP-401 escape hatch) accepts
//! an unverified admin either way - a caller reaching bunyip-api directly (an
//! at+jwt bearer token, another app in the suite) never passes through
//! bunyip-web's `verification_gate`, so this is the only place that requirement
//! is enforced for that caller.
//!
//! Env-gated the same way the other DB-backed integration tests are: with
//! `RLS_TEST_DATABASE_URL` unset it skips and stays green (bunyip CI has no
//! Postgres service). The URL must point at a throwaway, already-migrated
//! database:
//!
//! ```sh
//! RLS_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_732_test \
//!   cargo test -p bunyip-api --test verified_admin_gate -- --nocapture
//! ```

use actix_web::{test, web, App, HttpResponse};
use bunyip_api::middleware::{AdminUser, VerifiedAdminUser};
use bunyip_api::models::{CreateUser, User, UserRole};
use bunyip_api::repositories::UserRepository;
use bunyip_api::services::{JwtConfig, JwtService};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const JWT_SECRET: &str = "bunyip-732-test-secret-at-least-32-bytes-long";

async fn maybe_pool() -> Option<PgPool> {
    let url = std::env::var("RLS_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new().connect(&url).await.ok()?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

async fn seed_admin(pool: &PgPool) -> User {
    let email = format!("verified-gate-{}@example.test", Uuid::new_v4().simple());
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

fn bearer(jwt: &JwtService, user: &User) -> String {
    format!(
        "Bearer {}",
        jwt.create_access_token(user).expect("mint access token")
    )
}

async fn probe_verified(_admin: VerifiedAdminUser) -> HttpResponse {
    HttpResponse::Ok().finish()
}

async fn probe_plain(_admin: AdminUser) -> HttpResponse {
    HttpResponse::Ok().finish()
}

/// `VerifiedAdminUser` refuses an unverified admin (403, verification named in
/// the body) and accepts one who is verification-complete; `AdminUser` accepts
/// both, which is what keeps the BUNYIP-401 escape hatch open.
#[actix_rt::test]
async fn verified_admin_user_gates_on_verification_status() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(jwt.clone())
            .route("/probe-verified", web::get().to(probe_verified))
            .route("/probe-plain", web::get().to(probe_plain)),
    )
    .await;

    // Freshly created admin: no name, email unverified (CreateUser's defaults).
    let unverified = seed_admin(&pool).await;

    let req = test::TestRequest::get()
        .uri("/probe-verified")
        .insert_header(("authorization", bearer(&jwt, &unverified)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        403,
        "an unverified admin must be refused a verification-gated action"
    );
    let body = test::read_body(resp).await;
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("Verify your email"),
        "the refusal must name verification as the reason: {body_str}"
    );

    // The plain AdminUser escape-hatch extractor accepts the same unverified
    // admin: BUNYIP-401 must not reopen.
    let req = test::TestRequest::get()
        .uri("/probe-plain")
        .insert_header(("authorization", bearer(&jwt, &unverified)))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        200,
        "an unverified admin must still reach an escape-hatch action"
    );

    // Verification-complete: name present and email verified.
    UserRepository::update_profile(&pool, unverified.id, Some("Ada"), Some("Lovelace"), None)
        .await
        .expect("set name");
    UserRepository::set_email_verified(&pool, unverified.id)
        .await
        .expect("verify email");
    let verified = UserRepository::find_by_id(&pool, unverified.id)
        .await
        .expect("reload")
        .expect("still exists");

    let req = test::TestRequest::get()
        .uri("/probe-verified")
        .insert_header(("authorization", bearer(&jwt, &verified)))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        200,
        "a verification-complete admin must not be refused"
    );

    // Cleanup.
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(unverified.id)
        .execute(&pool)
        .await
        .unwrap();
}
