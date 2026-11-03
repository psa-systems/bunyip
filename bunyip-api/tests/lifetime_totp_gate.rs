//! BUNYIP-943 regression test: the lifetime grant/revoke endpoints require the
//! same TOTP re-confirmation `set_user_tier` requires (BUNYIP-431), since they
//! have the exact same billing-consequential effect (the `lifetime_member` flip
//! plus the $0 invoice subscription).
//!
//! Env-gated the same way the other DB-backed integration tests are: with
//! `RLS_TEST_DATABASE_URL` unset it skips and stays green (bunyip CI has no
//! Postgres service). The URL must point at a throwaway, already-migrated
//! database:
//!
//! ```sh
//! RLS_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_943_test \
//!   cargo test -p bunyip-api --test lifetime_totp_gate -- --nocapture
//! ```

use actix_web::{test, web, App};
use bunyip_api::config::TierConfig;
use bunyip_api::models::{CreateUser, User, UserRole};
use bunyip_api::repositories::UserRepository;
use bunyip_api::services::{
    unconfigured_stripe_config, AppKeySet, EventBus, JwtConfig, JwtService, StripeService,
    TotpService,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

const JWT_SECRET: &str = "bunyip-943-test-secret-at-least-32-bytes-long";

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
    let email = format!(
        "lifetime-totp-admin-{}@example.test",
        Uuid::new_v4().simple()
    );
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
    // VerifiedAdminUser requires verification-complete: name present and email verified.
    UserRepository::update_profile(
        pool,
        admin.id,
        Some(Some("Ada")),
        Some(Some("Lovelace")),
        Some(None),
    )
    .await
    .expect("set name");
    UserRepository::set_email_verified(pool, admin.id)
        .await
        .expect("verify email");
    UserRepository::find_by_id(pool, admin.id)
        .await
        .expect("reload admin")
        .expect("admin exists")
}

async fn seed_member(pool: &PgPool) -> User {
    let email = format!(
        "lifetime-totp-member-{}@example.test",
        Uuid::new_v4().simple()
    );
    UserRepository::create(
        pool,
        CreateUser {
            email,
            password_hash: Some("x".to_string()),
            role: UserRole::Subscriber,
        },
    )
    .await
    .expect("seed member")
}

fn bearer(jwt: &JwtService, user: &User) -> String {
    format!(
        "Bearer {}",
        jwt.create_access_token(user).expect("mint access token")
    )
}

fn test_key_set() -> AppKeySet {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(b"test-encrypt-key");
    key[16..].copy_from_slice(b"0123456789abcdef");
    AppKeySet::new(key, 1)
}

/// `POST .../lifetime` without a `totp_code` the acting admin has configured
/// returns a validation error and leaves `lifetime_member` unchanged (false).
#[actix_rt::test]
async fn grant_lifetime_without_totp_code_is_rejected_and_makes_no_change() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let stripe = Arc::new(StripeService::new(unconfigured_stripe_config()));
    let tier_config = Arc::new(RwLock::new(TierConfig::from_env()));
    let bus = Arc::new(EventBus::new());
    let totp_service = Arc::new(TotpService::new(
        test_key_set(),
        "bunyip-test".into(),
        pool.clone(),
    ));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(jwt.clone())
            .app_data(web::Data::new(stripe.clone()))
            .app_data(web::Data::new(tier_config.clone()))
            .app_data(web::Data::new(bus.clone()))
            .app_data(web::Data::new(totp_service.clone()))
            .service(web::scope("/v1").configure(bunyip_api::routes::admin::configure)),
    )
    .await;

    let admin = seed_admin(&pool).await;
    let member = seed_member(&pool).await;

    // No TOTP enrolled for the admin at all: `verify_code` 404s, mapped to the
    // same validation error `set_user_tier` returns.
    let req = test::TestRequest::post()
        .uri(&format!("/v1/admin/users/{}/lifetime", member.id))
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .set_json(serde_json::json!({ "totp_code": "000000" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "garbage/absent TOTP must be refused before any mutation"
    );

    let reloaded = UserRepository::find_by_id(&pool, member.id)
        .await
        .expect("reload member")
        .expect("member exists");
    assert!(
        !reloaded.lifetime_member,
        "a rejected grant must leave lifetime_member unchanged"
    );
}

/// `POST .../lifetime/revoke` without a valid `totp_code` likewise returns a
/// validation error and leaves `lifetime_member` unchanged (true).
#[actix_rt::test]
async fn revoke_lifetime_without_totp_code_is_rejected_and_makes_no_change() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let stripe = Arc::new(StripeService::new(unconfigured_stripe_config()));
    let tier_config = Arc::new(RwLock::new(TierConfig::from_env()));
    let bus = Arc::new(EventBus::new());
    let totp_service = Arc::new(TotpService::new(
        test_key_set(),
        "bunyip-test".into(),
        pool.clone(),
    ));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(jwt.clone())
            .app_data(web::Data::new(stripe.clone()))
            .app_data(web::Data::new(tier_config.clone()))
            .app_data(web::Data::new(bus.clone()))
            .app_data(web::Data::new(totp_service.clone()))
            .service(web::scope("/v1").configure(bunyip_api::routes::admin::configure)),
    )
    .await;

    let admin = seed_admin(&pool).await;
    let member = seed_member(&pool).await;
    UserRepository::grant_lifetime_membership(&pool, member.id, admin.id)
        .await
        .expect("seed lifetime member directly, bypassing the gated handler");

    let req = test::TestRequest::post()
        .uri(&format!("/v1/admin/users/{}/lifetime/revoke", member.id))
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .set_json(serde_json::json!({ "totp_code": "garbage" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        400,
        "garbage/absent TOTP must be refused before any mutation"
    );

    let reloaded = UserRepository::find_by_id(&pool, member.id)
        .await
        .expect("reload member")
        .expect("member exists");
    assert!(
        reloaded.lifetime_member,
        "a rejected revoke must leave lifetime_member unchanged"
    );
}
