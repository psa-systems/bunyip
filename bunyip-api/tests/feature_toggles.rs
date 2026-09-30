//! BUNYIP-840: the feature-toggle registry at the HTTP layer.
//!
//! The probe test needs no database. The admin-endpoint test needs a migrated
//! PostgreSQL named by `BUNYIP_TEST_DATABASE_URL` (or `RLS_TEST_DATABASE_URL`) and skips without one.

use std::sync::{Arc, RwLock};

use actix_web::{test, web, App};
use bunyip_api::config::{Config, TierConfig};
use bunyip_api::feature_toggles::{Feature, FeatureToggleSnapshot, FeatureToggles};
use bunyip_api::models::{CreateUser, User, UserRole};
use bunyip_api::repositories::{FeatureToggleRepository, UserRepository};
use bunyip_api::services::{unconfigured_stripe_config, JwtConfig, JwtService, StripeService};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

const JWT_SECRET: &str = "bunyip-840-test-secret-at-least-32-bytes-long";

/// The minimal non-production `Config`, as `support_tickets.rs` builds it.
fn test_config() -> Config {
    std::env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
    std::env::set_var("ENVIRONMENT", "development");
    std::env::set_var("SECRETS_STORAGE", "database");
    std::env::set_var("HOST_IP", "0.0.0.0");
    std::env::set_var("APP_PORT", "4000");
    Config::from_env().expect("minimal config resolves outside production")
}

async fn test_pool() -> Option<PgPool> {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"));
    let Ok(url) = url else {
        eprintln!("BUNYIP_TEST_DATABASE_URL / RLS_TEST_DATABASE_URL unset; skipping");
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

/// The public probe publishes every registered key next to the unchanged `orgs_enabled`.
#[actix_rt::test]
async fn setup_status_publishes_every_registry_key() {
    let config = test_config();
    let snapshot: FeatureToggleSnapshot = Arc::new(RwLock::new(FeatureToggles::from_rows([(
        "tenant_hostnames",
        true,
    )])));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(Arc::new(StripeService::new(
                unconfigured_stripe_config(),
            ))))
            .app_data(web::Data::new(Arc::new(
                RwLock::new(TierConfig::from_env()),
            )))
            .app_data(web::Data::new(snapshot))
            .route(
                "/v1/auth/setup/status",
                web::get().to(bunyip_api::handlers::setup_status),
            ),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/v1/auth/setup/status")
        .to_request();
    let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let features = &body["data"]["features"];
    for feature in Feature::ALL {
        assert!(
            features[feature.key()].is_boolean(),
            "{} is missing from the probe: {body}",
            feature.key()
        );
    }
    assert_eq!(features["tenant_hostnames"], true);
    assert!(
        body["data"]["orgs_enabled"].is_boolean(),
        "orgs_enabled stays on the probe: {body}"
    );
}

async fn seed_admin(pool: &PgPool, super_admin: bool) -> User {
    let user = UserRepository::create(
        pool,
        CreateUser {
            email: format!("toggle-{}@example.test", Uuid::new_v4().simple()),
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

/// Any admin may list the toggles; only the super admin may flip one, an
/// unknown key is a 404, and a flip is audited and reaches the snapshot.
#[actix_rt::test]
async fn only_the_super_admin_flips_a_registered_toggle() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let snapshot: FeatureToggleSnapshot = Arc::default();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(jwt.clone())
            .app_data(web::Data::new(snapshot.clone()))
            .service(web::scope("/v1").configure(bunyip_api::routes::admin::configure)),
    )
    .await;

    let admin = seed_admin(&pool, false).await;
    let super_admin = seed_admin(&pool, true).await;
    let before = FeatureToggleRepository::get_all(&pool).await.unwrap();

    let req = test::TestRequest::get()
        .uri("/v1/admin/feature-toggles")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .to_request();
    let listed: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(
        listed["data"].as_array().map(Vec::len),
        Some(Feature::ALL.len()),
        "every registered feature is listed: {listed}"
    );

    let req = test::TestRequest::put()
        .uri("/v1/admin/feature-toggles/tenant_hostnames")
        .insert_header(("authorization", bearer(&jwt, &admin)))
        .set_json(serde_json::json!({ "enabled": true }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        403,
        "an ordinary admin must not flip a toggle"
    );

    let req = test::TestRequest::put()
        .uri("/v1/admin/feature-toggles/not_a_feature")
        .insert_header(("authorization", bearer(&jwt, &super_admin)))
        .set_json(serde_json::json!({ "enabled": true }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), 404);
    let unknown: Option<(String,)> =
        sqlx::query_as("SELECT key FROM feature_toggles WHERE key = 'not_a_feature'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(unknown.is_none(), "an unknown key is never stored");

    let req = test::TestRequest::put()
        .uri("/v1/admin/feature-toggles/tenant_hostnames")
        .insert_header(("authorization", bearer(&jwt, &super_admin)))
        .set_json(serde_json::json!({ "enabled": true }))
        .to_request();
    let saved: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(saved["data"]["enabled"], true);
    assert_eq!(saved["data"]["updated_by"], super_admin.id.to_string());
    assert!(
        snapshot.read().unwrap().enabled(Feature::TenantHostnames),
        "the save refreshed the snapshot"
    );
    let audited: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_logs WHERE actor_id = $1 \
         AND action = 'admin_feature_toggle_updated'",
    )
    .bind(super_admin.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audited.0, 1, "the save is audited");

    // Restore the row this test touched, then drop the seeded accounts.
    match before.iter().find(|r| r.key == "tenant_hostnames") {
        Some(row) => {
            FeatureToggleRepository::set(&pool, &row.key, row.enabled, row.updated_by)
                .await
                .unwrap();
        }
        None => {
            sqlx::query("DELETE FROM feature_toggles WHERE key = 'tenant_hostnames'")
                .execute(&pool)
                .await
                .unwrap();
        }
    }
    for id in [admin.id, super_admin.id] {
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
