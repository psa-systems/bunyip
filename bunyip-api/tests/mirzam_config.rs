//! BUNYIP-997: the Mirzam integration settings at the HTTP layer.
//!
//! Needs a migrated PostgreSQL named by `BUNYIP_TEST_DATABASE_URL` (or
//! `RLS_TEST_DATABASE_URL`) and skips without one. Mirzam itself is a wiremock
//! stub, so the connection check runs against a real HTTP server.
//!
//! One test function on purpose: `mirzam_config` is a singleton row, so steps
//! that ran in parallel would overwrite each other's settings.

use std::sync::Arc;

use actix_web::{test, web, App};
use bunyip_api::config::{Config, SecretsProvider};
use bunyip_api::models::{CreateUser, User, UserRole};
use bunyip_api::repositories::{MirzamConfigRepository, UserRepository};
use bunyip_api::services::{JwtConfig, JwtService};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const JWT_SECRET: &str = "bunyip-997-test-secret-at-least-32-bytes-long";
const TOKEN: &str = "mzm_bunyip997_secret_token_value";

/// The minimal non-production `Config`, as `feature_toggles.rs` builds it.
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

async fn seed_admin(pool: &PgPool) -> User {
    UserRepository::create(
        pool,
        CreateUser {
            email: format!("mirzam-{}@example.test", Uuid::new_v4().simple()),
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

async fn stripe_webhook_ciphertext(pool: &PgPool) -> Option<Vec<u8>> {
    sqlx::query_scalar("SELECT webhook_secret FROM stripe_config WHERE id = 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Settings round trip, validation, the write-only token, the governed-secret
/// write landing in `mirzam_config` (never `stripe_config`), the audit row,
/// the connection check against a stub Mirzam, and the environment-mode 409.
#[actix_rt::test]
async fn mirzam_settings_token_and_connection_check() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let config = test_config();
    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let admin = seed_admin(&pool).await;
    let auth = bearer(&jwt, &admin);

    // Start from a clean singleton.
    sqlx::query(
        "UPDATE mirzam_config SET enabled = FALSE, base_url = '', updates_list = '', \
         notices_list = '', api_token = NULL, api_token_nonce = NULL WHERE id = 1",
    )
    .execute(&pool)
    .await
    .unwrap();
    let stripe_before = stripe_webhook_ciphertext(&pool).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(jwt.clone())
            .app_data(web::Data::new(config.app_key_set()))
            .app_data(web::Data::new(config.clone()))
            .service(web::scope("/v1").configure(bunyip_api::routes::admin::configure)),
    )
    .await;

    let get = || {
        test::TestRequest::get()
            .uri("/v1/admin/mirzam")
            .insert_header(("authorization", auth.clone()))
            .to_request()
    };
    let put = |body: serde_json::Value| {
        test::TestRequest::put()
            .uri("/v1/admin/mirzam")
            .insert_header(("authorization", auth.clone()))
            .set_json(body)
            .to_request()
    };

    let fresh: serde_json::Value = test::call_and_read_body_json(&app, get()).await;
    assert_eq!(fresh["data"]["has_api_token"], false, "{fresh}");
    assert_eq!(fresh["data"]["api_token_editable"], true, "{fresh}");
    assert_eq!(fresh["data"]["secrets_storage"], "database", "{fresh}");

    // Switching on with no token anywhere is refused, naming the token field.
    let mirzam = MockServer::start().await;
    let settings = serde_json::json!({
        "enabled": true,
        "base_url": format!("{}/", mirzam.uri()),
        "updates_list": "product-updates",
        "notices_list": "notices",
    });
    let resp = test::call_service(&app, put(settings.clone())).await;
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.to_string().contains("api_token"), "{body}");

    // A bad address and a bad slug are 400s, and nothing is written.
    for (field, bad) in [
        ("base_url", serde_json::json!("news.example.com")),
        ("updates_list", serde_json::json!("Product Updates")),
    ] {
        let mut body = settings.clone();
        body[field] = bad;
        body["api_token"] = serde_json::json!(TOKEN);
        let resp = test::call_service(&app, put(body)).await;
        assert_eq!(resp.status(), 400, "{field}");
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body.to_string().contains(field), "{body}");
    }
    let row = MirzamConfigRepository::get(&pool).await.unwrap();
    assert!(row.api_token.is_none() && row.base_url.is_empty());

    // A valid save with the token: stored encrypted, never echoed.
    let mut with_token = settings.clone();
    with_token["api_token"] = serde_json::json!(TOKEN);
    let saved: serde_json::Value = test::call_and_read_body_json(&app, put(with_token)).await;
    assert!(!saved.to_string().contains(TOKEN), "{saved}");
    assert_eq!(saved["data"]["has_api_token"], true, "{saved}");
    assert_eq!(
        saved["data"]["base_url"],
        mirzam.uri(),
        "the trailing slash is trimmed"
    );
    let row = MirzamConfigRepository::get(&pool).await.unwrap();
    let ciphertext = row.api_token.clone().expect("the token is stored");
    assert!(
        !String::from_utf8_lossy(&ciphertext).contains(TOKEN),
        "the token is stored encrypted"
    );
    assert_eq!(
        row.db_api_token(&config.app_key_set()).as_deref(),
        Some(TOKEN)
    );
    assert_eq!(row.updated_by, Some(admin.id));
    assert_eq!(
        stripe_webhook_ciphertext(&pool).await,
        stripe_before,
        "the token must never land in stripe_config"
    );

    // Read back: the flag, never the value.
    let read: serde_json::Value = test::call_and_read_body_json(&app, get()).await;
    assert_eq!(read["data"]["has_api_token"], true);
    assert_eq!(read["data"]["enabled"], true);
    assert!(!read.to_string().contains(TOKEN), "{read}");

    // A blank token keeps the stored one.
    let mut blank = settings.clone();
    blank["api_token"] = serde_json::json!("");
    let kept: serde_json::Value = test::call_and_read_body_json(&app, put(blank)).await;
    assert_eq!(kept["data"]["has_api_token"], true, "{kept}");
    let row = MirzamConfigRepository::get(&pool).await.unwrap();
    assert_eq!(
        row.api_token,
        Some(ciphertext),
        "the ciphertext is untouched"
    );

    // Every save is audited, and the audit row never carries the token.
    let audits: Vec<(serde_json::Value,)> = sqlx::query_as(
        "SELECT metadata FROM audit_logs WHERE actor_id = $1 \
         AND action = 'admin_mirzam_config_updated' ORDER BY created_at",
    )
    .bind(admin.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(audits.len(), 2, "both saves are audited");
    assert_eq!(audits[0].0["token_changed"], true);
    assert_eq!(audits[0].0["secret_store"], "database");
    assert_eq!(audits[1].0["token_changed"], false);
    for (metadata,) in &audits {
        assert!(!metadata.to_string().contains(TOKEN), "{metadata}");
    }

    // The check reads both lists with the saved token as a bearer token.
    for (slug, name, kind) in [
        ("product-updates", "Product Updates", "newsletter"),
        ("notices", "Account Notices", "notices"),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/lists/{slug}")))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 1, "slug": slug, "name": name, "kind": kind,
            })))
            .expect(1)
            .mount(&mirzam)
            .await;
    }
    let check = test::TestRequest::post()
        .uri("/v1/admin/mirzam/check")
        .insert_header(("authorization", auth.clone()))
        .to_request();
    let report: serde_json::Value = test::call_and_read_body_json(&app, check).await;
    assert_eq!(report["data"]["ok"], true, "{report}");
    assert_eq!(report["data"]["lists"][0]["name"], "Product Updates");
    assert_eq!(report["data"]["lists"][0]["kind"], "newsletter");
    assert_eq!(report["data"]["lists"][1]["kind"], "notices");
    assert!(!report.to_string().contains(TOKEN), "{report}");
    mirzam.verify().await;

    // Environment mode: the token is owned by a secret file, so a typed token
    // is a 409 and the read model says the field is read-only.
    let mut env_config = config.clone();
    env_config.secrets_provider = SecretsProvider::Environment;
    let env_app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(jwt.clone())
            .app_data(web::Data::new(env_config.app_key_set()))
            .app_data(web::Data::new(env_config))
            .service(web::scope("/v1").configure(bunyip_api::routes::admin::configure)),
    )
    .await;
    let mut with_token = settings.clone();
    with_token["api_token"] = serde_json::json!(TOKEN);
    let resp = test::call_service(&env_app, put(with_token)).await;
    assert_eq!(resp.status(), 409);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body.to_string().contains("MIRZAM_API_TOKEN_FILE"),
        "the 409 names the file to edit: {body}"
    );
    let read: serde_json::Value = test::call_and_read_body_json(&env_app, get()).await;
    assert_eq!(read["data"]["api_token_editable"], false, "{read}");
    assert_eq!(read["data"]["secrets_storage"], "environment", "{read}");

    // Leave the singleton as a fresh database has it, and drop the account.
    sqlx::query(
        "UPDATE mirzam_config SET enabled = FALSE, base_url = '', updates_list = '', \
         notices_list = '', api_token = NULL, api_token_nonce = NULL, updated_by = NULL \
         WHERE id = 1",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM audit_logs WHERE actor_id = $1")
        .bind(admin.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(admin.id)
        .execute(&pool)
        .await
        .unwrap();
}
