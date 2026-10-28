//! BUNYIP-998: account holders kept on Mirzam's two lists.
//!
//! Needs a migrated PostgreSQL named by `BUNYIP_TEST_DATABASE_URL` (or
//! `RLS_TEST_DATABASE_URL`) and skips without one. Mirzam is a wiremock stub.
//! The sync runs in spawned tasks; every step awaits `MirzamSync::idle`, which
//! resolves when those tasks have finished, so nothing sleeps.
//!
//! One test function on purpose: `mirzam_config` is a singleton row, so steps
//! that ran in parallel would overwrite each other's settings.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use actix_web::{test, web, App};
use bunyip_api::config::{Config, GovernedSecret, SecretsProvider, TierConfig};
use bunyip_api::models::{CreateUser, User, UserRole};
use bunyip_api::repositories::{MirzamConfigRepository, UserRepository};
use bunyip_api::services::mirzam_sync::MirzamSync;
use bunyip_api::services::{AuthService, EmailService, JwtConfig, JwtService};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const JWT_SECRET: &str = "bunyip-998-test-secret-at-least-32-bytes-long";
const TOKEN: &str = "mzm_bunyip998_secret_token_value";
const FAST: [Duration; 2] = [Duration::from_millis(10), Duration::from_millis(10)];

/// The minimal non-production `Config`, as `mirzam_config.rs` builds it.
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
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect to test database");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

/// A passwordless account with a name, unverified unless `verified`.
async fn seed_user(pool: &PgPool, role: UserRole, verified: bool) -> User {
    let user = UserRepository::create(
        pool,
        CreateUser {
            email: format!("sync-{}@example.test", Uuid::new_v4().simple()),
            password_hash: None,
            role,
        },
    )
    .await
    .expect("seed user");
    sqlx::query(
        "UPDATE users SET first_name = 'Ada', last_name = 'Lovelace', email_verified = $2 \
         WHERE id = $1",
    )
    .bind(user.id)
    .bind(verified)
    .execute(pool)
    .await
    .unwrap();
    UserRepository::find_by_id(pool, user.id)
        .await
        .unwrap()
        .unwrap()
}

/// Every Mirzam write answers success.
async fn mirzam_accepts_everything(mirzam: &MockServer) {
    mirzam.reset().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/subscribers"))
        .respond_with(ResponseTemplate::new(201))
        .mount(mirzam)
        .await;
    Mock::given(method("PATCH"))
        .and(path_regex(r"^/api/v1/subscribers/[^/]+$"))
        .respond_with(ResponseTemplate::new(200))
        .mount(mirzam)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/api/v1/subscribers/[^/]+/unsubscribe$"))
        .respond_with(ResponseTemplate::new(200))
        .mount(mirzam)
        .await;
}

/// Wait for the spawned sync tasks, bounded so a hang fails the test.
async fn settle(sync: &MirzamSync) {
    tokio::time::timeout(Duration::from_secs(30), sync.idle())
        .await
        .expect("the Mirzam sync tasks finish");
}

async fn received(mirzam: &MockServer) -> Vec<Request> {
    mirzam.received_requests().await.unwrap_or_default()
}

fn body(request: &Request) -> serde_json::Value {
    request.body_json().expect("a JSON body")
}

fn encoded(email: &str) -> String {
    urlencoding::encode(email).into_owned()
}

/// Assert the stub received exactly the two "email verified" adds for `email`.
fn assert_added_to_both(requests: &[Request], email: &str) {
    assert_eq!(requests.len(), 2, "{requests:#?}");
    let mut lists = Vec::new();
    for request in requests {
        assert_eq!(request.method.as_str(), "POST");
        assert_eq!(request.url.path(), "/api/v1/subscribers");
        assert_eq!(
            request.headers.get("authorization").unwrap(),
            &format!("Bearer {TOKEN}")
        );
        let sent = body(request);
        assert_eq!(sent["email"], email, "{sent}");
        assert_eq!(sent["name"], "Ada Lovelace", "{sent}");
        assert_eq!(sent["consent"], "recorded", "{sent}");
        assert_eq!(sent["consent_note"], "Account holder", "{sent}");
        assert_eq!(sent["keep_unsubscribed"], true, "{sent}");
        lists.push(sent["list"].as_str().unwrap().to_string());
    }
    assert_eq!(lists, ["product-updates", "notices"]);
}

/// Assert the stub received exactly the two "account deleted" unsubscribes.
fn assert_removed_from_both(requests: &[Request], email: &str) {
    assert_eq!(requests.len(), 2, "{requests:#?}");
    let lists: Vec<String> = requests
        .iter()
        .map(|request| {
            assert_eq!(request.method.as_str(), "POST");
            assert_eq!(
                request.url.path(),
                format!("/api/v1/subscribers/{}/unsubscribe", encoded(email))
            );
            body(request)["list"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(lists, ["product-updates", "notices"]);
}

#[actix_rt::test]
async fn account_events_keep_mirzam_in_step() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let config = test_config();
    let key_set = config.app_key_set();
    let jwt = JwtService::new(JwtConfig::from_secret(JWT_SECRET, "bunyip-test"));
    let mirzam = MockServer::start().await;

    // The integration on and complete, with the token in the `database`
    // provider and no failure recorded.
    bunyip_api::secrets::write_secret(
        &pool,
        &config,
        &key_set,
        SecretsProvider::Database,
        GovernedSecret::MirzamApiToken,
        TOKEN,
        None,
    )
    .await
    .expect("store the token");
    let enable = |on: bool| {
        let pool = pool.clone();
        let base_url = mirzam.uri();
        async move {
            sqlx::query(
                "UPDATE mirzam_config SET enabled = $1, base_url = $2, \
                 updates_list = 'product-updates', notices_list = 'notices', \
                 last_error = NULL, last_error_at = NULL WHERE id = 1",
            )
            .bind(on)
            .bind(base_url)
            .execute(&pool)
            .await
            .unwrap();
        }
    };
    enable(true).await;

    let sync = bunyip_api::mirzam_sync::mirzam_sync(pool.clone(), config.clone(), key_set.clone())
        .with_retry_delays(&FAST);
    let auth = AuthService::new(
        pool.clone(),
        jwt.clone(),
        Arc::new(RwLock::new(TierConfig::from_env())),
        None,
        Arc::new(EmailService::new_dev()),
        None,
        false,
        Vec::new(),
        Vec::new(),
    )
    .with_mirzam_sync(sync.clone());

    let admin = seed_user(&pool, UserRole::Admin, true).await;
    let admin_auth = format!("Bearer {}", jwt.create_access_token(&admin).unwrap());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(Arc::new(jwt.clone()))
            .app_data(web::Data::new(key_set.clone()))
            .app_data(web::Data::new(config.clone()))
            .app_data(web::Data::new(sync.clone()))
            .app_data(web::Data::new(
                None::<Arc<bunyip_oidc::services::oidc_provider::OidcProvider>>,
            ))
            .service(web::scope("/v1").configure(bunyip_api::routes::admin::configure)),
    )
    .await;

    // 1. Verifying an account adds it to both lists, with its name.
    mirzam_accepts_everything(&mirzam).await;
    let user = seed_user(&pool, UserRole::Subscriber, false).await;
    let token = auth
        .request_email_verification(user.id, None)
        .await
        .expect("verification token");
    auth.confirm_email_verification(token, None)
        .await
        .expect("verify");
    settle(&sync).await;
    assert_added_to_both(&received(&mirzam).await, &user.email);

    // 2. Changing the verified address moves the subscriber in place.
    mirzam_accepts_everything(&mirzam).await;
    let new_email = format!("moved-{}@example.test", Uuid::new_v4().simple());
    let (_, change_token) = auth
        .request_email_change(user.id, new_email.clone(), None, None)
        .await
        .expect("email change request");
    auth.confirm_email_change(change_token.expect("a verified account gets a token"), None)
        .await
        .expect("confirm email change");
    settle(&sync).await;
    let requests = received(&mirzam).await;
    assert_eq!(requests.len(), 1, "{requests:#?}");
    assert_eq!(requests[0].method.as_str(), "PATCH");
    assert_eq!(
        requests[0].url.path(),
        format!("/api/v1/subscribers/{}", encoded(&user.email))
    );
    assert_eq!(body(&requests[0]), serde_json::json!({"email": new_email}));

    // 3. Deleting the account unsubscribes the current address from both
    //    lists, and erases nothing.
    mirzam_accepts_everything(&mirzam).await;
    let resp = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri(&format!("/v1/admin/users/{}", user.id))
            .insert_header(("authorization", admin_auth.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    settle(&sync).await;
    assert_removed_from_both(&received(&mirzam).await, &new_email);

    // 4. With the integration off, nothing reaches Mirzam.
    enable(false).await;
    mirzam_accepts_everything(&mirzam).await;
    let off = seed_user(&pool, UserRole::Subscriber, false).await;
    let token = auth.request_email_verification(off.id, None).await.unwrap();
    auth.confirm_email_verification(token, None).await.unwrap();
    let resp = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri(&format!("/v1/admin/users/{}", off.id))
            .insert_header(("authorization", admin_auth.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    settle(&sync).await;
    assert!(received(&mirzam).await.is_empty());

    // 5. An unverified account is never sent, even when it is deleted.
    enable(true).await;
    let unverified = seed_user(&pool, UserRole::Subscriber, false).await;
    let resp = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri(&format!("/v1/admin/users/{}", unverified.id))
            .insert_header(("authorization", admin_auth.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    settle(&sync).await;
    assert!(received(&mirzam).await.is_empty());

    // 6. A failing Mirzam is retried, then the failure is recorded, without
    //    the token or the address, and the admin page shows it.
    mirzam.reset().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/subscribers"))
        .respond_with(ResponseTemplate::new(500).set_body_json(
            serde_json::json!({"error": {"code": "internal", "message": "database unavailable"}}),
        ))
        .mount(&mirzam)
        .await;
    let failing = seed_user(&pool, UserRole::Subscriber, false).await;
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/v1/admin/users/{}/email/verify", failing.id))
            .insert_header(("authorization", admin_auth.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    settle(&sync).await;
    // Three attempts on each list.
    assert_eq!(received(&mirzam).await.len(), 6);
    let row = MirzamConfigRepository::get(&pool).await.unwrap();
    let error = row.last_error.clone().expect("the failure is recorded");
    assert!(row.last_error_at.is_some());
    assert!(
        error.contains(&format!(
            "Adding user {} to list product-updates failed: Mirzam answered 500: database \
             unavailable",
            failing.id
        )),
        "{error}"
    );
    assert!(error.contains("list notices"), "{error}");
    assert!(!error.contains(TOKEN), "{error}");
    assert!(!error.contains(&failing.email), "{error}");

    let shown: serde_json::Value = test::call_and_read_body_json(
        &app,
        test::TestRequest::get()
            .uri("/v1/admin/mirzam")
            .insert_header(("authorization", admin_auth.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(shown["data"]["last_error"], error.as_str(), "{shown}");
    assert!(shown["data"]["last_error_at"].is_string(), "{shown}");
    assert!(!shown.to_string().contains(TOKEN), "{shown}");

    // 7. The next call that succeeds clears it. An admin address edit on a
    //    verified account Mirzam never had (404) adds the new address.
    mirzam.reset().await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mirzam)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/subscribers"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&mirzam)
        .await;
    let corrected = format!("corrected-{}@example.test", Uuid::new_v4().simple());
    let resp = test::call_service(
        &app,
        test::TestRequest::put()
            .uri(&format!("/v1/admin/users/{}/email", failing.id))
            .insert_header(("authorization", admin_auth.clone()))
            .set_json(serde_json::json!({"email": corrected, "verified": true}))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    settle(&sync).await;
    let requests = received(&mirzam).await;
    assert_eq!(requests[0].method.as_str(), "PATCH");
    assert_added_to_both(&requests[1..], &corrected);
    let row = MirzamConfigRepository::get(&pool).await.unwrap();
    assert_eq!(row.last_error, None);
    assert_eq!(row.last_error_at, None);

    // Leave the singleton off for the other suites.
    enable(false).await;
}
