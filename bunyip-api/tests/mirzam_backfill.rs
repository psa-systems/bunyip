//! BUNYIP-999: `bunyip-api mirzam-backfill` puts existing accounts on Mirzam's
//! two lists once.
//!
//! Needs a migrated PostgreSQL named by `BUNYIP_TEST_DATABASE_URL` (or
//! `RLS_TEST_DATABASE_URL`) and skips without one. Mirzam is a wiremock stub
//! that remembers what it was given, so a second run meets the `409`s a real
//! Mirzam would answer.
//!
//! One test function on purpose: `mirzam_config` is a singleton row, and the
//! backfill walks every verified account in the database, so steps that ran
//! in parallel would see each other's accounts and settings.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bunyip_api::config::{Config, GovernedSecret, SecretsProvider};
use bunyip_api::models::{CreateUser, User, UserRole};
use bunyip_api::repositories::UserRepository;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const TOKEN: &str = "mzm_bunyip999_secret_token_value";
const FAST: [Duration; 2] = [Duration::from_millis(5), Duration::from_millis(5)];

/// The minimal non-production `Config`, as `mirzam_sync.rs` builds it.
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

/// A passwordless subscriber, verified or not.
async fn seed_user(pool: &PgPool, verified: bool) -> User {
    let user = UserRepository::create(
        pool,
        CreateUser {
            email: format!("backfill-{}@example.test", Uuid::new_v4().simple()),
            password_hash: None,
            role: UserRole::Subscriber,
        },
    )
    .await
    .expect("seed user");
    sqlx::query("UPDATE users SET first_name = 'Ada', email_verified = $2 WHERE id = $1")
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

fn conflict(code: &str, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(409)
        .set_body_json(serde_json::json!({"error": {"code": code, "message": message}}))
}

/// `POST /api/v1/subscribers` the way Mirzam answers it: `201` the first time
/// an address joins a list, `409` code `conflict` after that; `409` code
/// `unsubscribed` for an address that unsubscribed from product updates when
/// the add keeps unsubscribes; `500` for an address whose calls always fail.
#[derive(Clone, Default)]
struct StubMirzam {
    on: Arc<Mutex<HashSet<(String, String)>>>,
    unsubscribed: Arc<Mutex<HashSet<String>>>,
    broken: Arc<Mutex<HashSet<String>>>,
}

impl Respond for StubMirzam {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let sent: serde_json::Value = request.body_json().expect("a JSON body");
        let email = sent["email"].as_str().unwrap().to_string();
        let list = sent["list"].as_str().unwrap().to_string();
        if self.broken.lock().unwrap().contains(&email) {
            return ResponseTemplate::new(500);
        }
        if list == "product-updates"
            && sent["keep_unsubscribed"] == true
            && self.unsubscribed.lock().unwrap().contains(&email)
        {
            return conflict("unsubscribed", "This address unsubscribed from that list.");
        }
        if self.on.lock().unwrap().insert((email, list)) {
            ResponseTemplate::new(201).set_body_json(serde_json::json!({}))
        } else {
            conflict(
                "conflict",
                "This address is already on that list (confirmed).",
            )
        }
    }
}

/// How many adds the stub received for `email`.
async fn adds_for(mirzam: &MockServer, email: &str) -> usize {
    mirzam
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.body_json::<serde_json::Value>().unwrap()["email"] == email)
        .count()
}

async fn verified_accounts(pool: &PgPool) -> usize {
    UserRepository::list_verified(pool).await.unwrap().len()
}

#[actix_rt::test]
async fn the_backfill_adds_each_verified_account_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let config = test_config();
    let key_set = config.app_key_set();
    let mirzam = MockServer::start().await;
    let stub = StubMirzam::default();
    Mock::given(method("POST"))
        .and(path("/api/v1/subscribers"))
        .respond_with(stub.clone())
        .mount(&mirzam)
        .await;
    let run = || bunyip_api::mirzam_sync::backfill(&pool, &config, &key_set, &FAST, Duration::ZERO);

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
    let set_config = |enabled: bool, base_url: String| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "UPDATE mirzam_config SET enabled = $1, base_url = $2, \
                 updates_list = 'product-updates', notices_list = 'notices' WHERE id = 1",
            )
            .bind(enabled)
            .bind(base_url)
            .execute(&pool)
            .await
            .unwrap();
        }
    };

    // 1. Switched off, or on without an address, it refuses and calls nothing.
    set_config(false, mirzam.uri()).await;
    let err = run().await.expect_err("an integration that is off refuses");
    assert!(err.to_string().contains("switched off"), "{err}");
    set_config(true, String::new()).await;
    let err = run().await.expect_err("an incomplete integration refuses");
    assert!(err.to_string().contains("incomplete"), "{err}");
    assert!(mirzam.received_requests().await.unwrap().is_empty());

    set_config(true, mirzam.uri()).await;
    let fresh = seed_user(&pool, true).await;
    let left = seed_user(&pool, true).await;
    let broken = seed_user(&pool, true).await;
    let unverified = seed_user(&pool, false).await;
    let deleted = seed_user(&pool, true).await;
    UserRepository::soft_delete(&pool, deleted.id)
        .await
        .unwrap();
    stub.unsubscribed.lock().unwrap().insert(left.email.clone());
    stub.broken.lock().unwrap().insert(broken.email.clone());
    // Accounts other tests left in the database are walked too.
    let total = verified_accounts(&pool).await;

    // 2. The first run adds every verified account, leaves the person who
    //    left product updates alone, and counts the failing one while the
    //    rest still go.
    let first = run().await.expect("first run");
    assert_eq!(first.left_alone, 1, "{first}");
    assert_eq!(first.failed, 1, "{first}");
    assert_eq!(first.added, total - 2, "{first}");
    assert_eq!(first.already_on, 0, "{first}");
    assert_eq!(first.failures.len(), 2, "{first}");
    for failure in &first.failures {
        assert!(failure.contains(&broken.id.to_string()), "{failure}");
        assert!(!failure.contains(&broken.email), "{failure}");
        assert!(!failure.contains(TOKEN), "{failure}");
    }
    assert!(!first.to_string().contains(TOKEN));
    assert_eq!(adds_for(&mirzam, &fresh.email).await, 2);
    assert_eq!(adds_for(&mirzam, &unverified.email).await, 0);
    assert_eq!(adds_for(&mirzam, &deleted.email).await, 0);
    // The person who left product updates is still not on it; notices, which
    // nobody leaves themselves, took them.
    {
        let on = stub.on.lock().unwrap();
        assert!(!on.contains(&(left.email.clone(), "product-updates".into())));
        assert!(on.contains(&(left.email.clone(), "notices".into())));
        assert!(on.contains(&(fresh.email.clone(), "product-updates".into())));
    }

    // 3. A second run changes nothing: everyone is already on, the person
    //    who left is still left alone.
    stub.broken.lock().unwrap().clear();
    let second = run().await.expect("second run");
    assert_eq!(
        second.added, 1,
        "the account that failed is added now: {second}"
    );
    assert_eq!(second.left_alone, 1, "{second}");
    assert_eq!(second.failed, 0, "{second}");
    assert_eq!(second.already_on, total - 2, "{second}");

    let third = run().await.expect("third run");
    assert_eq!(third.added, 0, "{third}");
    assert_eq!(third.left_alone, 1, "{third}");
    assert_eq!(third.failed, 0, "{third}");
    assert_eq!(third.already_on, total - 1, "{third}");
    assert!(!stub
        .on
        .lock()
        .unwrap()
        .contains(&(left.email.clone(), "product-updates".into())));

    set_config(false, String::new()).await;
}
