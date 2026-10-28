//! BUNYIP-983: the host-secrets route and the admin pair behind it, at the
//! HTTP layer.
//!
//! Needs a migrated PostgreSQL named by `BUNYIP_TEST_DATABASE_URL` (or
//! `RLS_TEST_DATABASE_URL`) and skips without one.
//!
//! One test function on purpose, like `mirzam_config.rs`: `mokosh_config` is a
//! singleton row, so steps running in parallel would overwrite each other.

use std::sync::Arc;

use actix_web::{test, web, App};
use base64::Engine;
use bunyip_api::config::Config;
use bunyip_api::models::{CreateUser, User, UserRole};
use bunyip_api::repositories::UserRepository;
use bunyip_api::services::{JwtConfig, JwtService};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

const JWT_SECRET: &str = "bunyip-983-test-secret-at-least-32-bytes-long";
const CLIENT_ID: &str = "123456789012-abc123def456.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "GOCSPX-bunyip983-test-value";
const KEY: &str = "mokosh/google_oauth_client";

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
            email: format!("host-secrets-{}@example.test", Uuid::new_v4().simple()),
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

/// A machine registration with a known secret and a given allow-list.
///
/// Written here rather than through `machine-client register`, which mints a
/// secret it prints once: a test needs to present the secret, and the hash goes
/// through the same [`hash_client_secret`] the verifier reads.
async fn register_machine_client(
    pool: &PgPool,
    name: &str,
    secret: &str,
    allowed_secret_keys: &[&str],
) -> Uuid {
    let client_id = Uuid::new_v4();
    let hash = bunyip_oidc::machine_client::hash_client_secret(secret)
        .await
        .expect("hash the client secret");
    sqlx::query(
        r#"
        INSERT INTO oauth_clients (
            client_id, client_secret_hash, client_type, name,
            redirect_uris, post_logout_redirect_uris,
            allowed_scopes, allowed_grant_types, allowed_secret_keys,
            token_endpoint_auth_method, require_pkce, audience
        ) VALUES (
            $1, $2, 'confidential', $3,
            ARRAY[]::TEXT[], ARRAY[]::TEXT[],
            ARRAY[]::TEXT[], ARRAY['client_credentials']::TEXT[], $4,
            'client_secret_basic', TRUE, 'https://bunyip.test/v1'
        )
        "#,
    )
    .bind(client_id)
    .bind(&hash)
    .bind(name)
    .bind(
        allowed_secret_keys
            .iter()
            .map(|k| k.to_string())
            .collect::<Vec<_>>(),
    )
    .execute(pool)
    .await
    .expect("register the machine client");
    client_id
}

fn basic(client_id: Uuid, secret: &str) -> String {
    let raw = format!("{client_id}:{secret}");
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

/// The admin pair, the changed-id confirmation, the allow-list, and the three
/// answers the route can give.
#[actix_rt::test]
async fn host_secrets_route_and_the_admin_pair_behind_it() {
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
        "UPDATE mokosh_config SET google_client_id = '', google_client_secret = NULL, \
         google_client_secret_nonce = NULL WHERE id = 1",
    )
    .execute(&pool)
    .await
    .unwrap();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(jwt.clone())
            .app_data(web::Data::new(config.app_key_set()))
            .app_data(web::Data::new(config.clone()))
            .service(
                web::scope("/v1")
                    .configure(bunyip_api::routes::admin::configure)
                    .configure(bunyip_api::routes::host::configure),
            ),
    )
    .await;

    let get_admin = || {
        test::TestRequest::get()
            .uri("/v1/admin/mokosh")
            .insert_header(("authorization", auth.clone()))
            .to_request()
    };
    let put_admin = |body: serde_json::Value| {
        test::TestRequest::put()
            .uri("/v1/admin/mokosh")
            .insert_header(("authorization", auth.clone()))
            .set_json(body)
            .to_request()
    };

    let fresh: serde_json::Value = test::call_and_read_body_json(&app, get_admin()).await;
    assert_eq!(fresh["data"]["has_google_client_secret"], false, "{fresh}");
    assert_eq!(fresh["data"]["google_client_id"], "", "{fresh}");
    assert_eq!(fresh["data"]["secrets_storage"], "database", "{fresh}");

    // A value that is not a Google client id is a 400 naming the field, so the
    // admin page can point at the input rather than showing a 500.
    let refused = test::call_service(
        &app,
        put_admin(serde_json::json!({
            "google_client_id": "not-a-client-id",
            "google_client_secret": CLIENT_SECRET,
        })),
    )
    .await;
    assert_eq!(refused.status(), 400);

    // An id with no secret anywhere is refused too: half a credential
    // authenticates as nothing.
    let half = test::call_service(
        &app,
        put_admin(serde_json::json!({ "google_client_id": CLIENT_ID })),
    )
    .await;
    assert_eq!(half.status(), 400);

    // The pair saves, the secret lands in `mokosh_config` as ciphertext, and
    // the read-back reports presence without the value.
    let saved: serde_json::Value = test::call_and_read_body_json(
        &app,
        put_admin(serde_json::json!({
            "google_client_id": CLIENT_ID,
            "google_client_secret": CLIENT_SECRET,
        })),
    )
    .await;
    assert_eq!(saved["data"]["google_client_id"], CLIENT_ID, "{saved}");
    assert_eq!(saved["data"]["has_google_client_secret"], true, "{saved}");
    assert!(
        !saved.to_string().contains(CLIENT_SECRET),
        "the response never carries the secret: {saved}"
    );
    let ciphertext: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT google_client_secret FROM mokosh_config WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    let ciphertext = ciphertext.expect("the database provider holds the secret");
    assert!(
        !String::from_utf8_lossy(&ciphertext).contains(CLIENT_SECRET),
        "stored encrypted, not in plaintext"
    );

    // The audit row names the admin, the key and a hash, never the value.
    let metadata: serde_json::Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_logs WHERE action = 'admin_mokosh_config_updated' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(metadata["secret_changed"], true, "{metadata}");
    assert_eq!(
        metadata["secret"], "MOKOSH_GOOGLE_CLIENT_SECRET",
        "{metadata}"
    );
    assert_eq!(metadata["secret_store"], "database", "{metadata}");
    assert_eq!(
        metadata["secret_sha256"].as_str().map(str::len),
        Some(64),
        "{metadata}"
    );
    assert!(
        !metadata.to_string().contains(CLIENT_SECRET),
        "the trail carries the hash, not the secret: {metadata}"
    );

    // BUNYIP-855 D10: a changed id is refused once, then accepted with the
    // confirmation. The secret is not resent, which is the point of keeping
    // the two halves separate.
    let other_id = "210987654321-zyx987wvu654.apps.googleusercontent.com";
    let warned = test::call_service(
        &app,
        put_admin(serde_json::json!({ "google_client_id": other_id })),
    )
    .await;
    assert_eq!(warned.status(), 409, "a changed id warns before it lands");
    let confirmed: serde_json::Value = test::call_and_read_body_json(
        &app,
        put_admin(serde_json::json!({
            "google_client_id": other_id,
            "confirm_client_id_change": true,
        })),
    )
    .await;
    assert_eq!(confirmed["data"]["google_client_id"], other_id);
    assert_eq!(
        confirmed["data"]["has_google_client_secret"], true,
        "the secret survived an id-only save: {confirmed}"
    );
    // Put the pair back, so the route reads the id it was set up with.
    let _: serde_json::Value = test::call_and_read_body_json(
        &app,
        put_admin(serde_json::json!({
            "google_client_id": CLIENT_ID,
            "confirm_client_id_change": true,
        })),
    )
    .await;

    // ---- the route ------------------------------------------------------
    let allowed_secret = "host-secrets-allowed-client-secret";
    let allowed =
        register_machine_client(&pool, "mokosh-host-secrets", allowed_secret, &[KEY]).await;
    let other_secret = "host-secrets-other-client-secret";
    let other = register_machine_client(&pool, "another-app", other_secret, &[]).await;
    let typo_secret = "host-secrets-typo-client-secret";
    let typo = register_machine_client(
        &pool,
        "typo-app",
        typo_secret,
        &["mokosh/google_oauth_clientt"],
    )
    .await;

    let fetch = |authorization: Option<String>, key: &str| {
        let mut req = test::TestRequest::get().uri(&format!("/v1/host/secrets/{key}"));
        if let Some(value) = authorization {
            req = req.insert_header(("authorization", value));
        }
        req.to_request()
    };

    // No credential at all: 401, before anything about the key is read.
    let anonymous = test::call_service(&app, fetch(None, KEY)).await;
    assert_eq!(anonymous.status(), 401);

    // Allow-listed: the pair, as the reader parses it.
    let served: serde_json::Value =
        test::call_and_read_body_json(&app, fetch(Some(basic(allowed, allowed_secret)), KEY)).await;
    assert_eq!(served["data"]["key"], KEY, "{served}");
    let value: serde_json::Value =
        serde_json::from_str(served["data"]["value"].as_str().expect("a string value"))
            .expect("the value is JSON");
    assert_eq!(value["client_id"], CLIENT_ID, "{value}");
    assert_eq!(value["client_secret"], CLIENT_SECRET, "{value}");

    // Registered, authentic, and not entitled: 403, whether or not the key
    // exists, so the route cannot be walked to enumerate the host's secrets.
    let forbidden = test::call_service(&app, fetch(Some(basic(other, other_secret)), KEY)).await;
    assert_eq!(forbidden.status(), 403);

    // Entitled to a key this build does not serve: 404. An operator's typo in
    // the allow-list, and the message says so.
    let unknown = test::call_service(
        &app,
        fetch(
            Some(basic(typo, typo_secret)),
            "mokosh/google_oauth_clientt",
        ),
    )
    .await;
    assert_eq!(unknown.status(), 404);

    // The key is servable and nothing is set: also a 404, with a different
    // sentence, because the fix is different.
    sqlx::query("UPDATE mokosh_config SET google_client_id = '' WHERE id = 1")
        .execute(&pool)
        .await
        .unwrap();
    let unset = test::call_service(&app, fetch(Some(basic(allowed, allowed_secret)), KEY)).await;
    assert_eq!(unset.status(), 404);

    // A disabled registration is indistinguishable from an unregistered one,
    // which is what revoking a calling app's access has to mean.
    sqlx::query("UPDATE oauth_clients SET disabled_at = NOW() WHERE client_id = $1")
        .bind(allowed)
        .execute(&pool)
        .await
        .unwrap();
    let revoked = test::call_service(&app, fetch(Some(basic(allowed, allowed_secret)), KEY)).await;
    assert_eq!(revoked.status(), 401);

    for client in [allowed, other, typo] {
        sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
            .bind(client)
            .execute(&pool)
            .await
            .unwrap();
    }
}
