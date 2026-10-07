//! BUNYIP-886 two-factor setup: setup refuses an enrolled account, needs the
//! current password, and confirm and resume need the one-time setup token.
//!
//! Drives the real handlers over HTTP against a real database. Env-gated like
//! the other DB-backed tests: with `RLS_TEST_DATABASE_URL` unset it skips.
//!
//! ```sh
//! RLS_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_886_test \
//!   cargo test -p bunyip-api --test totp_setup_token -- --nocapture
//! ```

use actix_web::{test, web, App};
use bunyip_api::config::TierConfig;
use bunyip_api::extractors::json_config;
use bunyip_api::handlers;
use bunyip_api::models::{CreateUser, User, UserRole, UserTotp};
use bunyip_api::repositories::{TotpRepository, UserRepository};
use bunyip_api::services::{
    argon2_offload, AppKeySet, AuthService, EmailService, JwtConfig, JwtService, LoginResult,
    TotpService,
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;

const JWT_SECRET: &str = "bunyip-886-test-secret-at-least-32-bytes-long";
/// 20 bytes of base32, clearing totp_rs's 128-bit minimum.
const PRESET_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn key_set() -> AppKeySet {
    AppKeySet {
        current: [0x42u8; 32],
        current_version: 1,
        previous: Vec::new(),
    }
}

async fn connect() -> Option<PgPool> {
    let url = std::env::var("RLS_TEST_DATABASE_URL").ok()?;
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

/// A password user, created directly (no HIBP or strength checks).
async fn seed_user(pool: &PgPool) -> (User, String) {
    let password = format!("Pw-{}-Aa1!", Uuid::new_v4().simple());
    let hash = argon2_offload::hash_password(password.clone())
        .await
        .expect("hash password");
    let user = UserRepository::create(
        pool,
        CreateUser {
            email: format!("setup-{}@example.test", Uuid::new_v4().simple()),
            password_hash: Some(hash),
            role: UserRole::Subscriber,
        },
    )
    .await
    .expect("seed user");
    (user, password)
}

/// The authenticator code for a base32 secret at the current step.
fn code_now(base32: &str) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(base32.as_bytes())
        .expect("base32 secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    TOTP::new(Algorithm::SHA1, 6, 0, 30, secret, None, String::new())
        .expect("build TOTP")
        .generate((now / 30) * 30)
}

/// A six-digit code that is certainly not one the server would accept now.
fn wrong_code(base32: &str) -> String {
    let right = code_now(base32);
    let first = right.as_bytes()[0];
    let swapped = if first == b'9' {
        '0'
    } else {
        (first + 1) as char
    };
    format!("{swapped}{}", &right[1..])
}

fn jwt() -> JwtService {
    JwtService::new(JwtConfig::from_secret(JWT_SECRET, "bunyip-test"))
}

/// SHA-256 hex, the same digest the service stores for a setup token.
fn sha256_hex(s: &str) -> String {
    jwt().hash_token(s)
}

async fn record(pool: &PgPool, user_id: Uuid) -> Option<UserTotp> {
    TotpRepository::find_by_user_id(pool, user_id)
        .await
        .expect("read user_totp")
}

/// The setup routes over the real handlers, plus a bearer for `user`.
macro_rules! harness {
    ($pool:expr, $totp:expr, $user:expr) => {{
        let jwt = Arc::new(jwt());
        let bearer = format!(
            "Bearer {}",
            jwt.create_access_token($user).expect("mint access token")
        );
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new($pool.clone()))
                .app_data(jwt)
                .app_data(web::Data::new(Arc::clone($totp)))
                .app_data(json_config())
                .route("/v1/auth/2fa/setup", web::post().to(handlers::setup_2fa))
                .route(
                    "/v1/auth/2fa/setup/resume",
                    web::post().to(handlers::resume_2fa_setup),
                )
                .route(
                    "/v1/auth/2fa/confirm",
                    web::post().to(handlers::confirm_2fa),
                ),
        )
        .await;
        (app, bearer)
    }};
}

/// POST `body` (or nothing) as the harness user; returns status and JSON body.
macro_rules! post {
    ($h:expr, $path:expr, $body:expr $(,)?) => {{
        let (app, bearer) = &$h;
        let mut req = test::TestRequest::post()
            .uri($path)
            .insert_header(("authorization", bearer.clone()));
        let body: Option<Value> = $body;
        if let Some(b) = body {
            req = req.set_json(b);
        }
        let resp = test::call_service(app, req.to_request()).await;
        let status = resp.status().as_u16();
        let bytes = test::read_body(resp).await;
        (
            status,
            serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
        )
    }};
}

fn totp_service(pool: &PgPool) -> Arc<TotpService> {
    Arc::new(TotpService::new(
        key_set(),
        "bunyip-test".to_string(),
        pool.clone(),
    ))
}

fn auth_service(pool: &PgPool) -> AuthService {
    AuthService::new(
        pool.clone(),
        jwt(),
        Arc::new(RwLock::new(TierConfig::from_env())),
        None,
        Arc::new(EmailService::new_dev()),
        None,
        false,
        Vec::new(),
        Vec::new(),
    )
}

fn field_of(body: &Value) -> &str {
    body["error"]["details"]["field"].as_str().unwrap_or("")
}

/// Regression: one POST used to reset an enrolled account to unverified, which
/// switched the sign-in challenge off. It must now be a 409 that changes nothing.
#[actix_rt::test]
async fn setup_on_an_enrolled_account_is_409_and_sign_in_still_challenges() {
    let Some(pool) = connect().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-886 enrolled-account test");
        return;
    };
    let totp = totp_service(&pool);
    let (user, password) = seed_user(&pool).await;
    totp.enroll_preset(user.id, PRESET_SECRET)
        .await
        .expect("enroll preset");
    let before = record(&pool, user.id).await.expect("enrolled row");
    let h = harness!(pool, &totp, &user);

    for body in [
        Some(json!({ "current_password": password })),
        Some(json!({ "current_password": "wrong" })),
        None,
    ] {
        let (status, resp) = post!(h, "/v1/auth/2fa/setup", body);
        assert_eq!(status, 409, "{resp}");
        assert_eq!(resp["error"]["code"], "CONFLICT", "{resp}");
    }

    let after = record(&pool, user.id).await.expect("row kept");
    assert!(after.verified, "verified must not be reset");
    assert_eq!(after.enabled_at, before.enabled_at);
    assert_eq!(after.encrypted_secret, before.encrypted_secret);
    assert_eq!(after.nonce, before.nonce);
    assert!(after.setup_token_hash.is_none());

    let login = auth_service(&pool)
        .login(
            user.email.clone(),
            password,
            Some("ua".into()),
            None,
            None,
            Some("device-886".into()),
            false,
        )
        .await
        .expect("login");
    assert!(
        matches!(login, LoginResult::TwoFactorRequired { .. }),
        "the next sign-in must still ask for a code"
    );
}

#[actix_rt::test]
async fn setup_without_or_with_a_wrong_password_stores_nothing() {
    let Some(pool) = connect().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-886 password test");
        return;
    };
    let totp = totp_service(&pool);
    let (user, _password) = seed_user(&pool).await;
    let h = harness!(pool, &totp, &user);

    // No body is what an older bunyip-web sends: a validation error, not a parse error.
    for (body, message) in [
        (None, "Enter your current password"),
        (Some(json!({})), "Enter your current password"),
        (
            Some(json!({ "current_password": "" })),
            "Enter your current password",
        ),
        (
            Some(json!({ "current_password": "not-the-password" })),
            "Invalid password",
        ),
    ] {
        let (status, resp) = post!(h, "/v1/auth/2fa/setup", body);
        assert_eq!(status, 400, "{resp}");
        assert_eq!(field_of(&resp), "current_password", "{resp}");
        assert_eq!(resp["error"]["message"], message, "{resp}");
    }
    assert!(
        record(&pool, user.id).await.is_none(),
        "a refused setup must store nothing"
    );
}

#[actix_rt::test]
async fn confirm_needs_a_live_setup_token_and_a_used_one_is_dead() {
    let Some(pool) = connect().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-886 token test");
        return;
    };
    let totp = totp_service(&pool);
    let (user, password) = seed_user(&pool).await;
    let h = harness!(pool, &totp, &user);

    let (status, started) = post!(
        h,
        "/v1/auth/2fa/setup",
        Some(json!({ "current_password": password })),
    );
    assert_eq!(status, 200, "{started}");
    let token = started["data"]["setup_token"]
        .as_str()
        .expect("setup token")
        .to_string();
    let secret = started["data"]["secret"]
        .as_str()
        .expect("secret")
        .to_string();

    // Only the hash is stored, with a ~15 minute expiry.
    let row = record(&pool, user.id).await.expect("pending row");
    assert!(!row.verified);
    assert_eq!(
        row.setup_token_hash.as_deref(),
        Some(sha256_hex(&token).as_str())
    );
    let ttl = row.setup_token_expires_at.expect("expiry") - chrono::Utc::now();
    assert!(ttl > chrono::Duration::minutes(14) && ttl <= chrono::Duration::minutes(15));

    // Missing (the older-client shape), blank and wrong tokens enroll nothing.
    for body in [
        json!({ "code": code_now(&secret) }),
        json!({ "code": code_now(&secret), "setup_token": "" }),
        json!({ "code": code_now(&secret), "setup_token": "not-the-token" }),
    ] {
        let (status, resp) = post!(h, "/v1/auth/2fa/confirm", Some(body));
        assert_eq!(status, 400, "{resp}");
        assert_eq!(field_of(&resp), "setup_token", "{resp}");
        assert_eq!(resp["error"]["message"], "This setup expired. Start again.");
        assert!(!record(&pool, user.id).await.expect("row").verified);
    }

    // An expired token enrolls nothing and cannot be resumed.
    sqlx::query(
        "UPDATE user_totp SET setup_token_expires_at = NOW() - INTERVAL '1 second' WHERE user_id = $1",
    )
    .bind(user.id)
    .execute(&pool)
    .await
    .expect("expire token");
    let (status, resp) = post!(
        h,
        "/v1/auth/2fa/confirm",
        Some(json!({ "code": code_now(&secret), "setup_token": token })),
    );
    assert_eq!(status, 400, "{resp}");
    assert_eq!(field_of(&resp), "setup_token", "{resp}");
    let (status, resp) = post!(
        h,
        "/v1/auth/2fa/setup/resume",
        Some(json!({ "setup_token": token })),
    );
    assert_eq!(status, 400, "{resp}");
    assert!(!record(&pool, user.id).await.expect("row").verified);
    let unchanged = UserRepository::find_by_id(&pool, user.id)
        .await
        .expect("reload")
        .expect("user");
    assert!(!unchanged.two_factor_enabled);

    // Restart, enroll with the fresh token, then try to reuse it.
    let (status, restarted) = post!(
        h,
        "/v1/auth/2fa/setup",
        Some(json!({ "current_password": password })),
    );
    assert_eq!(status, 200, "{restarted}");
    let token2 = restarted["data"]["setup_token"]
        .as_str()
        .expect("token")
        .to_string();
    let secret2 = restarted["data"]["secret"]
        .as_str()
        .expect("secret")
        .to_string();
    assert_ne!(token2, token, "a restart issues a new token");
    assert_ne!(secret2, secret, "a restart issues a new secret");

    let (status, done) = post!(
        h,
        "/v1/auth/2fa/confirm",
        Some(json!({ "code": code_now(&secret2), "setup_token": token2 })),
    );
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["data"]["codes"].as_array().map(Vec::len), Some(8));
    let row = record(&pool, user.id).await.expect("row");
    assert!(row.verified && row.enabled_at.is_some());
    assert!(row.setup_token_hash.is_none() && row.setup_token_expires_at.is_none());
    let enrolled = UserRepository::find_by_id(&pool, user.id)
        .await
        .expect("reload")
        .expect("user");
    assert!(enrolled.two_factor_enabled);

    for path in ["/v1/auth/2fa/confirm", "/v1/auth/2fa/setup/resume"] {
        let (status, resp) = post!(
            h,
            path,
            Some(json!({ "code": code_now(&secret2), "setup_token": token2 })),
        );
        assert_eq!(status, 409, "{path} with a used token: {resp}");
    }
    let still = record(&pool, user.id).await.expect("row");
    assert_eq!(still.encrypted_secret, row.encrypted_secret);
    assert_eq!(still.enabled_at, row.enabled_at);
}

#[actix_rt::test]
async fn a_wrong_code_then_resume_shows_the_same_key_and_the_right_code_enrolls() {
    let Some(pool) = connect().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-886 resume test");
        return;
    };
    let totp = totp_service(&pool);
    let (user, password) = seed_user(&pool).await;
    let h = harness!(pool, &totp, &user);

    let (_, started) = post!(
        h,
        "/v1/auth/2fa/setup",
        Some(json!({ "current_password": password })),
    );
    let data = &started["data"];
    let token = data["setup_token"].as_str().expect("token").to_string();
    let secret = data["secret"].as_str().expect("secret").to_string();

    let (status, resp) = post!(
        h,
        "/v1/auth/2fa/confirm",
        Some(json!({ "code": wrong_code(&secret), "setup_token": token })),
    );
    assert_eq!(status, 400, "{resp}");
    assert_eq!(field_of(&resp), "code", "{resp}");

    let (status, resumed) = post!(
        h,
        "/v1/auth/2fa/setup/resume",
        Some(json!({ "setup_token": token })),
    );
    assert_eq!(status, 200, "{resumed}");
    assert_eq!(resumed["data"]["secret"], data["secret"]);
    assert_eq!(resumed["data"]["otpauth_uri"], data["otpauth_uri"]);
    assert!(
        resumed["data"].get("setup_token").is_none(),
        "resume never mints a token"
    );

    let (status, done) = post!(
        h,
        "/v1/auth/2fa/confirm",
        Some(json!({ "code": code_now(&secret), "setup_token": token })),
    );
    assert_eq!(status, 200, "{done}");
    assert!(totp.is_enabled(user.id).await.expect("status"));
}

/// The E2E bootstrap re-enrolls its preset over an enrolled account, so a
/// re-seed stays idempotent, and it clears any setup in flight.
#[actix_rt::test]
async fn the_e2e_bootstrap_still_enrolls_its_preset() {
    let Some(pool) = connect().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-886 preset test");
        return;
    };
    let totp = totp_service(&pool);
    let (user, password) = seed_user(&pool).await;
    let h = harness!(pool, &totp, &user);
    let (status, _) = post!(
        h,
        "/v1/auth/2fa/setup",
        Some(json!({ "current_password": password })),
    );
    assert_eq!(status, 200);

    for _ in 0..2 {
        totp.enroll_preset(user.id, PRESET_SECRET)
            .await
            .expect("enroll preset");
        let row = record(&pool, user.id).await.expect("row");
        assert!(row.verified);
        assert!(row.setup_token_hash.is_none() && row.setup_token_expires_at.is_none());
    }
    assert!(totp
        .verify_code(user.id, &code_now(PRESET_SECRET))
        .await
        .expect("verify"));
}
