//! BUNYIP-373 suspicious-login notify-and-approve gate integration test.
//!
//! Proves the gate wired into `AuthService::login`: with `login_approval_enabled`
//! on, a login from a NEW device (once the user already has a baseline device)
//! withholds tokens and stores a pending approval challenge instead of logging
//! in, while a known device and the first-ever device are never gated. Also
//! proves `complete_login_approval` verifies the emailed code, mints tokens,
//! persists the approved country/device as the new baseline, and is single-use.
//!
//! The country signal (geoip) is deliberately left disabled (`geoip = None`) so
//! these cases isolate the net-new DEVICE signal without needing an IP2Location
//! `.BIN` fixture; the country half reuses BUNYIP-366's `login_location_decision`,
//! which is unit-tested in `services::auth`.
//!
//! Env-gated. bunyip CI has no Postgres service (`just check-container` runs the
//! workspace tests only), so with `RLS_TEST_DATABASE_URL` unset this test skips
//! and stays green. The URL must point at a throwaway database the test may
//! migrate:
//!
//! ```sh
//! RLS_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_appr_test \
//!   cargo test -p bunyip-api --test login_approval -- --nocapture
//! ```

use bunyip_api::config::TierConfig;
use bunyip_api::models::{CreateUser, UserRole};
use bunyip_api::repositories::{TokenRepository, UserRepository};
use bunyip_api::services::{
    AuthService, EmailService, JwtConfig, JwtService, LoginResult, PasswordService,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// At least 32 bytes so HS256 challenge signing is happy. A second `JwtService`
/// built from the same secret mints challenge tokens the service under test
/// accepts.
const JWT_SECRET: &str = "bunyip-373-test-secret-at-least-32-bytes-long";

/// Build an `AuthService` with the suspicious-login gate toggled as requested.
/// `geoip = None` disables the country signal so tests exercise the device
/// signal in isolation; `EmailService::new_dev()` swallows the approval email.
fn build_auth_service(pool: PgPool, login_approval_enabled: bool) -> AuthService {
    let jwt = JwtService::new(JwtConfig::from_secret(JWT_SECRET, "bunyip-test"));
    let tier = Arc::new(RwLock::new(TierConfig::from_env()));
    let email = Arc::new(EmailService::new_dev());
    AuthService::new(pool, jwt, tier, None, email, None, login_approval_enabled)
}

/// Seed a password user directly (bypassing `register`, which runs a network
/// HIBP breach check and strength validation not wanted in a hermetic test).
async fn seed_user(pool: &PgPool) -> (Uuid, String, String) {
    let email = format!("appr-{}@example.test", Uuid::new_v4().simple());
    let password = format!("Pw-{}-Aa1!zz", Uuid::new_v4().simple());
    let password_hash = PasswordService::new()
        .hash(&password)
        .expect("hash password");
    let user = UserRepository::create(
        pool,
        CreateUser {
            email: email.clone(),
            password_hash: Some(password_hash),
            role: UserRole::Subscriber,
        },
    )
    .await
    .expect("create seed user");
    (user.id, email, password)
}

async fn connect_and_migrate() -> Option<PgPool> {
    let url = std::env::var("RLS_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect to RLS_TEST_DATABASE_URL");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

async fn cleanup(pool: &PgPool, user_id: Uuid) {
    // login_approval_codes + login_devices + refresh tokens all cascade on the
    // user FK, so one delete reclaims everything the test wrote.
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("cleanup user");
}

#[tokio::test]
async fn new_device_triggers_approval_gate() {
    let Some(pool) = connect_and_migrate().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-373 gate test");
        return;
    };
    let auth = build_auth_service(pool.clone(), true);
    let (user_id, email, password) = seed_user(&pool).await;

    // First login from device A: no baseline device yet, so it is recorded as a
    // silent baseline and NOT gated.
    let r1 = auth
        .login(
            email.clone(),
            password.clone(),
            Some("ua".into()),
            None,
            None,
            Some("device-A".into()),
        )
        .await
        .expect("login A");
    assert!(
        matches!(r1, LoginResult::Success(..)),
        "the first device is a silent baseline, not gated"
    );
    assert_eq!(
        TokenRepository::count_login_devices(&pool, user_id)
            .await
            .unwrap(),
        1,
        "device A is recorded on a clean login"
    );

    // Second login from a DIFFERENT device: a baseline exists, so this is a new
    // device and the gate must withhold tokens.
    let r2 = auth
        .login(
            email.clone(),
            password.clone(),
            Some("ua".into()),
            None,
            None,
            Some("device-B".into()),
        )
        .await
        .expect("login B");
    assert!(
        matches!(r2, LoginResult::ApprovalRequired { .. }),
        "a new device must be gated (ApprovalRequired)"
    );

    // A pending approval challenge exists, and the new device was NOT recorded
    // (tokens were withheld, so device B is not yet trusted).
    assert!(
        TokenRepository::find_latest_valid_login_approval_code(&pool, user_id)
            .await
            .unwrap()
            .is_some(),
        "a pending approval code row was created"
    );
    assert_eq!(
        TokenRepository::count_login_devices(&pool, user_id)
            .await
            .unwrap(),
        1,
        "a gated login must NOT record the new device"
    );

    // Re-login from the KNOWN device A still succeeds (never gated).
    let r3 = auth
        .login(
            email.clone(),
            password.clone(),
            Some("ua".into()),
            None,
            None,
            Some("device-A".into()),
        )
        .await
        .expect("login A again");
    assert!(
        matches!(r3, LoginResult::Success(..)),
        "a known device is never gated"
    );

    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn gate_disabled_never_withholds() {
    let Some(pool) = connect_and_migrate().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-373 kill-switch test");
        return;
    };
    // Kill-switch OFF: the feature must be completely inert.
    let auth = build_auth_service(pool.clone(), false);
    let (user_id, email, password) = seed_user(&pool).await;

    auth.login(
        email.clone(),
        password.clone(),
        None,
        None,
        None,
        Some("dev-A".into()),
    )
    .await
    .expect("login A");
    let r = auth
        .login(
            email.clone(),
            password.clone(),
            None,
            None,
            None,
            Some("dev-B".into()),
        )
        .await
        .expect("login B");
    assert!(
        matches!(r, LoginResult::Success(..)),
        "gate off: a new device still logs straight in"
    );
    assert_eq!(
        TokenRepository::count_login_devices(&pool, user_id)
            .await
            .unwrap(),
        0,
        "gate off: no device tracking happens at all"
    );
    assert!(
        TokenRepository::find_latest_valid_login_approval_code(&pool, user_id)
            .await
            .unwrap()
            .is_none(),
        "gate off: no approval challenge is ever created"
    );

    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn complete_login_approval_mints_tokens_and_records_baseline() {
    let Some(pool) = connect_and_migrate().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-373 completion test");
        return;
    };
    let auth = build_auth_service(pool.clone(), true);
    let (user_id, _email, _password) = seed_user(&pool).await;

    // The live login flow generates a random code we cannot read, so craft the
    // challenge + row directly: a second JwtService on the SAME secret mints a
    // challenge the service accepts, and `hash_token` is plain SHA-256 so the
    // stored hash matches what the service computes from the submitted code.
    let jwt = JwtService::new(JwtConfig::from_secret(JWT_SECRET, "bunyip-test"));
    let challenge = jwt
        .create_login_approval_challenge_token(user_id)
        .expect("mint challenge");
    let code = "654321";
    let device_hash = jwt.hash_token("device-new");
    sqlx::query(
        "INSERT INTO login_approval_codes
            (user_id, code_hash, country, device_hash, device_info, expires_at)
         VALUES ($1, $2, 'US', $3, 'crafted-ua', NOW() + INTERVAL '15 minutes')",
    )
    .bind(user_id)
    .bind(jwt.hash_token(code))
    .bind(&device_hash)
    .execute(&pool)
    .await
    .expect("insert crafted approval challenge");

    // Wrong code: rejected, tokens withheld, attempt counted.
    assert!(
        auth.complete_login_approval(&challenge, "000000", None, None)
            .await
            .is_err(),
        "a wrong code is rejected"
    );
    assert_eq!(
        TokenRepository::find_latest_valid_login_approval_code(&pool, user_id)
            .await
            .unwrap()
            .expect("challenge still pending after a wrong guess")
            .attempts,
        1,
        "a wrong guess increments the attempt counter"
    );

    // Correct code: mints tokens and records the approved country + device as
    // the new baseline.
    let (tokens, user) = auth
        .complete_login_approval(&challenge, code, Some("crafted-ua".into()), None)
        .await
        .expect("complete approval with the correct code");
    assert!(!tokens.access_token.is_empty(), "an access token is minted");
    assert_eq!(user.id, user_id);

    let refreshed = UserRepository::find_by_id(&pool, user_id)
        .await
        .unwrap()
        .expect("user still exists");
    assert_eq!(
        refreshed.last_login_country.as_deref(),
        Some("US"),
        "the approved country is persisted as the new baseline"
    );
    assert!(
        TokenRepository::find_login_device(&pool, user_id, &device_hash)
            .await
            .unwrap()
            .is_some(),
        "the approved device is recorded as known"
    );

    // Single-use: the consumed challenge cannot be replayed.
    assert!(
        auth.complete_login_approval(&challenge, code, None, None)
            .await
            .is_err(),
        "a consumed approval challenge cannot be replayed"
    );

    cleanup(&pool, user_id).await;
}
