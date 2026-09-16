//! BUNYIP-726 country sign-in gate integration test.
//!
//! Proves `register`, `login`, and `verify_magic_link` are all refused by the
//! same country configuration, not just `login`. The gate resolves a country
//! through the geoip service (`GeoIpService`), which needs an IP2Location
//! `.BIN` fixture this suite does not carry; instead every case here leaves
//! `geoip = None` (the same isolation `login_approval.rs` uses for its device
//! tests) and sets a non-empty `country_allow`, so the client IP never
//! resolves to a country and the gate takes its "unresolved country with an
//! allow list configured" branch (BUNYIP-726 AC2) - refused, exactly like a
//! resolved-but-not-allowed country would be, and the same branch every
//! caller shares because all three delegate to `AuthService::enforce_country_gate`.
//!
//! Env-gated. bunyip CI has no Postgres service (`just check-container` runs
//! the workspace tests only), so with `RLS_TEST_DATABASE_URL` unset this test
//! skips and stays green. The URL must point at a throwaway database the test
//! may migrate:
//!
//! ```sh
//! RLS_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_gate_test \
//!   cargo test -p bunyip-api --test country_gate -- --nocapture
//! ```

use bunyip_api::config::TierConfig;
use bunyip_api::models::{CreateUser, UserRole};
use bunyip_api::repositories::UserRepository;
use bunyip_api::services::{
    argon2_offload, AuthService, EmailService, JwtConfig, JwtService, MagicLinkResult,
};
use bunyip_api::AppError;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

const JWT_SECRET: &str = "bunyip-726-test-secret-at-least-32-bytes-long";

/// Build an `AuthService` with the given country allow/deny lists and no
/// geoip resolver, isolating the "unresolved country" branch (see module doc).
fn build_auth_service(
    pool: PgPool,
    country_allow: Vec<String>,
    country_deny: Vec<String>,
) -> AuthService {
    let jwt = JwtService::new(JwtConfig::from_secret(JWT_SECRET, "bunyip-test"));
    let tier = Arc::new(RwLock::new(TierConfig::from_env()));
    let email = Arc::new(EmailService::new_dev());
    AuthService::new(
        pool,
        jwt,
        tier,
        None,
        email,
        None,
        false,
        country_allow,
        country_deny,
    )
}

async fn seed_user(pool: &PgPool) -> (Uuid, String, String) {
    let email = format!("gate-{}@example.test", Uuid::new_v4().simple());
    let password = format!("Pw-{}-Aa1!zz", Uuid::new_v4().simple());
    let password_hash = argon2_offload::hash_password(password.clone())
        .await
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
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("cleanup user");
}

#[tokio::test]
async fn country_gate_refuses_register_login_and_magic_link_alike() {
    let Some(pool) = connect_and_migrate().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-726 country gate test");
        return;
    };

    let gated = build_auth_service(pool.clone(), vec!["US".to_string()], Vec::new());
    let ungated = build_auth_service(pool.clone(), Vec::new(), Vec::new());
    let ip: IpAddr = "203.0.113.10".parse().unwrap();

    // register: refused before the user row is written.
    let reg_email = format!("gate-reg-{}@example.test", Uuid::new_v4().simple());
    let reg_password = format!("Pw-{}-Aa1!zz", Uuid::new_v4().simple());
    let register_err = gated
        .register(reg_email.clone(), reg_password, Some(ip))
        .await
        .expect_err("register must be refused by the country gate");
    assert!(matches!(register_err, AppError::Forbidden));
    assert!(
        UserRepository::find_by_email(&pool, &reg_email)
            .await
            .unwrap()
            .is_none(),
        "a refused register must not create the user row"
    );

    // login: refused before any credential check. Seed the user through the
    // ungated service so the gate under test is the only thing exercised.
    let (user_id, login_email, login_password) = seed_user(&pool).await;
    let login_result = gated
        .login(
            login_email.clone(),
            login_password,
            None,
            Some(ip),
            None,
            None,
            false,
        )
        .await;
    match login_result {
        Err(AppError::Forbidden) => {}
        Err(_) => panic!("login must be refused specifically by the country gate"),
        Ok(_) => panic!("login must be refused by the country gate"),
    }

    // verify_magic_link: refused before the single-use token is claimed.
    // `request_magic_link` is deliberately never gated (BUNYIP-726), so it
    // goes through the ungated service; only the redemption is under test.
    let token = ungated
        .request_magic_link(login_email.clone(), Some(ip))
        .await
        .expect("request magic link");
    let magic_result = gated
        .verify_magic_link(token.clone(), None, Some(ip), None)
        .await;
    match magic_result {
        Err(AppError::Forbidden) => {}
        Err(_) => panic!("verify_magic_link must be refused specifically by the country gate"),
        Ok(_) => panic!("verify_magic_link must be refused by the country gate"),
    }

    // The token must survive the refusal: it was never claimed, so redeeming
    // it through the ungated service still succeeds.
    let recovered = ungated
        .verify_magic_link(token, None, Some(ip), None)
        .await
        .expect("the refused attempt must not have burned the magic-link token");
    match recovered {
        MagicLinkResult::Success(_, resp, _) => {
            assert_eq!(resp.email, login_email);
        }
        _ => panic!("expected magic-link success once ungated"),
    }

    cleanup(&pool, user_id).await;
}
