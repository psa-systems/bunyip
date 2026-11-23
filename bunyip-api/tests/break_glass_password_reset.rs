//! BUNYIP-1096 Option E: the break-glass password-reset CLI mints a one-time
//! reset URL out-of-band of SMTP. These tests drive the helper against a real
//! Postgres (gated on `BUNYIP_TEST_DATABASE_URL`; skips if unset) and assert:
//!
//! - minting returns a URL containing the configured base + `/reset-password?token=…`
//! - the stored hash matches the raw token when fed back through the server's
//!   JWT HMAC pepper, so the `/reset-password` handler can verify it
//! - the audit row names `break-glass-cli` + `system`, with `actor_id` NULL
//! - an unknown email returns NotFound, not a silent success

use bunyip_api::break_glass::mint_break_glass_reset;
use bunyip_api::config::Config;
use bunyip_api::errors::AppError;
use bunyip_api::models::{CreateUser, UserRole};
use bunyip_api::repositories::UserRepository;
use bunyip_api::services::{JwtConfig, JwtService};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

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

fn test_config() -> Config {
    std::env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
    std::env::set_var("ENVIRONMENT", "development");
    std::env::set_var("SECRETS_STORAGE", "database");
    std::env::set_var("HOST_IP", "0.0.0.0");
    std::env::set_var("APP_PORT", "4000");
    std::env::set_var("APP_URL", "https://psa.systems");
    Config::from_env().expect("minimal config resolves outside production")
}

async fn seed_user(pool: &PgPool, email: &str) -> bunyip_api::models::User {
    UserRepository::create(
        pool,
        CreateUser {
            email: email.to_string(),
            password_hash: Some("x".to_string()),
            role: UserRole::Subscriber,
        },
    )
    .await
    .expect("seed user")
}

/// The URL carries `{APP_URL}/reset-password?token=<raw>`, and the stored
/// token_hash matches the raw token when hashed with the same JWT HMAC.
/// Without that match the `/reset-password` handler would reject every URL
/// the subcommand prints, which is the whole break-glass gap this exists to
/// close.
#[actix_rt::test]
async fn mint_returns_a_usable_reset_url_hashed_with_the_jwt_pepper() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let email = format!("brk-{}@a8n.run", Uuid::new_v4().simple());
    seed_user(&pool, &email).await;

    let config = test_config();
    let jwt_secret = "break-glass-test-secret-at-least-32-bytes-long";
    let outcome = mint_break_glass_reset(&pool, &config, &email, jwt_secret)
        .await
        .expect("mint succeeds");

    assert!(outcome
        .url
        .starts_with("https://psa.systems/reset-password?token="));
    let raw = outcome
        .url
        .rsplit_once("token=")
        .expect("URL has a token param")
        .1;
    let expected_hash =
        JwtService::new(JwtConfig::from_secret(jwt_secret, &config.app_name)).hash_token(raw);

    // The verifier hashes the raw token and looks for a matching row; a mint
    // that stored a different hash would make every minted URL reject.
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT token_hash FROM password_reset_tokens WHERE token_hash = $1 \
         AND used_at IS NULL AND expires_at > NOW()",
    )
    .bind(&expected_hash)
    .fetch_optional(&pool)
    .await
    .expect("query stored hash");
    assert!(
        row.is_some(),
        "the stored token_hash must equal JwtService::hash_token(raw) under the same JWT secret"
    );
}

/// BUNYIP-1096: the audit row names the operator as `break-glass-cli` /
/// `system` with `actor_id = NULL`, so an incident review can tell this path
/// apart from the normal admin-UI reset which carries the admin's user id.
#[actix_rt::test]
async fn mint_writes_an_audit_row_naming_the_break_glass_actor() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let email = format!("brk-{}@a8n.run", Uuid::new_v4().simple());
    let user = seed_user(&pool, &email).await;

    let config = test_config();
    let jwt_secret = "break-glass-test-secret-at-least-32-bytes-long";
    mint_break_glass_reset(&pool, &config, &email, jwt_secret)
        .await
        .expect("mint succeeds");

    let (actor_id, actor_email, actor_role): (Option<Uuid>, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT actor_id, actor_email, actor_role FROM audit_logs \
             WHERE action = 'break_glass_password_reset' \
             AND resource_type = 'user' AND resource_id = $1 \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .expect("audit row exists");

    assert!(
        actor_id.is_none(),
        "actor_id is NULL for a CLI-initiated mint"
    );
    assert_eq!(actor_email.as_deref(), Some("break-glass-cli"));
    assert_eq!(actor_role.as_deref(), Some("system"));
}

/// An unknown email returns NotFound, not a silent success - the operator
/// needs to know they fat-fingered the address, not get a URL printed for
/// nothing.
#[actix_rt::test]
async fn mint_refuses_unknown_email() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let config = test_config();
    let err = mint_break_glass_reset(
        &pool,
        &config,
        "nobody-here@example.invalid",
        "break-glass-test-secret-at-least-32-bytes-long",
    )
    .await
    .expect_err("unknown email must be an error");
    assert!(
        matches!(err, AppError::NotFound { .. }),
        "expected NotFound for unknown email, got {err:?}"
    );
}
