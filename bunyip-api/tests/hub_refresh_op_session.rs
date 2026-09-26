//! BUNYIP-636 PR 3b: hub `refresh_tokens` is bound to its op-session and the
//! hub refresh path (`AuthService::refresh_tokens`) reads and slides it.
//!
//! Two behavioural halves land here. First, the happy path: a rotation slides
//! the op-session's `idle_expires_at` forward, so activity on the hub keeps
//! the session the RP families also read alive - the "one session clock" the
//! ticket promises. Second, the refusal path: a revoked op-session stops the
//! next hub rotation, matching how PR 2 already refused an RP rotation.
//!
//! Env-gated. bunyip CI has no Postgres service (`just check-container` runs
//! the workspace tests only), so with `RLS_TEST_DATABASE_URL` unset this test
//! skips and stays green. The URL must point at a throwaway database the test
//! may migrate:
//!
//! ```sh
//! RLS_TEST_DATABASE_URL=postgres://bunyip:devpassword@localhost:5432/bunyip \
//!   cargo test -p bunyip-api --test hub_refresh_op_session -- --nocapture
//! ```

use bunyip_api::config::TierConfig;
use bunyip_api::models::{CreateRefreshToken, CreateUser, UserRole};
use bunyip_api::repositories::{TokenRepository, UserRepository};
use bunyip_api::services::{AuthService, EmailService, JwtConfig, JwtService, PasswordService};
use chrono::{DateTime, Duration, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// At least 32 bytes so HS256 refresh-token signing is happy. Matches the
/// shape `login_approval.rs` uses; the service built with this secret is
/// what mints AND rotates the refresh tokens the test drives.
const JWT_SECRET: &str = "bunyip-636-pr3b-test-secret-at-least-32-bytes-long";

fn build_auth_service(pool: PgPool) -> AuthService {
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
        Vec::new(),
        Vec::new(),
    )
}

async fn seed_user(pool: &PgPool) -> Uuid {
    let email = format!("hub-636-{}@example.test", Uuid::new_v4().simple());
    let password = format!("Pw-{}-Aa1!zz", Uuid::new_v4().simple());
    let password_hash = PasswordService::new()
        .hash(&password)
        .expect("hash password");
    let user = UserRepository::create(
        pool,
        CreateUser {
            email,
            password_hash: Some(password_hash),
            role: UserRole::Subscriber,
        },
    )
    .await
    .expect("create seed user");
    user.id
}

/// Directly seed an op-session at chosen deadlines so a test can build the
/// three refusal arms without running the full login flow. The `idle_ttl_seconds`
/// column is what the slide extends by, so it drives the OBSERVED post-slide
/// deadline the test asserts on.
async fn seed_op_session(
    pool: &PgPool,
    user_id: Uuid,
    expires_at: DateTime<Utc>,
    idle_expires_at: DateTime<Utc>,
    idle_ttl_seconds: i32,
    revoked: bool,
) -> Uuid {
    let sid = format!("test-sid-{}", Uuid::new_v4().simple());
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO op_sessions \
             (id, sid, user_id, created_at, last_active_at, expires_at, idle_expires_at, \
              idle_ttl_seconds, acr, amr, revoked_at) \
         VALUES \
             (gen_random_uuid(), $1, $2, NOW() - INTERVAL '10 minutes', \
              NOW() - INTERVAL '10 minutes', $3, $4, $5, 'urn:bunyip:loa:pwd', \
              ARRAY['pwd']::TEXT[], \
              CASE WHEN $6 THEN NOW() ELSE NULL END) \
         RETURNING id",
    )
    .bind(sid)
    .bind(user_id)
    .bind(expires_at)
    .bind(idle_expires_at)
    .bind(idle_ttl_seconds)
    .bind(revoked)
    .fetch_one(pool)
    .await
    .expect("seed op_session");
    id
}

/// Mint a hub refresh token by calling the same `JwtService::create_refresh_token`
/// and `TokenRepository::create_refresh_token` path production uses, then
/// bind it to an op-session so the rotation goes through the PR 3b path.
/// Returns the raw refresh token and the `expires_at` the row carries. Uses
/// a fixed 30-day window (matches remember-me's absolute cap), deliberately
/// longer than the op-session's absolute deadline in the slide test below,
/// so the assertion pins the op-session cap rather than the client cap.
async fn mint_and_link(
    auth: &AuthService,
    pool: &PgPool,
    user_id: Uuid,
    op_session_id: Uuid,
) -> (String, DateTime<Utc>) {
    let jwt = JwtService::new(JwtConfig::from_secret(JWT_SECRET, "bunyip-test"));
    let (raw, token_hash) = jwt.create_refresh_token(user_id).expect("mint jwt");
    let expires_at = Utc::now() + Duration::days(30);
    TokenRepository::create_refresh_token(
        pool,
        CreateRefreshToken {
            user_id,
            token_hash,
            device_info: None,
            ip_address: None,
            expires_at,
        },
    )
    .await
    .expect("persist refresh token");
    auth.link_refresh_token_to_op_session(&raw, user_id, op_session_id)
        .await
        .expect("link");
    (raw, expires_at)
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
    // FK cascades from users -> refresh_tokens, op_sessions clean up all
    // rows the test wrote.
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("cleanup");
}

async fn read_op_session_idle(pool: &PgPool, id: Uuid) -> DateTime<Utc> {
    sqlx::query_scalar::<_, DateTime<Utc>>("SELECT idle_expires_at FROM op_sessions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read idle_expires_at")
}

#[tokio::test]
async fn a_hub_refresh_rotation_slides_the_owning_op_session() {
    let Some(pool) = connect_and_migrate().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-636 PR 3b hub slide test");
        return;
    };

    let auth = build_auth_service(pool.clone());
    let user_id = seed_user(&pool).await;
    // Session absolute deadline 30 days out, idle deadline 1 hour out (as if
    // the user has been idle a while but is still within the idle window).
    // Idle TTL of 8 hours (the SESSION_IDLE_TTL_SECONDS default) is what the
    // slide extends by, so the observed post-slide idle should be roughly
    // 8 hours ahead of NOW().
    let now = Utc::now();
    let session_id = seed_op_session(
        &pool,
        user_id,
        now + Duration::days(30),
        now + Duration::hours(1),
        28_800,
        false,
    )
    .await;

    let (raw, _) = mint_and_link(&auth, &pool, user_id, session_id).await;
    let idle_before = read_op_session_idle(&pool, session_id).await;

    let _new = auth
        .refresh_tokens(raw, None, None)
        .await
        .expect("rotation succeeds against a live session");

    let idle_after = read_op_session_idle(&pool, session_id).await;

    assert!(
        idle_after > idle_before,
        "the rotation slid the op-session's idle deadline forward (before {idle_before}, after {idle_after})",
    );
    // Slide takes it to roughly `now + 8h`. Allow a wide margin for test
    // scheduling jitter, but pin the shape: post-slide is within seconds of
    // 8 hours ahead of NOW(), and never past the absolute deadline.
    let expected = Utc::now() + Duration::seconds(28_800);
    let delta = (idle_after - expected).num_seconds().abs();
    assert!(
        delta < 30,
        "post-slide idle_expires_at is within 30s of NOW() + 8h (delta={delta}s)",
    );

    cleanup(&pool, user_id).await;
}

#[tokio::test]
async fn a_hub_refresh_rotation_refuses_when_the_op_session_is_revoked() {
    let Some(pool) = connect_and_migrate().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-636 PR 3b refusal test");
        return;
    };

    let auth = build_auth_service(pool.clone());
    let user_id = seed_user(&pool).await;
    let now = Utc::now();
    let session_id = seed_op_session(
        &pool,
        user_id,
        now + Duration::days(30),
        now + Duration::hours(1),
        28_800,
        // Revoked at seed time - the rotation must refuse.
        true,
    )
    .await;

    let (raw, _) = mint_and_link(&auth, &pool, user_id, session_id).await;

    let err = auth
        .refresh_tokens(raw, None, None)
        .await
        .expect_err("a revoked op-session refuses the hub rotation");
    // BUNYIP-636 PR 3b maps the three refusal arms to `InvalidCredentials`
    // (the hub path's existing error type) so a revoked session reads the
    // same as any other invalid refresh at the wire, per BUNYIP-373.
    match err {
        bunyip_api::errors::AppError::InvalidCredentials => {}
        other => panic!("expected InvalidCredentials, got {other:?}"),
    }

    cleanup(&pool, user_id).await;
}
