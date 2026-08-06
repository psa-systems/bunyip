//! BUNYIP-428 TOTP acceptance-window + single-use regression.
//!
//! Proves against a real database what the `services::totp` unit tests can only
//! model in memory: `TotpService::verify_code` accepts a code once and refuses
//! every later submission of it, and the guarded UPDATE behind that
//! (`TotpRepository::claim_totp_step`, migration
//! `20260731000010_add_totp_last_used_step.sql`) picks exactly one winner when
//! two submissions of the same code race.
//!
//! Env-gated. bunyip CI has no Postgres service (`just check-container` runs the
//! workspace lib tests only), so with `RLS_TEST_DATABASE_URL` unset this test
//! skips and stays green. The URL must point at a throwaway database the test
//! may migrate:
//!
//! ```sh
//! RLS_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_totp_test \
//!   cargo test -p bunyip-api --test totp_single_use -- --nocapture
//! ```

use bunyip_api::repositories::TotpRepository;
use bunyip_api::services::{AppKeySet, TotpService};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;

/// 20 bytes of base32, clearing totp_rs's 128-bit minimum.
const SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn key_set() -> AppKeySet {
    AppKeySet {
        current: [0x42u8; 32],
        current_version: 1,
        previous: Vec::new(),
    }
}

/// The code the authenticator shows at unix time `ts`.
fn code_at(ts: u64) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(SECRET_BASE32.as_bytes())
        .expect("decode test secret");
    TOTP::new(
        Algorithm::SHA1,
        6,
        0,
        30,
        secret,
        Some("bunyip-test".to_string()),
        String::new(),
    )
    .expect("build TOTP")
    .generate(ts)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

async fn seed_user(pool: &PgPool) -> Uuid {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(user_id)
        .bind(format!("totp-{}@example.test", user_id.simple()))
        .execute(pool)
        .await
        .expect("seed user");
    user_id
}

async fn connect() -> Option<PgPool> {
    let url = std::env::var("RLS_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect to test database");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

#[tokio::test]
async fn accepted_code_is_never_accepted_twice() {
    let Some(pool) = connect().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping TOTP single-use test");
        return;
    };

    let user_id = seed_user(&pool).await;
    let service = TotpService::new(key_set(), "bunyip-test".to_string(), pool.clone());
    service
        .enroll_preset(user_id, SECRET_BASE32)
        .await
        .expect("enroll preset secret");

    // Submit the code for the step that is current right now. Generating from
    // the step start (rather than `now`) keeps the assertion stable even if the
    // clock crosses a boundary mid-test: the code stays inside the accepted
    // current-plus-previous pair either way.
    let step = now_secs() / 30;
    let code = code_at(step * 30);

    assert!(
        service.verify_code(user_id, &code).await.expect("verify"),
        "a fresh code must be accepted"
    );
    assert!(
        !service.verify_code(user_id, &code).await.expect("verify"),
        "the same code must be refused on replay"
    );

    // The step was recorded, so every older step is burned too.
    assert_eq!(
        TotpRepository::claim_totp_step(&pool, user_id, step as i64 - 1)
            .await
            .expect("claim older step"),
        0,
        "an older step must not be claimable after a newer one was consumed"
    );
}

#[tokio::test]
async fn concurrent_submission_of_one_code_has_exactly_one_winner() {
    let Some(pool) = connect().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping TOTP concurrency test");
        return;
    };

    let user_id = seed_user(&pool).await;
    let service = Arc::new(TotpService::new(
        key_set(),
        "bunyip-test".to_string(),
        pool.clone(),
    ));
    service
        .enroll_preset(user_id, SECRET_BASE32)
        .await
        .expect("enroll preset secret");

    let code = code_at((now_secs() / 30) * 30);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let service = Arc::clone(&service);
        let code = code.clone();
        handles.push(tokio::spawn(async move {
            service
                .verify_code(user_id, &code)
                .await
                .expect("verify must not error under contention")
        }));
    }

    let mut accepted = 0;
    for handle in handles {
        if handle.await.expect("join") {
            accepted += 1;
        }
    }
    assert_eq!(
        accepted, 1,
        "exactly one concurrent submission of a code may succeed"
    );
}
