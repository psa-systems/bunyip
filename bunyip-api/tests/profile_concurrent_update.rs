//! BUNYIP-951 regression test: two concurrent `UserRepository::update_profile`
//! calls that each touch a different field must both land, with neither
//! field reverted. Before the fix the caller resolved "field absent from the
//! request" by reading a snapshot and writing it back, so an interleaving
//! where both calls read before either wrote would lose one field's update;
//! the fix moves that resolution into the UPDATE statement itself via a
//! `CASE WHEN`, so it is safe under real concurrency.
//!
//! Env-gated like the other DB-backed integration tests: set
//! `BUNYIP_TEST_DATABASE_URL` (or reuse `RLS_TEST_DATABASE_URL`) to a
//! throwaway, migratable database; unset skips the test.

use bunyip_api::models::{CreateUser, UserRole};
use bunyip_api::repositories::UserRepository;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
async fn concurrent_partial_updates_do_not_revert_each_other() {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"));
    let Ok(url) = url else {
        eprintln!(
            "BUNYIP_TEST_DATABASE_URL / RLS_TEST_DATABASE_URL unset; skipping profile_concurrent_update test"
        );
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect to test database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");

    let email = format!(
        "profile-concurrent-{}@example.test",
        Uuid::new_v4().simple()
    );
    let user = UserRepository::create(
        &pool,
        CreateUser {
            email,
            password_hash: Some("x".to_string()),
            role: UserRole::Subscriber,
        },
    )
    .await
    .expect("seed user");

    // Both calls only set the field they own; the other is `None` (absent),
    // matching what the handler passes for a field the request body omitted.
    let set_first = UserRepository::update_profile(&pool, user.id, Some(Some("Ada")), None, None);
    let set_last =
        UserRepository::update_profile(&pool, user.id, None, Some(Some("Lovelace")), None);

    let (first_result, last_result) = tokio::join!(set_first, set_last);
    first_result.expect("set first_name");
    last_result.expect("set last_name");

    let final_user = UserRepository::find_by_id(&pool, user.id)
        .await
        .expect("read back user")
        .expect("user exists");

    assert_eq!(final_user.first_name.as_deref(), Some("Ada"));
    assert_eq!(final_user.last_name.as_deref(), Some("Lovelace"));
}
