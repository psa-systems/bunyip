//! BUNYIP-919: `count_new_feedback` counts only the rows an admin still needs to
//! look at: `status = 'new'` AND `is_spam = FALSE`. A `reviewed`, `responded`,
//! `closed`, or spam row is excluded.
//!
//! Env-gated. bunyip CI has no Postgres service (`just check-container` runs the
//! workspace tests only), so with `RLS_TEST_DATABASE_URL` unset this test skips
//! and stays green. The URL must point at a database the test may migrate:
//!
//! ```sh
//! RLS_TEST_DATABASE_URL=postgres://bunyip:devpassword@localhost:5432/bunyip \
//!   cargo test -p bunyip-api --test feedback_new_count -- --nocapture
//! ```

use bunyip_api::repositories::feedback::count_new_feedback;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

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

/// Insert one feedback row at a chosen status/spam, tagged in `message` so the
/// test can delete exactly its own rows afterwards. `message` is the only
/// NOT NULL column without a default; `status` and `is_spam` carry the values
/// under test.
async fn insert(pool: &PgPool, tag: &str, status: &str, is_spam: bool) {
    sqlx::query("INSERT INTO feedback (message, status, is_spam) VALUES ($1, $2, $3)")
        .bind(tag)
        .bind(status)
        .bind(is_spam)
        .execute(pool)
        .await
        .expect("insert feedback row");
}

#[tokio::test]
async fn count_new_feedback_counts_only_new_non_spam() {
    let Some(pool) = connect_and_migrate().await else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping BUNYIP-919 count test");
        return;
    };

    // Measure the delta the seeded rows add, so the assertion holds whatever the
    // shared database already contains.
    let tag = format!("bunyip-919-{}", Uuid::new_v4().simple());
    let before = count_new_feedback(&pool).await.expect("count before");

    insert(&pool, &tag, "new", false).await; // counted
    insert(&pool, &tag, "reviewed", false).await; // excluded: status
    insert(&pool, &tag, "responded", false).await; // excluded: status
    insert(&pool, &tag, "closed", false).await; // excluded: status
    insert(&pool, &tag, "new", true).await; // excluded: spam

    let after = count_new_feedback(&pool).await.expect("count after");
    assert_eq!(
        after - before,
        1,
        "only the one new, non-spam row is counted (reviewed/responded/closed/spam excluded)"
    );

    sqlx::query("DELETE FROM feedback WHERE message = $1")
        .bind(&tag)
        .execute(&pool)
        .await
        .expect("cleanup seeded rows");
}
