//! BUNYIP-344 cross-user row level security regression.
//!
//! Proves the `user_isolation` policy (migration
//! `20260713000010_rls_self_service_tables.sql`) fail-closes: with the
//! `app.current_user_id` GUC set to user A, a NOBYPASSRLS role cannot read or
//! write user B's rows on an isolated table (`trusted_devices`), even with a
//! crafted query that omits the `WHERE user_id = ...` filter. Mirrors
//! `mokosh-server/tests/rls_isolation.rs`.
//!
//! Env-gated. bunyip CI has no Postgres service (`just check-container` runs the
//! workspace lib tests only), so with `RLS_TEST_DATABASE_URL` unset this test
//! skips and stays green. The URL must point at a Postgres SUPERUSER (it creates
//! a role and `SET ROLE`s to it) on a throwaway database the test may migrate:
//!
//! ```sh
//! RLS_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_rls_test \
//!   cargo test -p bunyip-api --test rls_isolation -- --nocapture
//! ```

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

const TEST_ROLE: &str = "bunyip_rls_test_role";

/// Insert a user (only `email` is NOT NULL without a default) and one
/// trusted-device row owned by them. Runs as the superuser owner, so RLS is
/// bypassed for setup.
async fn seed_user_with_rows(pool: &PgPool, app_id: Uuid) -> Uuid {
    let user_id = Uuid::new_v4();
    let email = format!("rls-{}@example.test", user_id.simple());
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(user_id)
        .bind(&email)
        .execute(pool)
        .await
        .expect("seed user");
    sqlx::query(
        "INSERT INTO trusted_devices (user_id, token_hash, expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '1 day')",
    )
    .bind(user_id)
    .bind(format!("hash-{}", user_id.simple()))
    .execute(pool)
    .await
    .expect("seed trusted_device");
    sqlx::query(
        "INSERT INTO application_entitlements (user_id, application_id, source)
         VALUES ($1, $2, 'admin')",
    )
    .bind(user_id)
    .bind(app_id)
    .execute(pool)
    .await
    .expect("seed entitlement");
    user_id
}

#[tokio::test]
async fn user_isolation_policy_blocks_cross_user_access() {
    let Ok(admin_url) = std::env::var("RLS_TEST_DATABASE_URL") else {
        eprintln!("RLS_TEST_DATABASE_URL unset; skipping RLS isolation test");
        return;
    };

    let owner = PgPoolOptions::new()
        .max_connections(2)
        .connect(&admin_url)
        .await
        .expect("connect as owner/superuser");

    sqlx::migrate!("./migrations")
        .run(&owner)
        .await
        .expect("run migrations");

    // Provision (idempotently) an unprivileged NOBYPASSRLS role that can touch
    // the isolated tables. DROP OWNED + DROP ROLE first so re-runs are clean.
    sqlx::query(&format!(
        r#"DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                DROP OWNED BY {role};
                DROP ROLE {role};
            END IF;
            CREATE ROLE {role} NOLOGIN NOBYPASSRLS;
            GRANT USAGE ON SCHEMA public TO {role};
            GRANT SELECT, INSERT, UPDATE, DELETE
                ON trusted_devices, user_totp, recovery_codes,
                   application_entitlements, email_change_requests
                TO {role};
        END $$;"#,
        role = TEST_ROLE
    ))
    .execute(&owner)
    .await
    .expect("provision NOBYPASSRLS test role");

    // A real application to hang an entitlement off (FK). Seed migrations create
    // hosted apps, so one always exists.
    let app_id: Uuid = sqlx::query_scalar("SELECT id FROM applications LIMIT 1")
        .fetch_one(&owner)
        .await
        .expect("an application exists to seed an entitlement");

    let user_a = seed_user_with_rows(&owner, app_id).await;
    let user_b = seed_user_with_rows(&owner, app_id).await;

    // One transaction acting as the NOBYPASSRLS role with the per-user GUC set to
    // user A. `SET LOCAL` keeps both scoped to this transaction.
    let mut tx = owner.begin().await.expect("begin tx");
    sqlx::query(&format!("SET LOCAL ROLE {TEST_ROLE}"))
        .execute(&mut *tx)
        .await
        .expect("set local role");
    sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
        .bind(user_a.to_string())
        .execute(&mut *tx)
        .await
        .expect("set user GUC");

    // Crafted read: NO `WHERE user_id` filter. The policy must still scope the
    // result to user A's single row.
    let visible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_devices")
        .fetch_one(&mut *tx)
        .await
        .expect("crafted count");
    assert_eq!(
        visible, 1,
        "user A must see exactly their own row, not user B's"
    );

    // The one visible row must belong to A, and B's must be invisible.
    let owner_ids: Vec<Uuid> = sqlx::query("SELECT user_id FROM trusted_devices")
        .fetch_all(&mut *tx)
        .await
        .expect("crafted select")
        .into_iter()
        .map(|r| r.get::<Uuid, _>("user_id"))
        .collect();
    assert_eq!(owner_ids, vec![user_a], "only user A's row is visible");
    assert!(
        !owner_ids.contains(&user_b),
        "user B's row must be invisible to user A"
    );

    // A second isolated table, reached the same way the rerouted download gate
    // reads it: a crafted no-WHERE select on application_entitlements must still
    // scope to user A's single row. Read BEFORE the write-guard below, whose
    // rejected INSERT aborts the transaction.
    let ent_owners: Vec<Uuid> = sqlx::query("SELECT user_id FROM application_entitlements")
        .fetch_all(&mut *tx)
        .await
        .expect("crafted entitlement select")
        .into_iter()
        .map(|r| r.get::<Uuid, _>("user_id"))
        .collect();
    assert_eq!(
        ent_owners,
        vec![user_a],
        "user A must see only their own entitlement, not user B's"
    );

    // Write guard: inserting a row for user B is rejected by WITH CHECK. This
    // aborts the transaction, so it must come last.
    let cross_insert = sqlx::query(
        "INSERT INTO trusted_devices (user_id, token_hash, expires_at)
         VALUES ($1, 'evil', NOW() + INTERVAL '1 day')",
    )
    .bind(user_b)
    .execute(&mut *tx)
    .await;
    assert!(
        cross_insert.is_err(),
        "inserting a row for another user must violate the WITH CHECK policy"
    );

    tx.rollback().await.expect("rollback");

    // Control: with the GUC set to B, only B's row is visible - proving the
    // policy discriminates rather than simply hiding everything.
    let mut tx_b = owner.begin().await.expect("begin tx b");
    sqlx::query(&format!("SET LOCAL ROLE {TEST_ROLE}"))
        .execute(&mut *tx_b)
        .await
        .expect("set local role b");
    sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
        .bind(user_b.to_string())
        .execute(&mut *tx_b)
        .await
        .expect("set user GUC b");
    let b_ids: Vec<Uuid> = sqlx::query("SELECT user_id FROM trusted_devices")
        .fetch_all(&mut *tx_b)
        .await
        .expect("crafted select b")
        .into_iter()
        .map(|r| r.get::<Uuid, _>("user_id"))
        .collect();
    assert_eq!(b_ids, vec![user_b], "user B sees only their own row");
    tx_b.rollback().await.expect("rollback b");

    // Cleanup seeded rows (role is left for re-use; DROP OWNED at the top of the
    // next run reclaims it).
    for uid in [user_a, user_b] {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(uid)
            .execute(&owner)
            .await
            .expect("cleanup user");
    }
}
