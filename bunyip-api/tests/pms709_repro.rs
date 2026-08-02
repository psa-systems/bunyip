//! PMS-709 regression: the `demo-msp` seed template loads its whole documented
//! dataset, including entitlements.
//!
//! The loader grants demo entitlements with `source = 'seed'`. Before PMS-709
//! the `application_entitlements_source_check` constraint only permitted
//! 'admin' | 'stripe' | 'backfill', so every template load failed at the
//! entitlements step (SQLSTATE 23514) after already writing groups, apps and
//! users - a partial seed reported to the admin only as the generic
//! "A database error occurred". Migration 20260802000010 widened the constraint
//! to include 'seed'; this test proves the full dataset now loads.
//!
//! Env-gated like the other DB tests (`rls_isolation.rs`, `applications_catalog.rs`):
//! bunyip CI has no Postgres, so it skips unless `BUNYIP_TEST_DATABASE_URL`
//! (or `RLS_TEST_DATABASE_URL`) points at a throwaway database it may migrate:
//!
//! ```sh
//! BUNYIP_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_seed_test \
//!   cargo test -p bunyip-api --test pms709_repro -- --nocapture
//! ```

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

#[tokio::test]
async fn demo_msp_template_loads_full_dataset_including_entitlements() {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"));
    let Ok(url) = url else {
        eprintln!(
            "BUNYIP_TEST_DATABASE_URL / RLS_TEST_DATABASE_URL unset; skipping demo-msp seed test"
        );
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect to test database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");

    // Same entry path the admin "Load demo-msp" button drives on staging.
    bunyip_api::seed::seed_guard("staging", true).expect("seed allowed on staging");
    let tmpl = bunyip_api::seed::find_template("demo-msp").expect("demo-msp template exists");
    let file = bunyip_api::seed::parse(tmpl.json).expect("template parses");

    let summary = bunyip_api::seed::load(&pool, &file)
        .await
        .expect("demo-msp loads (regression: source='seed' check-constraint violation)");

    // The documented dataset: 42 users, 8 apps, 3 groups, 6 entitlements, 7 feedback.
    assert_eq!(summary.users, 42, "42 users");
    assert_eq!(summary.applications, 8, "8 apps");
    assert_eq!(summary.groups, 3, "3 groups");
    assert_eq!(summary.entitlements, 6, "6 entitlements");
    assert_eq!(summary.feedback, 7, "7 feedback");

    // The entitlements actually landed with the seed provenance (the row the
    // widened constraint now permits).
    let seed_entitlements: i64 =
        sqlx::query("SELECT COUNT(*) c FROM application_entitlements WHERE source = 'seed'")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("c");
    assert_eq!(
        seed_entitlements, 6,
        "6 seed-sourced entitlements in the DB"
    );

    // Re-running is idempotent (the button can be clicked twice).
    let again = bunyip_api::seed::load(&pool, &file)
        .await
        .expect("second load is idempotent");
    assert_eq!(again.users, 42);
    assert_eq!(again.entitlements, 6);
}
