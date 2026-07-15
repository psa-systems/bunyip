//! BUNYIP-374 (PMS-667): the applications catalog ends up with canonical
//! "Mokosh" display names, and vervain-agent is inactive by default, after all
//! migrations run.
//!
//! Env-gated like `rls_isolation.rs`: it needs a throwaway Postgres to migrate.
//! Set `BUNYIP_TEST_DATABASE_URL` (or reuse `RLS_TEST_DATABASE_URL`) to a
//! database this test may migrate; unset skips the test.

use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

#[tokio::test]
async fn applications_catalog_uses_canonical_names_and_disables_vervain() {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"));
    let Ok(url) = url else {
        eprintln!(
            "BUNYIP_TEST_DATABASE_URL / RLS_TEST_DATABASE_URL unset; skipping applications catalog test"
        );
        return;
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

    // After the distribution-catalog seed (20260602000050) and the BUNYIP-374
    // correction migration, the mokosh apps carry canonical "Mokosh" display
    // names and vervain-agent is inactive by default.
    let rows = sqlx::query(
        "SELECT slug, display_name, is_active FROM applications \
         WHERE slug IN ('mokosh-server','mokosh-api','mokosh-www','vervain-agent')",
    )
    .fetch_all(&pool)
    .await
    .expect("query applications catalog");

    let mut names = std::collections::HashMap::new();
    let mut active = std::collections::HashMap::new();
    for r in &rows {
        let slug: String = r.get("slug");
        names.insert(slug.clone(), r.get::<String, _>("display_name"));
        active.insert(slug, r.get::<bool, _>("is_active"));
    }

    assert_eq!(
        names.get("mokosh-server").map(String::as_str),
        Some("Mokosh Server")
    );
    assert_eq!(
        names.get("mokosh-api").map(String::as_str),
        Some("Mokosh API")
    );
    assert_eq!(
        names.get("mokosh-www").map(String::as_str),
        Some("Mokosh Web")
    );

    // No stale "Mokash" spelling survives anywhere in the catalog.
    for name in names.values() {
        assert!(
            !name.to_lowercase().contains("mokash"),
            "stale display name found: {name}"
        );
    }

    // vervain-agent ships disabled by default; a deployment enables it in the
    // admin UI when it is ready.
    assert_eq!(
        active.get("vervain-agent"),
        Some(&false),
        "vervain-agent should be inactive by default"
    );
}
