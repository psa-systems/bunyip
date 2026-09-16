//! Settings archive, against a real database (BUNYIP-714).
//!
//! Two properties the unit tests cannot reach, because both are about the
//! schema rather than the code: that a round trip actually restores what was
//! deleted and removes what was added (replace, not merge), and that every
//! column of every archived table is accounted for.
//!
//! Follows `applications_catalog.rs`: the suite needs a throwaway PostgreSQL and
//! skips with a printed notice when one is not configured, so a checkout with no
//! database still runs `cargo test` green.

use std::collections::BTreeSet;

use bunyip_api::settings_archive::{self, ExportOptions, ARCHIVED_TABLES};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

const STRONG_PASSPHRASE: &str = "correct-horse-battery-staple-vault-27";

async fn test_pool(purpose: &str) -> Option<PgPool> {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"));
    let Ok(url) = url else {
        eprintln!("BUNYIP_TEST_DATABASE_URL / RLS_TEST_DATABASE_URL unset; skipping {purpose}");
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

/// Every column of every archived table is either carried or deliberately left
/// behind, and the module says which.
///
/// This is the guard the whole exclusion-list design exists for. A migration
/// that adds a column to `applications` or `tier_config` is the ordinary way a
/// new admin-managed setting arrives, and nothing else would notice that the
/// archive stopped carrying the full row: the export still succeeds, the import
/// still succeeds, and the setting is silently lost on the one day it matters.
/// Reading `information_schema` rather than a hand-written list is what makes
/// that unmissable.
#[tokio::test]
async fn every_column_of_every_archived_table_is_carried_or_declared_excluded() {
    let Some(pool) = test_pool("the settings-archive column coverage test").await else {
        return;
    };

    let mut failures: Vec<String> = Vec::new();
    for table in ARCHIVED_TABLES {
        let rows = sqlx::query(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = $1",
        )
        .bind(table.table)
        .fetch_all(&pool)
        .await
        .expect("read information_schema.columns");

        let live: BTreeSet<String> = rows
            .iter()
            .map(|row| row.get::<String, _>("column_name"))
            .collect();
        assert!(
            !live.is_empty(),
            "{} is declared archived but does not exist in the database; \
             update ARCHIVED_TABLES in settings_archive.rs",
            table.table
        );

        let declared: BTreeSet<String> = table
            .archived
            .iter()
            .chain(table.excluded.iter())
            .map(|c| (*c).to_string())
            .collect();

        for column in live.difference(&declared) {
            failures.push(format!(
                "{}.{column} is in the database but is neither archived nor excluded",
                table.table
            ));
        }
        for column in declared.difference(&live) {
            failures.push(format!(
                "{}.{column} is declared in settings_archive.rs but no longer exists",
                table.table
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "the settings archive is out of step with the schema:\n  {}\n\nAdd each new column to \
         the table's `archived` list in settings_archive.rs, or to its `excluded` list with the \
         reason it is left behind (a surrogate key, a timestamp, an attribution column, or a \
         ciphertext whose plaintext is archived under governed_secrets).",
        failures.join("\n  ")
    );
}

/// A round trip restores what was deleted and removes what was added.
///
/// The mutations are deliberately in both directions, because a merge would pass
/// the first half on its own: an import that only inserted would restore the
/// deleted application and the deleted OAuth client and still leave the extra
/// rate-limit row and the extra application behind.
#[tokio::test]
async fn a_round_trip_restores_deletions_and_removes_additions() {
    let Some(pool) = test_pool("the settings-archive round-trip test").await else {
        return;
    };
    let Some(config) = test_config() else {
        eprintln!("the environment does not carry a usable bunyip Config; skipping");
        return;
    };
    let key_set = config.app_key_set();

    seed_fixture(&pool).await;

    let options = ExportOptions {
        include_catalog: true,
        include_oauth_clients: true,
    };
    let archived = settings_archive::export(&pool, &config, &key_set, options)
        .await
        .expect("export");
    let bytes = settings_archive::seal(&archived, STRONG_PASSPHRASE, &[])
        .await
        .expect("seal");

    // Mutate in both directions, as an operator or an accident would.
    sqlx::query("DELETE FROM applications WHERE slug = 'archive-fixture-app'")
        .execute(&pool)
        .await
        .expect("delete an application");
    sqlx::query("DELETE FROM oauth_clients WHERE name = 'archive-fixture-client'")
        .execute(&pool)
        .await
        .expect("delete an oauth client");
    sqlx::query(
        "INSERT INTO rate_limit_configs (action, max_requests, window_seconds, updated_at) \
         VALUES ('archive_fixture_extra', 7, 70, NOW()) ON CONFLICT (action) DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("add an extra rate limit row");
    sqlx::query(
        "INSERT INTO applications (id, name, slug, display_name, container_name, artifact_source) \
         VALUES (gen_random_uuid(), 'archive-fixture-extra', 'archive-fixture-extra', \
         'Extra', 'extra', 'release') ON CONFLICT (slug) DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("add an extra application");

    let reopened = settings_archive::open(&bytes, STRONG_PASSPHRASE)
        .await
        .expect("open");
    let report = settings_archive::apply(&pool, &config, &key_set, &reopened, None)
        .await
        .expect("apply");
    assert!(
        report.unapplied().is_empty(),
        "steps did not apply: {:?}",
        report.unapplied()
    );

    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM applications WHERE slug = 'archive-fixture-app'"
        )
        .await,
        1,
        "the deleted application was not restored"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM oauth_clients WHERE name = 'archive-fixture-client'"
        )
        .await,
        1,
        "the deleted oauth client was not restored"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM rate_limit_configs WHERE action = 'archive_fixture_extra'"
        )
        .await,
        0,
        "the extra rate-limit row survived a replace import"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM applications WHERE slug = 'archive-fixture-extra'"
        )
        .await,
        0,
        "the extra application survived a replace import"
    );

    // Idempotence: the second run is a no-op, which is what makes re-running a
    // partially failed import safe.
    let again = settings_archive::apply(&pool, &config, &key_set, &reopened, None)
        .await
        .expect("apply twice");
    assert!(
        again.plan.is_unchanged(),
        "a second import of the same archive still had work to do: {:?}",
        again.plan
    );
}

/// The rows the round trip deletes and restores. Created here rather than
/// assumed, so the test does not depend on what a particular database holds.
async fn seed_fixture(pool: &PgPool) {
    // The rows the test ADDS after exporting must not already be present, or
    // the archive carries them and the replace assertions pass vacuously. A
    // previous run that failed midway is exactly how that happens.
    sqlx::query("DELETE FROM rate_limit_configs WHERE action = 'archive_fixture_extra'")
        .execute(pool)
        .await
        .expect("clear a previous run's extra rate limit row");
    sqlx::query("DELETE FROM applications WHERE slug = 'archive-fixture-extra'")
        .execute(pool)
        .await
        .expect("clear a previous run's extra application");

    // A freshly-migrated `tier_config` has every tier visible with no price
    // mapped, which is exactly the state `visible_without_price_error` refuses.
    // The import validates before writing, so the fixture is a CONFIGURED
    // deployment rather than a default one.
    sqlx::query(
        "UPDATE tier_config SET free_price_id = 'price_fixture_free', \
         early_adopter_price_id = 'price_fixture_early', \
         standard_price_id = 'price_fixture_standard' WHERE id = 1",
    )
    .execute(pool)
    .await
    .expect("seed the tier prices");

    sqlx::query(
        "INSERT INTO applications (id, name, slug, display_name, container_name, artifact_source) \
         VALUES (gen_random_uuid(), 'archive-fixture-app', 'archive-fixture-app', \
         'Archive Fixture', 'archive-fixture', 'release') ON CONFLICT (slug) DO NOTHING",
    )
    .execute(pool)
    .await
    .expect("seed an application");

    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_type, name, redirect_uris, \
         post_logout_redirect_uris, allowed_scopes, allowed_grant_types, \
         token_endpoint_auth_method, audience) \
         SELECT gen_random_uuid(), gen_random_uuid(), 'confidential', \
         'archive-fixture-client', ARRAY['https://example.test/cb'], ARRAY[]::text[], \
         ARRAY['openid'], ARRAY['authorization_code'], 'client_secret_basic', 'bunyip' \
         WHERE NOT EXISTS \
         (SELECT 1 FROM oauth_clients WHERE name = 'archive-fixture-client')",
    )
    .execute(pool)
    .await
    .expect("seed an oauth client");
}

async fn count(pool: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.expect(sql)
}

/// A `Config` for the export path, which needs the encryption key set and the
/// declared secrets provider. Returns `None` when the environment does not carry
/// one, so the test skips rather than failing on a missing variable.
fn test_config() -> Option<bunyip_api::Config> {
    bunyip_api::Config::from_env().ok()
}
