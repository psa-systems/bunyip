//! bunyip-e2e-bootstrap - seed the E2E accounts by loading the committed
//! `seed/e2e.json` template through the file-driven seed loader (PSA-56;
//! formerly a hardcoded upsert in this bin).
//!
//! Standalone binary the Playwright suite (BUNYIP-52) relies on. It seeds the
//! two accounts the suite logs in as:
//!   - `e2e-user@a8n.run`  (subscriber)
//!   - `e2e-admin@a8n.run` (admin)
//!
//! The accounts, their roles, and the password source now live in the committed
//! `seed/e2e.json`, not in this bin. Both share one Argon2 password the loader
//! reads from `BUNYIP_E2E_TEST_USER_PASSWORD` (via the template's `password_env`;
//! the `_FILE` secret convention is honoured), so the plaintext never lives in a
//! fixture or the repo. CI injects it from Infisical `/bunyip/e2e/test_user_password`.
//!
//! Safety: refuses to run unless BOTH of these hold, so it can never touch a
//! production database:
//!   1. `BUNYIP_E2E_BOOTSTRAP_ALLOW=true`
//!   2. a non-production `ENVIRONMENT`. `Config` defaults it to `production` when
//!      unset, so "unset" is treated as production and blocked.
//!
//! The template scopes its `owns` to the two exact emails, so `--cleanup` (a
//! seed reset) can only ever delete those two accounts.
//!
//! Usage:
//!   bunyip-e2e-bootstrap            seed / refresh the accounts (idempotent)
//!   bunyip-e2e-bootstrap --dry-run  validate the template, write nothing
//!   bunyip-e2e-bootstrap --cleanup  delete the accounts (their `owns` scope)
//!   bunyip-e2e-bootstrap --help     show this message

use std::time::Duration;

use anyhow::{bail, Context};
use sqlx::postgres::PgPoolOptions;

use bunyip_api::config::{secret_env, Config};
use bunyip_api::seed;

/// The committed E2E seed template: the two accounts, owning their exact emails,
/// sourcing the shared password from `BUNYIP_E2E_TEST_USER_PASSWORD`.
const E2E_TEMPLATE: &str = include_str!("../../seed/e2e.json");

struct Options {
    cleanup: bool,
    dry_run: bool,
}

fn parse_args() -> anyhow::Result<Options> {
    let mut opts = Options {
        cleanup: false,
        dry_run: false,
    };
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--cleanup" => opts.cleanup = true,
            "--dry-run" => opts.dry_run = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other} (try --help)"),
        }
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "bunyip-e2e-bootstrap - seed the BUNYIP-52 E2E test accounts from seed/e2e.json\n\n\
         USAGE:\n\
         \x20   bunyip-e2e-bootstrap [--cleanup] [--dry-run] [--help]\n\n\
         FLAGS:\n\
         \x20   --cleanup   delete the test accounts (the template's owns scope)\n\
         \x20   --dry-run   validate the template and print the action, write nothing\n\
         \x20   --help      show this message\n\n\
         Requires BUNYIP_E2E_BOOTSTRAP_ALLOW=true and a non-production ENVIRONMENT.\n\
         The shared password is read from BUNYIP_E2E_TEST_USER_PASSWORD."
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = parse_args()?;

    // Config::from_env() loads .env, requires DATABASE_URL, and resolves
    // ENVIRONMENT (defaulting to "production" when unset).
    let config = Config::from_env().context("failed to load configuration")?;

    enforce_guards(&config)?;

    // Parse + validate the committed template up front (this is also the whole
    // of the dry-run's work).
    let file = seed::parse(E2E_TEMPLATE)
        .map_err(|e| anyhow::anyhow!("e2e.json template is invalid: {e}"))?;

    if opts.dry_run {
        let owns = file.effective_owns();
        if opts.cleanup {
            println!("[dry-run] would delete the E2E accounts {:?}", owns.emails);
        } else {
            println!(
                "[dry-run] would seed {} E2E accounts from the template",
                file.users.len()
            );
        }
        return Ok(());
    }

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .context("failed to connect to the database")?;

    // Migrations are owned by api startup; this tool only seeds rows, so it does
    // not run them (avoids racing the api's migrator in CI).

    if opts.cleanup {
        let s = seed::reset(&pool, &file.effective_owns())
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        println!(
            "cleaned up: removed {} accounts, {} feedback",
            s.users, s.feedback
        );
    } else {
        let s = seed::load(&pool, &file)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        println!("seeded {} E2E accounts", s.users);
    }

    Ok(())
}

/// Refuse to run against anything that could be production. Both checks live
/// here so a single missing guard cannot let the tool through.
///
/// Residual risk (accepted): the gate keys on `ENVIRONMENT`, not on
/// `DATABASE_URL`. A misconfiguration that sets a non-production `ENVIRONMENT`
/// while pointing `DATABASE_URL` at a production database would NOT be caught
/// here. Validating that would mean teaching the tool which DB hosts are
/// production, which is brittle and drifts. The blast radius is bounded: the
/// template owns only the two `e2e-*@a8n.run` emails and `--cleanup` deletes
/// exactly those (the reset guardrail forbids a whole-domain delete of a
/// non-reserved domain), so a misfire cannot harm real user data.
fn enforce_guards(config: &Config) -> anyhow::Result<()> {
    let allowed = secret_env("BUNYIP_E2E_BOOTSTRAP_ALLOW")
        .map(|v| v.trim() == "true")
        .unwrap_or(false);
    if !allowed {
        bail!("refusing to run: set BUNYIP_E2E_BOOTSTRAP_ALLOW=true to confirm this is a test environment");
    }

    let env_name = config.environment.trim();
    let prod_like = env_name.is_empty()
        || env_name.eq_ignore_ascii_case("production")
        || env_name.eq_ignore_ascii_case("prod");
    if prod_like {
        bail!(
            "refusing to run: ENVIRONMENT is '{}' (production-like or unset); E2E bootstrap is non-production only",
            config.environment
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::E2E_TEMPLATE;

    #[test]
    fn e2e_template_is_valid_and_email_scoped() {
        let f = bunyip_api::seed::parse(E2E_TEMPLATE).expect("e2e.json must be a valid seed file");
        assert_eq!(f.users.len(), 2);
        assert!(
            f.users
                .iter()
                .all(|u| u.password_env.as_deref() == Some("BUNYIP_E2E_TEST_USER_PASSWORD")),
            "both accounts source the password from the env var, not a committed literal"
        );
        let owns = f.effective_owns();
        // Scoped by the two exact emails, never a whole domain, so a reset can
        // only ever reclaim these two accounts (the guardrail forbids a
        // whole-domain reset of a real domain like a8n.run).
        assert!(owns.domains.is_empty());
        assert_eq!(owns.emails.len(), 2);
        assert!(owns.covers("e2e-user@a8n.run"));
        assert!(owns.covers("e2e-admin@a8n.run"));
    }
}
