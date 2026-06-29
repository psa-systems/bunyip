//! bunyip-e2e-bootstrap - idempotent seeding of the E2E test accounts.
//!
//! Standalone binary (NOT a server subcommand) that the Playwright suite
//! (BUNYIP-52) relies on. It upserts the two accounts the suite logs in as:
//!
//!   - `e2e-user@a8n.run`  (subscriber)
//!   - `e2e-admin@a8n.run` (admin)
//!
//! Both share one Argon2-hashed password read from the environment. CI injects
//! that value from Infisical `/bunyip/e2e/test_user_password` into
//! `BUNYIP_E2E_TEST_USER_PASSWORD` (the `_FILE` secret convention is honoured
//! too), so the plaintext never lives in a fixture or in this repo.
//!
//! Safety: the tool refuses to run unless BOTH of these hold, so it can never
//! touch a production database:
//!   1. `BUNYIP_E2E_BOOTSTRAP_ALLOW=true`
//!   2. a non-production `ENVIRONMENT`. `Config` defaults `ENVIRONMENT` to
//!      `production` when it is unset, so "unset" is treated as production and
//!      blocked; `production` and `prod` are blocked explicitly.
//!
//! Usage:
//!   bunyip-e2e-bootstrap            seed / refresh the accounts (idempotent)
//!   bunyip-e2e-bootstrap --dry-run  print what would change, write nothing
//!   bunyip-e2e-bootstrap --cleanup  delete the accounts by exact email match
//!   bunyip-e2e-bootstrap --help     show this message
//!
//! `--cleanup` and `--dry-run` may be combined to preview a deletion.

use std::time::Duration;

use anyhow::{bail, Context};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use bunyip_api::config::{secret_env, Config};
use bunyip_api::models::UserRole;
use bunyip_api::repositories::UserRepository;
use bunyip_api::services::PasswordService;

/// The two accounts the suite drives. Emails are lowercase literals so the
/// exact-match `ON CONFLICT (email)` / cleanup `WHERE email = $1` line up with
/// what gets inserted.
const ACCOUNTS: [(&str, UserRole); 2] = [
    (bunyip_api::E2E_ACCOUNT_EMAILS[0], UserRole::Subscriber),
    (bunyip_api::E2E_ACCOUNT_EMAILS[1], UserRole::Admin),
];

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
        "bunyip-e2e-bootstrap - seed the BUNYIP-52 E2E test accounts\n\n\
         USAGE:\n\
         \x20   bunyip-e2e-bootstrap [--cleanup] [--dry-run] [--help]\n\n\
         FLAGS:\n\
         \x20   --cleanup   delete the test accounts by exact email match\n\
         \x20   --dry-run   print the actions without writing anything\n\
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

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .context("failed to connect to the database")?;

    // Migrations are owned by api startup; this tool only seeds rows, so it does
    // not run them (avoids racing the api's migrator in CI).

    if opts.cleanup {
        cleanup(&pool, opts.dry_run).await
    } else {
        seed(&pool, opts.dry_run).await
    }
}

/// Refuse to run against anything that could be production. Both checks live
/// here so a single missing guard cannot let the tool through.
///
/// Residual risk (accepted): the gate keys on `ENVIRONMENT`, not on
/// `DATABASE_URL`. A misconfiguration that sets a non-production `ENVIRONMENT`
/// while pointing `DATABASE_URL` at a production database would NOT be caught
/// here. Validating that would mean teaching the tool which DB hosts are
/// production, which is brittle and drifts. The blast radius is bounded: the
/// tool only ever touches the two known `e2e-*@a8n.run` rows and `--cleanup`
/// deletes only those exact emails, so a misfire cannot harm real user data.
/// If that ever stops holding, add a DATABASE_URL allow-list here.
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

/// Upsert both accounts. Idempotent: a re-run resets the password, role, and
/// verified flag and revives a previously cleaned-up row, so CI re-runs are
/// no-ops in effect.
async fn seed(pool: &PgPool, dry_run: bool) -> anyhow::Result<()> {
    let raw_password = secret_env("BUNYIP_E2E_TEST_USER_PASSWORD").context(
        "BUNYIP_E2E_TEST_USER_PASSWORD is unset (CI injects it from Infisical /bunyip/e2e/test_user_password)",
    )?;
    // Trim before hashing. The E2E suite logs in with the TRIMMED password
    // (e2e/lib/env.ts `required()` returns `value.trim()`), and bunyip's login
    // trims the email but NOT the password. If the seed value carried trailing
    // whitespace (a newline from a secret-store fetch / file / paste is common),
    // the stored hash would be for "P\n" while the suite sends "P", failing
    // login with a confusing "email or password incorrect". Trimming both sides
    // removes the mismatch; passwords carry no meaningful surrounding whitespace.
    let password = raw_password.trim();
    if password.is_empty() {
        bail!("BUNYIP_E2E_TEST_USER_PASSWORD is empty");
    }

    // Hash once: both accounts share the password, so one PHC string suffices.
    let password_hash = PasswordService::new()
        .hash(password)
        .context("failed to hash the test password")?;

    for (email, role) in ACCOUNTS {
        if dry_run {
            let exists = email_exists(pool, email).await?;
            let verb = if exists { "update" } else { "create" };
            println!("[dry-run] would {verb} {email} (role={})", role.as_str());
            continue;
        }

        sqlx::query(
            r#"
            INSERT INTO users (email, password_hash, role, email_verified)
            VALUES ($1, $2, $3, TRUE)
            -- email uniqueness is a PARTIAL index (users_email_unique_active,
            -- migration 20260324000029): UNIQUE (email) WHERE deleted_at IS NULL.
            -- The conflict target must carry the same predicate, or Postgres
            -- rejects it with "no unique or exclusion constraint matching".
            ON CONFLICT (email) WHERE deleted_at IS NULL DO UPDATE SET
                password_hash = EXCLUDED.password_hash,
                role          = EXCLUDED.role,
                email_verified = TRUE,
                deleted_at    = NULL,
                updated_at    = NOW()
            "#,
        )
        .bind(email)
        .bind(&password_hash)
        .bind(role.as_str())
        .execute(pool)
        .await
        .with_context(|| format!("failed to upsert {email}"))?;

        println!("seeded {email} (role={})", role.as_str());
    }

    Ok(())
}

/// Hard-delete both accounts by exact email match.
async fn cleanup(pool: &PgPool, dry_run: bool) -> anyhow::Result<()> {
    for (email, _role) in ACCOUNTS {
        if dry_run {
            let exists = email_exists(pool, email).await?;
            if exists {
                println!("[dry-run] would delete {email}");
            } else {
                println!("[dry-run] {email} absent, nothing to delete");
            }
            continue;
        }

        // Shared hard-delete path (BUNYIP-246): also clears the non-cascade
        // audit_logs rows that would otherwise block `DELETE FROM users`.
        let removed = UserRepository::hard_delete_by_email(pool, email)
            .await
            .map_err(|e| anyhow::anyhow!("failed to delete {email}: {e}"))?;

        if removed > 0 {
            println!("deleted {email}");
        } else {
            println!("{email} absent, nothing to delete");
        }
    }

    Ok(())
}

/// Exact-email existence check used by the dry-run paths.
async fn email_exists(pool: &PgPool, email: &str) -> anyhow::Result<bool> {
    let found: Option<(uuid::Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await
        .with_context(|| format!("failed to look up {email}"))?;
    Ok(found.is_some())
}
