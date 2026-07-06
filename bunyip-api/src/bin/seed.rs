//! `seed` - load or reset file-driven seed data (PSA-50).
//!
//! Standalone binary. Reads a canonical seed JSON file and loads it into the
//! database through the domain repositories, or resets (removes) all seed data.
//!
//! Safety: refuses to run unless BOTH hold, so it can never touch production:
//!   1. `BUNYIP_SEED_ALLOW=true`
//!   2. a non-production `ENVIRONMENT` (`Config` treats unset as production).
//!
//! Every write is additionally scoped to the reserved seed email domain, so a
//! reset can only ever remove seed rows.
//!
//! Usage:
//!   seed import <file>            load a seed file (idempotent)
//!   seed import <file> --dry-run  parse + validate only, write nothing
//!   seed reset                    remove all seed data (users + feedback)
//!   seed reset --dry-run          show what a reset would target
//!   seed --help                   show this message

use std::time::Duration;

use anyhow::{bail, Context};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use bunyip_api::config::{secret_env, Config};
use bunyip_api::seed;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut dry_run = false;
    let mut positional: Vec<String> = Vec::new();
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => positional.push(other.to_string()),
        }
    }

    let config = Config::from_env().context("failed to load configuration")?;

    // Guard BEFORE touching the DB: explicit allow flag + non-production env.
    let allow = secret_env("BUNYIP_SEED_ALLOW")
        .map(|v| v.trim() == "true")
        .unwrap_or(false);
    seed::seed_guard(&config.environment, allow).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    match positional.first().map(String::as_str) {
        Some("import") => {
            let path = positional
                .get(1)
                .context("usage: seed import <file> [--dry-run]")?;
            let json =
                std::fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
            let file = seed::parse(&json).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            if dry_run {
                println!(
                    "[dry-run] valid seed file v{}: {} groups, {} apps, {} users, {} entitlements, {} feedback",
                    file.version,
                    file.application_groups.len(),
                    file.applications.len(),
                    file.users.len(),
                    file.entitlements.len(),
                    file.feedback.len(),
                );
                return Ok(());
            }
            let pool = connect(&config).await?;
            let s = seed::load(&pool, &file)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            println!(
                "seeded: {} groups, {} apps, {} users, {} entitlements, {} feedback",
                s.groups, s.applications, s.users, s.entitlements, s.feedback
            );
        }
        Some("reset") => {
            if dry_run {
                println!(
                    "[dry-run] reset would remove all users and feedback under @{}",
                    seed::SEED_EMAIL_DOMAIN
                );
                return Ok(());
            }
            let pool = connect(&config).await?;
            let s = seed::reset(&pool)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            println!("reset: removed {} users, {} feedback", s.users, s.feedback);
        }
        _ => {
            print_help();
            bail!("unknown or missing command (expected `import <file>` or `reset`)");
        }
    }

    Ok(())
}

async fn connect(config: &Config) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .context("failed to connect to the database")
}

fn print_help() {
    println!(
        "seed - load or reset file-driven seed data (PSA-50)\n\n\
         USAGE:\n\
         \x20   seed import <file> [--dry-run]   load a seed file (idempotent)\n\
         \x20   seed reset [--dry-run]           remove all seed data\n\
         \x20   seed --help                      show this message\n\n\
         Requires BUNYIP_SEED_ALLOW=true and a non-production ENVIRONMENT."
    );
}
