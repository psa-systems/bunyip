//! BUNYIP-79 one-time migration-checksum reconciliation.
//!
//! Commit `9c082eb` ("fix(migrations): close data-integrity gaps and gate
//! version collisions") edited 11 already-applied migration files in place
//! rather than renaming or re-versioning them. sqlx records a per-file SHA-384
//! in `_sqlx_migrations` on first apply and recomputes + compares it on every
//! subsequent start, so any database that had already applied the originals now
//! fails startup with `migration <version> was previously applied but has been
//! modified` and crash-loops until the recorded checksums are reconciled. (A
//! developer OP went dark for ~24h on exactly this.) See the issue and
//! `bunyip-api/migrations/README.md`.
//!
//! This heals ONLY the affected rows, surgically: for each known
//! `(version, pre-edit checksum)` pair, if the recorded checksum still equals
//! the BUNYIP-79 original it is rewritten to the current embedded checksum so
//! the immutability check passes. The `AND checksum = <original>` guard makes
//! the update idempotent and population-safe:
//!
//! - DBs that applied the originals (recorded == original) are healed.
//! - DBs freshly migrated after `9c082eb` (recorded == current) are left
//!   untouched (`rows_affected == 0`).
//! - Any genuinely-unexpected edit (recorded == neither) is left untouched, so
//!   the ratchet still catches real mistakes on these versions.
//!
//! IMPORTANT: this only unblocks STARTUP. It does NOT retro-apply the DDL guards
//! that `9c082eb` added to a database that already ran the original bodies; a
//! row marked applied is never re-run. Delivering those guards to already-
//! migrated data requires forward-only migrations and is tracked separately.

use sqlx::migrate::Migrator;
use sqlx::PgPool;
use tracing::{info, warn};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// `(version, BUNYIP-79 pre-edit SHA-384 hex)`. Only rows whose recorded
/// checksum still equals this original are reconciled. The replacement value is
/// taken from the embedded migrator, not hardcoded, so it stays correct if a
/// listed file is ever touched again.
const LEGACY_CHECKSUMS: &[(i64, &str)] = &[
    (20241230000014, "fad39fb3656fd2cc6f1e2fb5fcd8d4ac008d970dd16d356252a3744790fd954ed3b3146f4cdbdea4add856a724c05cd9"),
    (20241230000017, "31faddfdffa04e5a2b318078dc3760a65101ca01e059f99031ab25f62e83d269fcca12af524066e39d843a122668b5fc"),
    (20260313000021, "fe758aa402cf20c74c080d353ea17f4f8ce59efd0fb871d4007d3178e8a1b2cbe0baaa4eb383aa9766465792fe388d6a"),
    (20260319000025, "e22c60e6c8a9a572c341b933d5c14c797a5125e69cb8faee4bfdbd8d8bfb7af992266365adafa6532e63f602b4a1cfc2"),
    (20260417000040, "b1d9250685ac0713e3c611d1543b953e5e5d92684254f401dcac2b8c021fe3e01a7a87b8ed14c184ed8d11eed7c4e315"),
    (20260417000041, "eeabf66beb4eacd5facf23d8c796b49d2074073db55fc0b8734a44374f42aa3f02867435b0ec815cff7578444c3609d5"),
    (20260417000042, "d6b8b6e871c334b30199729c52ac6cb6c694f4ad1c2d80c9dbcae055229ea9b0b276361097679f94573ddcd7df4d1b7f"),
    (20260429000045, "65feb61908e7a4d0e8a128f5faed23264ad18c159ef64554bc8e5ebb1461ba57a03e86bca2a8e69d32230014e58fb1df"),
    (20260502000048, "7def758bb5f82900f679b9acd796eaaf0d8c22f5042a4322b6e57efaed0b1063434879ab08d05beb1dc73b74a881269c"),
    (20260602000050, "1b105a3b6cf5401bb7329fb7d29003b1e52c363ad008e1a21be6d2bd8cd5686df30fd6ddf4ab13ad381757b6feacbe6b"),
    (20260605000010, "14fddc4a09df80aef5d7269d72f607f4fa5d829d374b72cfe62347b66765413c593dedee3a91e33a18cfd3a51a92bb04"),
];

/// Reconcile the BUNYIP-79 in-place-edited migration checksums. Safe to run on
/// every startup: it is a no-op once healed and on freshly-migrated databases.
/// Must run BEFORE `Migrator::run`, which is where the mismatch would abort.
pub async fn reconcile_legacy_migration_checksums(pool: &PgPool) -> Result<(), sqlx::Error> {
    // A fresh database has no ledger yet (the migrator creates it). Nothing has
    // been applied, so there is nothing to reconcile and the UPDATE would fail
    // on a missing relation.
    let ledger: Option<String> = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations')::text")
        .fetch_one(pool)
        .await?;
    if ledger.is_none() {
        return Ok(());
    }

    let mut healed = 0u64;
    for (version, original_hex) in LEGACY_CHECKSUMS {
        // The current embedded checksum for this version (the post-edit hash).
        let Some(current) = MIGRATOR.iter().find(|m| m.version == *version) else {
            warn!(
                version,
                "BUNYIP-79 reconcile: version absent from embedded migrator; skipping"
            );
            continue;
        };
        let new_checksum: &[u8] = current.checksum.as_ref();

        let result = sqlx::query(
            "UPDATE _sqlx_migrations \
             SET checksum = $1 \
             WHERE version = $2 AND checksum = decode($3, 'hex')",
        )
        .bind(new_checksum)
        .bind(*version)
        .bind(*original_hex)
        .execute(pool)
        .await?;

        if result.rows_affected() > 0 {
            healed += result.rows_affected();
            info!(
                version,
                "BUNYIP-79 reconcile: rewrote stale migration checksum"
            );
        }
    }

    if healed > 0 {
        warn!(
            count = healed,
            "BUNYIP-79: reconciled {healed} legacy migration checksum(s) edited in place by 9c082eb; \
             startup can proceed. Note: this does not retro-apply those migrations' DDL guards to an \
             already-migrated database. See bunyip-api/migrations/README.md."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The allowlist must stay consistent with the embedded migrations: every
    /// listed version exists, every original hash is a well-formed SHA-384, and
    /// the listed pre-edit hash differs from the current embedded hash (i.e. the
    /// file really was edited in place). If a listed file is ever reverted or
    /// re-versioned, this fails and the stale entry must be dropped.
    #[test]
    fn legacy_allowlist_matches_embedded_migrator() {
        for (version, original_hex) in LEGACY_CHECKSUMS {
            let migration = MIGRATOR
                .iter()
                .find(|m| m.version == *version)
                .unwrap_or_else(|| panic!("version {version} not present in embedded migrator"));

            // SHA-384 is 48 bytes = 96 lowercase hex chars.
            assert_eq!(
                original_hex.len(),
                96,
                "version {version}: pre-edit hash is not 96 hex chars"
            );
            assert!(
                original_hex.bytes().all(|b| b.is_ascii_hexdigit()),
                "version {version}: pre-edit hash is not valid hex"
            );

            let current_hex: String = migration
                .checksum
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_ne!(
                &current_hex, original_hex,
                "version {version}: embedded checksum equals the listed pre-edit checksum, so the \
                 allowlist entry is stale (the file was reverted or never edited); drop it"
            );
        }
    }

    #[test]
    fn legacy_allowlist_has_no_duplicate_versions() {
        let mut seen = HashSet::new();
        for (version, _) in LEGACY_CHECKSUMS {
            assert!(
                seen.insert(*version),
                "duplicate version {version} in allowlist"
            );
        }
    }
}
