# Migrations

These migrations are applied on `bunyip-api` startup via
`sqlx::migrate!("./migrations")` (see `bunyip-api/src/main.rs`).

## Versioning and ordering

sqlx identifies and orders each migration by the **numeric version** that
precedes the first underscore in the filename - the full
`YYYYMMDDHHMMSS` timestamp, not the trailing 3-digit "index" humans tend to
read. As long as those 14-digit versions are unique and increasing, sqlx is
correct.

Parallel feature branches historically reused the trailing index across
different dates (010/020/040/041/042 each appear on several files). That is
harmless to sqlx - the full timestamps differ - but it misleads anyone reading
migration order at a glance.

To stop a genuine collision (two files sqlx would treat as the **same**
migration) from ever merging, CI runs `scripts/check-migration-versions.sh`,
which fails if any two migrations share a version or are out of order. The
trailing index is left as-is; renumbering already-applied files would diverge
`_sqlx_migrations` on live databases, so we gate future additions instead of
rewriting history.

When adding a migration, use a fresh `YYYYMMDDHHMMSS` stamp greater than every
existing one. Run `just check-migrations` (or the script directly) to verify.

## Known sequence gap: position 8

There is an intentional gap at `20241230000008`. The original
`20241230000008_seed_applications.sql` seed file was deleted; its slugs
(`rus`, `rustylinks`) no longer exist, and the dead subdomain backfills that
referenced them were removed from
`20241230000017_add_application_subdomain.sql`.

sqlx does not require contiguous version numbers, so the gap is functionally
inert and is left in place rather than renumbering applied history.

> Operational note: editing the body of an already-applied migration changes
> its sqlx SHA-384 checksum, so a database that applied the original body fails
> startup with `migration <version> was previously applied but has been
> modified` until the recorded checksum is reconciled. Prefer a forward-only
> migration over an in-place edit for exactly this reason.

## BUNYIP-79 in-place edits: automated checksum reconciliation

Commit `9c082eb` edited 11 already-applied migrations in place (closing
data-integrity gaps). To keep databases that applied the original bodies from
crash-looping, `bunyip-api/src/migrate_reconcile.rs` runs once at startup
**before** the migrator: for each of those 11 versions, if the recorded
checksum still equals the pre-edit value it is rewritten to the current embedded
checksum. The update is guarded by `AND checksum = <pre-edit hash>`, so it heals
only databases stuck on the old hash and is a no-op on freshly-migrated ones and
on any unexpected drift (the immutability check still catches genuine mistakes
on every other migration). A unit test (`legacy_allowlist_matches_embedded_migrator`)
keeps the allowlist honest against the embedded migration set.

Caveat: reconciliation only unblocks startup. A row marked applied is never
re-run, so the DDL guards `9c082eb` added are **not** retro-applied to a database
that already ran the original bodies. Delivering those guards to already-migrated
data requires new forward-only migrations and is tracked separately. This is why
new behavioral changes must ship as fresh migrations, not in-place edits.

## BUNYIP-457: source-check backfill (when forward-only is blocked)

The caveat above bit `20260605000010`: its `CHECK (source IN ('admin', 'stripe',
'backfill'))` on `application_entitlements.source` was added by the `9c082eb`
in-place edit, so a database that applied the pre-edit body never got the
constraint. `20260802000010` then widens that constraint to allow `'seed'` with a
bare `ALTER TABLE ... DROP CONSTRAINT application_entitlements_source_check`, which
raises `constraint ... does not exist` and aborts startup on those databases.

The usual fix (a new forward-only migration) is impossible here: `20260802000010`
is itself the failing migration, so the chain never reaches a later one on the
affected database. Instead `migrate_reconcile::backfill_entitlement_source_check`
runs at startup, **after** the checksum reconcile and **before** the migrator, and
adds the missing constraint so the migrator's `DROP` + `ADD` then succeeds and
widens it to include `'seed'`. It is tightly scoped and idempotent: it acts only
when `20260802000010` is not yet applied, the table exists, and the constraint is
absent, so it is a no-op on already-migrated databases (802 applied), on fresh
databases (table created in order by the migrator), and on every boot after it has
run once, and it can never fight a future migration that deliberately alters the
constraint. `20260802000010` itself is left unedited (immutable), so databases
that already applied it need no checksum reconciliation.

This is a deliberate exception to "deliver un-retro-applied guards via forward
migrations": use it only when the migration that depends on the guard is the one
that fails, leaving no earlier forward slot.
