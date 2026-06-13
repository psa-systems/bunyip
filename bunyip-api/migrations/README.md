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

> Operational note: before any deploy that touches the applied migration set,
> verify `_sqlx_migrations` on the target database. Editing the body of an
> already-applied migration changes its checksum; reconcile the recorded
> checksum (or confirm the environment re-migrates from scratch) before
> deploying.
