# Upgrades

A release is a new image tag for `bunyip-api` and `bunyip-web`. An upgrade is a pull and restart. This page covers the operator contract and what a safe rollforward looks like.

## Release artefacts

Each release publishes two images under `dev.a8n.run/psa-systems-private`:

- `bunyip-api:vX.Y.Z` is the api binary plus the embedded migrations for that version.
- `bunyip-web:vX.Y.Z` is the front-end.

Pin both to the same tag in `.env`. `BUNYIP_API_IMAGE` and `BUNYIP_WEB_IMAGE` are required; Compose refuses to start without them.

## The upgrade procedure

1. Read the release notes. A release that changes behaviour visible to operators (new required variable, deprecated env, new admin page) says so.
2. Pull both images to the host so the restart is quick:

   ```
   docker compose pull api web
   ```

3. Flip `BUNYIP_API_IMAGE` and `BUNYIP_WEB_IMAGE` in `.env` to the new tag.
4. Restart the two services:

   ```
   docker compose up --detach api web
   ```

5. Watch the api log for the migration section. New migrations run on this first start, in order; the log names each file.
6. Confirm `GET /health` returns ok and `GET /.well-known/openid-configuration` answers.

That is the whole procedure. A deployment that does nothing else survives.

## Migration immutability

A committed migration is immutable. A release never rewrites a migration that already shipped. The three outcomes on boot are:

- **Up to date.** No migrations run; the api begins serving.
- **Behind.** New migrations apply in order, then the api serves. Log lines name each file.
- **Ahead.** The image is older than the database. The api refuses to serve. Rolling the image forward is the resolution; do not roll the database back.

This is the guarantee that lets rollforwards be safe without coordinated rollbacks. An ops team that trusts it can pull a release before reading a change log.

A migration that is additive and backwards-compatible (new column with a safe default, new table, new index) rolls forward with no visible impact. A migration that is not backwards-compatible (column type change, dropped column) is announced in release notes; the operator has a procedure to follow, and the api tolerates both shapes during the window.

## Rollback

Short answer: roll forward. A deployment that hit an issue on the new release should stop writing from the admin UI, pin to the fix release when it lands, and run the same procedure above. A rollback to a prior image tag is refused by boot if the new image already migrated the database; the "ahead" case applies.

The one rollback the api supports is operational, not image-level: the admin can disable the one feature behind a feature flag if a release degrades it. The feature stays off until the flag flips back.

## Pre-production bake

For a production deployment, bake every release in staging first. Staging runs the same image and the same migration set; a bake that passes there proves the migrations apply cleanly.

A deployment that has no staging environment can at least restore the previous day's Postgres dump into a scratch host, run the upgrade there, and verify the drill in [Backups](backups.md) still passes. Catching a migration failure on a scratch host is far cheaper than catching it on production.

## Changelog

The repository's release notes are the canonical change log. Each release ends with:

- New required / renamed environment variables.
- New admin pages.
- New API routes.
- Deprecations with the removal window.
- Migration notes that need an operator step.

A release that does not touch operator-visible behaviour says so.
