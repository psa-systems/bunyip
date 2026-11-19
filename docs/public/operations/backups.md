# Backups

Three stores to back up. Everything else bunyip holds is derived.

## PostgreSQL

The primary store. `pg_dump` the `bunyip` database on a cadence the deployment's RPO can accept. Bunyip assumes the standard Postgres backup practices apply; it ships no backup orchestration of its own.

- A logical dump (`pg_dump --format=custom`) is the shortest path to a known-good restore.
- A physical backup (base backup plus WAL archive) is the right choice for a deployment that cannot afford the dump window.
- Exclude the `temp` schemas if you create any; the application does not use them.

Verify the restore procedure at least once per quarter against a scratch host. A backup that has never been restored is a wish, not a backup.

## The `./secrets/` directory

Group-1 startup secrets live as files under `./secrets/`. Back these up outside the database:

- `APP_ENCRYPTION_KEY` (the one key for every encrypted column)
- `JWT_SECRET`
- The OIDC signing key file
- Database credentials
- Any other `{NAME}_FILE` referent

A deployment that loses `APP_ENCRYPTION_KEY` cannot decrypt any sealed column. Treat that key the way a deployment treats the database master password: encrypted at rest, off-host, with the same recovery procedure the organization applies to production key material.

For deployments using the docker repo's SOPS-encrypted `compose-secrets.yml`, the SOPS backup is the secret backup. The repository on a secure host is a sufficient store.

## The OCI registry storage

If this deployment runs the OCI registry (`/v2/*`), the registry storage directory holds every uploaded blob and manifest. It is the second-largest store after Postgres and the slowest to rebuild (an operator would have to repush every image).

Rsync the registry storage to object storage on a cadence that matches image-publish frequency. A per-day sync is common.

## Infisical (if used)

A deployment with `SECRETS_STORAGE=infisical` is relying on Infisical for Group-2 secret storage. The Infisical backup is Infisical's responsibility, not bunyip's; bunyip only reads. Make sure Infisical itself is covered by the organization's secret-management runbook.

## What you do NOT need to back up

- The `./target/` and container caches. Rebuilt on image pull.
- The `dev` compose stack's volumes. Dev data.
- The log files on the host. Ship to the organization's log platform; the file on disk is for live tailing only.

## Restore drill

Twice a year, run the drill on a scratch host:

1. Spin a new host with a blank `./secrets/` and empty database.
2. Restore `./secrets/` from the off-host backup.
3. Restore the Postgres dump into a fresh database.
4. Bring up `docker compose` with the same `.env` values (image tags pinned to the running release).
5. Confirm `GET /health` returns ok, the OIDC discovery endpoint answers, and one admin can sign in.
6. If the deployment runs the registry, confirm a `docker pull` for a published image succeeds.

A drill that fails at any step is the drill's signal that the backup set is incomplete.
