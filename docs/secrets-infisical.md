# Application secrets

bunyip's secrets split by whether the app needs them to boot. **Group-1** startup secrets are file/SOPS-based and
provided directly. **Group-2** integration secrets come from the ONE provider the deployment declares in `SECRETS_STORAGE`
(BUNYIP-542): `environment`, `database` or `infisical`. `CLAUDE.md`'s "Secret sourcing (two tiers)" bullet is the
one-paragraph summary; the enforcement table and the per-mode write behaviour are in
[`configuration.md`](configuration.md#secrets_storage-where-the-integration-secrets-live-bunyip-542).

## Group-1: startup secrets (files / SOPS, not Infisical)

Group-1 secrets are file-based: `compose.yml` mounts each one from
`./secrets/<name>` at `/run/secrets/<name>`, and the api reads it through the
`{NAME}_FILE` convention so no value ever enters the process environment (BUNYIP-38). They are provided directly, not
fetched from any secrets manager:

- **Dev**: `scripts/init-secrets.nu` (`just init-secrets`) generates local throwaway values.
- **Deployments**: the SOPS-encrypted `compose-secrets.yml` (docker repo, per host) supplies them.

Group-1 secrets are **never** fetched from or synced with Infisical, so a bunyip-api restart never depends on Infisical
being reachable and no Rust code reads a Group-1 secret from Infisical.

The Group-1 secrets (the `{NAME}` half of each `{NAME}_FILE` entry in
`compose.yml`):

| Secret                          | Secret file              | Empty allowed | Meaning when empty                         |
|---------------------------------|--------------------------|---------------|--------------------------------------------|
| `POSTGRES_PASSWORD`             | `postgres_password`      | no            | postgres refuses to initialize             |
| `DATABASE_URL`                  | `database_url`           | no            | the api cannot connect                     |
| `JWT_SECRET`                    | `jwt_secret`             | no            | no session signing key                     |
| `BUNYIP_WEBHOOK_SIGNING_SECRET` | `webhook_signing_secret` | no            | no webhook dispatch signature (BUNYIP-332) |
| `APP_ENCRYPTION_KEY`            | `app_encryption_key`     | no            | no at-rest key (see the rotation note)     |
| `BUNYIP_APP_PASSWORD`           | `bunyip_app_password`    | yes           | per-user RLS inactive (BUNYIP-360)         |
| `APP_DATABASE_URL`              | `app_database_url`       | yes           | per-user RLS inactive (BUNYIP-360)         |
| `SETUP_DEFAULT_ADMIN`           | `setup_default_admin`    | yes           | no bootstrap admin is seeded               |
| `FORGEJO_API_TOKEN`             | `forgejo_api_token`      | yes           | Forgejo integration off                    |
| `BUNYIP_UPDATE_CHECK_TOKEN`     | `update_check_token`     | yes           | update check runs unauthenticated          |

The four `Empty allowed: no` rows other than `POSTGRES_PASSWORD` are the api's required set: with
`ENVIRONMENT=production` it logs one `ERROR` per missing one and exits non-zero rather than starting degraded
(BUNYIP-537). The full classification of every variable, required or not, is in
[`configuration.md`](configuration.md).

Deployments created before BUNYIP-537 have no `webhook_signing_secret` file. Create it (`just init-secrets` on a
self-host, or add the value to the SOPS
`compose-secrets.yml` on the docker hosts) BEFORE the next `docker compose up`, or compose aborts on the missing secret
file. The receiving app holds the same value: mokosh-server reads it as `BUNYIP_WEBHOOK_SECRET`.

`SMTP_PASSWORD` is deliberately absent from the table above: it is a Group-2 governed secret, so it comes from whichever
provider `SECRETS_STORAGE` declares. A deployment running `SECRETS_STORAGE=environment` adds `smtp_password`,
`stripe_secret_key` and `stripe_webhook_secret` as ordinary compose secrets and passes them as `{NAME}_FILE`; nothing
else changes about how they are provided.
`./secrets/oidc/*.pem` is out of scope: the OIDC signing keys are generated out of band.

### Rotating a Group-1 secret

Change the value in the secret file (the SOPS `compose-secrets.yml` on the host, or `./secrets/<file>` for a
self-host), then `docker compose up --detach` (or restart the affected service) so the process re-reads
`/run/secrets/*`. Two need more than that:

- **`POSTGRES_PASSWORD`** must be changed on the postgres role as well, and re-embedded in `DATABASE_URL` (plus
  `APP_DATABASE_URL` when RLS is on), in one edit so the set stays consistent.
- **`APP_ENCRYPTION_KEY`** is not complete after the file change. Set
  `APP_ENCRYPTION_KEY_PREV` (a `.env` variable in `compose.yml`, not a secret file)
  to the outgoing key, restart, run `docker compose run --rm api reencrypt-secrets`, then clear
  `APP_ENCRYPTION_KEY_PREV` and restart. The full procedure, including
  `APP_KEY_VERSION` and the admin key-health endpoints, is in
  [`encryption-key-rotation.md`](encryption-key-rotation.md).

## Group-2: the governed integration secrets

Four secrets are **governed** by `SECRETS_STORAGE`, because each has more than one possible provider: `SMTP_PASSWORD`,
`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`
and `SUPPORT_IMAP_PASSWORD`. The declared provider is the only one bunyip reads. There is no precedence chain and no
fallback.

**A note on the name.** The suite calls a selectable implementation a **provider**, and bunyip's code says
`SecretsProvider` (BUNYIP-642). The variable is still spelled `SECRETS_STORAGE` and the subcommands are still
`secrets-status` / `secrets-migrate` / `secrets-purge`, deliberately: renaming either would break every running
deployment and every runbook for a vocabulary change with no functional gain. Read "the declared provider" and
"`SECRETS_STORAGE`" as the same thing throughout.

bunyip-api reads the Infisical provider itself, in Rust (`crates/bunyip-domain/src/services/infisical.rs`, BUNYIP-525),
using a Universal Auth machine identity against the `/runtime` folder. There is no CLI and no sidecar.

Whether Infisical is a boot dependency is now **mode-scoped**:

- `SECRETS_STORAGE=database` / `environment`: Infisical is **not contacted at boot at all**, so it can never delay or
  block a restart.
- `SECRETS_STORAGE=infisical`: the read is **fail-closed**. An unreachable Infisical, bad credentials or a failed read
  logs one `ERROR` and exits 1. An operator who declared Infisical the provider of record is better served by a refusal
  than by a silent boot with email and payments disabled.

### Infisical folder layout

Only Group-2 (and the separate E2E credential) live in Infisical. Paths are **project-relative**: the machine identity
is scoped to the bunyip project, so no
`/bunyip` prefix is needed.

```
bunyip (project)
├── staging
│   ├── /runtime      <- the governed secrets (SMTP_PASSWORD, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, SUPPORT_IMAP_PASSWORD)
│   └── /bunyip/e2e   <- the E2E account password (docs/e2e.md)
└── prod
    └── /runtime
```

### Configuration

bunyip keeps its Infisical config together in the docker repo: only
`INFISICAL_ENABLED` is a plain env in `server/<host>/bunyip-api/compose-variables.yml`; every other key (address,
environment, project id, secret path, and the two credentials) lives in the SOPS `compose-secrets.yml`.

| Env var                   | Secret? | How read     | Default | Meaning                                                                                |
|---------------------------|---------|--------------|---------|----------------------------------------------------------------------------------------|
| `INFISICAL_ENABLED`       | no      | plain env    | `false` | Enable the Infisical provider. Used with `SECRETS_STORAGE=infisical`                   |
| `INFISICAL_ADDRESS`       | no      | plain env    | `""`    | Infisical base URL (e.g. `https://infisical.a8n.systems`)                              |
| `INFISICAL_PROJECT_ID`    | no      | plain env    | `""`    | the Infisical project (workspace) id                                                   |
| `INFISICAL_ENVIRONMENT`   | no      | plain env    | `""`    | (`staging`/`prod`); Infisical > Secrets > Project > Settings > Environments slug       |
| `INFISICAL_SECRET_PATH`   | no      | plain env    | `/`     | the folder to read (`/runtime`, project-relative)                                      |
| `INFISICAL_CLIENT_ID`     | yes     | `secret_env` | `""`    | Universal Auth machine-identity client id                                              |
| `INFISICAL_CLIENT_SECRET` | yes     | `secret_env` | `""`    | Universal Auth machine-identity client secret                                          |

The two credentials go through `secret_env`, so they honour the `{NAME}_FILE`
convention and can themselves be Group-1 file secrets. If either credential is empty the client is not built: in
`database` / `environment` mode that is harmless (Infisical is not read), and in `infisical` mode it is a fatal startup
error naming the missing variables.

### Access the machine identity needs

| Mode this deployment runs                          | Required access to `INFISICAL_SECRET_PATH` |
|----------------------------------------------------|--------------------------------------------|
| any mode, reading only                             | **read**                                   |
| `infisical`, admin pages saving secrets            | **write** as well                          |
| any mode, running `secrets-migrate --to infisical` | **write** as well                          |

Write access is what BUNYIP-542 adds to the requirement: the admin Stripe and Email pages upsert through the v3
raw-secrets endpoint, and a read-only identity fails the save with a 502 naming the missing scope. Grant it in the
Infisical project's machine-identity settings for the target environment.

## Migration runbook: changing `SECRETS_STORAGE`

Never change the variable and restart to see what happens. Under
`restart: unless-stopped` a wrong declaration is a crash loop, discovered only after the old configuration stopped
serving. The pre-flight runs against the CURRENT, healthy deployment.

Each step is `docker compose exec api /app/bunyip-api <subcommand>` (or
`docker compose run --rm api <subcommand>`). None of them prints a secret value.

1. **`bunyip-api secrets-status`** (add `--json` for machine output). Read-only. For each governed secret it reports
   which providers hold a value, which one is live under the current mode, and a readiness verdict for each candidate
   mode. The `--json` keys are unchanged by the BUNYIP-642 rename, so an existing script keeps working.
   Run this first, with nothing at risk.

2. **`bunyip-api secrets-migrate --to <mode> [--dry-run]`**. Copies each governed secret from its current live source
   into the target provider, leaving the source copy in place. `--dry-run` prints the plan and writes nothing.
    - `--to database` writes the encrypted columns.
    - `--to infisical` upserts each key (needs the write scope above).
    - `--to environment` cannot write, so it emits the exact `{NAME}_FILE` entries and `./secrets/*` paths to create;
      `secrets-status` verifies them afterwards.

3. **`bunyip-api secrets-status`** again. Every governed secret must read `ready`
   for the target mode.

4. **Set `SECRETS_STORAGE=<mode>` and restart.** The boot log names the declared provider, plus one `WARN` per copy still
   sitting outside it.

5. **Soak.** The old copies are untouched, so a wrong value is a rollback (set
   `SECRETS_STORAGE` back and restart), not an outage. This is exactly why the cutover does not delete anything.

6. **`bunyip-api secrets-purge --confirm`**. Removes the copies outside the declared provider. It refuses to run unless
   the declared provider holds every governed secret, and it is never invoked automatically. The `environment`
   provider cannot be written from the app, so its copies are reported as the
   `{NAME}_FILE` entries for the operator to remove.

Staging is migrated and soaked before production is touched.

### Changing the Infisical instance

The provider stays `infisical` and the instance changes: a new Infisical deployment, a migrated one, or a different
`INFISICAL_ENVIRONMENT` /
`INFISICAL_SECRET_PATH` on the same one. This is supported by the commands above, in a different order, and it needs a
hop through the database.

**Why the hop.** bunyip-api holds exactly ONE set of `INFISICAL_*` values (`InfisicalSettings::from_env` in
`crates/bunyip-domain/src/config.rs`), so no process, and therefore no command, can hold the old and the new instance
open at once. `secrets-migrate` reads from the DECLARED provider and writes to the provider named by `--to`, so declaring the
database in the middle turns one impossible copy into two ordinary ones.

Never just repoint `INFISICAL_*` and restart. The new instance is empty, so in
`infisical` mode the api either exits 1 (new instance not reachable, or its credentials not issued yet) or boots with
email and payments off, and the values are stranded on an instance it no longer talks to.

1. **Copy out of the old instance.** Declared provider is still `infisical`, pointing at the old instance and healthy. Run
   `docker compose exec api /app/bunyip-api secrets-migrate --to database --dry-run`, then the same without `--dry-run`.
   It reads the live values from the old instance and writes the encrypted `email_config` / `stripe_config` columns.
   `bunyip-api secrets-status` must then read `database: ready` for all three.

2. **Cut over to the database.** Set `SECRETS_STORAGE=database` and restart. This is now an ordinary database-mode
   deployment serving from those rows, and it is a state you can sit in indefinitely. With `INFISICAL_ENABLED=true` the
   boot logs one `WARN` per copy still on the old instance; that is the expected duplicate, not a fault.

3. **Repoint `INFISICAL_*` at the new instance** (address, project id, environment, secret path, and the two
   credentials) and restart to pick the values up. Nothing reads them: the declared provider is the database, and
   `database` mode makes no call to Infisical. Keep `INFISICAL_ENABLED=true`, so
   `secrets-status` still inspects the Infisical provider and can answer whether the NEW instance is ready; with it off,
   the `infisical:` rows read
   `not inspected` and the next step is unverifiable.

4. **Copy into the new instance.** Run
   `bunyip-api secrets-migrate --to infisical`. It reads the declared database provider and upserts each key into the new
   instance, which needs the **write**
   access in "Access the machine identity needs". `bunyip-api secrets-status`
   must then read `infisical: ready` for all three, and that answer now comes from the new instance.

5. **Cut over to the new instance.** Set `SECRETS_STORAGE=infisical` and restart. Confirm with
   `bunyip-api secrets-status`, soak, then
   `bunyip-api secrets-purge --confirm` to drop the database copies.

**Why it is safe.** Every intermediate state is a legal, running configuration, so the sequence can stop after any step
and resume days later. At each step the rollback is the provider just left: back to `infisical` on the old instance through
step 2, back to `database` after steps 3 to 5, since nothing is deleted until the explicit purge. Nothing is ever
mid-flight between two providers.

**The same procedure covers a change of `INFISICAL_ENVIRONMENT` or
`INFISICAL_SECRET_PATH`** on one instance. Those are connection parameters like the address, so the old and the new
location are equally invisible to each other and the hop is needed just the same.

**Cleanup the tooling cannot reach.** After step 5 the OLD instance still holds every secret, and bunyip-api can no
longer see it, so `secrets-purge` cannot touch it and no boot warning mentions it. Deleting those keys on the old
instance is a MANUAL step, done in its UI or with its own CLI, and it is part of this procedure. Skipping it leaves live
credentials on a decommissioned host that nothing is watching, which is worse than the duplicate the boot-time warning
exists to catch, precisely because nothing warns about it.

**Per-deployment scope.** Each deployment migrates its own secrets. Staging is where the procedure is rehearsed, never
the vehicle for another environment's values: staging runs a different database under a different `APP_ENCRYPTION_KEY`,
so it cannot stage production's secrets.

### Restart versus hot-apply

A secret changed through the admin pages hot-applies (the write-through reloads the email or Stripe service). A value
changed directly in Infisical, or in a secret file, needs a bunyip-api restart, because the boot read is the only
reader.

## Troubleshooting

| Symptom                                                                                                                                                   | Cause                                                                                                                                                                                                                                                                            |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Boot `ERROR`: `SECRETS_STORAGE is not usable`                                                                                                             | Unset or not one of `environment` / `database` / `infisical`. Set it; `database` matches a deployment whose secrets were entered on the admin pages.                                                                                                                             |
| Boot `ERROR`: `<SECRET> is absent from the declared <X> provider but present in the <Y> provider`                                                               | The copy lives in a provider this deployment does not read. Run `secrets-migrate --to <X>`, or declare `<Y>`.                                                                                                                                                                       |
| Boot `WARN`: `<SECRET> is also held by the <Y> provider`                                                                                                   | A leftover copy. Harmless today, live if the mode ever changes to `<Y>`. Clear it with `secrets-purge --confirm`.                                                                                                                                                                |
| Boot `WARN`: `<SECRET> is not set in the declared provider`                                                                                                  | No provider holds it; the named feature is off. Set it on the admin page or migrate it in.                                                                                                                                                                                          |
| Boot `ERROR`: Infisical `could not be read` in `infisical` mode                                                                                           | Fail-closed by design. Wrong `INFISICAL_CLIENT_ID` / `_CLIENT_SECRET`, no Universal Auth on `INFISICAL_ADDRESS`, or the instance is unreachable.                                                                                                                                 |
| After repointing `INFISICAL_*` at a new instance: boot `ERROR` Infisical `could not be read`, or one `WARN` per secret `is not set in the declared provider` | The instance was changed without the database hop, so the values are still on the OLD instance and nothing reads it now. Point `INFISICAL_*` back at the old instance, restart, and follow "Changing the Infisical instance" above.                                              |
| Infisical read returns HTTP 404 for a key                                                                                                                 | The key is not at the queried project/env/path: check `INFISICAL_SECRET_PATH`, `INFISICAL_ENVIRONMENT` and `INFISICAL_PROJECT_ID`. The v3 endpoint is confirmed correct on infisical.a8n.systems (401 unauthenticated), so a 404 is a lookup mismatch, not an API-version issue. |
| Admin save fails with "Could not write ... to Infisical"                                                                                                  | The machine identity lacks **write** access to `INFISICAL_SECRET_PATH`. Nothing was saved and nothing was reloaded.                                                                                                                                                              |
| Admin secret field is read-only, save returns 409                                                                                                         | `SECRETS_STORAGE=environment`. There is no writable provider: edit the file `{NAME}_FILE` points at and restart.                                                                                                                                                                    |
