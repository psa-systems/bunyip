# Application secrets

bunyip's secrets split by whether the app needs them to boot. **Group-1** startup
secrets are file/SOPS-based and provided directly; **Group-2** integration secrets
are fetched by the app from Infisical at runtime. Only Group-2 uses Infisical.
`CLAUDE.md`'s "Secret sourcing (two tiers)" bullet is the one-paragraph summary.

## Group-1: startup secrets (files / SOPS, not Infisical)

Group-1 secrets are file-based: `compose.yml` mounts each one from
`./secrets/<name>` at `/run/secrets/<name>`, and the api reads it through the
`{NAME}_FILE` convention so no value ever enters the process environment
(BUNYIP-38). They are provided directly, not fetched from any secrets manager:

- **Dev**: `scripts/init-secrets.nu` (`just init-secrets`) generates local
  throwaway values.
- **Deployments**: the SOPS-encrypted `compose-secrets.yml` (docker repo, per
  host) supplies them.

Group-1 secrets are **never** fetched from or synced with Infisical, so a
bunyip-api restart never depends on Infisical being reachable and no Rust code
reads a Group-1 secret from Infisical.

The Group-1 secrets (the `{NAME}` half of each `{NAME}_FILE` entry in
`compose.yml`):

| Secret                      | Secret file           | Empty allowed | Meaning when empty                     |
| --------------------------- | --------------------- | ------------- | -------------------------------------- |
| `POSTGRES_PASSWORD`         | `postgres_password`   | no            | postgres refuses to initialize         |
| `DATABASE_URL`              | `database_url`        | no            | the api cannot connect                 |
| `JWT_SECRET`                | `jwt_secret`          | no            | no session signing key                 |
| `APP_ENCRYPTION_KEY`        | `app_encryption_key`  | no            | no at-rest key (see the rotation note) |
| `BUNYIP_APP_PASSWORD`       | `bunyip_app_password` | yes           | per-user RLS inactive (BUNYIP-360)     |
| `APP_DATABASE_URL`          | `app_database_url`    | yes           | per-user RLS inactive (BUNYIP-360)     |
| `SETUP_DEFAULT_ADMIN`       | `setup_default_admin` | yes           | no bootstrap admin is seeded           |
| `FORGEJO_API_TOKEN`         | `forgejo_api_token`   | yes           | Forgejo integration off                |
| `BUNYIP_UPDATE_CHECK_TOKEN` | `update_check_token`  | yes           | update check runs unauthenticated      |

`SMTP_PASSWORD` is deliberately absent: it is Group-2-only (BUNYIP-529), from the
`/runtime` Infisical fetch or a DB `email_config` row (below). `./secrets/oidc/*.pem`
is out of scope: the OIDC signing keys are generated out of band.

### Rotating a Group-1 secret

Change the value in the secret store (the SOPS `compose-secrets.yml` on the host,
or `./secrets/<file>` for a self-host), then `docker compose up --detach` (or
restart the affected service) so the process re-reads `/run/secrets/*`. Two need
more than that:

- **`POSTGRES_PASSWORD`** must be changed on the postgres role as well, and
  re-embedded in `DATABASE_URL` (plus `APP_DATABASE_URL` when RLS is on), in one
  edit so the set stays consistent.
- **`APP_ENCRYPTION_KEY`** is not complete after the file change. Set
  `APP_ENCRYPTION_KEY_PREV` (a `.env` variable in `compose.yml`, not a secret file)
  to the outgoing key, restart, run `docker compose run --rm api reencrypt-secrets`,
  then clear `APP_ENCRYPTION_KEY_PREV` and restart. The full procedure, including
  `APP_KEY_VERSION` and the admin key-health endpoints, is in
  [`encryption-key-rotation.md`](encryption-key-rotation.md).

## Group-2: runtime fetch (Infisical)

bunyip-api itself fetches the secret from Infisical at boot, in Rust
(`crates/bunyip-domain/src/services/infisical.rs`, BUNYIP-525), using a Universal
Auth machine identity and reading the `/runtime` folder. There is no CLI and no
sidecar. Today the only Group-2 secret is `SMTP_PASSWORD`; more post-startup
integration secrets can follow the same path.

The fetch is **graceful**: any failure (Infisical unreachable, bad credentials,
missing key) leaves the secret unset and logs a warning, so the app always starts.
Infisical is never a boot dependency, which is why SMTP (a post-startup
integration, not needed to boot) is Group-2 while postgres/JWT/encryption keys stay
Group-1.

### Infisical folder layout

Only Group-2 (and the separate E2E credential) live in Infisical. Paths are
**project-relative**: the machine identity is scoped to the bunyip project, so no
`/bunyip` prefix is needed.

```
bunyip (project)
├── staging
│   ├── /runtime      <- Group-2 runtime fetch (SMTP_PASSWORD)
│   └── /bunyip/e2e   <- the E2E account password (docs/e2e.md)
└── prod
    └── /runtime
```

### Configuration

bunyip splits these across the deployment files: the non-secret keys are plain
env (in the docker repo, `server/<host>/bunyip-api/compose-variables.yml`), and
the two credentials live in the SOPS `compose-secrets.yml`.

| Env var                   | Secret? | How read     | Default | Meaning                                                   |
| ------------------------- | ------- | ------------ | ------- | --------------------------------------------------------- |
| `INFISICAL_ENABLED`       | no      | plain env    | `false` | master switch; the fetch runs only when `true`            |
| `INFISICAL_ADDRESS`       | no      | plain env    | `""`    | Infisical base URL (e.g. `https://infisical.a8n.systems`) |
| `INFISICAL_PROJECT_ID`    | no      | plain env    | `""`    | the Infisical project (workspace) id                      |
| `INFISICAL_ENVIRONMENT`   | no      | plain env    | `""`    | environment slug (`staging`/`prod`); legacy `INFISICAL_ENV` |
| `INFISICAL_SECRET_PATH`   | no      | plain env    | `/`     | the folder to read (`/runtime`, project-relative)         |
| `INFISICAL_CLIENT_ID`     | yes     | `secret_env` | `""`    | Universal Auth machine-identity client id                 |
| `INFISICAL_CLIENT_SECRET` | yes     | `secret_env` | `""`    | Universal Auth machine-identity client secret             |

The two credentials go through `secret_env`, so they honour the `{NAME}_FILE`
convention and can themselves be Group-1 file secrets. If either credential is
empty the client is not built and the fetch is skipped (fail-open). The machine
identity needs Universal Auth and read access to `INFISICAL_SECRET_PATH`
(`/runtime`) in the target environment.

### Source precedence

For a Group-2 secret that also has a config slot (`SMTP_PASSWORD` is the current
example), the value the app uses is resolved in this order, highest first:

1. The **database row**, when the feature stores one (`email_config.smtp_password`,
   set from the admin UI). This wins outright.
2. A **plain `SMTP_PASSWORD` env var**, read via `secret_env("SMTP_PASSWORD")`.
   Since BUNYIP-529 `SMTP_PASSWORD` is no longer a Group-1 file secret (it is gone
   from `compose.yml`), so this slot is normally empty; a leftover value in a
   deployment's SOPS `compose-secrets.yml` is the one thing that still shadows the
   fetch.
3. The **Group-2 Infisical fetch**.

The fetch fills the slot **only when it is empty** (`bunyip-api/src/main.rs` gates
it on `config.infisical.enabled && config.email.smtp_password.is_empty()`). With no
`email_config` DB row and no stray env value, Infisical is the source. If email
unexpectedly does not use Infisical, look for an `email_config` DB row or a
lingering `SMTP_PASSWORD` in the deployment's SOPS `compose-secrets.yml`.

### Validating a fetch

With `INFISICAL_ENABLED=true`, the credentials set, and no stray env/DB value, the
boot log shows:

```
Fetched SMTP_PASSWORD from Infisical (BUNYIP-525 Group-2 runtime secret)
```

Its absence, with the feature enabled, means the slot was already filled: look for
a lingering `SMTP_PASSWORD` in the SOPS `compose-secrets.yml` or a DB `email_config`
row.

## Troubleshooting (Group-2 fetch)

| Symptom | Cause |
| --- | --- |
| Boot warn, `infisical login failed` | Wrong `INFISICAL_CLIENT_ID` / `_CLIENT_SECRET`, or the identity lacks Universal Auth on `INFISICAL_ADDRESS`. Graceful: the app still starts. |
| Boot warn on the secret read, HTTP 404 | The key is not at the queried project/env/path: check `INFISICAL_SECRET_PATH`, `INFISICAL_ENVIRONMENT`, `INFISICAL_PROJECT_ID`, and that the key exists there. The v3 endpoint is confirmed correct on infisical.a8n.systems (401 unauthenticated), so a 404 is a lookup mismatch, not an API-version issue. |
| Feature enabled but no "Fetched ..." log line | The slot was already non-empty; a stray `SMTP_PASSWORD` env value or a DB `email_config` row won. Remove the stray value to use Infisical. |
| App starts, email off, boot warn about Infisical | Infisical unreachable or the key absent in `/runtime`. Graceful by design; the app boots and email stays off until the fetch succeeds on a later restart. |
