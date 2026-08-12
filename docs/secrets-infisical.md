# Application secrets from Infisical

bunyip sources secrets from Infisical in two tiers. **Group-1** startup secrets
are rendered to files before the container starts (sync, not fetch); **Group-2**
integration secrets are fetched by the app itself at runtime. This document
covers both: the Group-1 sync path first, then the
[Group-2 runtime fetch](#group-2-runtime-fetch). `CLAUDE.md`'s "Secret sourcing
(two tiers)" bullet is the one-paragraph summary of the same split.

## Group-1: file secrets (sync)

bunyip's core application secrets are file-based: `compose.yml` mounts each one
from `./secrets/<name>` at `/run/secrets/<name>`, and the api reads it through
the `{NAME}_FILE` convention so no value ever enters the process environment
(BUNYIP-38). `scripts/sync-secrets.nu` renders those files from Infisical
(BUNYIP-504).

The model is **sync, not fetch**. Infisical writes the files; the containers keep
reading `/run/secrets/*`. A bunyip-api restart therefore never depends on
Infisical being reachable, and no Rust code knows a Group-1 secret came from
Infisical.

`scripts/init-secrets.nu` remains the dev-box path: it generates throwaway values
locally. The two scripts do not collide - `init-secrets.nu` never overwrites a
non-empty file, and `sync-secrets.nu` writes only what Infisical says.

### Prerequisites

- The [`infisical` CLI](https://infisical.com/docs/cli/overview) on the host that
  runs the sync (not needed on dev boxes, not needed by the containers). The CLI
  is a Group-1 sync tool only; the Group-2 fetch uses no CLI.
- A machine identity in the bunyip Infisical project with Universal Auth enabled
  and read access to `/bunyip/app` in the environments you sync.

### Folder layout

One folder, one key per secret, per environment:

```
bunyip (project)
├── staging
│   ├── /bunyip/app      <- Group-1 file secrets (sync-secrets.nu)
│   ├── /runtime         <- Group-2 runtime fetch (project-relative; see below)
│   └── /bunyip/e2e      <- the E2E account password (docs/e2e.md)
└── prod
    ├── /bunyip/app
    └── /runtime
```

The Infisical key is the environment variable name the api reads, i.e. the
`{NAME}` half of the `{NAME}_FILE` entry in `compose.yml`:

| Infisical key (`/bunyip/app`) | Secret file             | Empty allowed | Meaning when empty                     |
| ----------------------------- | ----------------------- | ------------- | -------------------------------------- |
| `POSTGRES_PASSWORD`           | `postgres_password`     | no            | postgres refuses to initialize         |
| `DATABASE_URL`                | `database_url`          | no            | the api cannot connect                 |
| `JWT_SECRET`                  | `jwt_secret`            | no            | no session signing key                 |
| `APP_ENCRYPTION_KEY`          | `app_encryption_key`    | no            | no at-rest key (see the rotation note) |
| `BUNYIP_APP_PASSWORD`         | `bunyip_app_password`   | yes           | per-user RLS inactive (BUNYIP-360)     |
| `APP_DATABASE_URL`            | `app_database_url`      | yes           | per-user RLS inactive (BUNYIP-360)     |
| `SETUP_DEFAULT_ADMIN`         | `setup_default_admin`   | yes           | no bootstrap admin is seeded           |
| `FORGEJO_API_TOKEN`           | `forgejo_api_token`     | yes           | Forgejo integration off                |
| `BUNYIP_UPDATE_CHECK_TOKEN`   | `update_check_token`    | yes           | update check runs unauthenticated      |

The table is not maintained by hand on both sides: `sync-secrets.nu --self-test`
re-derives it from the `compose.yml` `secrets:` block and the `{NAME}_FILE`
service environment, and CI runs that self-test, so adding a compose secret
without mapping it here fails the build.

`SMTP_PASSWORD` is deliberately **not** in this Group-1 table: it is Group-2-only
(BUNYIP-529), sourced from the `/runtime` Infisical fetch or a DB
`email_config` row. See [Group-2: runtime fetch](#group-2-runtime-fetch).

`./secrets/oidc/*.pem` is **out of scope**. The OIDC signing keys are generated
out of band and the sync never touches them.

### Running the sync

```nu
$env.INFISICAL_CLIENT_ID = "<machine identity client id>"
$env.INFISICAL_CLIENT_SECRET = "<machine identity client secret>"

just sync-secrets --env prod --dry-run    # show the plan, write nothing
just sync-secrets --env prod              # write ./secrets/*
docker compose up --detach                # pick the new values up
```

`--env` defaults to `prod`. An already-exported `INFISICAL_TOKEN` short-circuits
the login, which is the better shape on a shared host: the Universal Auth
credentials are passed to `infisical login` as arguments and are visible in the
process list for the duration of that one call, whereas a pre-obtained token is
not.

Nushell reserves `env` as a variable name, so the script's own flag is
`--environment` (short `-e`); the `just` recipe accepts `--env` and translates.
Running `./scripts/sync-secrets.nu --environment prod` directly is equivalent.

Behaviour worth knowing:

- **Idempotent.** A value that already matches on disk is not rewritten, so a
  re-run leaves the file mtime alone and nothing restarts unnecessarily. Safe on
  a timer.
- **Atomic and 0400.** Each file is written to a temp file in the same directory,
  chmod 0400, then renamed over the target. A reader never sees a partial value.
- **Fails closed.** A mapped key that is absent from Infisical, or empty when the
  table above says it may not be, aborts the run naming the key **before**
  anything is written. An empty file is never created by accident, because an
  empty `bunyip_app_password` / `app_database_url` silently means "RLS off".
- **Quiet about values.** No mode prints a secret. The plan table carries the
  key, the file and the action only.
- **Scoped.** Only the keys in the table are read; anything else in
  `/bunyip/app` is left untouched.

### Rotating a Group-1 secret

1. Change the value in Infisical (`/bunyip/app`, the target environment).
2. `just sync-secrets --env <env>` on the host.
3. `docker compose up --detach` (or restart the affected service) so the process
   re-reads `/run/secrets/*`.

Two rotations need more than that:

- **`POSTGRES_PASSWORD`** must be changed on the postgres role as well, and
  `DATABASE_URL` (plus `APP_DATABASE_URL` when RLS is on) must embed the new
  value. Update all of them in Infisical in one edit so a single sync leaves the
  set consistent.
- **`APP_ENCRYPTION_KEY`** is not complete after a sync. Syncing the new key
  makes new writes use it, but existing rows still need the old key to read and
  then a re-encrypt pass:
  set `APP_ENCRYPTION_KEY_PREV` (a `.env` variable in `compose.yml`, not one of
  the synced secret files) to the outgoing key, sync the new
  `APP_ENCRYPTION_KEY`, restart, run
  `docker compose run --rm api reencrypt-secrets`, then clear
  `APP_ENCRYPTION_KEY_PREV` and restart. The full procedure, including
  `APP_KEY_VERSION` and the admin key-health endpoints, is in
  [`encryption-key-rotation.md`](encryption-key-rotation.md).

## Group-2: runtime fetch

The Group-1 path above renders files before the container starts. Group-2 is the
opposite: bunyip-api itself fetches the secret from Infisical at boot, in Rust
(`crates/bunyip-domain/src/services/infisical.rs`, BUNYIP-525), using a Universal
Auth machine identity and reading the `/runtime` folder. There is no CLI
and no sidecar. Today the only Group-2 secret is `SMTP_PASSWORD`; more
post-startup integration secrets can follow the same path.

The fetch is **graceful**: any failure (Infisical unreachable, bad credentials,
missing key) leaves the secret unset and logs a warning, so the app always
starts. Infisical is never a boot dependency, which is why SMTP (a post-startup
integration, not needed to boot) is Group-2 and postgres/JWT/encryption keys stay
Group-1.

### Configuration

bunyip splits these across the deployment files: the non-secret keys are plain
env (in the docker repo, `server/<host>/bunyip-api/compose-variables.yml`), and
the two credentials live in the SOPS `compose-secrets.yml`.

| Env var                   | Secret? | How read     | Default | Meaning                                                   |
| ------------------------- | ------- | ------------ | ------- | --------------------------------------------------------- |
| `INFISICAL_ENABLED`       | no      | plain env    | `false` | master switch; the fetch runs only when `true`            |
| `INFISICAL_ADDRESS`       | no      | plain env    | `""`    | Infisical base URL (e.g. `https://infisical.a8n.systems`) |
| `INFISICAL_PROJECT_ID`    | no      | plain env    | `""`    | the Infisical project (workspace) id                      |
| `INFISICAL_ENV`           | no      | plain env    | `""`    | the environment slug (`staging` / `prod`)                 |
| `INFISICAL_SECRET_PATH`   | no      | plain env    | `/`     | the folder to read (`/runtime`, project-relative)         |
| `INFISICAL_CLIENT_ID`     | yes     | `secret_env` | `""`    | Universal Auth machine-identity client id                 |
| `INFISICAL_CLIENT_SECRET` | yes     | `secret_env` | `""`    | Universal Auth machine-identity client secret             |

The two credentials go through `secret_env`, so they honour the `{NAME}_FILE`
convention and can themselves be Group-1 file secrets. If either credential is
empty the client is not built and the fetch is skipped (fail-open). The machine
identity needs Universal Auth and read access to `INFISICAL_SECRET_PATH`
(`/runtime`) in the target environment. Paths are project-relative: the identity is
scoped to the bunyip Infisical project, so no `/bunyip` prefix is needed. This is a
separate grant from the sync identity's read on the Group-1 folder (`/bunyip/app`).

### Source precedence

For a Group-2 secret that also has a config slot (`SMTP_PASSWORD` is the current
example), the value the app uses is resolved in this order, highest first:

1. The **database row**, when the feature stores one (`email_config.smtp_password`,
   set from the admin UI). This wins outright.
2. A **plain `SMTP_PASSWORD` env var**, read via `secret_env("SMTP_PASSWORD")`.
   Since BUNYIP-529 `SMTP_PASSWORD` is no longer a Group-1 file secret (it is gone
   from `compose.yml` and the `/bunyip/app` sync mapping), so this slot is normally
   empty; a leftover value in a deployment's SOPS `compose-secrets.yml` is the one
   thing that still shadows the fetch.
3. The **Group-2 Infisical fetch**.

The fetch fills the slot **only when it is empty** (`bunyip-api/src/main.rs` gates
it on `config.infisical.enabled && config.email.smtp_password.is_empty()`). With no
`email_config` DB row and no stray env value, Infisical is the source. If email
unexpectedly does not use Infisical, look for an `email_config` DB row or a
lingering `SMTP_PASSWORD` in the deployment's SOPS `compose-secrets.yml`.

### Validating a fetch

With `INFISICAL_ENABLED=true`, the credentials set, and no Group-1/DB value, the
boot log shows:

```
Fetched SMTP_PASSWORD from Infisical (BUNYIP-525 Group-2 runtime secret)
```

Its absence, with the feature enabled, means the slot was already filled: look
for a lingering Group-1 `SMTP_PASSWORD` or a DB `email_config` row.

## Troubleshooting

### Group-1 sync

| Message | Cause |
| --- | --- |
| `INFISICAL_CLIENT_ID is not set` | Neither the machine-identity pair nor `INFISICAL_TOKEN` is exported. |
| `infisical login failed` | Wrong client id/secret, or the identity lacks Universal Auth. |
| `key X is absent from Infisical /bunyip/app` | The key is missing, or the identity cannot read that folder/environment. Nothing was written. |
| `key X is empty in Infisical` | The key exists but is blank and the table above forbids empty for it. |
| `unknown environment '...'` | `--env` must be `staging` or `prod`. |

### Group-2 fetch

| Symptom | Cause |
| --- | --- |
| Boot warn, `infisical login failed` | Wrong `INFISICAL_CLIENT_ID` / `_CLIENT_SECRET`, or the identity lacks Universal Auth on `INFISICAL_ADDRESS`. Graceful: the app still starts. |
| Boot warn on the secret read, HTTP 404 | The key is not at the queried project/env/path: check `INFISICAL_SECRET_PATH`, `INFISICAL_ENV`, `INFISICAL_PROJECT_ID`, and that the key exists there. The v3 endpoint is confirmed correct on infisical.a8n.systems (401 unauthenticated), so a 404 is a lookup mismatch, not an API-version issue. |
| Feature enabled but no "Fetched ..." log line | The slot was already non-empty; a Group-1 `SMTP_PASSWORD` or a DB `email_config` row won. Remove the Group-1 value to use Infisical. |
| App starts, email off, boot warn about Infisical | Infisical unreachable or the key absent in `/runtime`. Graceful by design; the app boots and email stays off until the fetch succeeds on a later restart. |
