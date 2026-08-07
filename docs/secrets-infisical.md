# Application secrets from Infisical

bunyip's core application secrets are file-based: `compose.yml` mounts each one
from `./secrets/<name>` at `/run/secrets/<name>`, and the api reads it through
the `{NAME}_FILE` convention so no value ever enters the process environment
(BUNYIP-38). `scripts/sync-secrets.nu` renders those files from Infisical
(BUNYIP-504).

The model is **sync, not fetch**. Infisical writes the files; the containers keep
reading `/run/secrets/*`. A bunyip-api restart therefore never depends on
Infisical being reachable, and no Rust code knows Infisical exists.

`scripts/init-secrets.nu` remains the dev-box path: it generates throwaway values
locally. The two scripts do not collide - `init-secrets.nu` never overwrites a
non-empty file, and `sync-secrets.nu` writes only what Infisical says.

## Prerequisites

- The [`infisical` CLI](https://infisical.com/docs/cli/overview) on the host that
  runs the sync (not needed on dev boxes, not needed by the containers).
- A machine identity in the bunyip Infisical project with Universal Auth enabled
  and read access to `/bunyip/app` in the environments you sync.

## Folder layout

One folder, one key per secret, per environment:

```
bunyip (project)
├── staging
│   └── /bunyip/app      <- this document
│   └── /bunyip/e2e      <- the E2E account password (docs/e2e.md)
└── prod
    └── /bunyip/app
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
| `SMTP_PASSWORD`               | `smtp_password`         | yes           | outbound email unauthenticated / off   |
| `BUNYIP_UPDATE_CHECK_TOKEN`   | `update_check_token`    | yes           | update check runs unauthenticated      |

The table is not maintained by hand on both sides: `sync-secrets.nu --self-test`
re-derives it from the `compose.yml` `secrets:` block and the `{NAME}_FILE`
service environment, and CI runs that self-test, so adding a compose secret
without mapping it here fails the build.

`./secrets/oidc/*.pem` is **out of scope**. The OIDC signing keys are generated
out of band and the sync never touches them.

## Running the sync

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

## Rotating a secret

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

## Troubleshooting

| Message | Cause |
| --- | --- |
| `INFISICAL_CLIENT_ID is not set` | Neither the machine-identity pair nor `INFISICAL_TOKEN` is exported. |
| `infisical login failed` | Wrong client id/secret, or the identity lacks Universal Auth. |
| `key X is absent from Infisical /bunyip/app` | The key is missing, or the identity cannot read that folder/environment. Nothing was written. |
| `key X is empty in Infisical` | The key exists but is blank and the table above forbids empty for it. |
| `unknown environment '...'` | `--env` must be `staging` or `prod`. |
