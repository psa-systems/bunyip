# Configuration reference (bunyip-api)

Every environment variable bunyip-api reads, and how its absence is reported at
startup. The source of truth is `ENV_INVENTORY` in
`crates/bunyip-domain/src/config.rs`; a variable read without an entry there
fails `bunyip-api/tests/env_inventory.rs`. This file is the operator-facing
rendering of the same table.

Secrets resolve through the `{NAME}_FILE` convention first (a compose secret
under `/run/secrets/*`), then the plain variable (a dev `.env`). An empty value
counts as unset everywhere. The exception is the three governed integration
secrets below, which are `{NAME}_FILE`-only and are read only when
`SECRETS_STORAGE=environment`.

## The reporting contract (BUNYIP-537)

| Classification            | At startup                                                                    |
| ------------------------- | ----------------------------------------------------------------------------- |
| Required                  | one `ERROR` naming the variable, the reason and the remedy, then exit 1        |
| Required in production    | the same, but only when `ENVIRONMENT=production`; other environments fall back |
| Feature-gating (optional) | one `WARN` naming the variable and the functionality that is off               |
| Defaulted (optional)      | nothing: the default works and is documented below                            |

All required failures are collected in ONE pass, so a deployment missing four
variables learns about all four in one boot instead of one per restart. Nothing
in this path panics: a configuration mistake reads as a configuration error, not
as a crash with exit code 101.

Some entries are *gated*: they are only demanded (or warned about) once the
variable that switches their feature on is itself set. `OIDC_JWT_ACTIVE_KID` is
required only when `OIDC_ISSUER` is set; `INFISICAL_ADDRESS` warns only when
`INFISICAL_ENABLED` is on. That keeps an unused integration to one line rather
than one per variable in its group.

## Required

| Variable                        | Gate          | Why the api will not start without it                                                    |
| ------------------------------- | ------------- | ---------------------------------------------------------------------------------------- |
| `DATABASE_URL`                  | -             | the api cannot connect to postgres (required in every environment)                       |
| `SECRETS_STORAGE`               | -             | the deployment has not declared where its integration secrets live (required in every environment, see below) |
| `JWT_SECRET`                    | -             | no signing key for session access/refresh tokens                                         |
| `APP_ENCRYPTION_KEY`            | -             | no at-rest key for the TOTP, Stripe and SMTP secrets (BUNYIP-483)                        |
| `BUNYIP_WEBHOOK_SIGNING_SECRET` | -             | no HMAC key for outbound webhook dispatches (BUNYIP-332)                                 |
| `OIDC_JWT_PRIVATE_KEY_PATH`     | `OIDC_ISSUER` | the OIDC provider would sign with the development key path                               |
| `OIDC_JWT_ACTIVE_KID`           | `OIDC_ISSUER` | a `dev-` kid in production is consumed by RPs as legitimate (BUNYIP-258); also value-checked |
| `SMTP_HOST` / `EMAIL_ENABLED`   | -             | email disabled in production would log single-use login/reset tokens instead of sending them (BUNYIP-204) |

Every one except `DATABASE_URL` and `SECRETS_STORAGE` is required only on
`ENVIRONMENT=production`; development and staging fall back to documented
placeholder values.

## `SECRETS_STORAGE`: where the integration secrets live (BUNYIP-542)

`SECRETS_STORAGE` declares the ONE store bunyip reads its governed integration
secrets from. Legal values: `environment`, `database`, `infisical`. Unset or
unrecognised logs one `ERROR` naming the legal set and exits 1.

The governed set is exactly the secrets with more than one possible store:

| Secret                  | `database`                       | `environment`                | `infisical`               |
| ----------------------- | -------------------------------- | ---------------------------- | ------------------------- |
| `SMTP_PASSWORD`         | `email_config.smtp_password`     | `SMTP_PASSWORD_FILE`         | `<path>/SMTP_PASSWORD`    |
| `STRIPE_SECRET_KEY`     | `stripe_config.secret_key`       | `STRIPE_SECRET_KEY_FILE`     | `<path>/STRIPE_SECRET_KEY` |
| `STRIPE_WEBHOOK_SECRET` | `stripe_config.webhook_secret`   | `STRIPE_WEBHOOK_SECRET_FILE` | `<path>/STRIPE_WEBHOOK_SECRET` |

The declared store is the ONLY one consulted. There is no fallback and no
precedence chain: in `database` mode the environment slot and Infisical are not
read at all, and vice versa. Group-1 startup secrets (`DATABASE_URL`,
`JWT_SECRET`, `APP_ENCRYPTION_KEY`, ...) cannot be governed by this switch - the
database cannot hold the credential used to reach the database - and stay
file-based.

In `environment` mode a governed secret is read from `{NAME}_FILE` ONLY. A plain
`STRIPE_SECRET_KEY=sk_live_...` in a compose `environment:` block is visible to
`docker inspect` and to every child process, so it is deliberately not consulted.

### Startup enforcement, per governed secret

| Situation                                          | Behaviour                                                                    |
| -------------------------------------------------- | ---------------------------------------------------------------------------- |
| present in the declared store                       | use it                                                                       |
| absent everywhere                                   | feature off, one `WARN` naming the secret and the feature it gates           |
| absent from the declared store, present in another  | **fatal**: one `ERROR` naming the secret, both stores and `secrets-migrate`, then exit 1 |
| present in the declared store AND in another        | boot, and one `WARN` per duplicate naming `secrets-purge`                    |

"Present" means a non-null ciphertext column (database), a non-empty
`{NAME}_FILE` read (environment), or a successful key read (infisical). The
duplicate warning is what keeps a later mode change honest: a stale copy in a
store nobody reads today becomes live the moment someone flips the mode.

`infisical` mode is **fail-closed**: an unreachable Infisical or a failed read
aborts the boot, because the operator declared it the store of record.
`database` and `environment` mode never contact Infisical at boot, so it stays
off the boot path for them.

### Writing from the admin pages

| Mode          | Admin Stripe / Email secret fields                                                          |
| ------------- | -------------------------------------------------------------------------------------------- |
| `database`    | editable; encrypted under `APP_ENCRYPTION_KEY`, written to the row, service hot-reloaded    |
| `infisical`   | editable; written to `INFISICAL_SECRET_PATH` through the API (no DB write), service hot-reloaded, and an audit entry records the admin, the secret and the target store |
| `environment` | read-only, labelled with the owning store and the file to edit; the API answers 409          |

A failed Infisical write surfaces on the form and in the log with the underlying
cause, performs no reload and reports no success. The machine identity needs
**write** access to `INFISICAL_SECRET_PATH`; read access alone fails the save.

Non-secret configuration (`smtp_host`, `smtp_port`, `smtp_tls`, `smtp_username`,
`from_email`, the checkout URLs, the tier ids) stays editable in every mode: the
switch governs secrets only.

### Restart versus hot-apply

Only a change made through the admin pages hot-applies. A value changed directly
in Infisical, or in a secret file, takes effect on the next restart, because the
boot read is the only reader.

### Changing the store

Never by editing `SECRETS_STORAGE` and hoping. The pre-flight runs while the
current deployment is healthy: `bunyip-api secrets-status`, then
`secrets-migrate --to <target>`, then `secrets-status` again, then set
`SECRETS_STORAGE`, restart, soak, and finally `secrets-purge --confirm`. The
full runbook is in [`secrets-infisical.md`](secrets-infisical.md).

## Feature-gating (one `WARN`, boot continues)

| Variable                                | Gate                        | What is off without it                                       |
| --------------------------------------- | --------------------------- | ------------------------------------------------------------ |
| `APP_DATABASE_URL`                      | -                           | per-user RLS: reads fall back to the RLS-bypassing pool       |
| `BUNYIP_APP_PASSWORD`                   | -                           | the unprivileged `bunyip_app` RLS role is not provisioned     |
| `SETUP_DEFAULT_ADMIN`                   | -                           | no bootstrap admin is seeded                                  |
| `BOOTSTRAP_ADMIN_EMAIL`                 | -                           | no account is auto-promoted to first admin / super admin      |
| `TRUSTED_PROXY_CIDR`                    | -                           | forwarded client IPs are dropped (audit / rate limit see the proxy) |
| `OIDC_ISSUER`                           | -                           | the whole OIDC provider: no RP can log in through bunyip      |
| `FORGEJO_BASE_URL`                      | -                           | the distribution proxy has no upstream                        |
| `FORGEJO_API_TOKEN`                     | -                           | downloads cannot authenticate to Forgejo                      |
| `OCI_REGISTRY_ENABLED`                  | -                           | the OCI registry endpoint                                     |
| `OCI_REGISTRY_SERVICE`                  | `OCI_REGISTRY_ENABLED`      | the registry token realm cannot be derived                    |
| `SMTP_HOST`                             | -                           | transactional email (outside production, where it is required)|
| `ADMIN_NOTIFICATION_EMAILS`             | `SMTP_HOST`                 | admin notifications have no recipient                         |
| `IP2LOCATION_DB_PATH`                   | -                           | GeoIP enrichment on login-location alerts                     |
| `IP2PROXY_DB_PATH`                      | -                           | ASN / VPN enrichment on login alerts                          |
| `BUNYIP_UPDATE_CHECK_URL`               | -                           | the operator update checker                                   |
| `BUNYIP_UPDATE_CHECK_TOKEN`             | `BUNYIP_UPDATE_CHECK_URL`   | authenticated access to a private release feed                |
| `INFISICAL_ENABLED`                     | -                           | inspecting the Infisical store (`secrets-status` readiness)   |
| `INFISICAL_ADDRESS`                     | `INFISICAL_ENABLED`         | the Infisical server address                                  |
| `INFISICAL_PROJECT_ID`                  | `INFISICAL_ENABLED`         | the Infisical project                                         |
| `INFISICAL_CLIENT_ID`                   | `INFISICAL_ENABLED`         | the Universal Auth machine identity                           |
| `INFISICAL_CLIENT_SECRET`               | `INFISICAL_ENABLED`         | the Universal Auth machine-identity secret                    |
| `MOKOSH_APPS_REDIRECT_URIS`             | -                           | the mokosh-apps OIDC client keeps the migration-seeded URIs   |
| `MOKOSH_APPS_AUDIENCE`                  | -                           | the mokosh-apps OIDC client is not reconciled                 |
| `MOKOSH_APPS_POST_LOGOUT_REDIRECT_URIS` | `MOKOSH_APPS_REDIRECT_URIS` | its post-logout redirect list is reconciled empty             |
| `DRILLMARK_REDIRECT_URIS`               | -                           | the drillmark OIDC client keeps the migration-seeded URIs     |
| `DRILLMARK_AUDIENCE`                    | -                           | the drillmark OIDC client is not reconciled                   |
| `DRILLMARK_POST_LOGOUT_REDIRECT_URIS`   | `DRILLMARK_REDIRECT_URIS`   | its post-logout redirect list is reconciled empty             |
| `LETS_CHAT_REDIRECT_URIS`               | -                           | the lets-chat OIDC client keeps the migration-seeded URIs     |
| `LETS_CHAT_AUDIENCE`                    | -                           | the lets-chat OIDC client is not reconciled                   |
| `LETS_CHAT_POST_LOGOUT_REDIRECT_URIS`   | `LETS_CHAT_REDIRECT_URIS`   | its post-logout redirect list is reconciled empty             |
| `LETS_CHAT_CLIENT_SECRET_HASH`          | `LETS_CHAT_REDIRECT_URIS`   | the client keeps the migration's shared secret hash           |
| `MOKOSH_WEBHOOK_URL`                    | -                           | `account_deleted` events are never dispatched to mokosh       |
| `MOKOSH_BACKUP_API_URL`                 | -                           | account backup/restore falls back to the pending stub         |

## Defaulted (no boot-time log)

Every variable below has a working default; set it only to tune the deployment.

- **Identity and transport**: `ENVIRONMENT` (unset means `production`),
  `APP_NAME`, `APP_URL`, `HOST_IP`, `APP_PORT`, `RUST_LOG`, `CORS_ORIGIN`,
  `BUNYIP_WEB_ORIGIN`, `COOKIE_DOMAIN`, `BUNYIP_COOKIE_SHARED_DOMAIN`.
- **At-rest keys**: `APP_ENCRYPTION_KEY_PREV`, `APP_KEY_VERSION` (see
  [`encryption-key-rotation.md`](encryption-key-rotation.md)).
- **Email**: `EMAIL_ENABLED`, `EMAIL_LOG_TOKENS`, `SMTP_PORT`, `SMTP_TLS`,
  `SMTP_USERNAME`, `SMTP_EHLO_NAME`, `SMTP_FROM`.
- **Governed secrets** (read only when `SECRETS_STORAGE=environment`, and only
  as `{NAME}_FILE`): `SMTP_PASSWORD`, `STRIPE_SECRET_KEY`,
  `STRIPE_WEBHOOK_SECRET`.
- **Abuse controls**: `AUTO_BAN_ENABLED`, `AUTO_BAN_THRESHOLD`,
  `AUTO_BAN_WINDOW_SECS`, `AUTO_BAN_DURATION_SECS`, `LOGIN_APPROVAL_ENABLED`,
  `SIGNUP_BOT_GUARD_ENABLED`.
- **Rate limits**: `RATE_LIMIT_{ACTION}_MAX_REQUESTS` and
  `RATE_LIMIT_{ACTION}_WINDOW_SECONDS`, one pair per action
  (`crates/bunyip-domain/src/models/rate_limit.rs`). The names are built at
  runtime from the action, so they are a family rather than inventory entries;
  precedence is const -> env -> the `rate_limit_configs` DB row.
- **Tiers and billing**: `TIER_LIFETIME_SLOTS`, `TIER_EARLY_ADOPTER_SLOTS`,
  `TIER_EARLY_ADOPTER_TRIAL_DAYS`, `TIER_STANDARD_TRIAL_DAYS`,
  `BUNYIP_BILLING_TRIAL_PERIOD_DAYS`.
- **Distribution proxy**: `DOWNLOAD_CACHE_DIR`, `DOWNLOAD_CACHE_MAX_BYTES`,
  `DOWNLOAD_CONCURRENCY_PER_USER`, `DOWNLOAD_DAILY_LIMIT_PER_USER`,
  `FORGEJO_RELEASE_CACHE_TTL_SECS`.
- **OCI registry**: `OCI_REGISTRY_PORT`, `OCI_REGISTRY_REALM`,
  `OCI_BLOB_CACHE_DIR`, `OCI_BLOB_CACHE_MAX_BYTES`,
  `OCI_MANIFEST_CACHE_TTL_SECS`, `OCI_CONCURRENT_MANIFESTS_PER_USER`,
  `OCI_PULLS_PER_USER_PER_DAY`, `OCI_TOKEN_TTL_SECS`.
- **OIDC**: `OIDC_JWT_PUBLIC_KEYS_DIR`, `OIDC_ACCESS_TOKEN_TTL_SECONDS`,
  `OIDC_REFRESH_TOKEN_TTL_SECONDS`, `OIDC_REFRESH_IDLE_TTL_SECONDS`,
  `OIDC_CODE_TTL_SECONDS`, `OIDC_LIFECYCLE_EVENT_KEY`, `OIDC_RS_AUDIENCE`.
- **Infisical**: `INFISICAL_SECRET_PATH`, `INFISICAL_ENVIRONMENT`,
  `INFISICAL_ENV` (legacy alias).
- **Non-production tooling**: `BUNYIP_E2E_BOOTSTRAP_ALLOW`,
  `BUNYIP_E2E_TOTP_SECRET`, `BUNYIP_SEED_ALLOW`, `BUNYIP_GIT_SHA`.

## Secret files and compose coverage

The reference `compose.yml` passes every required secret as a `{NAME}_FILE`
secret, so `just init-secrets` followed by `docker compose up` boots on
`ENVIRONMENT=production` with no manual step. `SECRETS_STORAGE` is the one
required variable it passes with **no default** (`${SECRETS_STORAGE:?...}`), so
`docker compose up` aborts until the deployment states where its integration
secrets live. `compose.dev.yml` and `compose.dev-sso.yml` default it to
`database`, which is what dev has always used, so `just dev` is unchanged. The
secret files, their "empty allowed" status and the rotation procedure are in
[`secrets-infisical.md`](secrets-infisical.md).

The feature-gating variables are deliberately NOT all passed by `compose.yml`:
a self-host with no Forgejo, no GeoIP data, no Infisical and no RPs is a
supported deployment. Each one it omits produces the single boot warning above,
which is how an operator tells "off because I chose so" from "off because I
forgot".

## bunyip-web

bunyip-web is a separate binary with its own configuration
(`bunyip-web/src/config.rs`): `BUNYIP_BIND_ADDR`, `BUNYIP_API_URL`,
`BUNYIP_API_PUBLIC_ORIGIN`, `BUNYIP_OIDC_ISSUER`, `BUNYIP_APP_DOMAIN`,
`BUNYIP_COMMUNITY_URL`, `TRUSTED_PROXY_CIDR`, `APP_NAME`, `BRAND_THEME_CSS`,
`BRAND_DESCRIPTION`, `CSP_CONNECT_SRC`, `CSP_FORM_ACTION`, `RUST_LOG`. Every one
has a working default. It holds no secrets and reads none of the api variables
above, so the api's inventory does not cover it.
