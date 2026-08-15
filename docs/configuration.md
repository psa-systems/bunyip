# Configuration reference

Every environment variable bunyip reads, and every setting that lives inside the application instead. If a knob is not
in this document, it does not exist.

The dividing line:

- **Environment variables** (sections 1-8) are read once at process start. Changing one means restarting the container.
  They configure the deployment: where the process listens, which database it uses, what key material it holds.
- **In-app settings** (section 10) live in the database, are edited on the admin pages, and apply without a restart.
  They configure the product: Stripe credentials, pricing tiers, rate limits, SMTP.

Some settings exist in both places. There the environment variable is a **bootstrap default** and the database row wins;
those are marked as such and collected in section 7.

Related documents: [secrets-infisical.md](secrets-infisical.md) (the two secret tiers and the Infisical
fetch), [encryption-key-rotation.md](encryption-key-rotation.md)
(at-rest keys), [client-ip-forwarding.md](client-ip-forwarding.md) (the proxy trust
chain), [oci-registry-verification.md](oci-registry-verification.md)
(distribution proxy).

## How a value is resolved

1. **Plain environment variable**, e.g. `SMTP_HOST=smtp.example.com`.
2. **File-backed environment variable**, the `{NAME}_FILE` convention (BUNYIP-38). Every variable read through
   `secret_env` accepts `{NAME}_FILE` pointing at a file whose contents are the value. `compose.yml` uses this for all
   Group-1 secrets, so `docker inspect` and `/proc/<pid>/environ` never expose them. An empty file means "not
   configured".
3. **Infisical runtime fetch** (Group-2, BUNYIP-525), for `SMTP_PASSWORD` only today. It fills the slot *only if* the
   env/file slot is empty.
4. **Database row**, for the settings in section 7 and section 10. Highest precedence, applied after boot, no restart
   needed.

The "Source" column below says where a value comes from in the reference deployment (`compose.yml`):

| Source         | Meaning                                                                                                        |
|----------------|----------------------------------------------------------------------------------------------------------------|
| `.env`         | passed through by compose from the operator's `.env`                                                           |
| secret file    | a compose secret under `/run/secrets/*`, read via `{NAME}_FILE`                                                |
| literal        | hard-coded in the compose file, not operator-settable                                                          |
| **not passed** | the app reads it, but no compose file provides it. Add it to the api service's `environment:` block to use it. |

## Where the integration secrets live

Three secrets have more than one possible store, so "where is it?" is a real question for them and only for
them:

| Secret                | Database                                          | Environment                       | Infisical                |
|-----------------------|---------------------------------------------------|-----------------------------------|--------------------------|
| SMTP password         | `email_config.smtp_password` (+ nonce, `key_version`) | `SMTP_PASSWORD` / `_FILE`     | `/runtime/SMTP_PASSWORD` |
| Stripe secret key     | `stripe_config.secret_key` (+ nonce)              | none (BUNYIP-482 removed the name) | none                     |
| Stripe webhook secret | `stripe_config.webhook_secret` (+ nonce)          | none (BUNYIP-482 removed the name) | none                     |

The database columns are `BYTEA`: AES-256-GCM ciphertext plus nonce under `APP_ENCRYPTION_KEY`, written from the admin
Stripe and Email pages. Confirm what a running deployment actually holds without decrypting anything:

```nu
docker exec bunyip-postgres psql --username postgres --dbname bunyip --command "select (secret_key is not null) as has_secret_key, (webhook_secret is not null) as has_webhook_secret, key_version, updated_at from stripe_config"
docker exec bunyip-postgres psql --username postgres --dbname bunyip --command "select smtp_host, smtp_username, (smtp_password is not null) as has_password, key_version, updated_at from email_config"
docker exec bunyip-api env | lines | where {|l| $l =~ '^SMTP_PASSWORD' }
```

A populated database column plus empty output from the third command means the database row is the live source, and
Infisical will show nothing for that secret however long you look. That is the expected result of the precedence chain
above, not a misconfiguration.

Everything outside this set has exactly one store and no ambiguity: Group-1 startup secrets and the env-only
integration secrets (`FORGEJO_API_TOKEN`, `BUNYIP_UPDATE_CHECK_TOKEN`, `LETS_CHAT_CLIENT_SECRET_HASH`, the two
`INFISICAL_*` credentials) are file-backed environment variables, and nothing else can hold them. `APP_ENCRYPTION_KEY`
is the extreme case: it decrypts the database copies, so it can never live in them.

### Choosing a store, and what each one costs

| Store           | Set from                          | Applies without a restart                 | Cons                                                                                                                                                                                 |
|-----------------|-----------------------------------|-------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Database**    | admin Stripe / Email pages        | yes                                       | the value is only as recoverable as `APP_ENCRYPTION_KEY`; a restore under a rotated key needs `APP_ENCRYPTION_KEY_PREV` and a re-encrypt pass. Secrets live in the same backup as user data. |
| **Environment** | secret file, edited on the host   | no: restart to pick up a new value        | **the admin UI cannot write it**, so those fields are read-only and every rotation is a host edit plus a restart. Needs the Stripe names reintroduced (see below).                     |
| **Infisical**   | admin pages, or Infisical itself  | only for changes made through the admin pages | a remote dependency in the request path for saves, and a boot dependency when it is the declared store. The machine identity needs write access, not just read.                       |

The read-only consequence of `environment` is not a policy choice: a process cannot set an environment variable for its
own next boot, and `/run/secrets/*` is mounted read-only, so a save has nowhere to go. The admin form is read-only there
because the alternative is worse: the handler would encrypt the value into a database row that nothing reads and the
page would report success. Infisical has a write API and bunyip-api already holds a machine identity, so its admin
fields stay editable; the save writes through to Infisical and hot-reloads the affected service.

### Declaring the store, and moving between stores

Today the source is decided by the precedence chain in the previous section, which means a deployment cannot state its
intent and a stale copy in an unread store is invisible. BUNYIP-542 specifies a required `SECRETS_STORAGE` variable
(`environment` | `database` | `infisical`) that supersedes that chain: the declared store becomes the only source
consulted, and the enforcement at boot is

| Situation                                         | Behaviour                                                                      |
|---------------------------------------------------|--------------------------------------------------------------------------------|
| present in the declared store                     | use it                                                                         |
| absent everywhere                                 | feature off, one warning naming the feature                                    |
| absent from the declared store, present in another | fatal: error naming the secret, both stores and the remediation, then exit      |
| present in the declared store and also in another | boot, one warning per duplicate                                                |

Migration between stores is an operator procedure run against a **healthy** deployment, not a restart that either works
or takes the service down. The order matters:

1. `bunyip-api secrets-status` on the running service. Read-only, prints no secret values, and reports per-secret
   readiness for each candidate store.
2. `bunyip-api secrets-migrate --to <store>` copies each secret from its current live source into the target. Into
   `database` and `infisical` it writes directly; for `environment` it cannot write, so it emits the exact secret-file
   paths and `{NAME}_FILE` entries to create.
3. `bunyip-api secrets-status` again, confirming the target store is complete.
4. Set `SECRETS_STORAGE` to the new store and restart. The old copies are still in place, so a wrong value is a
   rollback rather than an outage.
5. Soak, then `bunyip-api secrets-purge --confirm` to remove the copies outside the declared store. This step is
   explicit and never automatic, and the duplicate warning at boot is what reminds you it is still outstanding.

Skipping step 5 is not harmless: a leftover copy becomes live the moment someone changes the mode back.

Two prerequisites are human steps, not code: every deployment must have `SECRETS_STORAGE` in its environment before the
api will boot, and a deployment choosing `infisical` needs its Universal Auth machine identity granted write access to
`INFISICAL_SECRET_PATH`. Runbook: [secrets-infisical.md](secrets-infisical.md).

## 1. Environmental

| Variable      | Read by  | Default      | Source |
|---------------|----------|--------------|--------|
| `ENVIRONMENT` | api      | `production` | `.env` |
| `RUST_LOG`    | api, web | `info`       | `.env` |

`ENVIRONMENT=production` (the default when unset) turns on the strict posture:

- email must resolve to enabled or the api refuses to start (BUNYIP-204),
- an OIDC kid beginning with `dev-` panics at boot (BUNYIP-258),
- `JWT_SECRET` and `BUNYIP_WEBHOOK_SIGNING_SECRET` lose their dev fallbacks and panic when unset,
- `EMAIL_LOG_TOKENS` is forced off so single-use tokens never reach a log.

Any other value (`development`, `staging`) is non-production.

## 2. Hosting

### Listeners

| Variable           | Read by | Default        | Source                                          |
|--------------------|---------|----------------|-------------------------------------------------|
| `HOST_IP`          | api     | `0.0.0.0`      | literal (container), `.env` (host publish side) |
| `APP_PORT`         | api     | `4000`         | literal `4401`                                  |
| `BUNYIP_BIND_ADDR` | web     | `0.0.0.0:4400` | literal                                         |

`HOST_IP` is two different settings that share a name. Inside the container it is the api's bind address and both
compose files hard-code it to `0.0.0.0`. In `.env`
it is the **host-side publish interface** for the port mappings, defaulting to
`127.0.0.1`. Setting `HOST_IP=0.0.0.0` in `.env` publishes the plaintext listeners on every host interface.

`APP_PORT` in `.env` is inert under compose: both files pass `4401` literally. It matters only when running the binary
directly.

### Database

| Variable              | Read by | Default         | Source                            |
|-----------------------|---------|-----------------|-----------------------------------|
| `DATABASE_URL`        | api     | none (required) | secret file `database_url`        |
| `APP_DATABASE_URL`    | api     | none            | secret file `app_database_url`    |
| `BUNYIP_APP_PASSWORD` | api     | none            | secret file `bunyip_app_password` |

`APP_DATABASE_URL` and `BUNYIP_APP_PASSWORD` drive per-user row level security (BUNYIP-344 / BUNYIP-360). When
`BUNYIP_APP_PASSWORD` is set the api creates the
`bunyip_app` (NOSUPERUSER NOBYPASSRLS) role at startup and sets that password on it; `APP_DATABASE_URL` then connects
the self-service pool as that role, so the password embedded in the URL must equal `BUNYIP_APP_PASSWORD`. Both empty
leaves RLS inactive and isolation at the application `WHERE user_id` layer only.

### Proxy trust

| Variable                 | Read by        | Default               | Source                              |
|--------------------------|----------------|-----------------------|-------------------------------------|
| `TRUSTED_PROXY_CIDR`     | api, web       | empty (trust nothing) | `.env`, RFC1918 fallback in compose |
| `WEB_TRUSTED_PROXY_CIDR` | (compose only) | RFC1918 fallback      | `.env`                              |

Comma-separated CIDRs. `X-Forwarded-For` / `X-Real-IP` are honoured only when the immediate socket peer is inside one of
these ranges. `WEB_TRUSTED_PROXY_CIDR` is not read by any binary: compose maps it onto the web service's own
`TRUSTED_PROXY_CIDR` so the two hops can be tuned separately. Full walkthrough:
[client-ip-forwarding.md](client-ip-forwarding.md).

### Service-to-service

| Variable                   | Read by | Default                        | Source |
|----------------------------|---------|--------------------------------|--------|
| `BUNYIP_API_URL`           | web     | `http://localhost:4401`        | `.env` |
| `BUNYIP_API_PUBLIC_ORIGIN` | web     | falls back to `BUNYIP_API_URL` | `.env` |

`BUNYIP_API_PUBLIC_ORIGIN` is the browser-facing origin (BUNYIP-192 / BUNYIP-510), used by the dashboard SSE subscriber
and the Stripe webhook URL the admin page prefills. Left unset in a real deployment, both point at an internal hostname
no browser and no Stripe delivery can reach.

### Compose-only (not read by any binary)

| Variable                                                | Purpose                                                                               |
|---------------------------------------------------------|---------------------------------------------------------------------------------------|
| `BUNYIP_API_IMAGE`, `BUNYIP_WEB_IMAGE`                  | pinned image tags. REQUIRED: `compose.yml` refuses to start without them (BUNYIP-237) |
| `BUNYIP_API_PORT`, `BUNYIP_WEB_PORT`, `BUNYIP_OCI_PORT` | host-side published ports                                                             |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`     | the postgres container's own settings                                                 |
| `HOST_UID`, `HOST_GID`                                  | in-container dev user, dev only                                                       |
| `CARGO_BUILD_JOBS`                                      | build concurrency cap, dev only                                                       |
| `DUNITE_GIT_TOKEN`                                      | optional token for an authed dunite mirror, build time only                           |

## 3. Application

| Variable            | Read by  | Default                                                   | Source         |
|---------------------|----------|-----------------------------------------------------------|----------------|
| `APP_NAME`          | api, web | `localhost` (api), `Bunyip` (web)                         | `.env`         |
| `APP_URL`           | api      | falls back to `CORS_ORIGIN`, then `http://localhost:5173` | **not passed** |
| `BUNYIP_APP_DOMAIN` | web      | empty                                                     | `.env`         |
| `BRAND_DESCRIPTION` | web      | built-in string                                           | **not passed** |
| `BRAND_THEME_CSS`   | web      | none                                                      | **not passed** |

`APP_URL` is the app's public base URL: it is the base for links inside transactional email and the first fallback for
the SMTP EHLO name. No compose file passes it, so in a compose deployment the base URL is always the **first
`CORS_ORIGIN` entry**. Add `APP_URL: ${APP_URL:-}` to the api service's
`environment:` block to make it settable.

## 4. Security and secrets

### Signing and at-rest key material

| Variable                        | Read by | Default                                   | Source                           |
|---------------------------------|---------|-------------------------------------------|----------------------------------|
| `JWT_SECRET`                    | api     | dev placeholder; **panics in production** | secret file `jwt_secret`         |
| `BUNYIP_WEBHOOK_SIGNING_SECRET` | api     | dev placeholder; **panics in production** | **not passed**                   |
| `APP_ENCRYPTION_KEY`            | api     | all-zero dev key                          | secret file `app_encryption_key` |
| `APP_ENCRYPTION_KEY_PREV`       | api     | empty                                     | `.env`                           |
| `APP_KEY_VERSION`               | api     | `1`                                       | **not passed**                   |

`APP_ENCRYPTION_KEY` is the ONE AES-256-GCM at-rest key (BUNYIP-483). It protects
`user_totp`, `stripe_config.secret_key` / `webhook_secret`, and
`email_config.smtp_password` alike. `APP_ENCRYPTION_KEY_PREV` is a comma-separated list of older keys still needed to
READ existing rows; clear it after running `bunyip-api reencrypt-secrets`. Runbook:
[encryption-key-rotation.md](encryption-key-rotation.md).

`BUNYIP_WEBHOOK_SIGNING_SECRET` (BUNYIP-332) signs OUTBOUND webhook dispatches so a receiving RP does not need bunyip's
access-token signing key. It panics at boot in production, and the reference `compose.yml` neither declares it as a
secret nor passes it, and `scripts/init-secrets.nu` does not generate it: a deployment must supply it by hand.

### Browser origin, CORS and cookies

| Variable                             | Read by | Default                   | Source         |
|--------------------------------------|---------|---------------------------|----------------|
| `CORS_ORIGIN`                        | api     | `http://localhost:5173`   | `.env`         |
| `BUNYIP_WEB_ORIGIN`                  | api     | first `CORS_ORIGIN` entry | **not passed** |
| `COOKIE_DOMAIN`                      | api     | none (host-scoped)        | `.env`         |
| `BUNYIP_COOKIE_SHARED_DOMAIN`        | api     | `false`                   | **not passed** |
| `CSP_CONNECT_SRC`, `CSP_FORM_ACTION` | web     | empty                     | **not passed** |

`CORS_ORIGIN` is a comma-separated list and carries three jobs: the CORS allow-list, the CSRF allow-list (BUNYIP-423, a
missing origin gets its cookie-authenticated writes refused with 403), and the fallback base URL (see
`APP_URL`). `BUNYIP_WEB_ORIGIN` pins the single login-UI origin explicitly, which a multi-RP deployment needs so the
authorize handler does not concatenate the comma-list onto `/login`.

`COOKIE_DOMAIN` alone does not share the OP session cookie across subdomains:
`BUNYIP_COOKIE_SHARED_DOMAIN=true` must opt in as well (BUNYIP-266). Setting one without the other logs a warning at
boot.

### First-admin bootstrap

| Variable                | Read by | Default | Source                            |
|-------------------------|---------|---------|-----------------------------------|
| `SETUP_DEFAULT_ADMIN`   | api     | none    | secret file `setup_default_admin` |
| `BOOTSTRAP_ADMIN_EMAIL` | api     | none    | `.env`                            |

`SETUP_DEFAULT_ADMIN` is `email:password` and seeds an admin on first boot.
`BOOTSTRAP_ADMIN_EMAIL` (BUNYIP-290) promotes whoever signs in with that address to admin while zero admins exist, with
no password in the environment; it is inert once any admin exists. That first admin is also the SUPER ADMIN
(`users.is_super_admin`), the only account allowed to change rate limits or ban IPs by hand (BUNYIP-413).
`BOOTSTRAP_ADMIN_EMAIL` is plain-env only: the
`{NAME}_FILE` convention does not apply.

### Opt-in abuse gates

| Variable                   | Read by | Default | Source         |
|----------------------------|---------|---------|----------------|
| `LOGIN_APPROVAL_ENABLED`   | api     | `false` | **not passed** |
| `SIGNUP_BOT_GUARD_ENABLED` | api     | `false` | **not passed** |

Both are off by default because both can reject legitimate traffic:
the login-approval gate (BUNYIP-373) can withhold a login, and the signup bot guard (BUNYIP-377) rejects any register
form that lacks the honeypot and timing token.

## 5. Identity provider (OIDC)

bunyip-api IS the OpenID Provider: it holds the signing key and serves
`/.well-known/*` and `/oauth2/*`. bunyip-web is a relying party. mokosh-server is a Resource Server only.

### bunyip-api as the OP

| Variable                         | Read by | Default                           | Source                      |
|----------------------------------|---------|-----------------------------------|-----------------------------|
| `OIDC_ISSUER`                    | api     | none (OIDC disabled)              | `.env`                      |
| `OIDC_JWT_PRIVATE_KEY_PATH`      | api     | `secrets/jwt_private.pem`         | `.env`, REQUIRED by compose |
| `OIDC_JWT_ACTIVE_KID`            | api     | `dev-key`                         | `.env`, REQUIRED by compose |
| `OIDC_JWT_PUBLIC_KEYS_DIR`       | api     | `secrets`                         | literal `/run/secrets/oidc` |
| `OIDC_ACCESS_TOKEN_TTL_SECONDS`  | api     | `600`, clamped to 60-900          | **not passed**              |
| `OIDC_REFRESH_TOKEN_TTL_SECONDS` | api     | `2592000` (30d)                   | **not passed**              |
| `OIDC_REFRESH_IDLE_TTL_SECONDS`  | api     | `1209600` (14d)                   | **not passed**              |
| `OIDC_CODE_TTL_SECONDS`          | api     | `60`, capped at 120               | **not passed**              |
| `OIDC_RS_AUDIENCE`               | api     | `urn:bunyip:rs`                   | **not passed**              |
| `OIDC_LIFECYCLE_EVENT_KEY`       | api     | `urn:bunyip:event:user-lifecycle` | **not passed**              |

The absence of `OIDC_ISSUER` disables the provider endpoints entirely. The key path and kid have no default in
`compose.yml` and abort `compose up` when unset (BUNYIP-258); a `dev-` prefixed kid panics at boot under
`ENVIRONMENT=production`, because a dev-named kid on production tokens is consumed happily by any RP whose JWKS lookup
follows what the OP advertises.

### bunyip-web as a relying party

| Variable                   | Read by       | Default                        | Source                         |
|----------------------------|---------------|--------------------------------|--------------------------------|
| `BUNYIP_OIDC_ISSUER`       | web           | falls back to `BUNYIP_API_URL` | `.env`                         |
| `BUNYIP_OIDC_CLIENT_ID`    | nothing today | n/a                            | `.env` via compose.dev-sso.yml |
| `BUNYIP_OIDC_REDIRECT_URI` | nothing today | n/a                            | `.env` via compose.dev-sso.yml |
| `BUNYIP_OIDC_SCOPES`       | nothing today | n/a                            | `.env` via compose.dev-sso.yml |

The last three are read by no binary in this workspace. They date from the pre-BUNYIP-299 Dioxus SPA, whose container
entrypoint rendered them into a same-origin `/config.json`; that entrypoint no longer exists. `compose.dev-sso.yml`
still requires `BUNYIP_OIDC_CLIENT_ID` and `BUNYIP_OIDC_REDIRECT_URI` at
`compose up`, and `just register-dev-clients` still prints the hub UUID for the operator to paste into `.env`, so the
value remains useful as a record of which client was registered (mokosh-apps holds its own copy).

## 6. Integrations

### Infisical (Group-2 runtime secrets)

| Variable                                         | Read by | Default | Source         |
|--------------------------------------------------|---------|---------|----------------|
| `INFISICAL_ENABLED`                              | api     | `false` | **not passed** |
| `INFISICAL_ADDRESS`                              | api     | empty   | **not passed** |
| `INFISICAL_PROJECT_ID`                           | api     | empty   | **not passed** |
| `INFISICAL_ENVIRONMENT` (legacy `INFISICAL_ENV`) | api     | empty   | **not passed** |
| `INFISICAL_SECRET_PATH`                          | api     | `/`     | **not passed** |
| `INFISICAL_CLIENT_ID`                            | api     | empty   | **not passed** |
| `INFISICAL_CLIENT_SECRET`                        | api     | empty   | **not passed** |

Group-1 startup secrets are never fetched from Infisical, so Infisical is never a boot dependency. Group-2 secrets
(`SMTP_PASSWORD` today) are fetched at runtime from the project-relative `/runtime` folder via a Universal Auth machine
identity; any failure leaves the feature off and boot continues. The two credentials honour the `{NAME}_FILE` convention
and can themselves be Group-1 file secrets. No compose file in this repo passes these, so enabling the fetch on a
compose deployment means adding them to the api service's `environment:`.
Runbook: [secrets-infisical.md](secrets-infisical.md).

### Email (SMTP)

Every variable here is a **bootstrap default**: the `email_config` DB row (admin Email page) overrides it per field and
applies without a restart (BUNYIP-351).

| Variable                    | Read by | Default                           | Source                      | DB column                   |
|-----------------------------|---------|-----------------------------------|-----------------------------|-----------------------------|
| `EMAIL_ENABLED`             | api     | `false`                           | `.env`                      | `enabled`                   |
| `SMTP_HOST`                 | api     | `localhost`                       | `.env`                      | `smtp_host`                 |
| `SMTP_PORT`                 | api     | `465` implicit / `587` starttls   | `.env`                      | `smtp_port`                 |
| `SMTP_TLS`                  | api     | `implicit`                        | `.env`                      | `smtp_tls`                  |
| `SMTP_USERNAME`             | api     | empty                             | `.env`                      | `smtp_username`             |
| `SMTP_PASSWORD`             | api     | empty, then Infisical             | **not passed** (deliberate) | `smtp_password` (encrypted) |
| `SMTP_FROM`                 | api     | `noreply@localhost`               | `.env`                      | `from_email`, `from_name`   |
| `SMTP_EHLO_NAME`            | api     | see below                         | `.env`                      | **none**                    |
| `ADMIN_NOTIFICATION_EMAILS` | api     | empty                             | `.env`                      | `admin_notification_emails` |
| `EMAIL_LOG_TOKENS`          | api     | `false`, forced off in production | **not passed**              | none                        |

`SMTP_PASSWORD` is one of the three secrets covered by
[Where the integration secrets live](#where-the-integration-secrets-live): which store holds it, what each store costs,
and how to move it.

Two behaviours are worth stating explicitly.

**The production email gate runs before the database is read.** `Config::from_env`
refuses to start when `ENVIRONMENT=production` and the env-only email config resolves to disabled. The `email_config`
row is loaded later, so it cannot satisfy that check. A deployment configured entirely through the admin UI still needs
either a real `SMTP_HOST` or `EMAIL_ENABLED=true` in the environment. Setting
`EMAIL_ENABLED=true` weakens the BUNYIP-204 fail-fast: the app then boots happily even if the DB row is later emptied,
and mail fails at send time instead.

**`SMTP_EHLO_NAME` has no admin-UI equivalent** and no `email_config` column. It is deployment identity (it must match
the sending host's DNS), not per-deployment SMTP tuning, so BUNYIP-507 kept it env-only alongside the base URL. The EHLO
name is resolved when the SMTP transport is built, which happens *after* the DB row is merged, in this order:

1. `SMTP_EHLO_NAME` (env only),
2. the host of the app base URL (env only: `APP_URL`, else `CORS_ORIGIN`),
3. the domain of the **resolved** from-address (`email_config.from_email` when set, else `SMTP_FROM`),
4. lettre's default, which inside a container is the container id and is what BUNYIP-507 existed to stop.

### Stripe

There is no Stripe environment variable (BUNYIP-482), and
`scripts/check-no-stripe-env.nu` fails the build if one reappears. Everything lives in the `stripe_config` row: see
section 10. The only billing env var is the trial-length bootstrap default in section 7. The at-rest key that encrypts
the stored Stripe secrets is `APP_ENCRYPTION_KEY`, which is key material, not Stripe configuration.

The secret key and webhook secret are two of the three secrets covered by
[Where the integration secrets live](#where-the-integration-secrets-live), including the trade-offs of each store and
the migration sequence. Storing them anywhere but the database means reintroducing the two Stripe-prefixed variable
names this guard forbids, as file-backed values only, and amending the guard to allow exactly those two in that form.
BUNYIP-542 covers both halves. Until then the guard is the reason this document does not spell the names out.

### Distribution proxy: downloads and OCI registry

Both verticals stay disabled until `FORGEJO_BASE_URL` and `FORGEJO_API_TOKEN` are set (BUNYIP-28). Token scopes and
reverse-proxy requirements:
[oci-registry-verification.md](oci-registry-verification.md).

| Variable                            | Read by | Default                             | Source                          |
|-------------------------------------|---------|-------------------------------------|---------------------------------|
| `FORGEJO_BASE_URL`                  | api     | none (feature off)                  | `.env`                          |
| `FORGEJO_API_TOKEN`                 | api     | none (feature off)                  | secret file `forgejo_api_token` |
| `FORGEJO_RELEASE_CACHE_TTL_SECS`    | api     | `300`                               | `.env`                          |
| `DOWNLOAD_CACHE_DIR`                | api     | `/var/cache/bunyip-downloads`       | literal                         |
| `DOWNLOAD_CACHE_MAX_BYTES`          | api     | `10737418240` (10 GiB)              | `.env`                          |
| `DOWNLOAD_CONCURRENCY_PER_USER`     | api     | `2`                                 | `.env`                          |
| `DOWNLOAD_DAILY_LIMIT_PER_USER`     | api     | `50`                                | `.env`                          |
| `OCI_REGISTRY_ENABLED`              | api     | `false`                             | `.env`                          |
| `OCI_REGISTRY_PORT`                 | api     | `18081`                             | literal                         |
| `OCI_REGISTRY_SERVICE`              | api     | `oci.example.com`                   | `.env`                          |
| `OCI_REGISTRY_REALM`                | api     | derived from `OCI_REGISTRY_SERVICE` | `.env` (dev compose only)       |
| `OCI_BLOB_CACHE_DIR`                | api     | `/var/cache/bunyip-oci`             | literal                         |
| `OCI_BLOB_CACHE_MAX_BYTES`          | api     | `53687091200` (50 GiB)              | `.env`                          |
| `OCI_MANIFEST_CACHE_TTL_SECS`       | api     | `300`                               | `.env`                          |
| `OCI_CONCURRENT_MANIFESTS_PER_USER` | api     | `2`                                 | `.env`                          |
| `OCI_PULLS_PER_USER_PER_DAY`        | api     | `50`                                | `.env`                          |
| `OCI_TOKEN_TTL_SECS`                | api     | `900`                               | `.env`                          |

`OCI_REGISTRY_SERVICE` is required when the registry is enabled (startup fails fast if empty). Leave
`OCI_REGISTRY_REALM` unset in production: pointing it at a localhost URL tells every docker client to fetch tokens from
its own loopback.

### Mokosh

| Variable                | Read by | Default                     | Source                         |
|-------------------------|---------|-----------------------------|--------------------------------|
| `MOKOSH_BACKUP_API_URL` | api     | none (Backup stays a stub)  | `.env` via compose.dev-sso.yml |
| `MOKOSH_WEBHOOK_URL`    | api     | none (registration skipped) | **not passed**                 |

`MOKOSH_BACKUP_API_URL` (BUNYIP-356) enables the Backup add-on to call Mokosh's
`/api/v1/data/{export,import}` with a short-lived, bunyip-minted Mokosh-audience
`at+jwt`. `MOKOSH_WEBHOOK_URL` is written onto the `mokosh` row in `applications`
at boot; unset leaves whatever the row already holds.

### Let's Chat

| Variable                              | Read by | Default                           | Source         |
|---------------------------------------|---------|-----------------------------------|----------------|
| `LETS_CHAT_REDIRECT_URIS`             | api     | none                              | **not passed** |
| `LETS_CHAT_AUDIENCE`                  | api     | none                              | **not passed** |
| `LETS_CHAT_POST_LOGOUT_REDIRECT_URIS` | api     | empty                             | **not passed** |
| `LETS_CHAT_CLIENT_SECRET_HASH`        | api     | keeps the migration's shared hash | **not passed** |
| `BUNYIP_COMMUNITY_URL`                | web     | empty (button hidden)             | `.env`         |

The first two gate the boot-time upsert of the Let's Chat row in `oauth_clients`:
with either unset, registration is skipped and logged, so an environment that never configured the client cannot
resurface a stale row. All four honour the
`{NAME}_FILE` convention. `BUNYIP_COMMUNITY_URL` (BUNYIP-329) is separate: it is the sidebar Community link in
bunyip-web, and empty hides the button so a deploy without a Let's Chat instance never shows a dead link.

### Update checker

| Variable                    | Read by | Default               | Source                           |
|-----------------------------|---------|-----------------------|----------------------------------|
| `BUNYIP_UPDATE_CHECK_URL`   | api     | none (check disabled) | `.env`                           |
| `BUNYIP_UPDATE_CHECK_TOKEN` | api     | none                  | secret file `update_check_token` |

### GeoIP enrichment

| Variable              | Read by | Default            | Source         |
|-----------------------|---------|--------------------|----------------|
| `IP2LOCATION_DB_PATH` | api     | none (feature off) | **not passed** |
| `IP2PROXY_DB_PATH`    | api     | none (feature off) | **not passed** |

Country resolution for login-location alerts (BUNYIP-366) and ASN / VPN enrichment (BUNYIP-437). Neither `.BIN` ships in
the image, so a deployment must mount the files and pass the paths. Refresh procedure:
[ip2-dataset-refresh.md](ip2-dataset-refresh.md).

## 7. Bootstrap defaults for in-app settings

Precedence for everything in this section is **const -> env -> DB row**. The env var seeds a fresh database; once an
admin saves the setting the row wins and applies without a restart, and a wiped database falls back to the env value.
**None of these is passed through by `compose.yml`**, so a deployment that wants a non-default seed must add it to the
api service's `environment:` block.

| Variable                             | Default    | Admin page        | DB table                               |
|--------------------------------------|------------|-------------------|----------------------------------------|
| `AUTO_BAN_ENABLED`                   | `true`     | Auto-ban settings | `auto_ban_config.enabled`              |
| `AUTO_BAN_THRESHOLD`                 | `5`        | Auto-ban settings | `auto_ban_config.threshold`            |
| `AUTO_BAN_WINDOW_SECS`               | `3600`     | Auto-ban settings | `auto_ban_config.window_secs`          |
| `AUTO_BAN_DURATION_SECS`             | `86400`    | Auto-ban settings | `auto_ban_config.ban_duration_secs`    |
| `RATE_LIMIT_{ACTION}_MAX_REQUESTS`   | per action | Rate Limits       | `rate_limit_configs.max_requests`      |
| `RATE_LIMIT_{ACTION}_WINDOW_SECONDS` | per action | Rate Limits       | `rate_limit_configs.window_seconds`    |
| `TIER_LIFETIME_SLOTS`                | `5`        | Pricing tiers     | `tier_config.lifetime_slots`           |
| `TIER_EARLY_ADOPTER_SLOTS`           | `5`        | Pricing tiers     | `tier_config.early_adopter_slots`      |
| `TIER_EARLY_ADOPTER_TRIAL_DAYS`      | `90`       | Pricing tiers     | `tier_config.early_adopter_trial_days` |
| `TIER_STANDARD_TRIAL_DAYS`           | `30`       | Pricing tiers     | `tier_config.standard_trial_days`      |
| `BUNYIP_BILLING_TRIAL_PERIOD_DAYS`   | `30`       | Stripe            | `stripe_config.trial_period_days`      |

`{ACTION}` is the upper-cased name of each action in `RateLimitConfig::ALL`:
`login`, `magic_link`, `password_reset`, `api_auth`, `api_unauth`, `registration`,
`registration_non_prod`, `oci_token_failures`, `oci_token_throughput`,
`two_factor_verify_failures`, `oci_token_ip_failures`, `oauth_token`,
`oauth_authorize`, `oauth_userinfo`, `oauth_revoke`, `oauth_discovery`,
`feedback_submit`, `smtp_test`. Either half may be set alone; an unparseable or non-positive value is ignored. Editing
rate limits or banning an IP by hand is super-admin-only (BUNYIP-413).

The email bootstrap defaults follow the same rule and are documented with the rest of the SMTP settings in section 6.

## 8. Development, build and test only

| Variable                                                       | Read by              | Purpose                                                                                                 |
|----------------------------------------------------------------|----------------------|---------------------------------------------------------------------------------------------------------|
| `EMAIL_LOG_TOKENS`                                             | api                  | log the full magic-link / reset URL at DEBUG when sending is off. Forced off in production (BUNYIP-204) |
| `BUNYIP_SEED_ALLOW`                                            | seed binary          | must be `true`, and `ENVIRONMENT` must not be production, or the seeder refuses to run                  |
| `BUNYIP_E2E_BOOTSTRAP_ALLOW`                                   | e2e bootstrap binary | same gate for the E2E fixture bootstrap                                                                 |
| `BUNYIP_E2E_TOTP_SECRET`                                       | e2e bootstrap binary | base32 TOTP secret for `--enable-2fa`; needs the same `APP_ENCRYPTION_KEY` as the api                   |
| `BUNYIP_GIT_SHA`                                               | api                  | build metadata surfaced by the version endpoint                                                         |
| `HOST_UID`, `HOST_GID`, `CARGO_BUILD_JOBS`, `DUNITE_GIT_TOKEN` | compose / build      | see section 2                                                                                           |

The E2E harness has its own `E2E_*` variables, documented in
[e2e.md](e2e.md) and `e2e/README.md`. They configure the Playwright suite, not bunyip, and `E2E_STRIPE_SECRET_KEY` is
the only Stripe-shaped name the build guard allows.

## 9. Variables the app reads that compose does not pass

Collected for auditing. Each is inert in the reference deployment until added to the api service's `environment:` block
(or, for the two web entries, the web service's).

| Variable                                                                   | Consequence of the gap                                                                                                       |
|----------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| `BUNYIP_WEBHOOK_SIGNING_SECRET`                                            | **api panics at boot in production.** Not in `compose.yml`'s `secrets:` block and not generated by `scripts/init-secrets.nu` |
| `APP_URL`                                                                  | base URL for email links and the EHLO fallback silently comes from `CORS_ORIGIN`                                             |
| `INFISICAL_*` (7)                                                          | the Group-2 runtime fetch cannot be enabled                                                                                  |
| `APP_KEY_VERSION`                                                          | key rotation cannot stamp a new version                                                                                      |
| `BUNYIP_WEB_ORIGIN`                                                        | multi-RP deployments cannot pin the login-UI origin                                                                          |
| `BUNYIP_COOKIE_SHARED_DOMAIN`                                              | cross-subdomain OP session cookie cannot be enabled                                                                          |
| `LOGIN_APPROVAL_ENABLED`, `SIGNUP_BOT_GUARD_ENABLED`                       | the two opt-in gates cannot be turned on                                                                                     |
| `OIDC_*_TTL_SECONDS`, `OIDC_RS_AUDIENCE`, `OIDC_LIFECYCLE_EVENT_KEY`       | token lifetimes and identifiers are fixed at their defaults                                                                  |
| `MOKOSH_WEBHOOK_URL`                                                       | the `applications.webhook_url` upsert never runs                                                                             |
| `LETS_CHAT_*` (4)                                                          | the Let's Chat OAuth client is never registered from the environment                                                         |
| `IP2LOCATION_DB_PATH`, `IP2PROXY_DB_PATH`                                  | GeoIP enrichment stays off                                                                                                   |
| `AUTO_BAN_*`, `RATE_LIMIT_*`, `TIER_*`, `BUNYIP_BILLING_TRIAL_PERIOD_DAYS` | seeds for a fresh DB cannot be set; the admin UI is the only path                                                            |
| `CSP_CONNECT_SRC`, `CSP_FORM_ACTION`, `BRAND_*` (web)                      | CSP additions and branding overrides are unavailable                                                                         |
| `EMAIL_LOG_TOKENS`                                                         | dev-only; correctly absent from production                                                                                   |

A deployment that runs its own compose file (the PSA hosts use the docker repo's per-host template, not this reference
file) may already pass some of these. This table describes `compose.yml` in this repository.

## 10. In-app settings (no environment variable)

These are edited on the admin pages and stored in the database. They apply without a restart. Nothing here has an
environment-variable equivalent unless the table says so.

### Stripe (`stripe_config`, admin page: Stripe)

Singleton row (`id = 1`). BUNYIP-482 removed every Stripe env var.

| Column                                    | Meaning                                                                                          |
|-------------------------------------------|--------------------------------------------------------------------------------------------------|
| `secret_key` + `secret_key_nonce`         | Stripe API secret key as AES-256-GCM ciphertext plus nonce (`BYTEA`), under `APP_ENCRYPTION_KEY` |
| `webhook_secret` + `webhook_secret_nonce` | Stripe webhook signing secret (`whsec_...`), same encoding                                       |
| `key_version`                             | which key in the set the row was written under                                                   |
| `app_tag`                                 | Stripe app tag                                                                                   |
| `success_url`, `cancel_url`               | checkout redirect targets. Unset defaults to the first `CORS_ORIGIN` entry                       |
| `trial_period_days`                       | signup free trial, 0-365. Env seed: `BUNYIP_BILLING_TRIAL_PERIOD_DAYS`                           |
| `price_id_personal`, `price_id_business`  | from the original table; no current code reads them (per-tier price ids live in `tier_config`)   |

Unconfigured means payment is simply disabled. Test-mode walkthrough:
[stripe-test-mode.md](stripe-test-mode.md).

### Pricing tiers (`tier_config`, admin page: Pricing tiers)

Singleton row. Slot counts and trial lengths have env seeds (section 7); the Stripe identifiers and the publish switch
have **no env source at all**.

| Column                                                                              | Meaning                                                                   |
|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `pricing_enabled`                                                                   | when false the public `/pricing` page 404s and every link to it is hidden |
| `free_price_id`, `lifetime_price_id`, `early_adopter_price_id`, `standard_price_id` | Stripe price ids per tier                                                 |
| `lifetime_product_id`, `early_adopter_product_id`, `standard_product_id`            | Stripe product ids per tier                                               |
| `lifetime_slots`, `early_adopter_slots`                                             | capacity per tier. Env seeds exist                                        |
| `early_adopter_trial_days`, `standard_trial_days`                                   | trial length per tier. Env seeds exist                                    |

### Email (`email_config`, admin page: Email)

Singleton row; every column is nullable and a NULL column falls back to the matching environment variable per field.
Column-to-variable mapping is in section 6. `smtp_password` is stored as ciphertext plus nonce with
`key_version`, encrypted under `APP_ENCRYPTION_KEY`. There is no column for the EHLO name.

### Auto-ban (`auto_ban_config`, admin page: Auto-ban settings)

Singleton row: `enabled`, `threshold`, `window_secs`, `ban_duration_secs`. Every column has an env seed (section 7).
Individual IPs are banned and lifted from the admin IP Bans screen, which is super-admin-only and takes effect on that
address's next request.

### Rate limits (`rate_limit_configs`, admin page: Rate Limits)

One row per action, keyed by the action name, with `max_requests` and
`window_seconds`. A present row overrides both the constant and the env seed. Super-admin-only (BUNYIP-413).

### Applications and OAuth clients

| Table                                                                | Set from                                                   | Notes                                                                |
|----------------------------------------------------------------------|------------------------------------------------------------|----------------------------------------------------------------------|
| `applications.forgejo_owner`, `.forgejo_repo`, `.pinned_release_tag` | admin Applications page                                    | an app is downloadable only when all three are set                   |
| `applications.webhook_url`                                           | admin Applications page                                    | also upserted at boot for the `mokosh` row from `MOKOSH_WEBHOOK_URL` |
| `oauth_clients`                                                      | `just register-dev-clients`, migrations, boot-time upserts | the Let's Chat row is upserted from `LETS_CHAT_*` when those are set |

### Per-user settings

Two-factor enrolment (`user_totp`, encrypted under `APP_ENCRYPTION_KEY`), trusted devices, active sessions and
notification preferences are per-user records managed from the member's own settings pages. They are product state, not
deployment configuration, and are listed here only so the boundary is explicit.
