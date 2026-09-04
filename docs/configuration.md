# Configuration reference

Every environment variable bunyip reads, how its absence is reported at startup, where its value comes from in the
reference deployment, and the settings that are not environment variables at all. If a knob is not in this document, it
does not exist.

The source of truth for the api's variables is `ENV_INVENTORY` in `crates/bunyip-domain/src/config.rs`; a variable read
without an entry there fails `bunyip-api/tests/env_inventory.rs`. The classification tables below are the
operator-facing rendering of that table, so they cannot drift from the code. The three sections that follow them are not
derivable from the inventory:

- [Which provider a running deployment is using](#which-provider-a-running-deployment-is-using), and what each
  provider costs.
- [Compose coverage](#secret-files-and-compose-coverage): what the api reads that this repository's `compose.yml` does
  not pass.
- [Settings that are not environment variables](#settings-that-are-not-environment-variables): the database-backed
  configuration, its admin pages and its columns.

The dividing line for that last one: **environment variables** are read once at process start, so changing one means
restarting the container, and they configure the deployment. **In-app settings** live in the database, are edited on the
admin pages, and apply without a restart, and they configure the product. Where a setting exists in both places the
database row wins, and it wins because that priority is DECLARED: see [configuration providers and their
precedence](#configuration-providers-and-their-precedence-bunyip-643644), which also adds the file provider between the
two and makes the serving provider reportable per key.

Secrets resolve through the `{NAME}_FILE` convention first (a compose secret under `/run/secrets/*`), then the plain
variable (a dev `.env`). An empty value counts as unset everywhere. The exception is the four governed integration
secrets below, which are `{NAME}_FILE`-only and are read only when `SECRETS_STORAGE=environment`.

## The configuration boundary: system-level vs application-level (BUNYIP-622)

Every configuration key is on one of two sides of a security-led boundary. A key is **system-level** when modifying it
grants access to the host, other tenants, or the network boundary. Everything else is **application-level**, including
every integration, because integrations must be manageable in-product by the MSP without a container restart.

The rule matters because of where each side can be written. System-level keys are read from the **environment only** and
have **no file or admin-API write path**: if the API could write one, any flaw that reached the API would become
host- or network-level exposure (adding an origin you do not control, repointing the database, moving the secrets
backend). The split is enforced **structurally, not by a permission check**: the type the admin settings API writes
(`SystemSettings` in `crates/bunyip-domain/src/sys_config.rs`) has no field for a system-level key, and its `entries`
method is the only mapping the code has from a field to a file, so there is no code path to persist one and no guard a
refactor could drop. `SYSTEM_LEVEL_ENV_KEYS` in that file is the machine-checked list;
`system_level_keys_never_enter_the_file_layer` fails the build if one ever becomes writable, or becomes a declared
configuration key the file layer could serve.

**System-level (environment only, never API-writable):**

| Key(s)                                                                                             | Why it is system-level          |
|----------------------------------------------------------------------------------------------------|---------------------------------|
| `CORS_ORIGIN`, `BUNYIP_WEB_ORIGIN`, `COOKIE_DOMAIN`                                                 | origins and domains the deployment trusts |
| `DATABASE_URL`, `APP_DATABASE_URL`, `BUNYIP_APP_PASSWORD`                                           | database connection             |
| `SECRETS_STORAGE`, `INFISICAL_HOST`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_PROJECT_ID`, `INFISICAL_ENVIRONMENT` | secrets backend location and credentials |
| `JWT_SECRET`, `APP_ENCRYPTION_KEY` (+ `_PREV`, `_VERSION`)                                          | signing and at-rest key material |

**Application-level (product-managed):** everything else. This includes every integration (SMTP, Stripe, IMAP, the OCI
registry, GeoIP), which is managed in the database through the admin pages (see [settings that are not environment
variables](#settings-that-are-not-environment-variables)), and the deployment toggles the [file
layer](#the-application-level-deployment-settings-and-the-admin-system-page-bunyip-579580622644) carries
(`LOGIN_APPROVAL_ENABLED`, `SIGNUP_BOT_GUARD_ENABLED`, `COUNTRY_ALLOW`, `COUNTRY_DENY`). A corollary the boundary must hold:
creating a username and password does not depend on any integration, so a self-hosted install with no email configured
can still create its first account (`account_creation_does_not_depend_on_the_email_integration` in
`services/auth.rs`).

The remaining environment variables in the tables below (ports, log level, tunables, feature-gating flags for
integrations) are application-level operational settings: they are read from the environment for operator convenience,
but none is API-writable, so none can be used to cross a trust boundary.

## The reporting contract (BUNYIP-537)

| Classification            | At startup                                                                     |
|---------------------------|--------------------------------------------------------------------------------|
| Required                  | one `ERROR` naming the variable, the reason and the remedy, then exit 1        |
| Required in production    | the same, but only when `ENVIRONMENT=production`; other environments fall back |
| Feature-gating (optional) | one `WARN` naming the variable and the functionality that is off               |
| Defaulted (optional)      | nothing: the default works and is documented below                             |

All required failures are collected in ONE pass, so a deployment missing four variables learns about all four in one
boot instead of one per restart. Nothing in this path panics: a configuration mistake reads as a configuration error,
not as a crash with exit code 101.

Some entries are *gated*: they are only demanded (or warned about) once the variable that switches their feature on is
itself set. `OIDC_JWT_ACTIVE_KID` is required only when `OIDC_ISSUER` is set; `INFISICAL_ADDRESS` warns only when
`INFISICAL_ENABLED` is on. That keeps an unused integration to one line rather than one per variable in its group.

## Required

| Variable                        | Gate          | Why the api will not start without it                                                                         |
|---------------------------------|---------------|---------------------------------------------------------------------------------------------------------------|
| `DATABASE_URL`                  | -             | the api cannot connect to postgres (required in every environment)                                            |
| `SECRETS_STORAGE`               | -             | the deployment has not declared where its integration secrets live (required in every environment, see below) |
| `JWT_SECRET`                    | -             | no signing key for session access/refresh tokens                                                              |
| `APP_ENCRYPTION_KEY`            | -             | no at-rest key for the TOTP, Stripe and SMTP secrets (BUNYIP-483)                                             |
| `BUNYIP_WEBHOOK_SIGNING_SECRET` | -             | no HMAC key for outbound webhook dispatches (BUNYIP-332)                                                      |
| `OIDC_JWT_PRIVATE_KEY_PATH`     | `OIDC_ISSUER` | the OIDC provider would sign with the development key path                                                    |
| `OIDC_JWT_ACTIVE_KID`           | `OIDC_ISSUER` | a `dev-` kid in production is consumed by RPs as legitimate (BUNYIP-258); also value-checked                  |
| `SMTP_HOST` / `EMAIL_ENABLED`   | -             | email disabled in production would log single-use login/reset tokens instead of sending them (BUNYIP-204)     |

Every one except `DATABASE_URL` and `SECRETS_STORAGE` is required only on `ENVIRONMENT=production`; development and
staging fall back to documented placeholder values.

## `SECRETS_STORAGE`: where the integration secrets live (BUNYIP-542)

`SECRETS_STORAGE` declares the ONE provider bunyip reads its governed integration secrets from. Legal values:
`environment`, `database`, `infisical`. Unset or unrecognised logs one `ERROR` naming the legal set and exits 1.

**Why the variable says storage and everything else says provider.** The suite's word for a selectable implementation
is **provider**, and bunyip's code says `SecretsProvider` (BUNYIP-642). The variable keeps its `SECRETS_STORAGE`
spelling and the subcommands keep their `secrets-status` / `secrets-migrate` / `secrets-purge` names, deliberately:
renaming either breaks every running deployment and every runbook for a vocabulary change with no functional gain. The
`secrets-status --json` keys and the `secrets_storage` field of the admin API responses are unchanged for the same
reason.

The governed set is exactly the secrets with more than one possible provider:

| Secret                  | `database`                     | `environment`                | `infisical`                    |
|-------------------------|--------------------------------|------------------------------|--------------------------------|
| `SMTP_PASSWORD`         | `email_config.smtp_password`   | `SMTP_PASSWORD_FILE`         | `<path>/SMTP_PASSWORD`         |
| `STRIPE_SECRET_KEY`     | `stripe_config.secret_key`     | `STRIPE_SECRET_KEY_FILE`     | `<path>/STRIPE_SECRET_KEY`     |
| `STRIPE_WEBHOOK_SECRET` | `stripe_config.webhook_secret` | `STRIPE_WEBHOOK_SECRET_FILE` | `<path>/STRIPE_WEBHOOK_SECRET` |
| `SUPPORT_IMAP_PASSWORD` | `email_config.imap_password`   | `SUPPORT_IMAP_PASSWORD_FILE` | `<path>/SUPPORT_IMAP_PASSWORD` |

The declared provider is the ONLY one consulted. There is no fallback and no precedence chain: in `database` mode the
environment slot and Infisical are not read at all, and vice versa. Group-1 startup secrets (`DATABASE_URL`,
`JWT_SECRET`, `APP_ENCRYPTION_KEY`, ...) cannot be governed by this switch - the database cannot hold the credential
used to reach the database - and stay file-based.

In `environment` mode a governed secret is read from `{NAME}_FILE` ONLY. A plain `STRIPE_SECRET_KEY=sk_live_...` in a
compose `environment:` block is visible to `docker inspect` and to every child process, so it is deliberately not
consulted.

### Startup enforcement, per governed secret

| Situation                                             | Behaviour                                                                                   |
|-------------------------------------------------------|---------------------------------------------------------------------------------------------|
| present in the declared provider                      | use it                                                                                      |
| absent everywhere                                     | feature off, one `WARN` naming the secret and the feature it gates                          |
| absent from the declared provider, present in another | **fatal**: one `ERROR` naming the secret, both providers and `secrets-migrate`, then exit 1 |
| present in the declared provider AND in another       | boot, and one `WARN` per duplicate naming `secrets-purge`                                   |

"Present" means a non-null ciphertext column (database), a non-empty `{NAME}_FILE` read (environment), or a successful
key read (infisical). The duplicate warning is what keeps a later mode change honest: a stale copy in a provider nobody
reads today becomes live the moment someone flips the mode.

`infisical` mode is **fail-closed**: an unreachable Infisical or a failed read aborts the boot, because the operator
declared it the provider of record. `database` and `environment` mode never contact Infisical at boot, so it stays off the
boot path for them.

### Writing from the admin pages

| Mode          | Admin Stripe / Email secret fields                                                                                                                                      |
|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `database`    | editable; encrypted under `APP_ENCRYPTION_KEY`, written to the row, service hot-reloaded                                                                                |
| `infisical`   | editable; written to `INFISICAL_SECRET_PATH` through the API (no DB write), service hot-reloaded, and an audit entry records the admin, the secret and the target provider |
| `environment` | read-only, labelled with the owning provider and the file to edit; the API answers 409                                                                                    |

A failed Infisical write surfaces on the form and in the log with the underlying cause, performs no reload and reports
no success. The machine identity needs **write** access to `INFISICAL_SECRET_PATH`; read access alone fails the save.

Non-secret configuration (`smtp_host`, `smtp_port`, `smtp_tls`, `smtp_username`,
`from_email`, the checkout URLs, the tier ids) stays editable in every mode: the switch governs secrets only.

### Restart versus hot-apply

Only a change made through the admin pages hot-applies. A value changed directly in Infisical, or in a secret file,
takes effect on the next restart, because the boot read is the only reader.

### Which provider a running deployment is using

`bunyip-api secrets-status` answers this from inside the container. To confirm from outside, without decrypting
anything:

```nu
docker exec bunyip-postgres psql --username postgres --dbname bunyip --command "select (secret_key is not null) as has_secret_key, (webhook_secret is not null) as has_webhook_secret, key_version, updated_at from stripe_config"
docker exec bunyip-postgres psql --username postgres --dbname bunyip --command "select smtp_host, smtp_username, (smtp_password is not null) as has_password, key_version, updated_at from email_config"
docker exec bunyip-api env | lines | where {|l| $l =~ '^(SECRETS_STORAGE|SMTP_PASSWORD)' }
```

A populated column with `SECRETS_STORAGE=database` means the row is the live source, and Infisical holding nothing for
that secret is the expected result rather than a misconfiguration. The database columns are `BYTEA`: AES-256-GCM
ciphertext plus nonce under `APP_ENCRYPTION_KEY`.

### What each provider costs

| Provider        | Set from                         | Applies without a restart                     | Cons                                                                                                                                                                        |
|-----------------|----------------------------------|-----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **database**    | admin Stripe / Email pages       | yes                                           | recoverable only with `APP_ENCRYPTION_KEY`; a restore under a rotated key needs `APP_ENCRYPTION_KEY_PREV` and a re-encrypt pass. The secrets share a backup with user data. |
| **environment** | secret file, edited on the host  | no: restart to pick up a new value            | **the admin UI cannot write it**, so those fields are read-only and every rotation is a host edit plus a restart.                                                           |
| **infisical**   | admin pages, or Infisical itself | only for changes made through the admin pages | a remote dependency in the save path, and a boot dependency when declared. The machine identity needs write access, not just read.                                          |

The read-only consequence of `environment` is structural, not a policy choice: a process cannot set an environment
variable for its own next boot and `/run/secrets/*` is mounted read-only, so a save has nowhere to go. The admin form is
read-only there because the alternative is worse, namely a handler that encrypts the value into a row nothing reads
while the page reports success.

### Changing the provider

Never by editing `SECRETS_STORAGE` and hoping. The pre-flight runs while the current deployment is healthy: `bunyip-api
secrets-status`, then `secrets-migrate --to <target>`, then `secrets-status` again, then set `SECRETS_STORAGE`, restart,
soak, and finally `secrets-purge --confirm`. The full runbook is in [ `secrets-infisical.md`](secrets-infisical.md).

Changing the Infisical **instance** (rather than the provider) needs the database as a staging hop, because bunyip-api
holds one set of `INFISICAL_*` values and can never see both instances at once. That procedure is tracked in BUNYIP-544
and belongs in the same runbook.

## Configuration providers and their precedence (BUNYIP-643/644)

`SECRETS_STORAGE` declares the ONE provider the governed secrets come from. Configuration is different: it comes from
several providers at once, in a **declared priority order**, and which one served a given value is reportable rather
than something you have to read the code to work out.

| Priority | Provider      | Where it is                                                          | Applies without a restart |
|----------|---------------|-----------------------------------------------------------------------|---------------------------|
| 1        | `database`    | the admin-managed rows: `email_config`, `auto_ban_config`, `tier_config`, `rate_limit_configs` | yes, the save hot-reloads |
| 2        | `file`        | `BUNYIP_CONFIG_DIR` (default `/app/config`), one file per key           | no, restart to apply      |
| 3        | `environment` | the variables in the tables above                                      | no, restart to apply      |

The highest-priority provider that holds a key serves it; when none does, the built-in default stands. The database is
first because that is where it already was: before BUNYIP-643 the `email_config` / `auto_ban_config` / `tier_config`
rows were applied on top of the environment per field, so an existing deployment resolves exactly the values it
resolved before. The file layer sits above the environment because a file that could not override a value baked
into compose would not be editable without a redeploy, which is the reason it exists. It is the ONE file-based layer:
BUNYIP-644 folded the YAML file that used to sit below the environment into it, and there is no second on-disk shape
and no second precedence rule.

The registry is the settings with **more than one** possible provider, the same rule the governed secrets follow: a
setting with exactly one source is not declared, because the declaration would be a no-op. So the Stripe price ids,
`pricing_enabled`, `orgs_enabled` and the per-tier visibility flags stay database-only columns, and `SMTP_EHLO_NAME`,
`APP_URL`, `APP_NAME`, `SUPPORT_INBOX_EMAIL` and `SUPPORT_IMAP_POLL_SECS` stay environment-only reads. The declared
keys are the SMTP and IMAP settings, `EMAIL_ENABLED`, `ADMIN_NOTIFICATION_EMAILS`, the four `AUTO_BAN_*` values, the
four `TIER_*` slot and trial lengths, the four application-level deployment settings the admin System page writes
(`LOGIN_APPROVAL_ENABLED`, `SIGNUP_BOT_GUARD_ENABLED`, `COUNTRY_ALLOW`, `COUNTRY_DENY`), and the
`RATE_LIMIT_{ACTION}_MAX_REQUESTS` / `_WINDOW_SECONDS` pair for every rate-limit action; `CONFIG_KEYS` in
`crates/bunyip-domain/src/config_providers.rs` is the source of truth, and every entry names a variable
`ENV_INVENTORY` classifies.

The rate-limit pair is the one part of both registries that is **generated** rather than written down (BUNYIP-645). Its
variable names are built from the action, so there is one pair per entry in `RateLimitConfig::ALL`
(`crates/bunyip-domain/src/models/rate_limit.rs`) in `CONFIG_KEYS` and in `ENV_INVENTORY` alike: adding an action
declares its cap in both, and neither registry can drift from the preset list. That is why the caps were the last
configuration outside this stack, and it is the only exception to "one `spec` per line".

### The file layer

There is **one** file-based configuration layer (BUNYIP-644): a directory, one file per key. `BUNYIP_CONFIG_DIR` names
it and defaults to `/app/config`, which the api image creates writable and `compose.yml` mounts as the named volume
`bunyip-config-layer`, so an edit outlives the container. A default directory that does not exist means the deployment
simply has no file layer, and configuration resolves from the database and the environment alone; a directory named
explicitly that cannot be read is an `ERROR` and reports as unreadable rather than as empty.

```nu
"smtp.example.net" | save --raw /app/config/SMTP_HOST
"587"              | save --raw /app/config/SMTP_PORT
"starttls"         | save --raw /app/config/SMTP_TLS
```

- A file is named for the key (`SMTP_FROM_EMAIL`) or for the variable that carries it (`SMTP_FROM`, which supplies both
  the address and the display name exactly as the environment variable does). A file named for the key wins.
- Contents are trimmed; an **empty file counts as absent**, not as an empty value.
- A file whose name is not a declared key is ignored with a `WARN` naming it, so a typo is visible rather than inert.
- The layer sits **above the environment**, so an operator edit changes a value compose already sets without a
  redeploy. That is the whole reason it exists.
- Nothing in bunyip writes it **except** the admin **System** page, and that page writes exactly the four
  application-level deployment settings below and nothing else. The write path is a type with no field for a
  system-level key, so the [configuration
  boundary](#the-configuration-boundary-system-level-vs-application-level-bunyip-622) does not move: an
  application-level setting is meant to be product-managed, and a system-level one still has no file or API write path
  at all.
- A rate-limit cap can be set here too, one file per key: `RATE_LIMIT_LOGIN_MAX_REQUESTS` sits between an admin-set
  `rate_limit_configs` row and the compose variable of the same name (BUNYIP-645).
- Group-1 startup values (`DATABASE_URL`, `APP_ENCRYPTION_KEY`, `JWT_SECRET`, `SECRETS_STORAGE`, the `INFISICAL_*`
  credentials) are environment-and-file only. The database provider **refuses** one with a startup error naming it and
  exit 1, because the database cannot hold the credential used to reach the database.

### The application-level deployment settings and the admin System page (BUNYIP-579/580/622/644)

Four settings are deployment toggles rather than product data, so they live in the file layer instead of the database:
`LOGIN_APPROVAL_ENABLED`, `SIGNUP_BOT_GUARD_ENABLED`, `COUNTRY_ALLOW` and `COUNTRY_DENY`. They are ordinary declared
keys, resolved by the same precedence as everything else: the file layer, then the environment variable of the same
name, then the built-in default. They have no database provider.

- **Admin screen** (BUNYIP-580): **Admin -> System** (`/admin/system-config`) edits them through a form. It shows the
  **effective** values, so what you save is what you were looking at. A save validates the values (country codes are
  2-letter) and writes one file per setting, each atomically; a cleared field removes its file, which is what "absent"
  means in this layer. Changes apply on the next restart.
- **Provenance on the page** (BUNYIP-648): under each field the page names the provider serving that setting and what
  saving will do to the others, so the two cases you would otherwise only find in the boot log or in `config-status`
  are on the screen you are editing. `GET /v1/admin/system-config` carries them per setting as the provider serving it,
  its `use` / `default` / `overridden` / `shadowed` condition and the providers holding it: the same facts
  `config-status` reports, and, like it, **no configuration value**. The four lines an operator sees:
    - the file layer serves it, and this form writes that layer;
    - the environment variable of the same name serves it, and saving here writes the file layer, which overrides that
      variable from the next restart;
    - the file layer serves it and the environment variable also sets it, so that copy is ignored today and becomes
      live again if the file value is cleared;
    - no provider sets it, so the built-in default applies.
- **Boundary**: the form and the request body have no field for a system-level origin, and neither does the type the
  handler writes, so the API has no path to persist one (BUNYIP-622). `SYSTEM_LEVEL_ENV_KEYS` in
  `crates/bunyip-domain/src/sys_config.rs` is the machine-checked list and
  `system_level_keys_never_enter_the_file_layer` fails the build if one ever becomes writable or becomes a declared
  key the file layer could serve.

**Migrating from the YAML file.** These settings used to live in a second file-based layer of their own: a YAML file at
`BUNYIP_CONFIG_FILE` (default `/app/config/config.yaml`), which ranked BELOW the environment. That layer is gone. On
the first start after the upgrade the api migrates it, needing no operator action:

- Each setting the YAML file holds is written as its own file in the file layer directory, then the YAML file is
  renamed to `config.yaml.migrated` and never read as configuration again. Each step logs at `INFO` naming the key.
- A setting the **environment** also holds is **dropped rather than migrated**, with one `WARN` naming it. The
  environment was already winning, and the file layer now outranks the environment, so carrying the value across would
  change the value the deployment resolves. Nothing else changes what a deployment resolves.
- A setting that already has a per-key file keeps the per-key file; the YAML value for it is dropped with an `INFO`.
- If a file cannot be written the value is still served from memory for that boot, an `ERROR` names the key, the YAML
  file is not renamed, and the migration is retried on the next start.

Two smaller changes come with it. The `{NAME}_FILE` indirection no longer applies to these four settings: the per-key
file in the layer directory is the file-based way to set them (the indirection is unchanged for secrets and for the
system-level keys). And `COUNTRY_ALLOW` / `COUNTRY_DENY` are now environment variables as well, comma separated, which
they were not under the YAML layer.

### Which provider is serving each value

```nu
docker exec bunyip-api bunyip-api config-status
docker exec bunyip-api bunyip-api config-status --json
```

Per key it prints the providers holding a value, the one serving it, and one of four conditions. No configuration value
is ever printed, exactly as `secrets-status` never prints a secret. The four conditions mirror the secrets enforcement
table:

| Condition     | Meaning                                                                | Secrets equivalent |
|---------------|------------------------------------------------------------------------|--------------------|
| `use`         | only the highest-priority provider holds it                            | used               |
| `default`     | no provider holds it, so the built-in default configures the setting   | feature off        |
| `overridden`  | the highest-priority provider holds it and so does a lower one, whose value is ignored today and becomes live if the higher one is cleared | duplicate |
| `shadowed`    | the highest-priority provider does not hold it, so a lower one serves  | misplaced          |

The severity differs in one place, deliberately. For a secret, "absent from the declared provider but present in
another" is FATAL, because the deployment declared ONE provider. For configuration it is `shadowed`, and it is normal: the
precedence is an order, and a lower provider serving a key is how an override is meant to work. Only `overridden` is
logged at boot, one `WARN` per ignored provider, which is the stale-copy case worth knowing about.

## Feature-gating (one `WARN`, boot continues)

| Variable                                | Gate                        | What is off without it                                              |
|-----------------------------------------|-----------------------------|---------------------------------------------------------------------|
| `APP_DATABASE_URL`                      | -                           | per-user RLS: reads fall back to the RLS-bypassing pool             |
| `BUNYIP_APP_PASSWORD`                   | -                           | the unprivileged `bunyip_app` RLS role is not provisioned           |
| `SETUP_DEFAULT_ADMIN`                   | -                           | no bootstrap admin is seeded                                        |
| `BOOTSTRAP_ADMIN_EMAIL`                 | -                           | no account is auto-promoted to first admin / super admin            |
| `TRUSTED_PROXY_CIDR`                    | -                           | forwarded client IPs are dropped (audit / rate limit see the proxy) |
| `OIDC_ISSUER`                           | -                           | the whole OIDC provider: no RP can log in through bunyip            |
| `FORGEJO_BASE_URL`                      | -                           | the distribution proxy has no upstream                              |
| `FORGEJO_API_TOKEN`                     | -                           | downloads cannot authenticate to Forgejo                            |
| `OCI_REGISTRY_ENABLED`                  | -                           | the OCI registry endpoint                                           |
| `OCI_REGISTRY_SERVICE`                  | `OCI_REGISTRY_ENABLED`      | the registry token realm cannot be derived                          |
| `SMTP_HOST`                             | -                           | transactional email (outside production, where it is required)      |
| `MAILER_WEBHOOK_SECRET`                 | -                           | the mailer bounce/complaint feedback webhook: the shared suppression list is never fed |
| `ADMIN_NOTIFICATION_EMAILS`             | `SMTP_HOST`                 | admin notifications have no recipient                               |
| `IP2LOCATION_DB_PATH`                   | -                           | GeoIP enrichment on login-location alerts                           |
| `IP2PROXY_DB_PATH`                      | -                           | ASN / VPN enrichment on login alerts                                |
| `BUNYIP_UPDATE_CHECK_URL`               | -                           | the operator update checker                                         |
| `BUNYIP_UPDATE_CHECK_TOKEN`             | `BUNYIP_UPDATE_CHECK_URL`   | authenticated access to a private release feed                      |
| `INFISICAL_ENABLED`                     | -                           | inspecting the Infisical provider (`secrets-status` readiness)      |
| `INFISICAL_ADDRESS`                     | `INFISICAL_ENABLED`         | the Infisical server address                                        |
| `INFISICAL_PROJECT_ID`                  | `INFISICAL_ENABLED`         | the Infisical project                                               |
| `INFISICAL_CLIENT_ID`                   | `INFISICAL_ENABLED`         | the Universal Auth machine identity                                 |
| `INFISICAL_CLIENT_SECRET`               | `INFISICAL_ENABLED`         | the Universal Auth machine-identity secret                          |
| `MOKOSH_APPS_REDIRECT_URIS`             | -                           | the mokosh-apps OIDC client keeps the migration-seeded URIs         |
| `MOKOSH_APPS_AUDIENCE`                  | -                           | the mokosh-apps OIDC client is not reconciled                       |
| `MOKOSH_APPS_POST_LOGOUT_REDIRECT_URIS` | `MOKOSH_APPS_REDIRECT_URIS` | its post-logout redirect list is reconciled empty                   |
| `DRILLMARK_REDIRECT_URIS`               | -                           | the drillmark OIDC client keeps the migration-seeded URIs           |
| `DRILLMARK_AUDIENCE`                    | -                           | the drillmark OIDC client is not reconciled                         |
| `DRILLMARK_POST_LOGOUT_REDIRECT_URIS`   | `DRILLMARK_REDIRECT_URIS`   | its post-logout redirect list is reconciled empty                   |
| `LETS_CHAT_REDIRECT_URIS`               | -                           | the lets-chat OIDC client keeps the migration-seeded URIs           |
| `LETS_CHAT_AUDIENCE`                    | -                           | the lets-chat OIDC client is not reconciled                         |
| `LETS_CHAT_POST_LOGOUT_REDIRECT_URIS`   | `LETS_CHAT_REDIRECT_URIS`   | its post-logout redirect list is reconciled empty                   |
| `LETS_CHAT_CLIENT_SECRET_HASH`          | `LETS_CHAT_REDIRECT_URIS`   | the client keeps the migration's shared secret hash                 |
| `MOKOSH_WEBHOOK_URL`                    | -                           | `account_deleted` events are never dispatched to mokosh             |
| `MOKOSH_BACKUP_API_URL`                 | -                           | account backup/restore falls back to the pending stub               |

## Defaulted (no boot-time log)

Every variable below has a working default; set it only to tune the deployment.

- **Configuration providers**: `BUNYIP_CONFIG_DIR` - the directory the file layer reads and the admin System page
  writes, one file per key (BUNYIP-643/644); default `/app/config`, and a default directory that does not exist means
  the deployment has no file layer. `BUNYIP_CONFIG_FILE` - the LEGACY YAML file, read once and migrated into that
  directory, then renamed aside. See [configuration providers and their
  precedence](#configuration-providers-and-their-precedence-bunyip-643644).
- **Identity and transport**: `ENVIRONMENT` (unset means `production`), `APP_NAME` (the BOOTSTRAP product name only:
  see [Branding](#branding-branding-admin-page-branding)), `APP_URL`, `HOST_IP`, `APP_PORT`, `RUST_LOG`, `CORS_ORIGIN`,
  `BUNYIP_WEB_ORIGIN`, `COOKIE_DOMAIN`, `BUNYIP_COOKIE_SHARED_DOMAIN`.
- **At-rest keys**: `APP_ENCRYPTION_KEY_PREV`, `APP_KEY_VERSION` (see [
  `encryption-key-rotation.md`](encryption-key-rotation.md)).
- **Email**: `EMAIL_ENABLED`, `EMAIL_LOG_TOKENS`, `SMTP_PORT`, `SMTP_TLS`,
  `SMTP_USERNAME`, `SMTP_EHLO_NAME`, `SMTP_FROM`, `SUPPORT_INBOX_EMAIL` (Reply-To for system mail: the monitored support
  inbox replies are ingested into, BUNYIP-571), and the inbound IMAP poller settings `SUPPORT_IMAP_HOST`,
  `SUPPORT_IMAP_PORT`, `SUPPORT_IMAP_USERNAME`, `SUPPORT_IMAP_MAILBOX`, `SUPPORT_IMAP_ENABLED`,
  `SUPPORT_IMAP_POLL_SECS`.
- **Governed secrets** (read only when `SECRETS_STORAGE=environment`, and only as `{NAME}_FILE`): `SMTP_PASSWORD`,
  `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `SUPPORT_IMAP_PASSWORD`.
- **Abuse controls**: `AUTO_BAN_ENABLED`, `AUTO_BAN_THRESHOLD`, `AUTO_BAN_WINDOW_SECS`, `AUTO_BAN_DURATION_SECS`,
  `LOGIN_APPROVAL_ENABLED`, `SIGNUP_BOT_GUARD_ENABLED`, `COUNTRY_ALLOW`, `COUNTRY_DENY`. The last four are also the
  [admin System page's settings](#the-application-level-deployment-settings-and-the-admin-system-page-bunyip-579580622644),
  so a file in the layer directory overrides the variable of the same name.
- **Rate limits**: `RATE_LIMIT_{ACTION}_MAX_REQUESTS` and `RATE_LIMIT_{ACTION}_WINDOW_SECONDS`, one pair per action
  (`crates/bunyip-domain/src/models/rate_limit.rs`). They are declared configuration keys, generated from the preset
  list, and resolve in the [declared provider order](#configuration-providers-and-their-precedence-bunyip-643644): the
  `rate_limit_configs` row, then a file under `BUNYIP_CONFIG_DIR`, then these variables, then the compile-time cap. A
  value that does not parse or is not positive is not a value: the next provider serves it and a `WARN` names both.
- **Tiers and billing**: `TIER_LIFETIME_SLOTS`, `TIER_EARLY_ADOPTER_SLOTS`, `TIER_EARLY_ADOPTER_TRIAL_DAYS`,
  `TIER_STANDARD_TRIAL_DAYS`, `BUNYIP_BILLING_TRIAL_PERIOD_DAYS`.
- **Distribution proxy**: `DOWNLOAD_CACHE_DIR`, `DOWNLOAD_CACHE_MAX_BYTES`, `DOWNLOAD_CONCURRENCY_PER_USER`,
  `DOWNLOAD_DAILY_LIMIT_PER_USER`, `FORGEJO_RELEASE_CACHE_TTL_SECS`.
- **OCI registry**: `OCI_REGISTRY_PORT`, `OCI_REGISTRY_REALM`, `OCI_BLOB_CACHE_DIR`, `OCI_BLOB_CACHE_MAX_BYTES`,
  `OCI_MANIFEST_CACHE_TTL_SECS`, `OCI_CONCURRENT_MANIFESTS_PER_USER`, `OCI_PULLS_PER_USER_PER_DAY`,
  `OCI_TOKEN_TTL_SECS`.
- **OIDC**: `OIDC_JWT_PUBLIC_KEYS_DIR`, `OIDC_ACCESS_TOKEN_TTL_SECONDS`, `OIDC_REFRESH_TOKEN_TTL_SECONDS`,
  `OIDC_REFRESH_IDLE_TTL_SECONDS`, `OIDC_CODE_TTL_SECONDS`, `OIDC_LIFECYCLE_EVENT_KEY`, `OIDC_RS_AUDIENCE`.
- **Infisical**: `INFISICAL_SECRET_PATH`, `INFISICAL_ENVIRONMENT` (read verbatim; must match the environment slug
  configured under Infisical > Secrets > Project > Settings > Environments exactly, e.g. `prod`).
- **Diagnostics**: `DB_POOL_METRICS_INTERVAL_SECS` - seconds between database pool samples (`size` / `idle` / `in_use` /
  `acquire_timeouts`, one `INFO` line per pool). Unset, empty or `0` means no sampling, which is the normal posture; set
  it (30 is a sensible value) while investigating database contention. The acquire-timeout counter is collected either
  way; only the periodic line is gated. See
  [`api-performance-measurements.md`](api-performance-measurements.md).
- **Non-production tooling**: `BUNYIP_E2E_BOOTSTRAP_ALLOW`, `BUNYIP_E2E_TOTP_SECRET`, `BUNYIP_SEED_ALLOW`,
  `BUNYIP_GIT_SHA`.

## Secret files and compose coverage

The reference `compose.yml` passes every required secret as a `{NAME}_FILE` secret, so `just init-secrets` followed by
`docker compose up` boots on `ENVIRONMENT=production` with no manual step. `SECRETS_STORAGE` is the one required
variable it passes with **no default** (`${SECRETS_STORAGE:?...}`), so `docker compose up` aborts until the deployment
states where its integration secrets live. `compose.dev.yml` and `compose.dev-sso.yml` default it to `database`, which
is what dev has always used, so `just dev` is unchanged. The secret files, their "empty allowed" status and the rotation
procedure are in [`secrets-infisical.md`](secrets-infisical.md).

The feature-gating variables are deliberately NOT all passed by `compose.yml`: a self-host with no Forgejo, no GeoIP
data, no Infisical and no RPs is a supported deployment. Each one it omits produces the single boot warning above, which
is how an operator tells "off because I chose so" from "off because I forgot".

### The gaps, explicitly

Every inventory entry the reference `compose.yml` does not pass through, so the gaps are visible instead of implied.
Each is inert until added to the api service's `environment:` block. A deployment running its own compose file (the PSA
hosts use the docker repo's per-host template) may already pass some of these; this table describes `compose.yml` in
this repository.

| Variable                                                            | Consequence of the gap                                                                       |
|---------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| `SMTP_PASSWORD`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`       | deliberate: governed secrets, read only as `{NAME}_FILE` under `SECRETS_STORAGE=environment` |
| `APP_URL`                                                           | the base URL for email links and the EHLO fallback silently comes from `CORS_ORIGIN`         |
| `INFISICAL_*` (7)                                                   | the `infisical` provider cannot be selected or inspected                                     |
| `BUNYIP_WEB_ORIGIN`                                                 | a multi-RP deployment cannot pin the login-UI origin                                         |
| `BUNYIP_COOKIE_SHARED_DOMAIN`                                       | the cross-subdomain OP session cookie cannot be enabled                                      |
| `MOKOSH_APPS_*`, `DRILLMARK_*`, `LETS_CHAT_*`                       | those OIDC clients keep whatever the migrations seeded; no reconciliation runs               |
| `MOKOSH_WEBHOOK_URL`, `MOKOSH_BACKUP_API_URL`                       | the `applications.webhook_url` upsert never runs; Backup stays a stub                        |
| `IP2LOCATION_DB_PATH`, `IP2PROXY_DB_PATH`                           | GeoIP and ASN / VPN enrichment stay off                                                      |
| `OCI_REGISTRY_REALM`                                                | the realm is always derived from `OCI_REGISTRY_SERVICE` (correct for production)             |
| `OIDC_LIFECYCLE_EVENT_KEY`                                          | the lifecycle event key is fixed at its default                                              |
| `BUNYIP_BILLING_TRIAL_PERIOD_DAYS`, `TIER_EARLY_ADOPTER_TRIAL_DAYS` | those bootstrap seeds cannot be set; the admin pages are the only path                       |
| `EMAIL_LOG_TOKENS`, `BUNYIP_E2E_BOOTSTRAP_ALLOW`, `BUNYIP_GIT_SHA`  | dev and build-time only; correctly absent from a production deployment                       |

The bootstrap-default families are in the same position: `AUTO_BAN_*`, `RATE_LIMIT_{ACTION}_*` and the remaining
`TIER_*` variables seed a fresh database and are not passed either, so on a deployed instance the admin pages are the
only way to change them.

bunyip-web's own variables (below) are passed by the `web` service, except `CSP_CONNECT_SRC` and `CSP_FORM_ACTION`.

## Settings that are not environment variables

These live in the database, are edited on the admin pages, and apply without a restart. Nothing here has an
environment-variable equivalent unless the table says so.

### Stripe (`stripe_config`, admin page: Stripe)

Singleton row (`id = 1`).

| Column                                    | Meaning                                                                                  |
|-------------------------------------------|------------------------------------------------------------------------------------------|
| `secret_key` + `secret_key_nonce`         | governed secret; ciphertext plus nonce when `SECRETS_STORAGE=database`                   |
| `webhook_secret` + `webhook_secret_nonce` | governed secret; same encoding                                                           |
| `key_version`                             | which key in the set the row was written under                                           |
| `app_tag`                                 | Stripe app tag                                                                           |
| `success_url`, `cancel_url`               | checkout redirect targets. Unset defaults to the first `CORS_ORIGIN` entry               |
| `trial_period_days`                       | signup free trial, 0-365. Env seed: `BUNYIP_BILLING_TRIAL_PERIOD_DAYS`                   |
| `price_id_personal`, `price_id_business`  | from the original table; no current code reads them (per-tier ids live in `tier_config`) |

Unconfigured means payment is simply disabled. Test-mode walkthrough:
[`stripe-test-mode.md`](stripe-test-mode.md).

### Pricing tiers (`tier_config`, admin page: Pricing Tiers)

Singleton row. The slot counts and trial lengths are declared configuration keys, so they also have a file and an
environment provider (see [the declared order](#configuration-providers-and-their-precedence-bunyip-643644)). The Stripe
identifiers, the two feature switches and the per-tier visibility flags have **no second provider at all**: the admin
page is their only source, which is exactly why they are not declared keys, so no file or environment value can ever
turn a feature on.

| Column                                                                              | Meaning                                                                   |
|-------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `pricing_enabled`                                                                   | when false the public `/pricing` page 404s and every link to it is hidden |
| `orgs_enabled`                                                                      | when false `/organizations` 404s and its nav entry is not rendered        |
| `free_price_id`, `lifetime_price_id`, `early_adopter_price_id`, `standard_price_id` | Stripe price ids per tier                                                 |
| `lifetime_product_id`, `early_adopter_product_id`, `standard_product_id`            | Stripe product ids per tier                                               |
| `lifetime_visible`, `early_adopter_visible`, `standard_visible`                     | per-tier visibility on `/pricing`. A visible tier must have a price id    |
| `lifetime_slots`, `early_adopter_slots`                                             | capacity per tier. Env seeds exist                                        |
| `early_adopter_trial_days`, `standard_trial_days`                                   | trial length per tier. Env seeds exist                                    |

`PUT /v1/admin/tier-config` refuses a save that would leave a tier it touches visible with no price id (BUNYIP-609),
naming every such tier in one message: the public payload is built from the price ids, so a visible tier with no price
is dropped from `/pricing` silently. A free or lifetime tier is mapped to a real $0.00 Stripe price, so "shown but
priceless" is never a state the page can render. A request that sends neither half for a tier (the slots and trials
form) leaves that tier alone, so a row saved in that state before the check existed is corrected by the catalog form,
not by an unrelated save.

`orgs_enabled` is the organizations and teams switch (BUNYIP-493), saved by the Tiers & Slots form on the same page so
it never rides the catalog form's Stripe validation. It is published on the public feature-flags probe
`GET /v1/auth/setup/status`, answered from the process-wide tier-config snapshot the admin save hot-reloads, so the
probe still reads no table. bunyip-web reads that probe once before its listener binds and every 60 seconds after, and
installs the value into the process-wide cell its nav and its flagged routes read: a change reaches the web app within
a minute with no restart, and a read that fails leaves the feature off rather than guessing it on.

### Branding (`branding`, admin page: Branding)

Singleton row (`id = 1`), the source of truth for every occurrence of the product name and for the sharing metadata
(BUNYIP-561). It ships EMPTY: a migration is committed code, and the point of the record is that product copy is not
committed code.

| Column                                                       | Meaning                                                                                                             |
|--------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| `brand_name`                                                 | the nav mark, the browser-title suffix, `og:site_name`, every email subject, and the TOTP issuer for NEW enrolments |
| `tagline`                                                    | the hero caption, the footer line and the bunyip-web startup banner                                                 |
| `meta_description`                                           | `<meta name="description">` and `og:description`                                                                    |
| `og_image_url`                                               | `og:image` / `twitter:image`; must be an absolute `http(s)://` URL                                                  |
| `theme_css`                                                  | CSS custom-property declarations emitted into `:root` (the brand ramp). No `<` or `>`; 4096 characters              |
| `theme_color_light`, `theme_color_dark`                      | the two `<meta name="theme-color">` values (browser chrome). Hex colours (`#rgb`, `#rrggbb`, `#rrggbbaa`)           |
| `mark_updated_at`, `favicon_updated_at`, `mascot_updated_at` | version markers for the three image slots. NULL means the slot is unset                                             |

The images themselves live in `branding_assets`, one row per key, as bytes in a Postgres `BYTEA` (the same storage
`user_avatars` uses; bunyip-api has no static mount, so an uploaded image can never be served from an origin where it
could execute). The admin uploads three: `mark`, `favicon` and `mascot`. The favicon upload is kept as `favicon-source`
and the whole icon set is DERIVED from it in the same transaction (`favicon-16`, `favicon-32`, `favicon-48`,
`favicon-192`,
`favicon-512`, `apple-touch-icon`, `favicon-ico`), so an operator uploads once and a partially replaced icon set is not
a state the deployment can reach. Each is served unauthenticated from `GET /v1/branding/assets/{kind}` and proxied
same-origin by bunyip-web at `/brand/{kind}?v=<version>`.

Resolution, stated once:

- `brand_name` is the row value when non-empty, otherwise `APP_NAME`. `APP_NAME` is therefore a **bootstrap default for
  a database that has never been branded**, not a way to rename a running deployment.
- `tagline`, `meta_description` and `og_image_url` are the row value when non-empty, otherwise **empty**, and an empty
  value means the markup is **omitted**: no `<meta name="description">`, no `og:description`, no
  `og:image`, no tagline line, and no title suffix when `brand_name` is empty. No literal is ever substituted.
- `theme_css`, `theme_color_light` and `theme_color_dark` are the row value when non-empty, otherwise **omitted**: no
  `:root` block and no `theme-color` meta. There is no environment variable and no compiled-in colour behind them; the
  `#2f4e2e` / `#161a16` defaults bunyip-web used to carry are gone (BUNYIP-560), as are the three bootstrap variables
  that briefly replaced them (BUNYIP-568).
- The **mark** falls back to a built-in glyph drawn in the theme's own colour (a shape, not artwork). The **favicon**
  falls back to the icon set committed under
  `bunyip-web/assets/`, root `/favicon.ico` included. The **mascot** falls back to the hero illustration committed under
  `bunyip-web/assets/` (`bunyip-hero-448.webp` / `bunyip-hero-718.webp`), the same "committed file, admin upload
  overrides" shape as the favicon set (BUNYIP-605).
- An upload that fails validation (not an image, over 2 MiB, over 4096 px, or a source the icon set cannot be derived
  from) writes **nothing** and renders its reason above the form.

A save writes the row and refreshes the api-side cache in the same request, so email subjects and the TOTP issuer follow
immediately. Every other api process re-reads the row every **60 seconds**, and bunyip-web fetches `GET /v1/branding`
once at startup (before it binds) and then every **60 seconds**, so an admin edit is visible in the browser within one
interval. A startup fetch failure logs at
`error` and serves unbranded chrome; a later refresh failure logs at `warn` and keeps the last good values.

bunyip-web has **no** brand-text and **no** palette environment variables. `APP_NAME` and
`BRAND_DESCRIPTION` were removed from it (BUNYIP-561). The brand ASSETS (mark, favicon set, mascot art) and the palette
are columns of this record too (BUNYIP-560), and the three bootstrap variables that briefly backed the palette were
removed with the plumbing that read them (BUNYIP-568).

### Email (`email_config`, admin page: Email)

Singleton row; every column is nullable and a NULL column means this row's provider does not hold that key, so the next
provider in the [declared order](#configuration-providers-and-their-precedence-bunyip-643644) (the file provider, then the
environment) serves it. `smtp_password` and `imap_password` are the exceptions: they are governed secrets and follow
`SECRETS_STORAGE`, never this stack. There is no column for the EHLO name: `SMTP_EHLO_NAME` is deployment identity, not
SMTP tuning (BUNYIP-507), so it stays environment-only alongside the base URL and the poll interval.

The **Source** the page shows is the highest-priority provider holding any of this section's keys, so it can now read
`file` as well as `database` or `environment`. Run `bunyip-api config-status` for the per-key answer.

### Auto-ban (`auto_ban_config`, admin page: Auto-ban Settings)

Singleton row: `enabled`, `threshold`, `window_secs`, `ban_duration_secs`. Every column is a declared configuration key,
so it also has a file and an environment provider (see [the declared
order](#configuration-providers-and-their-precedence-bunyip-643644)); a stored value that cannot narrow to its in-memory
width is not held, so the next provider serves it rather than the value wrapping. Individual IPs
are banned and lifted from the admin IP Bans screen, which is super-admin-only and takes effect on that address's next
request.

### Rate limits (`rate_limit_configs`, admin page: Rate Limits)

One row per action, keyed by the action name, with `max_requests` and
`window_seconds`. Super-admin-only (BUNYIP-413).

This table is the **database provider** for that action's two declared keys (BUNYIP-645), so a present row wins over a
file value, a compose variable and the compile-time cap in the [one declared
order](#configuration-providers-and-their-precedence-bunyip-643644), and `bunyip-api config-status` answers "which
provider is serving the login cap" per action. It resolves nothing on its own: before BUNYIP-645 the order lived in the
body of `RateLimitConfigRepository::effective` and there was no way to ask that question.

The enforcement path reads a process-wide 30-second snapshot of the whole table rather than one row per rate-limit
decision (BUNYIP-556); the providers are layered and every preset resolved through them once per snapshot, so a
rate-limit decision is a lookup and costs no query and no provider read. A save invalidates the snapshot in the api process that took the write, so the new cap is in
force on the next request there; another api process picks it up within the 30 seconds. If the table cannot be read, the
last good snapshot keeps being enforced and the failure is logged at `error`: a refresh failure never silently reverts
the platform to its compile-time caps.

### Applications and OAuth clients

| Table                                                                | Set from                                                          | Notes                                                                               |
|----------------------------------------------------------------------|-------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `applications.forgejo_owner`, `.forgejo_repo`, `.pinned_release_tag` | admin Applications page                                           | an app is downloadable only when all three are set                                  |
| `applications.webhook_url`                                           | admin Applications page                                           | also upserted at boot for the `mokosh` row from `MOKOSH_WEBHOOK_URL`                |
| `oauth_clients`                                                      | migrations, boot-time reconciliation, `just register-dev-clients`, `bunyip-api machine-client` | the `MOKOSH_APPS_*`, `DRILLMARK_*` and `LETS_CHAT_*` variables reconcile these rows |

`oauth_clients` is also the suite's machine-identity registry: a registration that is confidential, authenticates with
`client_secret_basic` and lists `client_credentials` in `allowed_grant_types` may call the mailer relay
(`POST /v1/mailer/send`, BUNYIP-602). `bunyip-api machine-client register` / `rotate` / `disable` / `list` is the
supported way to provision one; it prints the plaintext secret once and stores only the Argon2id hash. That family, the
two rate-limit actions the relay adds (`mailer_send`, `mailer_auth_failures`) and the SMTP/DNS prerequisites are in
[`mailer-relay.md`](mailer-relay.md).

### Per-user settings

Two-factor enrolment (`user_totp`, encrypted under `APP_ENCRYPTION_KEY`), trusted devices, active sessions and
notification preferences are per-user records managed from the member's own settings pages. They are product state, not
deployment configuration, and are listed here only so the boundary is explicit.

## bunyip-web

bunyip-web is a separate binary with its own configuration (`bunyip-web/src/config.rs`): `BUNYIP_BIND_ADDR`,
`BUNYIP_API_URL`, `BUNYIP_API_PUBLIC_ORIGIN`, `BUNYIP_OIDC_ISSUER`, `BUNYIP_APP_DOMAIN`, `BUNYIP_COMMUNITY_URL`,
`TRUSTED_PROXY_CIDR`, `CSP_CONNECT_SRC`, `CSP_FORM_ACTION`, `RUST_LOG`. Every one has a working default. It holds no
secrets and reads none of the api variables above, so the api's inventory does not cover it.

It has no `APP_NAME` and no `BRAND_DESCRIPTION`: the product name, tagline, meta description and Open Graph image are
the admin-managed `branding` record above (BUNYIP-561), fetched from bunyip-api rather than read from the environment.

It has no palette variables either (BUNYIP-568). The `:root` custom-property block that recolours every in-page token
and the two `<meta name="theme-color">` values that paint the browser chrome (Android address bar, iOS status bar, PWA
splash) under `prefers-color-scheme: light` and `dark` are the `theme_css`, `theme_color_light` and `theme_color_dark`
columns of that same record, so one admin edit moves the page and the chrome together (BUNYIP-549 / BUNYIP-560). There
is **no compiled-in default** behind them: an empty column means the `:root` block and the `theme-color` metas are
omitted rather than painted one product's green. Set the palette on the admin Branding page.
