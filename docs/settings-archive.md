# Backing up and restoring settings

bunyip keeps its configuration in the database: branding, the palette and the brand assets, the tier and pricing flags, the email and Stripe rows, the rate-limit overrides, the application catalogue and the OAuth client registrations are all edited from the admin pages. That is what makes a rebrand or a cap change reversible with no deploy, and it is also what makes a wiped postgres volume lose every one of them at once.

`bunyip-api settings-export` writes all of it to ONE passphrase-encrypted file, and `bunyip-api settings-import` puts it back. The archive is readable on a machine that has neither `APP_ENCRYPTION_KEY` nor the old database, because the governed integration secrets are resolved to plaintext during the export and the whole file is sealed under the operator's passphrase instead.

A `pg_dump` does not replace this. A dump carries the users, the sessions, the audit log and the download cache too, and it cannot be handed to anyone: the encrypted secret columns travel with it while the key that reads them does not.

Both commands run as `docker compose exec api /app/bunyip-api <subcommand>` (or `docker compose run --rm api <subcommand>` when the api container is not up). Neither prints a setting value, a secret or a hash: the plan and the report name sections, columns, keys and counts only.

## The passphrase

No flag takes the passphrase itself. A command-line argument is visible in `ps`, in the shell history and in `docker inspect`, and this one unlocks every integration secret at once, so the passphrase comes from a file:

```nu
docker compose exec api /app/bunyip-api settings-export --passphrase-file /run/secrets/archive_passphrase --output /tmp/bunyip-settings-20260915.json
```

`--passphrase-file -` reads it from stdin instead. At most one trailing newline is stripped, so `echo "..." | ...` works and a passphrase that genuinely ends in whitespace still survives.

Export refuses a passphrase shorter than 16 characters, or one that scores below 4 out of 4 on zxcvbn's guessability scale, and says which of the two rules failed. The deployment's own brand name and the host part of `APP_URL` are fed to the scorer as known words, so a passphrase built out of them is rejected rather than credited. Use several unrelated words. Import applies no strength check at all: by then the file exists and its passphrase is whatever it is.

Keep the archive and its passphrase apart. Losing the passphrase makes the file unreadable; there is no recovery path, and that is the point.

## Export

```nu
docker compose exec api /app/bunyip-api settings-export --passphrase-file <path|-> --output <path> [--include-catalog] [--include-oauth-clients]
```

| Flag | Meaning |
|------|---------|
| `--passphrase-file <path\|->` | Where the passphrase is read from. `-` means stdin. Required. |
| `--output <path>` | Where the archive is written. Required. Never `-`: stdout carries the log lines too. |
| `--include-catalog` | Also archive the application groups, applications, per-application documentation pages and Stripe price entitlements. |
| `--include-oauth-clients` | Also archive the `oauth_clients` registrations, hashed client secrets included. |

`--output` refuses a path that already exists, and there is no `--force`. Overwriting one archive with another is the mistake that cannot be undone, and the two files are indistinguishable from outside. Choose another path, or move the existing file aside. The file is created with mode `0600` as it is created, so there is no window in which it is world readable.

The suggested filename is `bunyip-settings-YYYYMMDD.json`.

## Import

```nu
docker compose exec api /app/bunyip-api settings-import --passphrase-file <path|-> --input <path> [--dry-run]
```

| Flag | Meaning |
|------|---------|
| `--passphrase-file <path\|->` | Where the passphrase is read from. `-` means stdin. Required. |
| `--input <path>` | The archive to read. Required. Never `-`. |
| `--dry-run` | Print the plan and exit 0 without writing anything. |

Run `--dry-run` first, every time. It opens the archive, checks both version guards, validates every row and prints exactly what a real run would change, section by section. Nothing is written.

## The wipe-and-restore procedure

This is the case the archive exists for: the postgres volume is gone or is being deliberately discarded, and the deployment has to come back with its settings intact.

1. **Export, while the deployment is still healthy.** An archive taken after the volume is gone is empty.

   ```nu
   docker compose exec api /app/bunyip-api settings-export --passphrase-file /run/secrets/archive_passphrase --output /tmp/bunyip-settings-20260915.json --include-catalog --include-oauth-clients
   docker compose cp api:/tmp/bunyip-settings-20260915.json ./bunyip-settings-20260915.json
   ```

   Copy the file off the host and store it where you store the passphrase's counterpart, but not beside it.

2. **Stop the stack.**

   ```nu
   docker compose down
   ```

3. **Remove the postgres volume.** Name it explicitly rather than using `down --volumes`, which takes every volume the project owns.

   ```nu
   docker volume rm bunyip_postgres_data
   ```

4. **Start the stack and let the api migrate and seed.** `bunyip-api` applies its migrations on startup, and `SETUP_DEFAULT_ADMIN` seeds the bootstrap administrator into the empty database. Wait for the api to report itself healthy before continuing: the import refuses to run against a database whose schema version does not match the binary's.

   ```nu
   docker compose up --detach
   docker compose logs --follow api
   ```

5. **Dry-run the import.** Everything will read as an insert or a change, because the database is fresh.

   ```nu
   docker compose cp ./bunyip-settings-20260915.json api:/tmp/restore.json
   docker compose exec api /app/bunyip-api settings-import --passphrase-file /run/secrets/archive_passphrase --input /tmp/restore.json --dry-run
   ```

6. **Import for real.**

   ```nu
   docker compose exec api /app/bunyip-api settings-import --passphrase-file /run/secrets/archive_passphrase --input /tmp/restore.json
   ```

7. **Restart bunyip-api.** A running process holds the tier configuration in memory and reads the system settings at boot, so it does not see a CLI import live. The report's last line says so too.

   ```nu
   docker compose restart api
   ```

8. **Delete the copy inside the container.** `/tmp/restore.json` holds every integration secret in plaintext once its passphrase is known.

   ```nu
   docker compose exec api rm /tmp/restore.json
   ```

The users are NOT restored by this procedure: they were never in the archive. A wiped deployment comes back with the bootstrap administrator `SETUP_DEFAULT_ADMIN` seeded and no one else, and its members sign up or are re-invited.

## What is archived

Always, with no flag:

| Section | Source |
|---------|--------|
| `branding` | The singleton `branding` row: name, tagline, meta description, Open Graph image, the theme CSS and the two theme colours, and the three asset timestamps. |
| `branding_assets` | Every row of `branding_assets`, bytes included: the mark, the uploaded favicon source AND every size derived from it, and the mascot. |
| `tier_config` | The singleton `tier_config` row: the slot counts, the trial lengths, the Stripe price and product ids, and the `pricing_enabled` / `orgs_enabled` / per-tier visibility flags. |
| `auto_ban_config` | The singleton `auto_ban_config` row. |
| `email_config` | The singleton `email_config` row, minus the encrypted password columns (their plaintext is archived under `governed_secrets`). |
| `stripe_config` | The singleton `stripe_config` row, minus the encrypted secret columns (same). |
| `rate_limit_configs` | Every per-action cap override. |
| `system_settings` | The four settings the file configuration layer at `BUNYIP_CONFIG_DIR` holds: login approval, the signup bot guard, and the two country lists. |
| `governed_secrets` | The plaintext of `SMTP_PASSWORD`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` and `SUPPORT_IMAP_PASSWORD`, resolved through whichever provider `SECRETS_STORAGE` declares. |

Behind `--include-catalog`:

| Section | Notes |
|---------|-------|
| `application_groups` | Keyed by `slug`. |
| `applications` | Keyed by `slug`. The `group_id` foreign key is carried as the referenced group's SLUG, because a uuid generated in the old database names nothing in the new one. |
| `application_docs` | Keyed by (application slug, doc slug). |
| `stripe_price_entitlements` | Carried as (Stripe price id, application slug) pairs. |

Behind `--include-oauth-clients`:

| Section | Notes |
|---------|-------|
| `oauth_clients` | Keyed by `client_id`. `client_secret_hash` IS archived, so a restore keeps every calling app's existing credential working. The plaintext secret is not in the archive, because it is not in the database either. |

## What is NOT archived

Deliberately absent, because it is operational history rather than configuration, and restoring it over a live deployment would be a data migration wearing a settings restore's clothes:

- users and everything per-user (sessions, TOTP enrolments, memberships, entitlements, avatars)
- `ip_bans`
- `mailer_suppressions`
- `application_versions`
- `download_cache`
- `audit_logs`
- any file outside the database, other than the four `system_settings` keys

Also absent: the surrogate ids, the `created_at` / `updated_at` timestamps, the `updated_by` / `created_by` attribution columns (the importing run writes those itself, and a CLI import writes NULL, which is the honest value for a change no admin account made), and the encrypted secret columns whose plaintext travels under `governed_secrets`.

Every other column of every archived table is carried. That is enforced rather than promised: `bunyip-api/tests/settings_archive.rs` reads `information_schema.columns` for each archived table and fails the build on a column that is neither archived nor in the module's declared exclusion list, so a migration that adds a new admin-managed setting cannot silently drop it from every export.

## Replace semantics

Import is REPLACE, not merge.

- A section **present** in the archive ends up holding exactly the archive's content.
- A section **absent** from the archive (only the two flag-gated ones can be absent) is not touched at all. An archive taken without `--include-catalog` leaves the target's applications alone.

For the singleton rows, that means every archived column is overwritten, column by column. For the keyed tables, the table ends up holding exactly the archive's rows:

- a key in both is updated **in place**, so the row keeps its id and its cascaded children;
- a key only the archive has is inserted;
- a key only the target has is **deleted**.

The plan names every deletion and what goes with it. Deleting an application removes its documentation pages, its versions, its entitlements, its price entitlements and its download-cache rows; deleting an OAuth client removes its authorisation codes, its refresh-token families and tokens, its per-user access grants and its pending lifecycle deliveries. Read the dry run before confirming.

Because every section is a replace, the import is idempotent: running it twice lands in the same place as running it once, and re-running after a partial failure is safe.

## Governed secrets on import

The four governed integration secrets are written through whichever provider `SECRETS_STORAGE` declares:

- an archived value is written to the provider;
- an archived `null` purges the provider's value;
- a value that already matches is left alone.

`SECRETS_STORAGE=environment` is the exception, because it is the one read-only provider: a process cannot set a variable for its own next boot, and the compose secret files are mounted read-only. In that mode the environment must ALREADY hold exactly the archived value (or hold nothing, where the archive holds `null`). Anything else fails the import naming the `{NAME}_FILE` to set or remove, for example "write the archived value into the file `SMTP_PASSWORD_FILE` points at (`./secrets/smtp_password`), then re-run the import". A `--dry-run` surfaces the same refusal, so it is visible before any write.

## The archive format

The file is JSON. Only the envelope is readable; the settings are the ciphertext.

```json
{
  "format": "bunyip-settings-archive",
  "format_version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "version": 19,
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 4,
    "salt": "<base64, 16 random bytes>"
  },
  "cipher": {
    "algorithm": "aes-256-gcm",
    "nonce": "<base64>"
  },
  "ciphertext": "<base64>"
}
```

The key is Argon2id over the passphrase, at the parameters and salt the file carries, to 32 bytes. Reading the parameters from the file (rather than assuming today's) is what keeps an old archive openable after the defaults move. The ciphertext is AES-256-GCM, the same primitive every at-rest secret column uses, and it is authenticated: one flipped byte fails the open outright rather than yielding partial plaintext. A failed decryption reports "wrong passphrase, or the archive is damaged", because AES-GCM genuinely cannot tell the two apart.

An unknown `format` or an unknown `format_version` is refused by name before a key is derived, so a file that merely looks similar does not cost 100 ms of Argon2 to reject.

## The two version guards

Both subcommands compare the highest applied migration in `_sqlx_migrations` against the last migration compiled into the running binary, before doing anything else. A mismatch names both versions and exits 1: a settings row is shaped by the schema, and a subcommand runs BEFORE the startup migration step on purpose, so "the image is newer than the volume" is the ordinary state right after a deploy. The remedy is in the message: start bunyip-api once so it migrates, then re-run.

Import applies a second guard: the archive records the schema version it was exported from, and an archive from another version is refused naming both. Export from a deployment at the target's version, or restore into one at the archive's.

## When an import does not complete

The database sections are written in ONE transaction, so that half is all-or-nothing. Two steps cannot join it: the governed secrets may live in Infisical or be owned by the environment, and the system settings are a file layer. A fourth step re-reads every section afterwards and requires it to equal the archive.

The report prints a verdict per step, and a run with any step unapplied exits 1 naming them. Fix the cause and re-run the same import: every step is a replace, so the steps that already landed are a no-op the second time.
