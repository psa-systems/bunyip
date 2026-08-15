# At-rest encryption key: rotation and consolidation runbook

Bunyip encrypts three kinds of secret in Postgres with ONE key,
`APP_ENCRYPTION_KEY` (BUNYIP-483):

| table           | columns                                                    |
| --------------- | ---------------------------------------------------------- |
| `user_totp`     | `encrypted_secret` + the `pending_*` staged re-key columns  |
| `stripe_config` | `secret_key`, `webhook_secret`                              |
| `email_config`  | `smtp_password`                                             |

Three environment variables drive it (each honours the `{NAME}_FILE`
compose-secret convention):

- `APP_ENCRYPTION_KEY` - hex, 32 bytes. Every new write uses it. Required in
  production: the api logs one startup configuration `ERROR` naming the variable
  and the remedy, then exits non-zero (BUNYIP-537). Malformed key material (not
  hex, or not 32 bytes) is reported the same way. Outside production an unset
  key falls back to the all-zero DEVELOPMENT key with a loud warning.
- `APP_ENCRYPTION_KEY_PREV` - comma-separated hex keys still needed to READ rows
  written under an earlier key. Empty on a steady-state deployment.
- `APP_KEY_VERSION` - the version stamped on rows written under the current key
  (default `1`). Bump it when rotating so the admin rotation pages can tell old
  rows from new.

Reads try the current key first and fall back through every previous key, so a
deployment stays up for the whole window: nothing is a flag day.

## Re-encrypt pass

```
docker compose run --rm api reencrypt-secrets
```

The subcommand connects, rewrites every value that is not already on the current
key and version, prints a summary, and exits without starting the server or
running migrations. It is idempotent: a second run reports `0 rewritten`. A value
that no key in the set can decrypt is reported by name and left untouched (never
cleared), and the command exits non-zero so the run is not mistaken for success.
Take a database backup first; the pass is operator-triggered precisely so you
control when it happens.

The admin API exposes the same pass per store: `GET /v1/admin/key-health`,
`GET /v1/admin/key-rotation/{totp|stripe|email}/status` and
`POST /v1/admin/key-rotation/{totp|stripe|email}/reencrypt`.

## Rotating to a new key

1. Generate the new key: `openssl rand -hex 32`.
2. Move the current key into `APP_ENCRYPTION_KEY_PREV` (prepend it to the list if
   the list is not empty), set `APP_ENCRYPTION_KEY` to the new key, and bump
   `APP_KEY_VERSION`.
3. Restart the api. Existing rows still read through the previous key; new writes
   use the new key.
4. Run the re-encrypt pass. `key-rotation/{key_id}/status` reports
   `rotation_complete: true` for every store when it is done.
5. Clear `APP_ENCRYPTION_KEY_PREV` and restart. The old key is now unused.

## Migrating a deployment that predates the consolidation

Older deployments provisioned two independent keys: one for the TOTP secrets and
one shared by the Stripe and SMTP secrets. To collapse them:

1. Pick the key for `APP_ENCRYPTION_KEY`. A fresh key is fine; so is reusing one
   of the two you already have.
2. Set `APP_ENCRYPTION_KEY_PREV` to BOTH retired keys, comma-separated (order
   does not matter; every key is tried).
3. Replace the two secret files with one: `./secrets/app_encryption_key`. The
   compose file now mounts only that, as `APP_ENCRYPTION_KEY_FILE`.
4. Restart the api and confirm `GET /v1/admin/key-health` reports `healthy` for
   `totp`, `stripe` and `email` (rows still on a retired key read fine and are
   flagged `needs_reencrypt: true`).
5. Run the re-encrypt pass, then clear `APP_ENCRYPTION_KEY_PREV` and restart.

Do not drop the retired keys from `APP_ENCRYPTION_KEY_PREV` before step 5
succeeds with no undecryptable values: their rows would become unreadable, which
means users locked out of 2FA and Stripe/SMTP credentials that have to be
re-entered.

Accepting more than one previous key exists only for this migration. Dropping it
(and this section) once every deployment has completed step 5 is BUNYIP-491.
