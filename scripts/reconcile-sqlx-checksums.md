# Reconcile `_sqlx_migrations` after in-place migration edits (BUNYIP-101)

Companion to [`reconcile-sqlx-checksums.sql`](./reconcile-sqlx-checksums.sql).

Context: commit `9c082eb` (BUNYIP-79, `fix(migrations): close data-integrity
gaps`) edited 11 already-applied migration files in place. sqlx's checksum
check refuses to boot when on-disk content disagrees with the row recorded
in `_sqlx_migrations`. The script above brings the staging / production
databases back into agreement.

## When to run

Once per database, before bringing up an image built off `main` newer than
`9c082eb`. Symptom on boot:

```
ERROR bunyip_api: Failed to run database migrations
  error=migration 20241230000014 was previously applied but has been modified
```

(Or any of the other 10 versions listed in the script.)

## How to run

1. Stop bunyip-api so it stops crashlooping while you reconcile:

   ```nu
   ^docker stop bunyip-api-app
   ```

2. Resolve the DB connection (host, port, user, db name). On c-01 / nc-01 they
   live in `server/<host>/bunyip-api/compose-secrets.yml` under
   `POSTGRES_*`. Decrypt with sops, copy the values.

3. Run the script with `--single-transaction --set ON_ERROR_STOP=on` so any
   failure rolls everything back:

   ```nu
   ^psql --host <host> --port <port> --username bunyip --dbname bunyip \
         --single-transaction --set ON_ERROR_STOP=on \
         --file scripts/reconcile-sqlx-checksums.sql
   ```

   On success the final line is `reconcile complete: 11 checksums updated,
   schema deltas applied`.

4. Verify:

   ```sql
   SELECT version, encode(checksum, 'hex') FROM _sqlx_migrations
    WHERE version IN (
       20260319000025, 20260313000021, 20260605000010, 20241230000014,
       20260417000040, 20260429000045, 20260417000042, 20260602000050,
       20260417000041, 20260502000048, 20241230000017
    )
    ORDER BY version;
   ```

   Should return 11 rows, each with the hex string the script wrote.

5. Restart bunyip-api:

   ```nu
   ^docker start bunyip-api-app
   ^docker logs --tail 40 bunyip-api-app
   ```

   Watch for `Database migrations completed` and no `previously applied but
   has been modified` errors.

6. Smoke test:

   ```nu
   ^curl --silent --output /dev/null --write-out '%{http_code}\n' \
        https://api.a8n.systems/health
   # 200
   ```

   Plus a real OIDC login through drillmark / mokosh-apps.

7. Repeat on the next environment (staging then prod).

## What the script changes

| Migration | Schema delta | Why |
| --- | --- | --- |
| `20260319000025_encrypt_stripe_secrets` | none | New `DO` guard fails closed on populated rows; already-applied DROP/ADD is unchanged. |
| `20260313000021_add_feedback_attachments` | 2 `CHECK` constraints | `size_bytes <= 5 MiB`, `octet_length(data) = size_bytes`. |
| `20260605000010_create_application_entitlements` | 1 `CHECK` | `source IN ('admin','stripe','backfill')`. |
| `20241230000014_create_email_change_requests` | `UNIQUE(token_hash)` | Matches the other single-use token tables. Script raises if duplicates exist. |
| `20260417000040_create_oidc_clients` | 1 `CHECK` | `refresh_idle_ttl_seconds BETWEEN 3600 AND 7776000`. |
| `20260429000045_add_price_ids_to_tier_config` | new column | `lifetime_price_id TEXT`. |
| `20260417000042_create_oidc_tokens` | `COMMENT ON COLUMN` | Documents the intentional no-FK on `lifecycle_event_outbox.user_id`. |
| `20260602000050_seed_distribution_catalog` | recreate index | `idx_applications_is_hosted` becomes a plain (non-partial) index. |
| `20260417000041_create_oidc_sessions_and_codes` | none | Comment-only edit. |
| `20260502000048_register_mokosh_oidc_client` | `UPDATE oauth_clients` | Set `disabled_at` on the abandoned placeholder client. |
| `20241230000017_add_application_subdomain` | none | Removed `UPDATE`s targeted slugs that never existed. |

And in every case, `UPDATE _sqlx_migrations SET checksum = decode(<sha384>, 'hex') WHERE version = <ts>`.

## Hash recomputation

If a future PR edits one of these migration files again, the hash in the
script goes stale. To regenerate every hash from the current file content:

```nu
cd bunyip-api/migrations
^sha384sum 20260319000025_encrypt_stripe_secrets.sql 20260313000021_add_feedback_attachments.sql 20260605000010_create_application_entitlements.sql 20241230000014_create_email_change_requests.sql 20260417000040_create_oidc_clients.sql 20260429000045_add_price_ids_to_tier_config.sql 20260417000042_create_oidc_tokens.sql 20260602000050_seed_distribution_catalog.sql 20260417000041_create_oidc_sessions_and_codes.sql 20260502000048_register_mokosh_oidc_client.sql 20241230000017_add_application_subdomain.sql
```

Replace the corresponding `decode(...)` literals in the SQL.
