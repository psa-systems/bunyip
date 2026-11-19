# Secrets

Bunyip's secrets split by whether the api needs them to boot. Two tiers:

- **Group-1** startup secrets are files on disk. They are read at container start and never come from a remote store.
- **Group-2** integration secrets come from the ONE store the deployment declares in `SECRETS_STORAGE`. The choices are `environment`, `database`, `infisical`. Rotating one Group-2 secret touches only that store.

The split exists because the store itself needs credentials to open. A bootstrap loop (fetch my database password from a database) is broken by design; the store is reached only after the api is running.

## Group-1: startup secrets (files)

Compose mounts each Group-1 secret from `./secrets/<name>` at `/run/secrets/<name>`. The api reads it through the `{NAME}_FILE` convention so no value ever enters the process environment. A `docker inspect` on the api container will not show the value.

What ships as Group-1:

- `DATABASE_URL` (admin pool, migration-granted)
- `APP_DATABASE_URL` (self-service pool, as the `bunyip_app` RLS role)
- `BUNYIP_APP_PASSWORD` (the `bunyip_app` role password, set at first boot)
- `APP_ENCRYPTION_KEY` (one 32-byte key for every encrypted column)
- `JWT_SECRET` (session JWT HMAC key)
- The OIDC signing key file at `OIDC_JWT_PRIVATE_KEY_PATH` (Ed25519 private key)
- Any other secret the api needs to serve its first request

Where the files come from:

- **Dev**: `just init-secrets` writes throwaway values under `./secrets/`.
- **Deployment**: the SOPS-encrypted `compose-secrets.yml` kept per host supplies them. The docker repo documents the convention.

A Group-1 secret is never fetched from Infisical. A bunyip-api restart therefore never depends on Infisical being reachable.

## Group-2: integration secrets (SECRETS_STORAGE)

Bunyip integrates with services that need credentials to call: SMTP for mail, Stripe for billing webhooks, support IMAP for inbound. These are Group-2 secrets, and the deployment picks exactly one source for them:

- `SECRETS_STORAGE=environment`: the api reads each secret from an environment variable at start. Simple, but `docker inspect` can see the values. Fine for dev, not for production.
- `SECRETS_STORAGE=database`: the secrets live in rows on the `integration_secrets` table, edited on the admin Settings page. The api reads a database row sealed with `APP_ENCRYPTION_KEY`. Rotation is edit-and-save; no restart.
- `SECRETS_STORAGE=infisical`: the api pulls from the project named by `INFISICAL_*`. One shared source for a fleet with many services.

The chosen value is **required**; there is no default. A deployment that leaves `SECRETS_STORAGE` unset refuses to boot. The variable's own classification in the registry says why.

## Rotating a Group-1 secret

1. Write the new value to `./secrets/<name>` on the host.
2. Restart the api container.
3. Verify `GET /health` returns ok and the OIDC discovery endpoint still answers.

`APP_ENCRYPTION_KEY` is a special case: rotating it requires re-encrypting every row that depends on it. The one-shot migration path for that lives in the internal docs and is not covered here; a deployment that needs to rotate it should coordinate with the platform team. Routine rotation is not necessary because the key never leaves the host.

The OIDC signing key is rotated through JWKS overlap, not through this file-swap path. See [OIDC provider](oidc-provider.md).

## Rotating a Group-2 secret

### `SECRETS_STORAGE=database`

Edit the row on the admin Settings page. The new value is sealed with `APP_ENCRYPTION_KEY` on write and the mailer / Stripe client picks it up on the next request. No restart needed.

### `SECRETS_STORAGE=infisical`

Rotate in Infisical; the client refreshes its cache on the next read and new values apply within one TTL window. For an immediate takeover, restart the api container.

### `SECRETS_STORAGE=environment`

Edit `.env`, restart the api container.

## What should not live in secrets

- Branding strings (product name, palette, copy). These live on the `branding` row and are seeded from `APP_NAME` only until the row is populated.
- Feature flags. These are `features` rows.
- Rate-limit overrides. These are `rate_limit_overrides` rows.

A deployment that puts any of the above in an env var or a Group-2 secret has forgotten that the database wins by declaration, and will fight the UI.

## Related

- [Host secrets](operations/host-secrets.md) covers the small read channel that bunyip exposes to allow-listed machine clients so they can fetch a registry secret without logging in as a user.
- [Configuration](configuration.md) lists every environment variable bunyip reads.
- [Troubleshooting](troubleshooting.md) covers the common failures of a deployment reaching Infisical or SMTP.
