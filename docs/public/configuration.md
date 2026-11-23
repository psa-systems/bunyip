# Configuration

For a deployment operator wiring environment variables and the Group-1 secret files. This is the operator-facing view. Every variable bunyip reads, grouped by subsystem; the source of truth for the exhaustive list is `ENV_INVENTORY` in the api source, which the repository's `check-doc-surface` guard keeps in step with the internal `docs/configuration.md` reference.

## Two kinds of knob

- **Environment variables** are read once at process start. Changing one means restarting the container. They configure the deployment.
- **In-app settings** live in the database and are edited on the admin pages. They apply without a restart and configure the product. Where the same knob exists in both planes, the database row wins by declaration.

This page covers the environment-variable half. The admin pages describe the in-app settings in the UI itself.

## Hosting

- `APP_PORT` (default `4401`) is the api listen port inside the container.
- `BUNYIP_BIND_ADDR` (default `0.0.0.0:4400`) is the web listen address inside the container.
- `HOST_IP` (default `0.0.0.0`) is the api bind address.
- `BUNYIP_API_URL` (default `http://api:4401`) is how `bunyip-web` reaches `bunyip-api` server-side.
- `BUNYIP_API_PUBLIC_ORIGIN` is the browser-facing origin of the api, used for OIDC redirect URIs and Stripe webhooks. Required for production. Pair it with `OIDC_ISSUER` below to get the apex/subdomain split some deployments use (e.g. `bunyip.example.com` for the browser, `api.bunyip.example.com` for the issuer).
- `OIDC_ISSUER` is the `Issuer` claim bunyip-api mints into OIDC tokens. There is no fallback to `BUNYIP_API_URL`: leaving it unset disables the OIDC endpoints entirely.
- `APP_URL` is the public base URL used to build links in outgoing email.
- `APP_NAME` (default `PSA Systems`) is the product name shown on the sign-in page before the branding row is seeded. Once the `branding` row is populated it wins.
- `TRUSTED_PROXY_CIDR` and `WEB_TRUSTED_PROXY_CIDR` restrict which upstream proxies the api and web honour forwarded headers from. A request from outside these CIDRs is treated as the socket IP.

## Database

- `DATABASE_URL` connects the admin pool (migration-granted). File-based through the `DATABASE_URL_FILE` convention.
- `APP_DATABASE_URL` connects the self-service pool as `bunyip_app`, the per-user RLS role.
- `BUNYIP_APP_PASSWORD` sets the `bunyip_app` role password on first boot. File-based through `BUNYIP_APP_PASSWORD_FILE`.
- Pools are sized for 10 connections each, measured against the healthy p99 of the request path. Raise only on acquire timeouts, and respect PostgreSQL's connection limit.

## Encryption and signing

- `APP_ENCRYPTION_KEY` is the one 32-byte key that protects every encrypted database column. File-based.
- `JWT_SECRET` is the session JWT HMAC key. File-based.
- `OIDC_JWT_PRIVATE_KEY_PATH` points at the Ed25519 private key used to sign OIDC id_tokens and access tokens. The matching public key is served at `/oauth2/jwks`.
- `OIDC_JWT_ACTIVE_KID` is the key id the api advertises as active. Rotate by adding a new key to the store, flipping this to the new kid, then retiring the old key after the token lifetime passes.

## Email (SMTP)

- `EMAIL_ENABLED` (default `false` in dev, required `true` in production).
- `SMTP_FROM` is the envelope sender on every piece of mail bunyip emits.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME` name the relay.
- The SMTP password is a Group-2 integration secret: it comes from the store `SECRETS_STORAGE` declares, never from the environment. See [Secrets](secrets.md).
- `EMAIL_LOG_TOKENS` writes the magic-link URL to the api log at DEBUG. Allowed in dev; forced off in production boot.

## OIDC provider

- Discovery is served at `/.well-known/openid-configuration` on the api.
- The signing keys above (`OIDC_JWT_PRIVATE_KEY_PATH`, `OIDC_JWT_ACTIVE_KID`) are the only OP-side material in the environment. Everything else (allowed scopes per client, grant types, audiences, redirect URIs) lives on `oidc_clients` rows and is edited on the admin page.
- `OIDC_ACCESS_TOKEN_TTL_SECONDS` and `OIDC_REFRESH_TOKEN_TTL_SECONDS` cap bearer lifetimes.

## Secrets storage (SECRETS_STORAGE)

Required; no default. One of `environment`, `database`, `infisical`. Governs where Group-2 integration secrets (SMTP password, Stripe credentials, support IMAP password) live. See [Secrets](secrets.md) for the full model.

## Infisical (only when SECRETS_STORAGE=infisical)

- `INFISICAL_ENABLED` turns the client on. A client that never reaches out is inert.
- `INFISICAL_ADDRESS`, `INFISICAL_PROJECT_ID`, `INFISICAL_ENVIRONMENT` name the project to read from.
- `INFISICAL_CLIENT_ID` and the matching `INFISICAL_CLIENT_SECRET_FILE` authenticate the client.

## Rate limiting

- The baseline per-IP cap every api route sits under is the fixed constant `RateLimitConfig::API_UNAUTH`; there is no environment override. Individual routes may add tighter per-user caps on top; the floor never raises them.
- The whitelist that bypasses the floor is not an environment variable: it is the admin-managed `rate_limit_whitelist` table, edited on the admin Rate Limits page.

## Feature flags

Feature flags are `features` rows in the database, not environment variables. A new feature ships off and is turned on from the admin page. Environment variables cannot flip a feature.

## IP geolocation

- `IP2LOCATION_DB_PATH` points at the `IP2LOCATION-LITE-DB` binary used by the geolocation enrichment. Not required; absent means country is never resolved.

## What is not an environment variable

- Product copy, palette, logos: these live on the one `branding` row and are edited on the Branding admin page. The sign-in page reads them before auth, so a wrong value is visible to anonymous visitors.
- Allowed OIDC scopes, grant types and redirect URIs per client: `oidc_clients` rows on the admin Clients page.
- Rate-limit per-route overrides: `rate_limit_overrides` rows.
- Login approval policy: one `settings` row.

## Where to look next

- [Secrets](secrets.md) for the Group-1 vs Group-2 split and the `SECRETS_STORAGE` modes.
- [OIDC provider](oidc-provider.md) for client registration and the admin pages that drive the OP.
- [Troubleshooting](troubleshooting.md) for the common failures caused by a wrong value in this list.
