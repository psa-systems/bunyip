# Bunyip Technical Requirements Document (TRD)

This document describes how Bunyip is built and how it behaves, as read from the code in this repository. It is a
description of the current implementation, not a statement of intent. Where a fact could not be confirmed in code, it
is listed in [Section 16](#16-unverified-areas) instead of being asserted. Status and planning live in the tracker,
not here. Companion conventions are in [`CLAUDE.md`](../CLAUDE.md) and [`docs/invariants/`](invariants/).

## 1. Purpose and scope

Bunyip is the PSA Systems SaaS platform. It provides:

- account signup and sign-in (password, magic link, two-factor, login approval)
- subscription billing through Stripe
- a platform admin area
- an OpenID Connect / OAuth 2.1 provider for first-party products
- an authenticated OCI registry front for application images
- application downloads and a catalog of hosted applications

Out of scope: the products that consume the OIDC provider, and the shared `dunite-*` crates (consumed as git
dependencies and not described here beyond how Bunyip uses them).

## 2. System architecture

### 2.1 Workspace layout

| Member | Kind | Role |
|---|---|---|
| `bunyip-web` | binary (Axum 0.7, Maud 0.26, htmx) | Browser-facing server-rendered front-end; a backend-for-frontend (BFF) over `/v1` |
| `bunyip-api` | binary (actix-web 4) | Backend, OIDC issuer, wiring, `main.rs`, migrations |
| `crates/bunyip-domain` | library | Models, repositories, services, app `Config`, email templates |
| `crates/bunyip-oidc` | library | OIDC / OAuth 2.1 vertical |
| `crates/bunyip-oci` | library | OCI registry vertical |
| `crates/web-kit` | library | Branding-free SSR building blocks (Maud, htmx), CSRF and client-IP middleware |

Dependency direction is strictly downward: `bunyip-api -> bunyip-oci / bunyip-oidc -> bunyip-domain -> dunite-core`.
`bunyip-web` is standalone and talks to `bunyip-api` over HTTP.

### 2.2 External dependencies

- `dunite-*` crates from a git repository, pinned by `rev` in the `bunyip-{domain,oci,oidc}` and `bunyip-api`
  manifests. Three distinct revs are in use (core graph, update-check and events, image-upload), per
  `bunyip-api/Cargo.toml`.
- PostgreSQL 18 (compose image tag `postgres:18.2-alpine3.23`).
- Stripe (billing), SMTP and IMAP (mail), a Forgejo instance (release artifacts and OCI upstream), and a secret
  store (Infisical) selectable through `SECRETS_STORAGE`.

### 2.3 Toolchain

- Rust `1.98.1`, pinned in `rust-toolchain.toml` with `clippy` and `rustfmt`; the builder image tag moves in lockstep.
- Locked versions: actix-web 4.18.1, axum 0.7.9, maud 0.26.0, sqlx 0.8.6 (`Cargo.lock`).
- Only `bunyip-oidc` uses compile-time `sqlx::query!`; builds use `SQLX_OFFLINE=true` with a committed `.sqlx/`.

### 2.4 Ports

| Service | Port |
|---|---|
| `bunyip-web` | 4400 |
| `bunyip-api` | 4401 |
| OCI registry listener (separate actix app) | `OCI_REGISTRY_PORT`, default 18081 |

## 3. Cross-cutting behavior

### 3.1 bunyip-api middleware stack

Outermost to innermost (`bunyip-api/src/main.rs`):

1. `AutoBanMiddleware` - rejects banned IPs first.
2. `RateLimitFloor` - default per-IP and per-user cap beneath every route.
3. CORS (`max_age` 3600).
4. `OriginGuard` (CSRF) - Origin/Referer check on cookie-authenticated writes against `CORS_ORIGIN`.
5. `RequestIdMiddleware`.
6. `SecurityHeaders` with a CSP (`connect-src` and `form-action` widened with the CORS origins).
7. Access logger (logs the trusted external client IP).
8. `TracingLogger`.
9. `Compress` - streamed responses opt out through `mark_uncompressed`.

JSON body limit is 32 KB by default; malformed input returns the `AppError` envelope. The OCI listener is a second
actix `App` with plain `SecurityHeaders`.

### 3.2 bunyip-web middleware stack

Order in `bunyip-web/src/main.rs`: unknown-host gate, CSRF (Origin, falling back to Referer host, must equal `Host`),
client-IP forwarding (trusted proxies), CSP, compression. The CSP is `default-src 'self'`, `script-src 'self'`,
`style-src 'self' 'unsafe-inline'`, `frame-ancestors 'none'`, `object-src 'none'`, with the API origin and Stripe
hosts allowed in `form-action`. HSTS and the other security headers are set by the edge proxy, not by the app.
Compression exempts already-compressed content (release installers, webfonts). `/assets` responses carry a long
immutable `Cache-Control`; references are versioned by `asset()` as `path?v=<version>`.

### 3.3 Rate limiting

- **Floor:** `API_AUTH` (100 requests / 60 s, keyed by user) and `API_UNAUTH` (60 / 60 s, keyed by IP). 429 responses
  carry `Retry-After`. Exempt paths: `/`, `/health`, `/version`, `/e2e-bootstrapped`, `/v1/health`, `/v1/version`,
  `/v1/auth/register-challenge`, `/v1/webhooks/stripe`, `/v1/pricing`, `/v1/auth/setup/status`,
  `/v1/mailer/send`, `/v1/mailer/webhooks/feedback`. `OPTIONS` is exempt.
- **Per-action limits** (`crates/bunyip-domain/src/models/rate_limit.rs`):

| Action | Limit |
|---|---|
| `LOGIN` | 10 / 60 s (per IP, per IP+email, per email) |
| `MAGIC_LINK` | 3 / 600 s |
| `PASSWORD_RESET` | 3 / 3600 s |
| `REGISTRATION` | 10 / 3600 s |
| `TWO_FACTOR_VERIFY_FAILURES` | 5 / 900 s, per user; locks verification for the window |
| `FEEDBACK_SUBMIT` | 20 / 3600 s |
| `SMTP_TEST` | 6 / 300 s |
| `MAILER_SEND` | 60 / 60 s, per client id |
| `MAILER_AUTH_FAILURES` | 10 / 60 s, per IP |
| `HOST_SECRET_READ` | 30 / 60 s |
| `HOST_SECRET_AUTH_FAILURES` | 10 / 60 s, per IP |
| `ADMIN_DIAGNOSTICS` | 60 / 60 s |

  OAuth (`OAUTH_TOKEN` 60, `OAUTH_AUTHORIZE` 120, `OAUTH_USERINFO` 240, `OAUTH_REVOKE` 60, `OAUTH_DISCOVERY` 120)
  and OCI (`OCI_TOKEN_FAILURES` 5, `OCI_TOKEN_THROUGHPUT` 60, `OCI_TOKEN_IP_FAILURES` 20) limits exist; their window
  lengths were not captured (Section 16).
- **Overrides:** a `rate_limit_configs` row per action (`max_requests > 0`, `window_seconds > 0`) or the
  `RATE_LIMIT_{ACTION}_MAX_REQUESTS` / `_WINDOW_SECONDS` environment variables. Config and whitelist caches have a
  30 s TTL. A whitelist table exempts addresses.
- **Auto-ban:** `AUTO_BAN_ENABLED` (default true), `AUTO_BAN_THRESHOLD` 5, `AUTO_BAN_WINDOW_SECS` 3600,
  `AUTO_BAN_DURATION_SECS` 86400; values may also come from the `auto_ban_config` row. Bans are held in memory and
  persisted to `ip_bans` asynchronously.

### 3.4 Authentication primitives

| Item | Value |
|---|---|
| Access token | HS256 JWT, 30 minutes, cookie `access_token` (Authorization header also accepted; cookie first) |
| Refresh token | JWT 30 days; effective lifetime is the DB row and cookie: 30 days with remember-me, 1 day without |
| Opaque token storage | SHA-256 hex hash |
| Cookie attributes | HttpOnly, SameSite=Lax, Path=/, Secure and Domain configurable (`Config::cookies_secure`) |
| Trusted-device cookie | `bunyip_trusted_device`, 30 days |
| OP session cookie | `bunyip_op_session`, 7 days |
| 2FA challenge token | 5 minutes |
| Login-approval challenge | 15 minutes |
| Signup challenge | stateless signed token, 30 minutes |

Extractors (`crates/bunyip-domain/src/middleware/auth.rs`): `AuthenticatedUser`, `OptionalUser`, `AdminUser`,
`VerifiedAdminUser` (admin with verified 2FA), `SuperAdminUser` (admin and `users.is_super_admin`, read from the
database, not the JWT), `MemberUser` (active membership).

Hashing: passwords and machine-client secrets use Argon2id, always run on the blocking pool through
`argon2_offload`. Recovery codes use Argon2id (m=19 MiB, t=2, p=1); a legacy unsalted SHA-256 form is still verified.

### 3.5 Errors

Failures return an `AppError` envelope with a non-2xx status. Webhook, OCI and OIDC endpoints return their
protocol-specific error shapes. `OciError::Internal` always goes through `errors::context`, which logs first.

## 4. Data layer

- PostgreSQL through sqlx 0.8. Migrations run at startup (`sqlx::migrate!("./migrations")`). There are 121 SQL
  migration files plus a README in `bunyip-api/migrations/`.
- Committed migrations are immutable (sqlx checksums every byte); fixes go forward as a new file.
- Two pools of max 10 connections each (primary, and the row-level-security `bunyip_app` pool when
  `APP_DATABASE_URL` is set), so one replica holds up to 20 connections.
- Row-level security is enabled and forced (policy `user_isolation`, keyed on `app.current_user_id`) on
  `trusted_devices`, `user_totp`, `recovery_codes`, `application_entitlements`, `email_change_requests`.

### 4.1 At-rest encryption

One key set (`APP_ENCRYPTION_KEY`, previous keys in `APP_ENCRYPTION_KEY_PREV`, version in `APP_KEY_VERSION`) protects
every encrypted column. Decryption tries the current key, then each previous key. Encrypted columns store ciphertext,
a nonce and a `key_version`:

| Table | Encrypted data |
|---|---|
| `user_totp` | TOTP secret and the pending secret during rekey |
| `stripe_config` | Stripe secret key and webhook secret |
| `email_config` | SMTP and IMAP passwords |
| mailing-list integration config table | API token |
| `host_secrets` | Google client secret |

### 4.2 Table families (from migrations)

| Family | Tables |
|---|---|
| Accounts and sessions | `users`, `user_avatars`, `refresh_tokens`, `refresh_token_families`, `refresh_tokens_v2`, `access_token_blocklist`, `op_sessions` |
| One-time tokens | `magic_link_tokens`, `password_reset_tokens`, `email_verification_tokens`, `email_change_requests`, `admin_invites` |
| 2FA and devices | `user_totp`, `recovery_codes`, `trusted_devices`, `login_approval_codes`, `login_devices` |
| Protection | `ip_bans`, `auto_ban_config`, `rate_limits`, `rate_limit_history`, `rate_limit_traffic`, `rate_limit_whitelist`, `rate_limit_configs`, `audit_logs` |
| Feedback and support | `feedback`, `feedback_archive`, `feedback_attachments`, `feedback_spam_reasons`, `support_tickets`, `support_messages` |
| Mail | `mailer_suppressions`, `email_config` |
| Billing | `stripe_config`, `tier_config`, `stripe_webhook_events`, `stripe_price_entitlements` |
| Catalog | `applications`, `application_groups`, `application_versions`, `application_docs`, `application_entitlements`, `download_cache`, `download_daily_counts` |
| OIDC | `oauth_clients`, `oauth_authorization_codes`, `user_application_access`, `oauth_client_user_tenants`, `lifecycle_event_outbox`, `lifecycle_event_delivery` |
| OCI | `oci_blob_cache`, `oci_pull_daily_counts` |
| Config and branding | `feature_toggles`, `branding` (single row), the mailing-list integration config, `host_secrets` |

Stripe `payment_history`, `invoices` and `subscriptions` tables were created and later dropped; invoice data is read
live from Stripe.

## 5. Configuration system

- **Classification:** every environment variable is declared in `ENV_INVENTORY` with a class: `Required` (api will not
  start), `RequiredInProduction`, `FeatureGating` (one boot warning when absent), `Defaulted`. Startup reports all
  failures together and does not `panic!`. `DATABASE_URL` and `SECRETS_STORAGE` (`environment`, `database` or
  `infisical`) are always required.
- **Resolution order** (`ConfigStack`): `database` (admin-managed singleton rows), then `file`
  (`BUNYIP_CONFIG_DIR`, one file per key), then `environment`. A key held by two providers is logged as `Overridden`
  at boot; a key served by a lower provider is reported as `Shadowed` in the status contract.
- **Group-1 secrets** (never writable to the database provider): `DATABASE_URL`, `APP_DATABASE_URL`,
  `BUNYIP_APP_PASSWORD`, `JWT_SECRET`, `APP_ENCRYPTION_KEY`, `APP_ENCRYPTION_KEY_PREV`, `APP_KEY_VERSION`,
  `BUNYIP_WEBHOOK_SIGNING_SECRET`, `SECRETS_STORAGE`, and the five `INFISICAL_*` keys. Startup secrets are read from
  files named by `{NAME}_FILE`.
- **Stripe** configuration is database-only; no `STRIPE_*` environment surface is allowed.
- **Feature toggles:** a registry of `Feature` rows, off by default, stored in `feature_toggles.key`. One feature is
  registered (`tenant_hostnames`). Flips are super-admin only.
- **Settings archive:** settings move as one passphrase-encrypted file; import replaces, never merges.
- Full variable reference: [`docs/configuration.md`](configuration.md).

## 6. Authentication and account features

### 6.1 `/v1/auth/*` routes

| Method and path | Auth |
|---|---|
| POST `/register`; GET `/register-challenge` | none |
| POST `/login` | none |
| POST `/logout`; GET `/logout` | optional |
| POST `/logout-all` | authenticated |
| POST `/refresh` | refresh cookie |
| POST `/magic-link`; POST `/magic-link/verify` | none |
| POST `/login-approval/verify` | challenge token |
| POST `/password-reset`; GET `/password-reset/verify`; POST `/password-reset/confirm` | none |
| POST `/2fa/setup`, `/2fa/setup/resume`, `/2fa/confirm`, `/2fa/disable`, `/2fa/recovery-codes`, `/2fa/rekey`, `/2fa/rekey/confirm`; GET `/2fa/status` | authenticated |
| POST `/2fa/verify` | 2FA challenge token |
| POST `/invite/accept` | invite token |
| GET `/redirect` | optional |
| GET `/setup/status` | none (feature-flag probe) |

### 6.2 Login behavior

- Login is rate-limited three ways (Section 3.3). A valid trusted-device cookie can skip the TOTP prompt for
  non-admins; admins always complete full 2FA.
- Response shapes: `{requires_2fa: true, challenge_token}`, `{requires_approval: true, challenge_token}` for a
  suspicious login, or cookies set with `amr = ["pwd"]`.
- A bootstrap admin is promoted at sign-in (`ensure_bootstrap_admin`).
- Login-location alerts: when the geo-IP country changes, an email is sent unless the user opted out
  (`users.login_location_alerts`, default true). The first attributable login records the country without alerting.

### 6.3 One-time token lifetimes

| Token | Lifetime |
|---|---|
| Magic link | 15 minutes |
| Password reset | 1 hour |
| Email change | 1 hour |
| Email verification | 1 hour |
| Admin invite | 7 days |
| Login-approval code | 15 minutes, max 5 attempts, stored hashed |
| TOTP setup token | 15 minutes, stored hashed |

Single-use tokens are consumed with a guarded `UPDATE ... used_at IS NULL` and the result is branched on.

### 6.4 Two-factor

TOTP uses SHA-1, a 30 s step and zero skew. The secret is AES-encrypted at rest. Recovery codes are single-use and
can be regenerated. Rekey runs as setup then confirm, with the pending secret held in `user_totp`. Setup returns 409
for an already-enrolled account and requires the password.

### 6.5 `/v1/users/*` (all authenticated)

`GET /me`, `PUT /me/profile`, `GET|POST|DELETE /me/avatar` (resized to at most 512 px), `POST /me/consents`,
`GET /me/oauth-clients/{client_id}/identity`, `PUT /me/password`, `POST /me/email`, `POST /me/email/confirm`,
`POST /me/email/verify`, `POST /me/email/verify/confirm`, `GET /me/sessions`, `POST /me/sessions/revoke-others`,
`DELETE /me/sessions/{session_id}`, `GET /me/trusted-devices`, `POST /me/trusted-devices/{id}/revoke`, `DELETE /me`.

Account deletion requires the password (and a TOTP code when 2FA is on). It is a soft delete: it cancels the Stripe
subscription, revokes tokens, clears cookies, fans out a webhook and event, and removes the account from the
newsletter lists. A hard delete (`?purge`) is allowed only outside production with an explicit bootstrap flag. A
deleted email address stays reserved (`email_permanent_reservation`) so it cannot be re-registered.

### 6.6 Admin identity features

Admin invites, user management (status, role, email, 2FA reset, password reset, impersonation, delete), IP bans (list
and unban by an admin; create is super-admin), auto-ban config, rate-limit overview, history, whitelist and config
(config writes are super-admin), audit logs, mailer suppressions, support tickets, and account backup and restore
(`/v1/account/backup`, `/restore`, 8 MiB limit, admin only).

## 7. Billing

### 7.1 Model

Membership status (`users.membership_status`): `none`, `active`, `past_due`, `canceled`, `grace_period`. Stripe
`trialing` maps to `active`; trial state is `users.trial_ends_at`. Tiers: `lifetime`, `free`, `early_adopter`,
`standard`. `has_used_trial` governs trial eligibility at checkout.

Access rule: an admin is allowed; so is a lifetime member, a user inside `trial_ends_at`, and a `grace_period` user
while `grace_period_end` is in the future; otherwise only `active` has access.

### 7.2 Checkout and portal (`/v1/memberships/*`, authenticated)

| Route | Behavior |
|---|---|
| GET `/me` | membership summary |
| POST `/checkout` | locks the user row; 409 when already active; 400 without a configured price; creates the Stripe customer if needed; returns `{checkout_url, session_id}` |
| POST `/cancel` | sets cancel-at-period-end (or cancels directly when there is no Stripe customer) and re-mints the access cookie |
| POST `/cancel-now` | 409 when already canceled or none; cancels immediately |
| POST `/reactivate` | 404 without a subscription; 409 when not scheduled for cancellation |
| POST `/billing-portal` | `{url}`; 404 without a customer |
| GET `/payments` | live Stripe invoices, `per_page` clamped 1..100 |

Also: `GET /v1/billing/invoices`, `GET /v1/billing/invoices/{invoice_id}/download` (ownership checked),
`POST /v1/billing/setup-intent` (unauthenticated, registration-rate-limited, requires a valid signup token), and the
public `GET /v1/pricing` (cached; unpublished when `pricing_enabled` is false).

### 7.3 Stripe webhook (`POST /v1/webhooks/stripe`)

Fail-closed: an unset webhook secret returns 500; a missing signature returns Unauthorized; a bad signature or body is
rejected. Idempotency uses `stripe_webhook_events(event_id PK, event_type, received_at, status)`:

- A new event is claimed as `processing`; a `processing` row older than 15 minutes can be reclaimed.
- A `done` row returns 200 without running handlers; an in-flight row returns 409 so Stripe retries.
- Handler success finalizes the row `done`; handler failure deletes the `processing` row and returns the error so
  Stripe retries.

| Event | Effect |
|---|---|
| `checkout.session.completed` | status `active`, welcome email, `MembershipCreated` audit (skipped with no `metadata.user_id`) |
| `customer.subscription.created` / `.updated` | map Stripe status, upgrade tier by product, sync entitlements, audit |
| `customer.subscription.deleted` | `canceled`, reset tier, clear grace, revoke Stripe entitlements, email, audit (skips lifetime members and users with another active subscription) |
| `invoice.payment_succeeded` | clears an open grace period, sets `active`, audit, email |
| `invoice.payment_failed` | opens a 30-day grace period (`grace_period`), audit, email |

Status mapping: `active`/`trialing` -> `active`; `past_due` -> `past_due`; `canceled`, `unpaid`, `incomplete`,
`incomplete_expired`, `paused` -> `canceled`; any other value -> `canceled`, logged as an error.

Entitlement sync revokes all `source = 'stripe'` rows then grants the applications mapped from each subscription's
price; admin-sourced grants are untouched. Errors propagate so Stripe retries.

### 7.4 Stripe admin (`/v1/admin/stripe/*`, admin)

Config get and put (secrets masked on read; a non-writable secrets provider rejects secret writes), permission check,
products and prices (list, create, update, archive, unarchive, replace price), and webhook endpoint management.
Stripe errors are mapped to bunyip-authored messages naming the missing permission; Stripe message text is not passed
through.

### 7.5 Tier configuration

`tier_config` (single row) holds slot counts, trial days, price and product ids per tier, `pricing_enabled`,
per-tier visibility flags and `orgs_enabled`. Admin routes: `GET|PUT /v1/admin/tier-config`,
`PUT /v1/admin/tier-settings`, membership grant and revoke, lifetime grant and revoke, and
`POST /v1/admin/users/{user_id}/tier` (verified admin plus a TOTP code, checked before any change).

## 8. Application catalog and entitlements

- `applications` carry identity, `subdomain`, `webhook_url`, `sort_order`, Forgejo release source
  (`forgejo_owner`, `forgejo_repo`, `pinned_release_tag`, `artifact_source` of `release` or `generic_package`), OCI
  source (`oci_image_owner`, `oci_image_name`, `pinned_image_tag`), `group_id`, `release_notes_url` and
  `requires_entitlement`.
- Visibility: a restricted application is returned to an admin or an entitled user and is a 404 to everyone else.
- Entitlements: `application_entitlements` (PK user + application, `source` of `admin`, `stripe`, `backfill`, `seed`)
  and `stripe_price_entitlements` mapping a price to applications.
- Public: `GET /v1/applications[/{slug}]`, `GET /v1/application-groups`, application docs (`/v1/applications/{slug}/docs`,
  `/v1/application-docs`).
- Member: `GET /v1/downloads`, `GET /v1/applications/{slug}/downloads[...]`. Entitlement is checked before any
  rate-limit slot; a concurrency limit and a durable daily cap apply.
- Admin: application, group and doc CRUD, reorder, download and OCI refresh, entitlement grant and revoke, restricted
  toggle, Stripe price mapping.

Organizations are a feature flag only (`tier_config.orgs_enabled`). The web page `/organizations` renders a
placeholder when the flag is on and the branded 404 when off. There are no organization tables or API routes.

## 9. OIDC / OAuth 2.1 provider

Routes (served by `bunyip-api`; the provider is absent when OIDC is not enabled in config):

| Endpoint | Method |
|---|---|
| `/.well-known/openid-configuration` | GET |
| `/.well-known/jwks.json` | GET |
| `/oauth2/authorize` | GET |
| `/oauth2/token` | POST |
| `/oauth2/userinfo` | GET |
| `/oauth2/revoke` | POST |
| `/oauth2/logout` (RP-initiated) | GET |

There is no introspection endpoint and no dynamic client registration; clients are rows in `oauth_clients`, created by
SQL migrations, startup upserts, or the `machine-client` CLI.

### 9.1 Discovery document

`response_types_supported: ["code"]`, `response_modes_supported: ["query"]`, grant types `authorization_code` and
`refresh_token`, subject type `public`, ID-token alg `EdDSA`, token auth `client_secret_basic` and `none`, PKCE
`S256` required, scopes `openid`, `email`, `offline_access`, `dmarc:read`, `dmarc:write`, back-channel logout
supported, `request` and `request_uri` parameters unsupported. Served with `Cache-Control: public, max-age=300`.

### 9.2 Behavior

| Item | Behavior |
|---|---|
| Grants | Only `authorization_code` and `refresh_token`; per-client `allowed_grant_types` enforced at `/token` |
| PKCE | `S256` only; `oauth_clients.require_pkce` defaults true |
| Client auth | `none` (public client) or `client_secret_basic` (confidential, Argon2 verify); `private_key_jwt` is refused |
| `redirect_uri` | Byte-exact; a bare loopback registration allows any port and path (RFC 8252), parsed to block userinfo and subdomain bypasses |
| Authorization code | TTL `OIDC_CODE_TTL_SECONDS` (default 60, max 120); consumed under `FOR UPDATE`; replay revokes the token family |
| Consent | `openid`, `email`, `offline_access` need no consent screen; other scopes need a stored grant; first-party clients skip consent; consent UI is served by `bunyip-web`, the grant is written by `POST /v1/users/me/consents` |
| Access token | RFC 9068 JWT (`typ: at+jwt`, EdDSA); TTL per client, 60 to 900 s (default 600) |
| ID token | EdDSA JWT |
| Refresh token | Hashed in `refresh_tokens_v2`; rotation in a SERIALIZABLE transaction; reuse revokes the family (`reuse_detected`) and writes an audit row; absolute TTL per client (default 30 days) and idle TTL (default 14 days) |
| Carried on rotation | tenant, `auth_time`, `acr`/`amr`, OP session id (`sid`); a tenant must still be assigned at each rotation |
| OP session | Idle deadline slides on every rotation within an absolute cap; ordinary sign-in idle 8 h and absolute 1 day; remember-me idle 14 days and absolute 30 days |
| Signing keys | Ed25519 from `OIDC_JWT_PRIVATE_KEY_PATH`, `OIDC_JWT_ACTIVE_KID`, and a directory of older public keys kept in the JWKS; a `dev-` key id fails the production config check |
| Back-channel logout | `logout+jwt`; lifecycle events use `lifecycle-event+jwt` via an outbox |
| Tenant claim | Per client `tenant_claim_name`; zero assignments errors, one auto-selects, several render a picker |
| Other config | `OIDC_ISSUER`, `OIDC_LIFECYCLE_EVENT_KEY`, `OIDC_RS_AUDIENCE` |

### 9.3 Machine clients

Registered with the `client_credentials` marker grant. Credentials are HTTP Basic, verified directly at the consuming
endpoint (no token is minted). Consumers: `POST /v1/mailer/send` (and `/v1/mailer/webhooks/feedback`, HMAC-signed,
fail-closed) and `GET /v1/host/secrets/{KEY}` (allow-list in `oauth_clients.allowed_secret_keys`; an allow-list miss is
403 regardless of key existence). CLI: `bunyip-api machine-client register|rotate|disable|list`; the secret is printed
once and never logged.

## 10. OCI registry

A separate listener (enabled by `OCI_REGISTRY_ENABLED` plus a configured Forgejo client). It is read-only.

| Route | Behavior |
|---|---|
| GET `/auth/token` | HTTP Basic email and password; issues a bearer JWT (TTL `OCI_TOKEN_TTL_SECS`, default 900) signed with the app JWT secret; single `repository:<slug>:pull` scope only |
| GET `/v2`, `/v2/` | Version probe; 401 with `WWW-Authenticate` when no bearer |
| GET, HEAD `/v2/{slug}/manifests/{reference}` | Manifest from the upstream Forgejo registry |
| GET, HEAD `/v2/{slug}/blobs/{digest}` | Blob, through a disk cache |
| POST, PUT, PATCH, DELETE `/v2/...` | Rejected (`Unsupported`, 405) |

- Token exchange needs an active membership and a per-product entitlement; failures are audited and denial maps to
  `NameUnknown`. A pre-hashed Argon2 string is verified for unknown users (anti-enumeration).
- Manifest access: the pinned tag, any `sha256` digest, or a recorded non-yanked entry in `application_versions`.
- Caches: manifest cache (`OCI_MANIFEST_CACHE_TTL_SECS`, default 300), on-disk blob cache
  (`OCI_BLOB_CACHE_DIR`, `OCI_BLOB_CACHE_MAX_BYTES`, default 50 GiB, LRU).
- Limits: `OCI_CONCURRENT_MANIFESTS_PER_USER` (default 2) and `OCI_PULLS_PER_USER_PER_DAY` (default 50), counted per
  tag-addressed manifest request only.
- Errors used: `Unauthorized`, `Denied`, `NameUnknown`, `ManifestUnknown`, `BlobUnknown`, `TooManyRequests`,
  `Upstream` (an upstream 401 or 403 is logged as rejected service credentials), `Unsupported`.

## 11. Email

`EmailService` sends through SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS`,
`SMTP_FROM`, `SMTP_EHLO_NAME`) or the database `email_config` row. Inbound support mail uses IMAP
(`SUPPORT_IMAP_*`). Templates are `.html` and `.txt` pairs over a shared base: `account_created`,
`admin_feedback_notification`, `admin_invite`, `email_change_notification`, `email_change_verify`, `email_verify`,
`feedback_response`, `grace_period_reminder`, `login_approval`, `magic_link`, `membership_canceled`,
`new_login_location`, `password_changed`, `password_reset`, `payment_failed`, `payment_succeeded`, `smtp_test`,
`support_reply`, `welcome`. Subjects take the product name from the branding record, not `APP_NAME`.

Suppression: `mailer_suppressions(address PK, reason, detail, ...)`, with `reason` of `bounce` or `complaint`, fed by
the signed provider webhook and checked on every send. A suppressed relay send returns status `suppressed` with no
message id.

## 12. Feedback

`POST /v1/feedback` (rate-limited) stores feedback with request metadata. A pure classifier flags spam on the first of
three signals: sender-domain mimicry, a URL with three or more tags, or a hosting-provider network name. The reason is
stored in `feedback_spam_reasons`. Admins review, mark or unmark spam, archive, restore, export, respond (verified
admin), and download attachments.

## 13. Web front-end (bunyip-web)

### 13.1 BFF behavior

- The browser talks only to `bunyip-web`. It calls `bunyip-api` `/v1/*` server-side, forwarding the `Cookie` header
  verbatim and relaying `Set-Cookie` back.
- On a 401 it calls `/auth/refresh` once and retries with the merged cookies; it also forces a refresh when the role
  claim is stale for an admin gate.
- Outbound calls add `X-Forwarded-For` and the user agent.
- Four `TtlCache` instances on `AppState`: pricing (30 s), applications (30 s), documented apps (30 s), setup status
  (60 s).
- Feature flags (`orgs_enabled` and the registry) are loaded at startup with a 5 s timeout and refreshed every 60 s. A
  failed load never turns a flag on; startup logs an error, a later refresh logs a warning and keeps the last value.
- Branding is cached in an `RwLock` (loaded at startup, refreshed every 60 s) with an unbranded fallback. Brand assets
  are served at `/brand/:kind`.

### 13.2 Guards

`guard` redirects signed-out users to `/login`, pins an admin without 2FA to `/settings/2fa/setup`, and sends users
with unfinished onboarding to `/onboarding`. `admin_guard` adds a redirect of non-admins to `/dashboard`.

### 13.3 Pages

| Area | Routes |
|---|---|
| Public | `/`, `/healthz`, `/pricing`, `/our-story`, `/roadmap`, `/terms`, `/privacy`, `/docs`, `/docs/:slug`, `/apps/:slug/docs[/:doc_slug]`, `/feedback` |
| Auth | `/login`, `/login/2fa`, `/login/approval`, `POST /logout`, `/register`, `/magic-link`, `/password-reset[/confirm]`, `/invite/accept`, `/settings/confirm-email`, `/settings/verify-email` |
| Account | `/onboarding`, `/oauth2/consent`, `/settings` and its profile, avatar, email, password, sessions, trusted-device, 2FA setup, recovery-codes, rekey and account-delete actions |
| Member | `/dashboard`, `/applications`, `/downloads[/:slug/:asset]`, `/billing`, `/checkout/success`, `/membership-required`, `/membership[/subscribe|cancel|cancel-now|reactivate|billing-portal]`, `/community`, `/organizations` (flag-gated) |
| Admin | `/admin` and sections for status, providers, audit logs, logs, seed, invites, IP bans, rate limits, users, memberships, feedback, applications, groups, entitlements, tier settings, features, branding, email, mailer suppressions, system config, mail-provider and product integrations, auto-ban settings, and Stripe (products, prices, webhooks) |
| Backup | `/integrations/backup`, `/integrations/backup/download`, `POST /integrations/backup/restore` |

Mutations are plain form posts. htmx is vendored (2.0.3) and loaded only on the admin users page, where a request with
`HX-Request` returns just the `#users-panel` fragment. The CSP allows only same-origin scripts.

### 13.4 UI rules

Semantic theme tokens only (no color literals in the shell), dark mode through a small inline-free script
(`assets/js/theme.js`), thumb-only scrollbars, Title Case section names, terse empty states, and no prices or deadlines
as literals. Authenticated navigation comes from `shell_nav_sections()`. The full rules are in
[`docs/invariants/ui.md`](invariants/ui.md).

## 14. Build, CI and deployment

### 14.1 Topology (`compose.yml`)

| Service | Image | Notes |
|---|---|---|
| `postgres` | `postgres:18.2-alpine3.23` | healthcheck via `pg_isready`; named data volume |
| `api` | `${BUNYIP_API_IMAGE}` (required, pinned) | ports 4401 and the OCI port; mounts the OIDC key directory read-only, a config-layer volume, and OCI and download cache volumes |
| `web` | `${BUNYIP_WEB_IMAGE}` (required, pinned) | port 4400; holds no secrets |

Ports bind to loopback by default. All services share one private bridge network. Cache volumes are named volumes,
never bind mounts. Secrets are file-based compose secrets. `compose.dev.yml` builds from the Dockerfiles with per-user
names; `compose.dev-sso.yml` layers a reverse-proxy network on top. See
[`docs/self-hosting.md`](self-hosting.md) and [`docs/dev-sso-three-repo-runbook.md`](dev-sso-three-repo-runbook.md).

### 14.2 Task runner

`just` drives development. `just check` is the umbrella gate: justfile and migration checks, workflow and shell
contract checks, serde-compat, env and config parity, Argon2 offload, no-Bash, scrollbar, CSS-current, UI-copy,
price, brand and theme literal checks, em-dash check, doc-surface, cache-mount and cache-key checks, dependency audit,
then build, clippy, fmt and the docker builder stage. Toolchain-less machines use `just check-container`.

### 14.3 CI workflows (`.forgejo/workflows/`)

`check` (push and PR), `audit` (weekly dependency audit), `build-api` and `build-web` (image builds),
`create-release` (on merge of a release PR, via `pull_request_target`), `release-images` (dispatch the tagged image
builds), `e2e` and `e2e-pr` (Playwright), `renovate` (scheduled). Every workflow job runs under Nushell.

### 14.4 Releases

`just create-release <major|minor|hotfix>` bumps `[workspace.package].version` and opens a release PR; merging it
creates the tag, release and images. The two images are released and pinned as a matched pair.

## 15. Test coverage

Playwright specs in `e2e/tests` cover login and logout, magic link, password reset, profile, sessions, email change,
subscribe and billing portal, OIDC authorize redirect, and the OIDC authorize-token-userinfo-refresh flow. Several are
skipped without a mail sink or Stripe key. Specs for signup, two-factor, re-registration blocking, password change,
subscription cancel and the consent screen are present but disabled with `test.fixme`. No spec covers the admin area,
feedback, or the organizations flag. Unit and integration tests are run by `just check`.

## 16. Unverified areas

These were not confirmed in code while writing this document:

- Exact Argon2 parameters for user passwords (only recovery-code parameters were read).
- Request and response bodies and per-handler error codes for most routes.
- Registration rules: bot guard, password strength and breach check (`services/password_breach.rs` exists).
- Audit-log action enum values.
- Window lengths for the OAuth and OCI rate-limit actions.
- The `dunite-stripe` call details, `reconcile_prices.rs`, the mailing-list sync service, `reencrypt.rs`, `secrets.rs`.
- How an expired grace period is swept to `canceled`, how signup sets `trial_ends_at`, and the caller of the
  grace-period reminder email.
- The extractor type on some admin routes (inferred from the `/admin` scope).
- Recipe bodies for several `check-*` gates (likely in the imported `common` justfile or `scripts/`).
- `private_key_jwt` client auth is refused in code; a `dpop_bound` column exists on `oauth_clients` but its use was not traced.
- The exact HTML behavior of the consent and tenant-picker pages.
