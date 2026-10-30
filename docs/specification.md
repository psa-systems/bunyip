# Bunyip Specification

This document describes what the Bunyip workspace implements, as read from the source in this repository. Where a
statement and the code disagree, the code is the authority.

## 1. Purpose and scope

Bunyip is a SaaS account, billing and distribution platform. Operators and members use it for:

- account signup and sign-in (password, magic link, two-factor, login approval)
- subscription billing through Stripe
- a platform admin area
- an OpenID Connect / OAuth 2.1 provider (the OP) for first-party relying-party products
- a read-only, authenticated OCI registry front for application images
- authenticated application downloads and a catalog of hosted applications
- a mailer relay and a host-secret/host-config read API for registered machine clients

It does not: host the products that consume its OIDC provider; accept image pushes (OCI writes are rejected);
provide dynamic OIDC client registration or token introspection; store invoices or payment history (read live from
Stripe).

## 2. Architecture

### 2.1 Workspace members (`Cargo.toml`)

| Member | Kind | Role |
|---|---|---|
| `bunyip-api` | binary (actix-web 4) | Backend `/v1` API, OIDC issuer, OCI listener, migrations, maintenance subcommands |
| `bunyip-web` | binary (Axum 0.7) | Server-rendered browser front-end; a backend-for-frontend over the API |
| `crates/bunyip-domain` | library | Models, repositories, services, `Config`, middleware, email templates |
| `crates/bunyip-oidc` | library | OIDC / OAuth 2.1 routes, handlers and provider service |
| `crates/bunyip-oci` | library | OCI registry routes, handlers, caches, token service |
| `crates/web-kit` | library | Shared server-rendered UI pieces, CSRF and client-IP middleware |

`bunyip-api` has four binaries: `bunyip-api` (default), `bunyip-e2e-bootstrap` (E2E account seeder), `seed`
(file-driven seed loader) and `gen-demo-seed` (emits seed JSON, never touches a database). `e2e/` is a Playwright
project (Node) that drives the deployed stack.

Shared framework crates are consumed as git dependencies and are not part of this workspace. The workspace version is
set once in `[workspace.package]`. The Rust toolchain is pinned in `rust-toolchain.toml` (with `clippy` and `rustfmt`).

### 2.2 Runtime and data flow

- The browser talks only to `bunyip-web`. It calls `bunyip-api` `/v1/*` server-side, forwarding the `Cookie` header and
  relaying `Set-Cookie`, and adds `X-Forwarded-For` with the resolved end-user address.
- `bunyip-api` is the only component with a database. PostgreSQL is accessed with sqlx; migrations run at startup
  (`sqlx::migrate!("./migrations")`).
- `bunyip-api` runs two actix `HttpServer`s in one process: the primary API and, when enabled, the OCI registry
  listener.
- Relying-party products use `/.well-known/*` and `/oauth2/*` on `bunyip-api`; the login and consent UI is served by
  `bunyip-web`.

### 2.3 Listeners

| Listener | Default port | Source |
|---|---|---|
| `bunyip-web` | 4400 (`BUNYIP_BIND_ADDR`) | `bunyip-web` config |
| `bunyip-api` primary | 4401 (`APP_PORT`, bind address `HOST_IP`) | `Config` |
| OCI registry | 18081 (`OCI_REGISTRY_PORT`) | `Config`, only when enabled |

## 3. Functional requirements

### 3.1 Accounts and sessions

- A visitor can register (a signup challenge from `GET /v1/auth/register-challenge` is required), sign in with
  password, request a magic link, reset a password, and accept an admin invite.
- Login returns either a session (cookies), a two-factor challenge, or a login-approval challenge. A trusted-device
  cookie can skip the TOTP prompt for non-admins.
- The access token is a JWT in the `access_token` cookie (30 minutes). The refresh token is in the `refresh_token`
  cookie; its absolute lifetime is 30 days with remember-me and 1 day without.
- A user can list and revoke sessions, list and revoke trusted devices, change password, change and verify email,
  upload an avatar, record OAuth consents, and delete the account (`DELETE /v1/users/me`).
- Two-factor (TOTP) supports setup, confirm, verify, disable, recovery-code regeneration and rekey.
- One-time token lifetimes in code: magic link 15 minutes, password reset 1 hour, email verification and email change
  1 hour, admin invite 7 days, login-approval code 15 minutes, trusted device 30 days.
- Resend of verification and reset mail is limited to a rolling 3600 second window.

### 3.2 Billing

- A member can start a Stripe checkout, cancel at period end, cancel immediately, reactivate, open the billing portal,
  and list payments and invoices (read live from Stripe). `GET /v1/pricing` is public.
- The Stripe webhook (`POST /v1/webhooks/stripe`) verifies the signature, records events in `stripe_webhook_events`
  for idempotency and applies membership changes. A payment failure opens a 30-day grace period.
- Stripe credentials are stored encrypted in `stripe_config` and edited by an admin; admin routes manage products,
  prices (create, update, archive, unarchive, replace) and webhook endpoints.
- Tier and slot settings live in `tier_config`; an admin can grant and revoke membership and lifetime membership.

### 3.3 Applications, entitlements and downloads

- Applications and groups are catalog rows. Public routes list applications, groups and application docs.
- Entitlements (`application_entitlements`) gate restricted applications; Stripe prices can be mapped to applications
  (`stripe_price_entitlements`).
- Members download release assets through the API, which proxies a Forgejo-compatible release source, with a
  per-user concurrency limit, a per-user daily limit and an on-disk cache.
- An admin can refresh the release and OCI metadata of an application.

### 3.4 OIDC provider

- Authorization-code flow with mandatory PKCE `S256`, refresh-token rotation with reuse detection, userinfo,
  revocation, RP-initiated logout and back-channel logout, JWKS publication, and EdDSA-signed tokens.
- Per-client tenant assignment (`oauth_client_user_tenants`), lifecycle events through an outbox
  (`lifecycle_event_outbox`, `lifecycle_event_delivery`).
- Machine clients (registered in `oauth_clients` with the `client_credentials` marker) authenticate with HTTP Basic
  at the mailer relay and host endpoints.

### 3.5 OCI registry

- Read-only pull of application images through an authenticated token exchange and a proxied upstream registry, with a
  manifest cache and a disk blob cache.

### 3.6 Feedback, support and mail

- Public `POST /v1/feedback` stores feedback; admins review, mark spam, archive, restore, export and respond.
- Support tickets and messages are ingested from a monitored mailbox over IMAP and answered by admins.
- Outbound mail goes through SMTP. A suppression list (`mailer_suppressions`) is checked on relayed sends and fed by a
  signed bounce/complaint webhook.

### 3.7 Administration

Admin routes cover users, roles, invites, IP bans, auto-ban config, rate-limit overview/history/whitelist/config, audit
logs, error logs, feature toggles, branding and brand assets, email and mailer settings, system configuration,
product-integration configuration, provider status, key health and key rotation, notifications, seed
export/import, and account backup/restore.

## 4. Interfaces

### 4.1 `bunyip-api` HTTP routes

Auth column: none, optional (cookie if present), user (valid access token), admin, machine (HTTP Basic machine
client), signed (signature checked in the handler).

Root level:

| Method and path | Auth |
|---|---|
| GET `/`, `/health`, `/version`, `/e2e-bootstrapped` | none |
| GET `/.well-known/openid-configuration`, `/.well-known/jwks.json` | none |
| GET `/oauth2/authorize`, `/oauth2/userinfo`, `/oauth2/logout`; POST `/oauth2/token`, `/oauth2/revoke` | per OAuth rules |

`/v1/auth` (auth is per handler; challenge and setup routes carry their own tokens):

`POST /register`, `GET /register-challenge`, `POST /login`, `POST /logout`, `GET /logout`, `POST /logout-all`,
`POST /refresh`, `POST /magic-link`, `POST /magic-link/verify`, `POST /login-approval/verify`,
`POST /password-reset`, `GET /password-reset/verify`, `POST /password-reset/confirm`, `POST /2fa/setup`,
`POST /2fa/setup/resume`, `POST /2fa/confirm`, `POST /2fa/verify`, `POST /2fa/disable`, `POST /2fa/recovery-codes`,
`POST /2fa/rekey`, `POST /2fa/rekey/confirm`, `GET /2fa/status`, `POST /invite/accept`, `GET /redirect`,
`GET /setup/status`.

`/v1` other scopes:

| Scope | Routes |
|---|---|
| `/health`, `/version` | GET, none |
| `/users` | GET/DELETE `/me`; PUT `/me/profile`; GET/POST/DELETE `/me/avatar`; POST `/me/consents`; GET `/me/oauth-clients/{client_id}/identity`; PUT `/me/password`; POST `/me/email`, `/me/email/confirm`, `/me/email/verify`, `/me/email/verify/confirm`; GET `/me/sessions`; POST `/me/sessions/revoke-others`; DELETE `/me/sessions/{session_id}`; GET `/me/trusted-devices`; POST `/me/trusted-devices/{id}/revoke` |
| `/account` | backup download and restore (admin) |
| `/downloads` | GET list |
| `/events` | GET (server-sent events stream) |
| `/applications` | GET `""`, `/{slug}`, `/{slug}/downloads`, `/{slug}/downloads/{asset_name}`, `/{slug}/downloads/{version}/{asset_name}`, `/{slug}/docs`, `/{slug}/docs/{doc_slug}` |
| `/application-docs`, `/application-groups` | GET list |
| `/billing` | POST setup-intent; GET `/invoices`, `/invoices/{invoice_id}/download` |
| `/feedback` | POST `""` |
| `/mailer` | POST `/send`, POST `/webhooks/feedback` (machine and signed) |
| `/memberships` | GET `/me`, `/payments`; POST `/checkout`, `/cancel`, `/cancel-now`, `/reactivate`, `/billing-portal` |
| `/pricing`, `/branding`, `/branding/assets/{kind}` | GET, none |
| `/webhooks` | POST `/stripe` (signed) |
| `/host` | GET `/secrets/{key}`, `/config/{key}` (machine) |
| `/admin` | admin; see 4.2 |

### 4.2 `/v1/admin` route families

`stats`, `health`, `integrations`, `providers/status`, `key-health`, `users` (list, get, delete, status, role, email,
email verify, two-factor reset, reset-password, impersonate, lifetime, lifetime revoke, tier, entitlements),
`applications` (CRUD, reorder, docs, group, restricted, stripe-prices, downloads refresh, oci refresh),
`application-docs`, `application-groups`, `memberships` (list, grant, revoke), `account-deletes/{user_id}/replay`,
`ip-enrichment`, `ip-bans`, `mailer-suppressions`, `rate-limits` (list, history, overview, reset, whitelist),
`rate-limit-configs`, `audit-logs`, `logs`, `seed` (templates, export, import), `feedback` (list, new-count, export,
archive, restore, attachments, status, mark-spam, unmark-spam, respond, delete), `support/tickets`, `system-config`,
`oauth-clients/{client_id}/user-tenants`, `invites`, `pricing/status`, `tier-config`, `tier-settings`,
`feature-toggles`, `branding` (and assets), `email` (get, put, test, test-send), `mirzam`, `mokosh`, `auto-ban-config`,
`stripe` (config, permissions, products, prices, webhooks), `notifications`, `key-rotation/{key_id}/status` and
`/reencrypt`.

### 4.3 OCI listener

| Route | Behavior |
|---|---|
| GET `/auth/token` | token exchange |
| GET `/v2`, `/v2/` | version probe |
| GET, HEAD `/v2/{slug}/manifests/{reference}` | manifest |
| GET, HEAD `/v2/{slug}/blobs/{digest}` | blob |
| POST, PUT, PATCH, DELETE `/v2/{tail}` | rejected as unsupported |

### 4.4 `bunyip-web` routes

Public: `/healthz`, `/`, `/pricing`, `/our-story`, `/roadmap`, `/terms`, `/privacy`, `/docs`, `/docs/:slug`,
`/apps/:slug/docs[/:doc_slug]`, `/brand/:kind`, `/favicon.ico`, static files under `/assets`. Authentication pages:
`/login`, `/logout`, `/register`, `/settings/confirm-email`, `/settings/verify-email`. Member pages: `/dashboard`,
`/applications`, `/downloads`, `/downloads/:slug/:asset`, `/billing`, `/checkout/success`, `/membership-required`,
`/membership`, `/community`, `/settings` and its sessions, trusted-device and two-factor sub-routes. Admin pages live
under `/admin` (status, providers, audit logs, logs, seed, invites, IP bans, rate limits, users, memberships, feedback,
applications, groups, entitlements, tier settings, features, branding, email, mailer suppressions, system config,
integrations, auto-ban settings, Stripe products/prices/webhooks) plus `/integrations/backup`. Unmatched routes return
the branded 404. Mutations are form posts.

### 4.5 `bunyip-api` subcommands

Run as `bunyip-api <subcommand>`; any other argument is an error that lists the known names.

| Subcommand | Purpose |
|---|---|
| `secrets-status [--json]` | report which store serves each governed secret |
| `secrets-migrate --to <environment\|database\|infisical> [--dry-run] [--allow-missing]` | move governed secrets between stores |
| `secrets-purge [--confirm]` | remove secrets from non-selected stores |
| `config-status [--json]` | report which provider serves each admin-managed configuration key |
| `machine-client register\|rotate\|disable\|list` | manage machine-client credentials |
| `reconcile-duplicate-prices [--apply]` | report (or archive) duplicate active Stripe prices |
| `settings-export`, `settings-import` | move settings as an encrypted archive |
| `mirzam-backfill` | backfill mailing-list sync |
| `reencrypt-secrets` | re-encrypt stored secrets under the current key |

## 5. Data model

PostgreSQL. Migrations are in `bunyip-api/migrations/` (122 `.sql` files plus a README) and are applied at startup.
Committed migrations are not edited in place.

Tables created by migrations (excluding dropped ones), by family:

| Family | Tables |
|---|---|
| Accounts and sessions | `users`, `user_avatars`, `refresh_tokens`, `refresh_token_families`, `refresh_tokens_v2`, `access_token_blocklist`, `op_sessions` |
| One-time tokens | `magic_link_tokens`, `password_reset_tokens`, `email_verification_tokens`, `email_change_requests`, `admin_invites` |
| Two-factor and devices | `user_totp`, `recovery_codes`, `trusted_devices`, `login_approval_codes`, `login_devices` |
| Protection and audit | `ip_bans`, `auto_ban_config`, `rate_limits`, `rate_limit_history`, `rate_limit_traffic`, `rate_limit_whitelist`, `rate_limit_configs`, `audit_logs`, `admin_notifications` |
| Feedback and support | `feedback`, `feedback_archive`, `feedback_attachments`, `feedback_spam_reasons`, `support_tickets`, `support_messages` |
| Mail | `email_config`, `mailer_suppressions` |
| Billing | `stripe_config`, `tier_config`, `stripe_webhook_events`, `stripe_price_entitlements` |
| Catalog | `applications`, `application_groups`, `application_versions`, `application_docs`, `application_entitlements`, `download_cache`, `download_daily_counts` |
| OIDC | `oauth_clients`, `oauth_authorization_codes`, `user_application_access`, `oauth_client_user_tenants`, `lifecycle_event_outbox`, `lifecycle_event_delivery`, `account_delete_dispatch_failures` |
| OCI | `oci_blob_cache`, `oci_pull_daily_counts` |
| Configuration and branding | `feature_toggles`, `branding`, `branding_assets`, `mirzam_config`, `mokosh_config` |

`subscriptions`, `payment_history` and `invoices` were created and later dropped.

Constraints and behavior verified in code:

- Row-level security is enabled and forced with policy `user_isolation` on `trusted_devices`, `user_totp`,
  `recovery_codes`, `application_entitlements` and `email_change_requests`. It takes effect only for the unprivileged
  `bunyip_app` role (pool from `APP_DATABASE_URL`); without it the app pool falls back to the primary pool.
- Each database pool allows 10 connections; with the RLS pool configured one replica holds up to 20.
- `stripe_webhook_events` carries `event_id`, `event_type`, `received_at` and a processing status.
- The feature-toggle registry holds one feature, `tenant_hostnames`.
- At-rest encryption uses one AES-256-GCM key set (`APP_ENCRYPTION_KEY`, previous keys in `APP_ENCRYPTION_KEY_PREV`)
  for TOTP secrets, Stripe credentials and the SMTP password.

## 6. Configuration

### 6.1 Mechanism

Every environment variable `bunyip-api` reads is declared in `ENV_INVENTORY` with a class; a test fails the build if
`bunyip-api` or `bunyip-web` source reads an undeclared variable.

- Required: startup fails with one error line per missing variable, exit non-zero (`DATABASE_URL`, `SECRETS_STORAGE`).
- Required in production (`ENVIRONMENT` is `production`, the default): `JWT_SECRET`, `APP_ENCRYPTION_KEY`,
  `BUNYIP_WEBHOOK_SIGNING_SECRET`, and, when `OIDC_ISSUER` is set, `OIDC_JWT_PRIVATE_KEY_PATH` and
  `OIDC_JWT_ACTIVE_KID`.
- Feature-gating: one startup warning per absent variable naming the feature that is off.
- Defaulted: documented in `docs/configuration.md`.
- Secrets can be supplied as `{NAME}_FILE` (path to a file; an empty file means not configured).
- Admin-managed configuration resolves through a provider stack: database rows, then files in `BUNYIP_CONFIG_DIR`,
  then environment.
- `SECRETS_STORAGE` (`environment`, `database` or `infisical`) selects the one store for governed integration secrets
  (SMTP password, Stripe keys, IMAP password, mailing-list token, a hosted-product OAuth client secret).

### 6.2 Variables by area (names from `ENV_INVENTORY`)

| Area | Variables |
|---|---|
| Runtime | `ENVIRONMENT`, `RUST_LOG`, `HOST_IP`, `APP_PORT`, `APP_NAME`, `APP_URL`, `BUNYIP_CONFIG_FILE`, `BUNYIP_CONFIG_DIR`, `DB_POOL_METRICS_INTERVAL_SECS`, `DUNITE_ARGON2_MAX_CONCURRENT`, `DUNITE_ARGON2_PERMIT_TIMEOUT_SECS` |
| Database | `DATABASE_URL`, `APP_DATABASE_URL`, `BUNYIP_APP_PASSWORD` |
| Secrets and keys | `SECRETS_STORAGE`, `JWT_SECRET`, `APP_ENCRYPTION_KEY`, `APP_ENCRYPTION_KEY_PREV`, `APP_KEY_VERSION`, `BUNYIP_WEBHOOK_SIGNING_SECRET`, `INFISICAL_ENABLED`, `INFISICAL_ADDRESS`, `INFISICAL_PROJECT_ID`, `INFISICAL_ENVIRONMENT`, `INFISICAL_SECRET_PATH`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET` |
| Browser origin and cookies | `CORS_ORIGIN` (also the CSRF allow-list), `BUNYIP_WEB_ORIGIN`, `COOKIE_DOMAIN`, `BUNYIP_COOKIE_SHARED_DOMAIN`, `CSP_CONNECT_SRC`, `CSP_FORM_ACTION` |
| Client IP and abuse | `TRUSTED_PROXY_CIDR`, `COUNTRY_ALLOW`, `COUNTRY_DENY`, `AUTO_BAN_ENABLED`, `AUTO_BAN_THRESHOLD`, `AUTO_BAN_WINDOW_SECS`, `AUTO_BAN_DURATION_SECS`, `IP2LOCATION_DB_PATH`, `IP2PROXY_DB_PATH`, `RATE_LIMIT_{ACTION}_MAX_REQUESTS`, `RATE_LIMIT_{ACTION}_WINDOW_SECONDS` |
| First admin | `SETUP_DEFAULT_ADMIN`, `BOOTSTRAP_ADMIN_EMAIL` |
| Sign-in policy | `LOGIN_APPROVAL_ENABLED`, `SIGNUP_BOT_GUARD_ENABLED` |
| OIDC provider | `OIDC_ISSUER`, `OIDC_JWT_PRIVATE_KEY_PATH`, `OIDC_JWT_ACTIVE_KID`, `OIDC_JWT_PUBLIC_KEYS_DIR`, `OIDC_ACCESS_TOKEN_TTL_SECONDS` (default 600, clamped 60 to 900), `OIDC_REFRESH_TOKEN_TTL_SECONDS` (default 2592000), `OIDC_REFRESH_IDLE_TTL_SECONDS` (default 1209600), `OIDC_CODE_TTL_SECONDS` (default 60, max 120), `SESSION_IDLE_TTL_SECONDS` (default 28800), `SESSION_IDLE_TTL_REMEMBER_SECONDS` (default 1209600), `OIDC_LIFECYCLE_EVENT_KEY`, `OIDC_RS_AUDIENCE` |
| Hosted-product OIDC clients | `*_REDIRECT_URIS`, `*_AUDIENCE`, `*_POST_LOGOUT_REDIRECT_URIS` and one client secret hash for each of the three seeded hosted products; `MOKOSH_WEBHOOK_URL`, `MOKOSH_BACKUP_API_URL`, `MOKOSH_PROVIDER_STATUS_URL`, `DRILLMARK_PROVIDER_STATUS_URL`, `PROVIDER_STATUS_CLIENT_ID`, `PROVIDER_STATUS_CLIENT_SECRET` |
| Email | `EMAIL_ENABLED`, `EMAIL_LOG_TOKENS`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_EHLO_NAME`, `SMTP_FROM`, `ADMIN_NOTIFICATION_EMAILS`, `MAILER_WEBHOOK_SECRET`, `SUPPORT_INBOX_EMAIL`, `SUPPORT_IMAP_HOST`, `SUPPORT_IMAP_PORT`, `SUPPORT_IMAP_USERNAME`, `SUPPORT_IMAP_PASSWORD`, `SUPPORT_IMAP_MAILBOX`, `SUPPORT_IMAP_ENABLED`, `SUPPORT_IMAP_POLL_SECS` |
| Stripe (read only as `*_FILE`) | `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` |
| Billing and tiers | `TIER_LIFETIME_SLOTS`, `TIER_EARLY_ADOPTER_SLOTS`, `TIER_EARLY_ADOPTER_TRIAL_DAYS`, `TIER_STANDARD_TRIAL_DAYS`, `BUNYIP_BILLING_TRIAL_PERIOD_DAYS` |
| Distribution | `FORGEJO_BASE_URL`, `FORGEJO_API_TOKEN`, `DOWNLOAD_CACHE_DIR`, `DOWNLOAD_CACHE_MAX_BYTES`, `DOWNLOAD_CONCURRENCY_PER_USER`, `DOWNLOAD_DAILY_LIMIT_PER_USER`, `FORGEJO_RELEASE_CACHE_TTL_SECS` |
| OCI | `OCI_REGISTRY_ENABLED`, `OCI_REGISTRY_SERVICE` (required when enabled), `OCI_REGISTRY_PORT`, `OCI_REGISTRY_REALM`, `OCI_BLOB_CACHE_DIR`, `OCI_BLOB_CACHE_MAX_BYTES`, `OCI_MANIFEST_CACHE_TTL_SECS`, `OCI_CONCURRENT_MANIFESTS_PER_USER`, `OCI_PULLS_PER_USER_PER_DAY`, `OCI_TOKEN_TTL_SECS` |
| Update check | `BUNYIP_UPDATE_CHECK_URL`, `BUNYIP_UPDATE_CHECK_TOKEN` |
| Other integrations | `MIRZAM_API_TOKEN`, `MOKOSH_GOOGLE_CLIENT_SECRET` |
| Test and seed tooling | `BUNYIP_E2E_BOOTSTRAP_ALLOW`, `BUNYIP_E2E_TOTP_SECRET`, `BUNYIP_SEED_ALLOW` |
| `bunyip-web` | `BUNYIP_BIND_ADDR`, `BUNYIP_API_URL`, `BUNYIP_API_PUBLIC_ORIGIN`, `BUNYIP_OIDC_ISSUER`, `BUNYIP_APP_DOMAIN`, `BUNYIP_COMMUNITY_URL`, `TRUSTED_PROXY_CIDR`, `RUST_LOG` |

The full per-variable reference is `docs/configuration.md`.

## 7. Security

- **Tokens and cookies.** Session access tokens are HS256 JWTs signed with `JWT_SECRET`; OIDC tokens are EdDSA JWTs
  signed with the Ed25519 key at `OIDC_JWT_PRIVATE_KEY_PATH`. Cookies: `access_token`, `refresh_token`,
  `bunyip_trusted_device`, `bunyip_op_session`.
- **Authorization extractors** (`crates/bunyip-domain/src/middleware/auth.rs`): authenticated user, optional user,
  admin, verified admin (two-factor verified), super admin, member.
- **CSRF.** `bunyip-api` checks Origin/Referer on cookie-authenticated writes against `CORS_ORIGIN`. `bunyip-web`
  enforces same-origin on state-changing posts.
- **Headers.** `bunyip-api` sets security headers and a CSP whose `connect-src` and `form-action` are widened with
  the CORS origins. `bunyip-web` sets a CSP on every response.
- **Rate limits.** A floor of 100 requests per 60 s keyed by user (authenticated) and 60 per 60 s keyed by IP
  (unauthenticated), with exempt health, version, pricing, Stripe webhook and mailer paths. Per-action limits
  (requests / seconds): `LOGIN` 10/60, `MAGIC_LINK` 3/600, `PASSWORD_RESET` 3/3600, `REGISTRATION` 10/3600,
  `TWO_FACTOR_VERIFY_FAILURES` 5/900, `FEEDBACK_SUBMIT` 20/3600, `SMTP_TEST` 6/300, `MAILER_SEND` 60/60,
  `MAILER_AUTH_FAILURES` 10/60, `HOST_SECRET_READ` 30/60, `HOST_SECRET_AUTH_FAILURES` 10/60, `HOST_CONFIG_READ` 30/60,
  `HOST_CONFIG_AUTH_FAILURES` 10/60, `ADMIN_DIAGNOSTICS` 60/60, `OAUTH_TOKEN` 60/60, `OAUTH_AUTHORIZE` 120/60,
  `OAUTH_USERINFO` 240/60, `OAUTH_REVOKE` 60/60, `OAUTH_DISCOVERY` 120/60, `OCI_TOKEN_FAILURES` 5/60,
  `OCI_TOKEN_THROUGHPUT` 60/60, `OCI_TOKEN_IP_FAILURES` 20/60. Overrides come from `rate_limit_configs` rows or the
  `RATE_LIMIT_*` variables.
- **Auto-ban.** Offending IPs are banned in memory and persisted to `ip_bans` (defaults from the `AUTO_BAN_*`
  variables); the ban check is the outermost API middleware.
- **Input.** JSON bodies are limited to 32768 bytes; malformed input returns the generic error envelope.
- **Secrets at rest.** AES-256-GCM key set (section 5). Secrets can be mounted as files. Startup reports every missing
  required secret together and exits non-zero rather than panicking.
- **OIDC.** Only `authorization_code` and `refresh_token` grants, PKCE `S256`, EdDSA ID tokens, back-channel logout.
  Discovery advertises `response_types_supported: ["code"]`.
- **Stripe webhook.** Signature verified; handler failure returns an error so Stripe retries.
- **Machine clients.** Credentials are verified against an Argon2id hash on `oauth_clients`; the secret is shown once
  by the CLI. Host-secret reads are limited to an allow-list on the caller's registration.
- **Transport headers** such as HSTS are not set by `bunyip-web`; the edge proxy is expected to set them.

## 8. Integrations and dependencies

| Role | Service |
|---|---|
| Database | PostgreSQL (compose image `postgres:18.2-alpine3.23`) |
| Payments | Stripe |
| Mail out / in | SMTP relay; IMAP mailbox for support ingestion |
| Release and image source | Forgejo-compatible server (release assets, generic packages, container registry) |
| Secret store | Infisical (when `SECRETS_STORAGE=infisical`) |
| Geo / proxy data | IP2Location and IP2Proxy database files (optional) |
| Update check | HTTP endpoint at `BUNYIP_UPDATE_CHECK_URL` (optional) |
| First-party products | OIDC relying parties, a backup adapter, a provider-status feed and a mailing-list sync, each gated by its own variables |

## 9. Deployment and operations

- `compose.yml` runs three services on one bridge network: `postgres`, `api` and `web`. The `api` and `web` images are
  required, pinned tags (`BUNYIP_API_IMAGE`, `BUNYIP_WEB_IMAGE`). Published ports bind to `HOST_IP` (default
  loopback): 4401, 18081 and 4400.
- Secrets are compose file secrets read through the `{NAME}_FILE` convention. Containers run with `no-new-privileges`,
  all capabilities dropped (four re-added for the entrypoint user switch) and a read-only root filesystem.
- Named volumes: Postgres data, a configuration-layer directory (`/app/config`), the OCI blob cache and the download
  cache. The OIDC key directory is mounted read-only.
- `bunyip-api/oci-build/Dockerfile` builds a static musl image with `HEALTHCHECK` on `GET /v1/health` (30 s interval)
  and entrypoint `gosu-entrypoint.sh /app/bunyip-api`. `bunyip-web/oci-build/Dockerfile` builds a glibc image with
  entrypoint `gosu-entrypoint.sh` and `CMD /app/bunyip-web`. `bunyip-api/Dockerfile` and `bunyip-web/Dockerfile` are
  the development images (`cargo watch`).
- `compose.dev.yml` and `compose.dev-sso.yml` are development variants.
- `just` drives development; `just pre-commit` and `just check` are the gates. CI workflows are in
  `.forgejo/workflows/`: `check`, `audit`, `build-api`, `build-web`, `create-release`, `e2e`, `e2e-pr`, `renovate`.
- Liveness: `GET /health` and `GET /v1/health` on the API, `GET /healthz` on the web server (no database dependency).
  `GET /version` reports the build version, revision and update status.
- `GET /e2e-bootstrapped` returns `false` without querying when `ENVIRONMENT` is production.

## 10. Non-functional behavior

- **Logging.** `tracing` with an `EnvFilter` from `RUST_LOG` (default `info`), initialized before configuration loads
  so configuration failures are logged. An in-memory error-log buffer feeds the admin logs view. The access log
  records the trusted external client IP; every request carries a request id.
- **Middleware order in `bunyip-api`** (outermost first): auto-ban, rate-limit floor, CORS (`max_age` 3600), CSRF
  origin guard, request id, security headers, access log, request tracing, response compression.
- **Middleware order in `bunyip-web`** (outermost first): compression, CSP, client-IP forwarding, CSRF origin check,
  unknown-host gate.
- **Errors.** Failures return an error envelope with a non-2xx status; OIDC, OCI and webhook endpoints use their
  protocol-specific error shapes.
- **Shutdown.** The primary server uses a 30 second shutdown timeout.
- **Refresh jobs.** The API re-reads branding and feature toggles every 60 seconds.
- **Audit.** Security-relevant actions are written to `audit_logs`.
- **Database pool metrics** are sampled when `DB_POOL_METRICS_INTERVAL_SECS` is set.
