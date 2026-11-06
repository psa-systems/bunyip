# Bunyip serves Mokosh's Google OAuth client

Design for BUNYIP-855. Replaces PMS-1430's manual "operator pastes `GOOGLE_CONTACTS_CLIENT_ID` / `_SECRET` into Mokosh's Infisical `/app`" step with a Bunyip-served path that an operator edits once in Bunyip's admin surface.

The parent epic is BUNYIP-652 ("Secrets, CI and environment configuration"). This doc covers the Google OAuth pair as the first instance of the pattern; the shape here applies to any future deployment-wide credential Mokosh needs to receive from Bunyip (SMTP, update-check endpoint, future provider credentials).

Scoped to design only. Two implementation tickets are filed alongside and named at the end.

## Context

Numbers below are grounded in `origin/main` of both repositories.

**On the Mokosh side.** Mokosh has a Bunyip CONFIGURATION provider (`src/config/bunyip.rs`, PMS-987), built from `BUNYIP_CONFIG_URL` + `BUNYIP_CONFIG_CLIENT_ID` + `BUNYIP_CONFIG_CLIENT_SECRET`, that exchanges a `client_credentials` grant at `POST /v1/oauth2/token` and reads each declared key from `GET /v1/config/{KEY}` once at startup. Mokosh has NO Bunyip app-secret provider: the four implementations of `AppSecretProvider` are environment, file, database and Infisical (`src/app_secrets/`, PMS-988). Its `env` provider reads `{NAME}_FILE` only, never a plain variable (`src/app_secrets/env.rs:42`, BUNYIP-38). The hosted deployment (`MOKOSH_DEPLOYMENT_MODE: saas`) declares `database` as the secret provider via `SAAS_PROVIDER_DEFAULTS` (`src/utils/deployment.rs:426`); it carries `INFISICAL_*` in its SOPS `compose-secrets.yml` so those providers are BUILT, but the SaaS defaults do not declare Infisical and so none of that is read on `c-01` or `nc-01` today. PMS-1440 asks whether that should change; this design does not depend on the answer.

**On the Bunyip side.** Bunyip has NO `/v1/config/{KEY}` route today (its own configuration lives in `crates/bunyip-domain/src/config_providers.rs` for Bunyip itself, BUNYIP-643). Its machine-credential registry is `oauth_clients` (`bunyip-api machine-client register|rotate|disable|list`, BUNYIP-604); the token endpoint already issues `client_credentials` tokens to any client whose `allowed_grant_types` includes it. The discovery document advertises only `authorization_code` and `refresh_token` on the SPA client, which is correct for the SPA client; the machine client's capabilities are not advertised there. Bunyip holds its own secrets in its own Infisical project (`/runtime` folder, `docs/secrets-infisical.md`); it has no credentials for Mokosh's Infisical project and nothing in this design gives it any.

**What PMS-1430 shipped (mokosh-server #994, merged 2026-09-30).** Mokosh's Google Contacts OAuth client (id + secret) is now a host-wide pair read through `OauthClient::from_app_secrets` at boot, resolved once and handed to the router and the contact-sync worker. Not re-read mid-process. The two keys live under names `GOOGLE_CONTACTS_CLIENT_ID` and `GOOGLE_CONTACTS_CLIENT_SECRET` in whatever declared secret provider the deployment's profile sets. On the hosted deployments that is Postgres (encrypted with `ENCRYPTION_KEY`); the manual step PMS-1430 named was `provider-migrate --from file --to database`, not an Infisical paste.

**On the Mokosh ← Bunyip authenticated direction.** Bunyip-to-Mokosh already carries a machine credential (`PROVIDER_STATUS_CLIENT_ID` / `_SECRET`, BUNYIP-634); the reverse direction (Mokosh ← Bunyip) is what PMS-987 built for configuration and what this design extends for secrets.

## Decisions

Each answers one or more of the 11 questions on the YT ticket.

**D1. Pull, not push (Q1).** Mokosh pulls from Bunyip. Bunyip never writes to Mokosh's Infisical project and never holds credentials for it, which is the whole point of keeping the two projects separate. The design is a direct extension of the mechanism PMS-987 already built: machine-credential auth, token exchange, per-key GET.

**D2. The secret lives in Bunyip's Infisical project (Q2, Q8).** Bunyip stores the Google client pair in its own Infisical project (`/runtime` folder, same shape as its other secrets today). Mokosh does not keep a copy. The PMS-1430 requirement "credential must be stored in Infisical" is satisfied by Bunyip's Infisical project; Mokosh's own Infisical `/app` folder stays untouched on the hosted deployments that do not declare it anyway. Self-hosted deployments keep the PMS-1430 options (operator-provided through environment/file/database/Infisical in Mokosh); the hosting profile selects the Bunyip provider on `saas`.

**D3. Serve the id and the secret as one unit (Q3).** PMS-1430 governs the pair as one credential ("an id and secret from different Google projects cannot be mixed"), so Bunyip serves them atomically from one key: `mokosh/google_oauth_client`, whose value is a JSON object `{"client_id": "...", "client_secret": "..."}`. Rotating one without the other is a bug in Google's console, not a legitimate operator action.

**D4. Dedicated secrets route, not `/v1/config/{KEY}` (Q4).** `/v1/config/{KEY}` is Mokosh's configuration path (PMS-987) and reads non-secret values; routing a sealed credential through it conflates two registries that the rest of both systems keep apart. Add `GET /v1/host/secrets/{KEY}` to Bunyip; keep `/v1/config/{KEY}` reserved for Mokosh's own CONFIGURATION provider. The route lives beside the host-config endpoints an operator-level machine client already addresses (`bunyip-api/src/handlers/host/`).

**D5. Machine identity (Q5).** Mokosh's caller for `/v1/host/secrets` is a dedicated `oauth_clients` registration with `client_credentials` in `allowed_grant_types` and NO other grants. The mailer-relay shape (BUNYIP-602) is the precedent. The token endpoint already honours this grant; what the discovery document advertises is a separate ticket (BUNYIP-TODO on the Bunyip side) and does not affect this flow because Mokosh calls `/v1/oauth2/token` by URL, not by discovery.

**D6. Per-client allow-list of keys (Q6).** Each `oauth_clients` row for a host-secrets caller carries an `allowed_secret_keys` column (new; `TEXT[]`) that names exactly the keys that client may read. Default is the empty array. The read handler refuses with 403 if the requested key is not in the client's allow-list. The default-deny shape mirrors `allowed_grant_types` and `allowed_scopes`. The Mokosh client's row holds a single entry: `["mokosh/google_oauth_client"]`. A new deployment-wide key for another relying party adds a new row rather than widening Mokosh's.

**D7. Refresh is restart-only for this pair; pattern allows mid-process refresh later (Q7).** Mokosh resolves `OauthClient::from_app_secrets` once at boot (`main.rs` hands the result to the router and the worker), so even if the Bunyip provider implements a mid-process re-read, nothing downstream notices. The design states this explicitly so no operator UI promises "takes effect without a deploy". Adding mid-process re-read for other secrets later is a Mokosh-side change (not blocked by this design).

**D8. Self-hosted deployments stay on the existing options (Q8).** `MOKOSH_DEPLOYMENT_MODE` already drives the provider table (`SAAS_PROVIDER_DEFAULTS` vs `SELF_HOSTED_PROVIDER_DEFAULTS`). The Bunyip app-secret provider is added to the SaaS default table; the self-hosted default keeps the four existing options and the operator-provided value they expect. No code path in self-hosted Mokosh calls Bunyip.

**D9. Bootstrap credentials live in SOPS, as they do today (Q9).** The `BUNYIP_CONFIG_URL` + `BUNYIP_CONFIG_CLIENT_ID` + `BUNYIP_CONFIG_CLIENT_SECRET` triad for the CONFIGURATION provider sits in Mokosh's SOPS `compose-secrets.yml` on `c-01` and `nc-01` today. The new provider reuses that triad under new names (`BUNYIP_SECRETS_URL` + `BUNYIP_SECRETS_CLIENT_ID` + `BUNYIP_SECRETS_CLIENT_SECRET`), separated so the config and the secrets registrations can rotate independently and so a leak of one does not expose the other. Alternative: have the two providers share one machine client and distinguish per request via `allowed_secret_keys` vs `allowed_config_keys`, rejected because `oauth_clients` has no notion of "config vs secrets scope" today and the row-plus-allow-list pattern (D6) is the simpler extension.

**D10. Rotation warnings (Q10).** Bunyip's admin page for the Google pair warns before accepting a changed `client_id`: "Replacing the client id invalidates every tenant's existing refresh token for Google Contacts. The next contact-sync call for each affected tenant will fail with `invalid_grant` and the tenant will need to reconnect." Bunyip does not count affected tenants (it cannot read Mokosh's tenant data) and does not block the save, only names the consequence. Secret-only rotation (same id, new secret) emits a softer notice: existing refresh tokens continue to work.

**D11. Sequencing (Q11).** PMS-1430 landed first and shipped the single-key seam; this design replaces its manual-paste step on deployments where PMS-1430's output is already in the declared provider. The hosted deployments carried the pair into Postgres via `provider-migrate --from file --to database`, so a rollout of the Bunyip-served path on those deployments goes: (1) land the Bunyip and Mokosh implementation tickets below; (2) move the pair into Bunyip's Infisical project; (3) `provider-migrate --from database --to bunyip` on each hosted Mokosh; (4) `UPDATE app_secrets SET value = NULL WHERE key IN ('GOOGLE_CONTACTS_CLIENT_ID', 'GOOGLE_CONTACTS_CLIENT_SECRET')` on each hosted deployment and verify a clean restart. Self-hosted deployments are untouched.

## Design

### Ownership

Bunyip owns the Mokosh Google OAuth client as deployment-wide configuration for the suite. The pair is stored in Bunyip's Infisical `/runtime` folder as a single JSON blob under one key (`mokosh/google_oauth_client`, D3). An operator with Bunyip admin access edits it; nothing else does.

### Delivery direction

Pull. Mokosh authenticates to Bunyip as a `client_credentials` machine identity, requests the key by name, receives the JSON blob, decodes it into the `GOOGLE_CONTACTS_CLIENT_ID` and `GOOGLE_CONTACTS_CLIENT_SECRET` values the seam already consumes. Bunyip never writes to Mokosh.

```
┌──────────┐  POST /v1/oauth2/token      ┌──────────┐
│ Mokosh   │ ───────────────────────────▶│ Bunyip   │
│ (hosted) │ ◀───access_token────────────│          │
│          │                             │          │
│          │  GET /v1/host/secrets/      │          │
│          │      mokosh/google_oauth_   │          │
│          │      client                 │          │
│          │ ───────────────────────────▶│          │
│          │ ◀──{"client_id":"...",──────│          │
│          │     "client_secret":"..."}  │          │
└──────────┘                             └──────────┘
```

### Startup behaviour

Mokosh gains a new `AppSecretProvider` beside the four existing implementations:

- `BunyipAppSecretProvider` reads `BUNYIP_SECRETS_URL` + `BUNYIP_SECRETS_CLIENT_ID` + `BUNYIP_SECRETS_CLIENT_SECRET` from the environment at boot (SOPS supplies them, D9) and knows how to GET one host-secret key.
- It is wired into `SAAS_PROVIDER_DEFAULTS` as the declared `ProviderKind::Secrets` for keys that match the `mokosh/*` prefix pattern; the other keys fall back to the deployment's existing declaration.
- Boot classification (per `docs/providers.md`): the Bunyip provider is `Built`, `Declared`, and `Required` on `saas`. Bunyip unreachable at boot → Mokosh refuses to start with `Classification::Unavailable` and names the Bunyip URL in the error. A Bunyip that answers but has no value for the key → `Classification::Missing` and the operator-visible remedy says "set `mokosh/google_oauth_client` in Bunyip's admin surface". A Bunyip that returns 403 → `Classification::Forbidden` and the remedy says "the Mokosh machine client's `allowed_secret_keys` is missing this key".
- The PMS-1430 acceptance test that reads the pair "from Infisical `/app`" is replaced by the equivalent that reads it from `BunyipAppSecretProvider`.

The hard-coded prefix (`mokosh/*`) in the provider's key-matcher mirrors the pattern mokosh-server already uses to route `app`/`tenant` keys to different providers (`AppSecretProviderKind::select_for`); any key outside the prefix falls through to the next provider in priority order.

### Management over time

Admin surface: a new row on Bunyip's existing "Host configuration" admin page (`bunyip-web/src/handlers/admin*.rs`), labelled "Google OAuth client (Mokosh contact sync)". The row shows presence + provenance (set / not set, who last changed it, when, same shape as `settings_archive`'s audit row) and never the value. A `[Edit]` button opens a modal with two fields (`client_id`, `client_secret`), prefilled with the current id and a "replace to change" placeholder for the secret.

Save:

- Validates the id matches `[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com` (Google's shape).
- Writes a single JSON blob to Bunyip's Infisical `/runtime/mokosh/google_oauth_client`.
- Writes an `audit_logs` row naming the admin, the time, the key, and the content hash of the new value (never the value itself).
- If the id changed, shows the warning D10 names before accepting the save.

Mokosh picks up the new value on the next restart (D7). Bunyip's admin page says so in a one-line note under the row.

Rotation of the Mokosh machine client credential (`BUNYIP_SECRETS_CLIENT_SECRET`) is a separate operator action handled by Bunyip's existing `bunyip-api machine-client rotate <id>` command (BUNYIP-604); Mokosh needs the new secret in its SOPS file before the next restart.

### Blast radius

- The Mokosh machine client can read only `mokosh/google_oauth_client` (D6). A separately-registered client for any other RP cannot read it; a widened `allowed_secret_keys` must be an explicit change to that client's row.
- Bunyip's existing provider-status credential (`PROVIDER_STATUS_CLIENT_ID` / `_SECRET`) is read-only against Mokosh and does not gain any Bunyip-side authority.
- Mokosh has no write path to Bunyip's secret store. The admin edit is Bunyip-side only.
- Bunyip's Infisical identity is unchanged; the new `/runtime/mokosh/*` keys sit under the same Universal Auth project folder the rest of its runtime secrets live in.

### Migration

Per D11:

1. Bunyip side: implement the route, the `allowed_secret_keys` column + its guard, and the admin page row.
2. Mokosh side: implement `BunyipAppSecretProvider` and add it to `SAAS_PROVIDER_DEFAULTS` under the `mokosh/*` prefix matcher.
3. Operator: move the current `GOOGLE_CONTACTS_CLIENT_ID` + `GOOGLE_CONTACTS_CLIENT_SECRET` values out of Mokosh's declared provider into Bunyip's Infisical `/runtime/mokosh/google_oauth_client`.
4. Operator: `provider-migrate --from database --to bunyip` on each hosted Mokosh (new provider is the from-nothing-to-Bunyip equivalent of the existing migrate verb).
5. Operator: NULL the old rows and restart Mokosh; `provider-verify` must report the Bunyip provider as the declared source and no stale copies elsewhere.
6. Self-hosted deployments: no action. The SaaS table changes; the self-hosted table does not.

A `database` → `bunyip` migrate step is additive to the existing migrate verbs because it does not write to Bunyip (Bunyip is the destination's source of truth already, and the operator sets it there separately). The verb's job is to confirm readability from Bunyip and NULL the stale copy; it does not transport a value Bunyip did not already hold.

## Not changed by this design

- Mokosh's `/v1/config/{KEY}` CONFIGURATION provider (PMS-987) stays what it is for non-secret deployment-wide values.
- Mokosh's four existing app-secret providers (environment, file, database, Infisical) stay the self-hosted options.
- The PMS-1430 seam (`OauthClient::from_app_secrets`) does not change; the Bunyip provider is just a fifth implementation of the trait it already consumes.
- Bunyip's SPA client (`b0000000-0000-4000-8000-000000000002`), lets-chat client (BUNYIP-57 / LC-448), drillmark client, mailer-relay client (BUNYIP-602) and provider-status client (BUNYIP-634) are untouched.

## Implementation plan

Two tickets land this design. Each has its own acceptance criteria, file list, and runbook update. Neither is in scope for THIS ticket; BUNYIP-855 is just the design.

- **Bunyip side**: new `GET /v1/host/secrets/{KEY}` route; new `allowed_secret_keys TEXT[]` column on `oauth_clients` with the per-client guard; admin page row for "Google OAuth client (Mokosh contact sync)" with the rotation warning; audit-log writes on edit; registration of the Mokosh machine client via `bunyip-api machine-client register` with the one-key allow-list.
- **Mokosh side**: new `BunyipAppSecretProvider` in `src/app_secrets/bunyip.rs`; env-inventory registration of `BUNYIP_SECRETS_URL` + `BUNYIP_SECRETS_CLIENT_ID_FILE` + `BUNYIP_SECRETS_CLIENT_SECRET_FILE`; wire into `SAAS_PROVIDER_DEFAULTS` with the `mokosh/*` key-prefix matcher; `provider-migrate` adopts `--to bunyip` as the terminal destination; PMS-1430 README's "Before this PR is merged" step updates to point at the Bunyip admin page.

The two tickets specify their own acceptance criteria, including the full round-trip ("operator sets `mokosh/google_oauth_client` in Bunyip once, both hosted Mokosh boxes boot cleanly with no `GOOGLE_CONTACTS_*` in their declared provider, contact sync continues to issue new refresh tokens, admin page on Bunyip reflects the change").
