# Integrations

Bunyip is a hub, not a leaf. This page covers what bunyip talks to and what talks to bunyip, from the operator's angle: what each integration enables, what to configure, what breaks when the other side is unreachable.

## Downstream relying parties (OIDC RPs)

Every other product in the fleet (Mokosh server, Drillmark, Lets chat and others) authenticates against bunyip. From bunyip's side, a relying party is a row on `oidc_clients` with a client id, secret, redirect URI, scopes and audience. See [OIDC provider](oidc-provider.md) for the full flow.

What breaks when bunyip is unreachable:

- No new sign-in on any downstream RP; existing bearer sessions keep working until TTL.
- No key rotation can propagate; RPs that cached the old JWKS keep verifying.
- Every password reset and sign-up link is dead until bunyip comes back.

## Infisical (secret store)

Bunyip can read Group-2 integration secrets from Infisical instead of the database or the environment. Set `SECRETS_STORAGE=infisical` plus the four `INFISICAL_*` variables; see [Configuration](configuration.md).

What Infisical gives bunyip:

- One canonical source for integration secrets across the fleet.
- Operator-side rotation that the api picks up within a TTL window without a restart.
- Access audit on Infisical's side for who fetched what.

What breaks when Infisical is unreachable:

- Group-1 startup secrets are unaffected; the api boots without touching Infisical.
- Group-2 secrets fail to fetch; the integrations backed by them (SMTP mail, Stripe webhooks, support IMAP) fail per-request with a visible error until Infisical answers again. The api does not crash.
- The admin Settings pages for integration secrets stay reachable; they show the last-known value and let the operator edit, but a write still goes to Infisical.

## SMTP (outbound mail)

Bunyip sends magic links, approval emails, invite emails and recovery-code reminders through a configured SMTP relay. Set `EMAIL_ENABLED=true`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_FROM`; the password lives in the Group-2 store.

What breaks when SMTP is unreachable:

- Magic links do not arrive; new sign-ups cannot complete.
- Login-approval emails do not arrive; every held sign-in stays held forever.
- Password reset is broken.

There is no production-usable fallback today while SMTP is down; the relay itself must be fixed. `EMAIL_LOG_TOKENS`, which writes tokens to the api log, is dev-only and is forced off in production.

## Stripe (billing)

Stripe is the billing integration. Two secrets live in the Group-2 store (secret key and webhook signing secret); the publishable key is a Group-2 config value exposed to the front-end.

Webhook endpoint: `POST /webhooks/stripe`. The signature is verified with the webhook secret; a bad signature is `400` and the request is not retried.

What breaks when Stripe is unreachable:

- The admin pricing pages that render live product and price data show an error banner; bunyip continues to serve.
- Incoming webhooks queue on Stripe's side and are delivered on recovery; bunyip does not poll.

## Mailer relay (fleet-internal)

`POST /v1/mailer/send` is a send-only relay bunyip exposes to allow-listed machine clients in the fleet, so a service that needs to send a transactional email reuses bunyip's SMTP wiring instead of running its own relay. The relay is scoped to pre-configured templates; a caller cannot supply arbitrary HTML.

The caller is a machine-client row on bunyip (an API token minted in the admin Clients page, bound to a service account). The route is 401 for anything else.

## Host secrets and host config (fleet-internal)

Allow-listed machine clients also reach `/v1/host/secrets/{KEY}` and `/v1/host/config/{KEY}` to fetch a single registry value. See [Host secrets](operations/host-secrets.md) for the operator-side setup.

## IP geolocation (IP2Location LITE)

Bunyip can consume the IP2Location LITE binary database to resolve `country` from an IP for the login-approval country trigger. Point `IP2LOCATION_DB_PATH` at the binary. Without it, the country trigger never fires.

The LITE database is a free download that refreshes periodically; the internal runbook covers the pull cadence. Nothing in bunyip phones home for updates.

## OCI registry

Bunyip hosts the fleet's internal OCI registry at `/v2/*`. Push and pull are bearer-authenticated with scoped tokens. See [OCI registry](features/oci-registry.md).

## What does NOT integrate (today)

- No IdP federation (Entra ID, Google Workspace, Okta): bunyip is the OP, users sign in to bunyip directly.
- No SAML: bunyip is OIDC-only on the issuer side.
- No webhook delivery for every internal event: audit log is the source, polled on the admin side.
- No upstream SSO (single sign-on via another IdP): bunyip does not act as a relying party.
