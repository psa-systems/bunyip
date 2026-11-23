# API

The public REST surface on `bunyip-api`. Grouped by concern. Routes are listed by their HTTP method and path; details of request and response shapes live in the OpenAPI document the api serves, and in the admin test harness.

Every route sits behind the rate-limit floor unless noted. Every `v1/` route accepts a bearer on `Authorization: Bearer ...` (an `at+jwt` access token from the OP, or a `sfk_`-prefixed API token).

## Health and version

- `GET /health` returns `{"status":"ok"}` once migrations finish and the OIDC OP is ready. Unauthenticated.
- `GET /v1/version` returns build metadata (version + hash + date). Unauthenticated.

## OIDC provider

The OP endpoints are served at the api host and announced through discovery.

- `GET /.well-known/openid-configuration`
- `GET /oauth2/jwks`
- `GET /oauth2/authorize`
- `POST /oauth2/token`
- `POST /oauth2/revoke`
- `POST /oauth2/introspect`

See [OIDC provider](oidc-provider.md) for the flow details.

## Authentication for bunyip's own callers

- `POST /v1/auth/login` exchanges a password (and optional TOTP code) for a session. Rate limited by the `AuthRateLimiter` on failure only; a success does not count.
- `GET /v1/auth/login/approval/{claim_reference}` polls a held sign-in. Returns `pending` (202), `approved` (200 with the JWT, once), `already_collected` / `expired` (410) or `not_found` (404).
- `POST /v1/auth/magic-link/request` sends a single-use link for a sign-up or a password reset.
- `POST /v1/auth/password/reset` consumes a reset token.
- `POST /v1/auth/logout` ends the session and the refresh token.

## API tokens

- `GET /v1/account/api-tokens` lists the caller's tokens (label, expiry, revocation, last-used).
- `POST /v1/account/api-tokens` mints a new token. Password-confirmed. The plaintext is shown once in the response.
- `POST /v1/account/api-tokens/{id}/revoke` revokes.

## Two-factor

- `GET /v1/account/two-factor` returns the account's enrolment status, including the recovery-code count.
- `POST /v1/account/two-factor/start` stores a pending seed and renders the QR code; password-confirmed.
- `POST /v1/account/two-factor/confirm` enrols the pending seed; needs a current code plus the one-time setup token.
- `POST /v1/account/two-factor/disable` removes the factor; password + a current code; refused for `super_admin`.
- `POST /v1/account/two-factor/rekey/start` begins a re-key while already enrolled; password + a current code.
- `POST /v1/account/two-factor/rekey/confirm` swaps the seed on a correct code + setup token. Recovery codes and session state are untouched.
- `POST /v1/account/two-factor/recovery-codes` regenerates the recovery codes. Requires password + a current code.

## Device management

- `GET /v1/account/devices` lists the browsers the account has completed a sign-in from; the current one is marked.
- `POST /v1/account/devices/{id}/remove` revokes a recorded device. Password-confirmed. The browser becomes inert for its next sign-in and is held for re-enrolment.

## Feedback

- `POST /v1/feedback` creates a feedback row. Unauthenticated (public form) or authenticated (signed-in user), per the deployment's choice. Runs through the four-signal spam classifier.
- `GET /v1/admin/feedback` lists feedback for the review page. Admin only.
- `POST /v1/admin/feedback/{id}/mark-spam` and `/unmark-spam` flip the classification.

See [Feedback](features/feedback.md).

## OCI registry

Bunyip hosts a thin OCI registry for internal images. The endpoints mirror the OCI distribution-spec v2.

- `GET /v2/` returns `200` for a client that satisfies the bearer check.
- `GET /v2/{name}/manifests/{reference}`
- `GET /v2/{name}/blobs/{digest}`
- `POST /v2/{name}/blobs/uploads/`
- `PUT /v2/{name}/blobs/uploads/{uuid}?digest=...`
- `PUT /v2/{name}/manifests/{reference}`

Writes require a token with the `oci:push` scope; reads require `oci:pull`. See [OCI registry](features/oci-registry.md).

## Host secrets and host config

A small read channel for allow-listed machine clients. Lets a deployment component fetch a registry secret (or a config key) from bunyip without logging in as a user, and without each component holding its own copy.

- `GET /v1/host/secrets/{KEY}` returns the value of a registry secret for the caller's allow-listed client.
- `GET /v1/host/config/{KEY}` returns the value of a registry config key.

Both routes are 404 for an unknown key, 403 for a caller outside the allow-list. See [Host secrets](operations/host-secrets.md) for the operator-facing setup.

## Mailer relay

- `POST /v1/mailer/send` sends a transactional mail on behalf of a different fleet service. Authenticated by machine-client token only; the send is scoped to a configured template.
- `POST /v1/mailer/webhooks/feedback` accepts inbound bounce/complaint callbacks from the mail provider, authenticated by an `X-Webhook-Signature` HMAC over the body rather than a machine-client token, exempt from the per-IP floor.

A deployment that wants cross-service mail standardized goes through this endpoint rather than giving every service its own SMTP relationship. See [Integrations](integrations.md).

## Audit events

Every mutating admin action lands in the audit log. The admin page is the only way to read it today; there is no API read route for audit. See [Audit log](features/audit-log.md) for the filter model.

## Branding

- `GET /v1/branding` returns the public branding payload (product name, palette, logo URL). Unauthenticated so the sign-in page can render it.
- `PUT /v1/admin/branding` writes the single `branding` row. Admin only.
- `GET /v1/branding/assets/{kind}` returns a brand image (mark, mascot, derived favicon set) by kind, unauthenticated.

See [Branding](branding.md).

## Not covered here

- The dev-only helpers under `/v1/dev/*`. They are gated on dev mode and absent in a production image.
- The internal OCI maintenance routes (garbage collection, cache eviction). These are admin surfaces, not caller-facing APIs.
