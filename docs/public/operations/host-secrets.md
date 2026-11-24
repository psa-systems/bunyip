# Host secrets

An allow-listed machine client can fetch one registry secret or one registry config key from bunyip without logging in as a user. Two small read routes serve that:

- `GET /v1/host/secrets/{KEY}` returns the value of a declared registry secret.
- `GET /v1/host/config/{KEY}` returns the value of a declared registry config key.

This page covers the operator setup. The caller view is in [API](../api.md).

## When you want this

A deployment component (a cron runner, an agent, an auxiliary service) needs a credential at boot but does not want to:

- carry its own copy of the credential,
- or impersonate a user to read it.

The host-secrets channel gives it a read-only, allow-listed path to the one value it needs.

## When you do NOT want this

- The caller is a user, not a machine. Users authenticate through the OIDC flow, not through this endpoint.
- The caller needs read access to arbitrary secrets in a store. Infisical is the general secret store; host-secrets exposes one declared entry at a time.
- The caller needs write access. These routes are read-only.

## Setting up a machine client

1. Open the admin Clients page and create a new machine client. Give it a name tied to the service (`drillmark-ingestor`, `backup-runner`).
2. Mint a token for the client. The token is shown once.
3. Add the client id to the allow-list for the specific `{KEY}` the client is meant to read. One list per secret, one list per config key. A client not on the list for a key is 403, even with a valid token.

The allow-list is an explicit opt-in: a new secret is not readable until a client is added for it.

## Declaring a key

A key must be in the registry to be served. The registry lives in code; adding a new secret or config key is a code change, not an admin edit. That is intentional: the surface of what host-secrets can disclose is pinned at build time, so a misconfigured admin never accidentally exposes a new value.

When a new release adds a new declarable key, the release notes name it. The operator then edits the admin page to put the value into the chosen secret storage, and to add the caller to the allow-list.

## What the response carries

- `200` with the value as plain text, or as a JSON object when the key is declared as structured.
- `404` for a key not in the registry.
- `403` for a caller not on the allow-list for the key.
- `401` for a missing or invalid token.

The api never returns more than the one requested key per call; a caller that needs three keys makes three calls.

## Rotation

A rotation of a key's value is the same procedure as any other Group-2 secret: edit on the admin page (database mode) or edit in Infisical (infisical mode). The next read sees the new value.

A rotation of a client's token (the caller's credential) is done from the client's token page. The old token is revoked on the same screen; the new token is shown once.

## Audit

Every `GET /v1/host/secrets/*` request goes to the application log, not the audit log. A served read logs at INFO, keyed by the calling client and the secret name. A rejected credential or an unentitled key logs at WARN. A key this build does not serve (an operator typo in `allowed_secret_keys`) logs at ERROR. A key that is allow-listed and declared but has no value set yet is not logged at all; the caller only sees the 404.

An operator who wants to answer "who fetched this key in the last day" greps the application log for the client id or key name; the Audit page does not cover this endpoint.
