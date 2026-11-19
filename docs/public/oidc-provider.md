# OIDC provider

Bunyip is the OpenID Connect provider (OP) for every relying party (RP) in the fleet. Mokosh server, Drillmark, Lets chat and others verify `at+jwt` access tokens against bunyip's JWKS. This page covers how to wire a new RP, what the OP endpoints answer, and how key rotation works.

## Discovery

Every RP starts at the discovery URL:

```
https://api.${BUNYIP_HOST}/.well-known/openid-configuration
```

The document names:

- `issuer` (matches `BUNYIP_API_PUBLIC_ORIGIN`)
- `authorization_endpoint` (`/oauth2/authorize`)
- `token_endpoint` (`/oauth2/token`)
- `jwks_uri` (`/oauth2/jwks`)
- `revocation_endpoint` and `introspection_endpoint` (RFC 7009 / 7662)
- `scopes_supported`, `response_types_supported`, `grant_types_supported`, `code_challenge_methods_supported` (PKCE is required)

An RP library that honours discovery needs no other configuration from an operator except the client id, client secret, and the redirect URI.

## JWKS

Keys are served at `/oauth2/jwks`. Each entry carries a `kid` (key id), `alg` (`EdDSA` today, keys are Ed25519), `kty` (`OKP`) and the curve coordinates.

The active signing key is named by `OIDC_JWT_ACTIVE_KID`. A rotation adds a new key file to the signing store, flips the active kid, and then (after the access-token lifetime passes) retires the old key file. Both keys appear in the JWKS during the overlap so an RP that cached the old `kid` can still verify an in-flight token. A fast rotation forces every live token to fail verification; use that only for a key compromise.

## Register a client

Clients live as rows on `oidc_clients` and are edited from the admin Clients page. The form fields:

- `client_id` and `client_secret` (shown once at creation).
- `client_type`: `confidential` for server-side RPs, `public` for in-browser clients.
- `name` is the display label shown on the consent / sign-in screens.
- `redirect_uris`: an exact-match allow-list. Wildcards are refused. One URI per line.
- `allowed_scopes`: the scopes this client may ask for. Anything outside the list is rejected at the authorize step, not deferred.
- `allowed_grant_types`: `authorization_code` plus optionally `refresh_token`. Password grant is not supported; use the browser flow.
- `audience`: the resource server audience to claim in issued tokens. Downstream RPs verify `aud` against the server they are.

PKCE is required for every client. A client that sends no `code_challenge` to `/oauth2/authorize` is refused with `invalid_request`.

## Authorization code + PKCE

Standard OIDC flow:

1. RP generates a `code_verifier` and derives a `code_challenge`.
2. RP redirects the user to `authorization_endpoint` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `code_challenge`, `code_challenge_method=S256`, `state`, `nonce`.
3. User signs in with bunyip (or is already signed in); consent is implicit for first-party fleet RPs. A tighter deployment that wants explicit consent flips the client's `require_consent` column.
4. Bunyip redirects back to the RP's `redirect_uri` with `code` and `state`.
5. RP posts to `token_endpoint` with the code, the `code_verifier`, and its credentials.
6. Bunyip verifies the code (single-use, short-lived, bound to the challenge) and returns `access_token`, optionally `refresh_token`, and `id_token`.

An RP that does not store the `code_verifier` across the redirect will fail step 5. That is the most common first-wire mistake; the browser error names `invalid_grant`.

## Refresh and revocation

`refresh_token` is optional per client; omit it from `allowed_grant_types` to force every RP session to re-authenticate on access-token expiry.

Revocation uses the RFC 7009 endpoint. A revoked refresh token forbids any future exchange; a revoked access token is checked at introspection time only (there is no token-level pub/sub). For a user sign-out that must invalidate every live access token, the deployment flips the session epoch; that invalidates every bearer that carries the old epoch without waiting for TTL.

## Token claims

- `iss`: the issuer URL (matches discovery).
- `sub`: the user id (opaque, immutable for the account's lifetime).
- `aud`: the audience the RP registered.
- `exp`, `iat`, `nbf`: lifetimes.
- `scope`: the granted scopes, space-separated.
- `kid` in the header: names the signing key in JWKS.

The id_token additionally carries `email`, `email_verified`, `name`, and the `at_hash` binding to the access token in the same response.

An RP that reads a claim not listed here should either register it as a new scope or ask the Users admin for it. Bunyip does not add claims to id_tokens outside the set that OIDC + the RP's scopes grant.

## Downstream RP verification

Every downstream RP is responsible for:

1. Fetching JWKS from bunyip, with a cache that honours the `Cache-Control` headers and a backoff for network failures.
2. Verifying the `at+jwt` signature against the matching `kid`.
3. Checking `iss`, `aud`, `exp` (and optionally `nbf`), and the scope needed for the route being called.
4. Refusing with `401` on any failure. A stale JWKS cache after a bunyip key rotation is the usual reason a long-lived RP suddenly rejects everyone.

[Troubleshooting](troubleshooting.md) covers the common failure of an RP's JWKS cache going stale.

## Logout

Bunyip does not implement OpenID Back-Channel Logout today. A user who signs out of bunyip-web ends the session cookie and the refresh token on bunyip; downstream RPs continue to honour any live `at+jwt` until TTL. A global sign-out that must evict every RP session needs the session-epoch flip above.
