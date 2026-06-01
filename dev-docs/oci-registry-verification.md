# OCI registry proxy: verification runbook (BUNYIP-31)

How to run and verify the bunyip OCI registry proxy against the private
Forgejo instance, end to end, on a dev box. Production wiring (Traefik
subdomain, secrets) is BUNYIP-32; this document covers the local loop and
records what the production deployment must reproduce.

## What is being verified

```
docker CLI ──login/pull──> bunyip-api OCI server (:18081)
                              │  bearer-token auth (member credentials)
                              │  per-app entitlement + rate limits
                              │  manifest/blob caching
                              └──service token──> private Forgejo (/v2 API)
```

Members authenticate with their Bunyip email + password. Bunyip authenticates
to Forgejo with a single service-account token. Members never see Forgejo
credentials.

## Prerequisites

1. **Forgejo service token.** Forgejo (dev.a8n.run) -> Settings ->
   Applications -> Generate New Token with scopes:
   - `read:package` (container images + generic packages)
   - `read:repository` (release-attachment downloads; not needed for OCI-only
     verification)

   The token owner must have access to the org that hosts the images
   (`psa-systems-private`).

2. **A published image.** The bunyip release pipeline publishes
   `dev.a8n.run/psa-systems-private/bunyip-api:<tag>`; any tag listed at
   <https://dev.a8n.run/psa-systems-private/-/packages> works.

3. **Docker CLI** on the dev box. `localhost` registries are treated as
   insecure by Docker automatically; no daemon config needed.

## Local verification procedure

### 1. Configure and start the stack

```nushell
# .env (gitignored)
"FORGEJO_BASE_URL=https://dev.a8n.run
FORGEJO_API_TOKEN=<service token>
OCI_REGISTRY_ENABLED=true
OCI_REGISTRY_SERVICE=localhost:18081
OCI_REGISTRY_REALM=http://localhost:18081/auth/token
" | save --append .env

just dev-detach
```

Confirm the second listener started:

```nushell
docker logs $"dev-bunyip-api-($env.USER)" | grep "OCI registry"
# expect: Starting OCI registry server  address=0.0.0.0:18081
```

### 2. Create a member and an application row

Register a user through the web UI (http://localhost:4400) or the API, then
mark it as a member and add a pullable application (slug `bunyip-api` here,
pinned to a real published tag):

```nushell
docker exec -i $"dev-bunyip-postgres-($env.USER)" psql -U bunyip -d bunyip -c "
UPDATE users SET membership_status = 'active' WHERE email = 'member@example.com';
INSERT INTO applications (name, slug, display_name, container_name,
    oci_image_owner, oci_image_name, pinned_image_tag)
VALUES ('bunyip-api', 'bunyip-api', 'Bunyip API', 'unused',
    'psa-systems-private', 'bunyip-api', 'v0.1.1');
"
```

### 3. docker login (acceptance: token endpoint)

```nushell
docker login localhost:18081 --username member@example.com
# password: the member's Bunyip password
# expect: Login Succeeded
```

What happened: Docker probed `GET /v2/` -> 401 + `WWW-Authenticate: Bearer
realm="http://localhost:18081/auth/token",service="localhost:18081"` ->
fetched the realm with Basic auth -> bunyip verified the member's password +
membership and issued a registry JWT.

### 4. docker pull, entitled (acceptance: proxy + multi-arch)

```nushell
docker pull localhost:18081/bunyip-api:v0.1.1
# expect: pull completes; image id listed by `docker images`
```

The pinned-tag rule means only the configured tag (or digests) can be pulled;
`docker pull localhost:18081/bunyip-api:other-tag` must return
`MANIFEST_UNKNOWN`.

### 5. Blob cache hit (acceptance: caching)

```nushell
docker rmi localhost:18081/bunyip-api:v0.1.1
docker pull localhost:18081/bunyip-api:v0.1.1
docker logs $"dev-bunyip-api-($env.USER)" | grep -c "blob cache"
```

The second pull must not re-download blobs from Forgejo (verify via api logs:
no upstream blob GETs on the second pull; the `oci_blob_cache` table rows'
`last_accessed_at` advance instead).

### 6. Denial paths (acceptance: OCI error envelope)

```nushell
# Unknown repository -> NAME_UNKNOWN 404 envelope
docker pull localhost:18081/not-a-real-app:v1

# Non-member -> login fails with 401
docker logout localhost:18081
docker login localhost:18081 --username nonmember@example.com

# Rate limit: set OCI_PULLS_PER_USER_PER_DAY=1 in .env, restart, pull twice
# -> second pull returns TOOMANYREQUESTS with Retry-After
```

### 7. Cleanup

```nushell
docker logout localhost:18081
just dev-down
```

## Findings log

| Date | Item | Result |
|------|------|--------|
| | docker login via token endpoint | |
| | docker pull (single-arch manifest) | |
| | multi-arch index passthrough | |
| | blob cache hit on second pull | |
| | NAME_UNKNOWN / DENIED envelopes | |
| | rate-limit TOOMANYREQUESTS + Retry-After | |
| | Forgejo basic-auth with empty username accepted | |

## Production notes (input to BUNYIP-32)

- `OCI_REGISTRY_SERVICE` must equal the public registry hostname
  (e.g. `registry.<base-domain>`); leave `OCI_REGISTRY_REALM` unset so it
  defaults to `https://<service>/auth/token` behind TLS.
- The reverse proxy must route BOTH `/v2/*` and `/auth/token` on that hostname
  to the api container's OCI port, and must not buffer/limit blob response
  bodies (images can be hundreds of MB).
- The Forgejo service token is a secret: production uses the existing secret
  mechanism, never compose environment defaults.
- Known engine caveat: bunyip authenticates to Forgejo's `/v2` API with HTTP
  basic auth using an EMPTY username and the token as password
  (`dunite-oci::ForgejoRegistryClient`). If verification shows Forgejo
  rejecting this, the fix is to send the service-account username alongside
  the token (engine change in dunite-oci).
