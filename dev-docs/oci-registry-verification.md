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

Verified 2026-06-02 against dev.a8n.run (Forgejo), image
`psa-systems-private/bunyip-api:v0.1.1`, on the dev stack (`just dev-detach`).

| Date | Item | Result |
|------|------|--------|
| 2026-06-02 | docker login via token endpoint | PASS (admin member; token TTL 900s) |
| 2026-06-02 | docker pull (pinned tag) | PASS (8 layers, ~4s first pull) |
| 2026-06-02 | multi-arch index passthrough | PASS (index digest -> child manifests by digest -> blobs) |
| 2026-06-02 | blob cache hit on second pull | PASS (oci_blob_cache rows touched, not re-fetched; 9 blobs / 44 MB) |
| 2026-06-02 | pinned-tag enforcement (other tag) | PASS (MANIFEST_UNKNOWN) |
| 2026-06-02 | NAME_UNKNOWN envelope (unknown repo) | PASS |
| 2026-06-02 | bad credentials rejected | PASS (and the 5/min/email login rate limit fires -> docker shows "toomanyrequests") |
| 2026-06-02 | non-member denied | PASS (401; audit reason no_active_membership) |
| 2026-06-02 | Forgejo basic-auth with empty username accepted | PASS (manifests + blobs; caveat below resolved) |
| 2026-06-02 | OCI audit trail | PASS (oci_login_failed / oci_pull_requested / oci_pull_completed rows) |
| not tested | daily pull cap TOOMANYREQUESTS + Retry-After | covered by dunite-oci unit tests; needs a low-limit restart to exercise live |

### Bugs found during verification

1. **Root-owned cache volumes break every blob fetch (fixed).** Fresh named
   volumes mounted at `/var/cache/bunyip-oci` / `/var/cache/bunyip-downloads`
   are created root-owned; the api container runs as the host user, so every
   blob write failed with Permission denied, surfacing to docker as 502 on all
   blobs (manifests, which are memory-cached, still worked). Fixed by
   pre-creating the cache dirs WITH ownership in both the dev and production
   api Dockerfiles, so first-mount volume initialization inherits it.
2. **dunite-oci flattens blob-fetch errors** (the Permission denied above
   surfaced as a generic "Upstream"/502 with no diagnostic anywhere). Same
   error-fidelity problem that dunite-download fixed in review; tracked in
   PSA-35.
3. **bunyip-web dev container is broken** (pre-existing, unrelated to OCI):
   `bun` lives in `/root/.bun` inside the builder image and the container runs
   as the host user -> "bun: Permission denied" crash loop. Needs its own fix.
4. Cosmetic: the OCI server sends HSTS / CSP headers (SecurityHeaders
   middleware) on plain-HTTP responses; harmless for docker clients.

## Production notes (input to BUNYIP-32)

- `OCI_REGISTRY_SERVICE` must equal the public registry hostname
  (e.g. `registry.<base-domain>`); leave `OCI_REGISTRY_REALM` unset so it
  defaults to `https://<service>/auth/token` behind TLS.
- The reverse proxy must route BOTH `/v2/*` and `/auth/token` on that hostname
  to the api container's OCI port, and must not buffer/limit blob response
  bodies (images can be hundreds of MB).
- The Forgejo service token is a secret: production uses the existing secret
  mechanism, never compose environment defaults.
- The production runtime image must pre-create `/var/cache/bunyip-oci` and
  `/var/cache/bunyip-downloads` owned by `appuser` (it does, as of BUNYIP-31)
  so the production volumes mounted there are writable. Mount NAMED volumes at
  those paths; a host bind-mount does NOT inherit image ownership and must be
  chowned to the container uid by the operator.
- RESOLVED caveat: Forgejo accepts the engine's basic auth with an empty
  username and the token as password, for both manifests and blobs. No engine
  change needed.
