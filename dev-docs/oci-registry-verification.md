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

## Automated verification

Most of the matrix below is scripted; once the stack is up (step 1) run:

```nushell
just verify-oci
# or with explicit coordinates:
just verify-oci <slug> <owner> <image> <tag>
```

It seeds the application row, then checks: the /v2/ auth challenge, docker
login, the entitled pull, pinned-tag enforcement, and the blob-cache second
pull, exiting non-zero on the first failure. The manual steps below remain as
reference and for the cases the script does not cover (non-member denial, rate
limits, log inspection).

## Local verification procedure

### 1. Configure and start the stack

```nushell
# .env (gitignored)
"FORGEJO_BASE_URL=https://dev.a8n.run
FORGEJO_API_TOKEN=<service token>
OCI_REGISTRY_ENABLED=true
" | save --append .env

just dev-detach
```

The dev compose file derives the registry hostname and token realm from
`BUNYIP_OCI_PORT` (default `localhost:18081`); no further OCI configuration is
needed for local verification.

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
just dev-stop
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

## dev-sso verification (Traefik registry subdomain)

`just dev-sso` (or the api-only overlay) routes the registry through Traefik on
`<user>-bunyip-registry.a8n.run` with a real certificate. Wiring details live
in `dev-docs/dev-sso-three-repo-runbook.md` section 9. Differences from the
localhost procedure above:

- Do NOT set `OCI_REGISTRY_SERVICE` / `OCI_REGISTRY_REALM` in `.env`; the
  overlay pins the service to the Traefik hostname and the realm derives to
  `https://<service>/auth/token`.
- The challenge advertises that https realm:
  `curl --silent --include https://<user>-bunyip-registry.a8n.run/v2/` must
  return 401 with
  `WWW-Authenticate: Bearer realm="https://<user>-bunyip-registry.a8n.run/auth/token",...`
- docker login / pull target the Traefik hostname instead of localhost:18081;
  the rest of the matrix (pinned-tag enforcement, cache hits, denials) is
  identical and `just verify-oci` covers it for the localhost path.

Verified live on dev-01 (2026-06-02): login + pull of
`psa-systems-private/bunyip-api:v0.1.1` through
`https://nate-bunyip-registry.a8n.run` with a valid Let's Encrypt certificate.

## Production notes (CANONICAL: operator configuration rules)

This section is the single source for production distribution-proxy
configuration; compose.yml, .env.example, and the dev-sso runbook point here.

### Configuration rules

- `OCI_REGISTRY_SERVICE` must equal the public registry hostname
  (e.g. `registry.<base-domain>`); leave `OCI_REGISTRY_REALM` unset so it
  defaults to `https://<service>/auth/token` behind TLS. Startup fails fast if
  the registry is enabled with an empty service or a malformed realm.
- The Forgejo service token is a secret with scopes `read:package` +
  `read:repository`. Generate: Forgejo -> Settings -> Applications -> Generate
  New Token. In production it lives in the file-based compose secret
  `./secrets/forgejo_api_token` (mounted at `/run/secrets/forgejo_api_token`,
  read by the api via `FORGEJO_API_TOKEN_FILE`); an empty file keeps the
  distribution proxy disabled. Dev still uses the plain `.env`
  `FORGEJO_API_TOKEN` var (unchanged). File-based secrets never appear in
  `docker inspect` output or `/proc/<pid>/environ`, unlike plain environment
  variables (BUNYIP-38).
- Upgrading a pre-BUNYIP-38 deployment: run `./scripts/init-secrets.sh` before
  `docker compose up`. It migrates the secret values from your existing `.env`
  into the `./secrets/*` files (including `forgejo_api_token`).
- Cache volumes: mount NAMED volumes at `/var/cache/bunyip-oci` and
  `/var/cache/bunyip-downloads`. The image pre-creates those paths owned by
  the runtime user (uid 1001) and named volumes inherit that ownership on
  first use. A host bind-mount does NOT inherit it, mounts root-owned, and
  every blob/asset write fails (Permission denied -> 502 on all pulls). If a
  bind-mount is unavoidable: `chown 1001:1001 <host dir>` first.

### Reverse-proxy requirements + reference configs

The proxy must route BOTH `/v2/*` and `/auth/token` on the registry hostname
to the api container's port 18081, terminate TLS, and must not buffer or
size-limit response bodies (image layers are hundreds of MB).

Caddy:

```caddyfile
registry.example.com {
    # Both /v2/* and /auth/token go to the same upstream; no body limits.
    reverse_proxy 127.0.0.1:18081 {
        flush_interval -1
    }
}
```

Traefik (file provider):

```yaml
http:
  routers:
    bunyip-registry:
      rule: Host(`registry.example.com`)
      entryPoints:
        - websecure
      tls:
        certResolver: your-resolver
      service: bunyip-registry
  services:
    bunyip-registry:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:18081
```

nginx (note the body-size and buffering directives; defaults break pulls):

```nginx
server {
    listen 443 ssl;
    server_name registry.example.com;
    # ... ssl_certificate / ssl_certificate_key ...
    client_max_body_size 0;
    proxy_buffering off;
    proxy_request_buffering off;
    location / {
        proxy_pass http://127.0.0.1:18081;
        proxy_set_header Host $host;
    }
}
```

### Resolved caveats

- Forgejo accepts the engine's basic auth with an empty username and the token
  as password, for both manifests and blobs. No engine change needed.
