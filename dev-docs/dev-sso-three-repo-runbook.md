# dev-sso across three repos: design, spin-up, and every obstacle behind it

Snapshot: 2026-05-31. Covers how the Traefik-routed dev SSO stack (`just dev-sso`)
works across **bunyip**, **mokosh-server**, and **mokosh-apps**, why it is shaped
the way it is, and the full list of obstacles hit bringing it up on **desktop-02
over Nebula** (plus how each was fixed). Read this before touching dev-sso infra
or onboarding a new dev box.

## 1. What dev-sso is and the three repos

`just dev-sso` layers `compose.dev-sso.yml` on top of `compose.dev.yml` to run a
per-developer, Traefik-routed, TLS-terminated instance on real `*.a8n.run`
hostnames, so the cross-origin OIDC/SSO flows can be exercised the way they run
in production (you cannot do that on `localhost`).

| Repo | Role | dev-sso hostname (user `long`) | Upstream port |
| --- | --- | --- | --- |
| `bunyip` | SaaS hub / account + billing UI; **its own OIDC issuer** (new) | `long-bunyip.a8n.run` + `long-bunyip-registry.a8n.run` (OCI registry, sec 9) | web 4400; api 4401 internal, registry 18081 via Traefik |
| `mokosh-server` | Identity provider (the OIDC issuer the SPA still points at) | `long-mokosh-api.a8n.run` | 4301 |
| `mokosh-apps` | The PSA client SPA (relying party) | `long-mokosh.a8n.run` | 4301 |

The hostnames follow `<username>-<service>.a8n.run`. Username comes from `${USER}`.

## 2. The topology (the single most important thing to understand)

```
  Browser (your Mac, on the Nebula mesh: 172.30.0.x)
     |  https://long-bunyip.a8n.run
     |  *.a8n.run resolves to 152.53.242.183 == dev-01.niceguyit.biz
     v
  [ dev-01 ]  the SHARED public edge (DNS points here for everyone)
     |  ...but your stack does NOT run here...
     v
  [ desktop-02 ]  where YOU run the stacks (more resources)
     LAN IP 172.16.100.120 | Nebula IP 172.30.0.11
     network-traefik (one Traefik, TWO https entrypoints):
        - web-secure   :20443  published on 172.16.100.120 (LAN only)
        - nebula-secure :443   published on 172.30.0.11   (Nebula, asDefault)
     |
     v
  per-developer container stacks (bunyip / mokosh-server / mokosh-apps)
```

Key consequence: global DNS sends every browser to **dev-01**, but you run on
**desktop-02**. The only path from your Mac to desktop-02's containers is the
**Nebula mesh** (172.30.0.11). And desktop-02's Traefik only carries your dev
routers on the **`nebula-secure`** entrypoint, not `web-secure`. This is the root
of most "can't be reached" pain in section 6.

## 3. Design rationale (the "why it was built like this")

### 3.1 Why per-developer `<user>-<service>.a8n.run` hostnames
Multiple developers share the same Nebula/Traefik infra. Isolation is achieved by
prefixing the **hostname**, the **container_name**, and the **Traefik router/label
keys** with `${USER}` - NOT by changing the compose project name. The compose
project name is deliberately left at the repo default; overriding it would make
compose treat the shared external network as foreign and refuse to start (see the
comment block in each `compose.dev-sso.yml`).

### 3.2 Why you register the OIDC client once (`just register-bunyip-client`)
OIDC's authorization-code + PKCE flow requires the **relying party** (the SPA,
`bunyip-web`) to be **pre-registered with the identity provider** (`mokosh-server`)
before it can ask for a code. `register-bunyip-client` inserts a row into
mokosh-server's `oauth_clients` table:

- `MOKOSH_CLIENT_NAME=bunyip-web`, `TYPE=public`, `AUTH_METHOD=none` -> a
  **public client using PKCE** (no client secret; a browser SPA cannot keep one).
- `REDIRECT_URIS=https://<user>-bunyip.a8n.run/auth/callback`,
  `GRANT_TYPES=authorization_code refresh_token`, `AUDIENCE=<mokosh-api origin>`.

It prints a **client_id UUID**, which you paste into bunyip's `.env` as
`BUNYIP_OIDC_CLIENT_ID`. The SPA then sends that UUID on every `/oauth2/authorize`
request so the IdP knows which client is asking and which redirect_uri is allowed.

Why **once**: the registration is a **persisted DB row** in mokosh-server's
Postgres - it survives restarts. The recipe is **idempotent on the client name**,
so re-running is safe but unnecessary. The same UUID is intended to be reused in
every mokosh-server instance (so one bunyip image works against staging + prod),
which is why bunyip has no runtime fallback for `client_id` - an unset one is a
hard configuration error, not something to invent.

### 3.3 Why two Traefik entrypoints, and `nebula-secure`
desktop-02's `network-traefik` defines `web-secure` (:20443, bound to the LAN IP)
and `nebula-secure` (:443, bound to the Nebula IP, `asDefault=true`). dev nodes are
reached over Nebula, so the dev-sso routers MUST bind `nebula-secure` to be
reachable from your Mac. `web-secure` is LAN-only and invisible over the mesh. Each
router also sets `tls.certresolver=cert-cloudflare` so Traefik issues a real
Let's Encrypt wildcard-capable cert via the Cloudflare DNS-01 challenge (the CF
API tokens live in the Traefik container), giving a trusted lock with no warning.

### 3.4 Why the `private` network is `external: true` + a recipe pre-create
The per-developer network `dev-<app>-private-${USER}` is shared by a stack's
services and is created **out of band** by the `just dev*` recipe
(`docker network inspect || docker network create`). compose.dev.yml declares it
`external: true` so compose **attaches** to that pre-created network instead of
trying to **own** it. If compose owns it, it stamps a `com.docker.compose.network`
label and rejects any pre-existing unlabeled network - see obstacle 6.6.

### 3.5 Why list-syntax Traefik labels (not the usual map syntax)
Docker Compose v2.40 interpolates `${USER}` inside string **values** but NOT inside
map **keys**. The Traefik router name lives in the label **key**
(`traefik.http.routers.bunyip-${USER}.rule`). In map syntax the `${USER}` in that
key stays literal, the router is named `bunyip-${USER}`, and routing breaks
(default cert + 404). In **list/sequence** syntax the whole `key=value` is one
string value, so `${USER}` interpolates correctly. This is why all three overlays
use `- traefik.http.routers.<svc>-${USER}.rule=...`. (This deliberately departs
from the repo convention of map-syntax labels; the bug forces it.)

### 3.6 Why HOST_UID / HOST_GID matter
The dev images bind-mount the repo at `/app` and run as a non-root user. The repo
is owned by your host user (uid 10002 here) with `0700` perms. compose interpolates
`${HOST_UID}/${HOST_GID}` for the container `user:` mapping and the image build
args; if they fall back to 1000, the container user cannot read the bind-mounted
0700 repo and crash-loops with "can't cd to /app/...". The justfile must export
`HOST_UID`/`HOST_GID` (named exactly that) - see obstacle 6.7.

### 3.7 Why bunyip needs Ed25519 OIDC keys on disk
After the dunite rebuild, **bunyip-api is itself an OIDC issuer**
(`OIDC_ISSUER=http://localhost:4401`; the provider is gated on that var in
`main.rs`). It loads an Ed25519 signing key at startup
(`OIDC_JWT_PRIVATE_KEY_PATH=/run/secrets/oidc/dev-2026.pem`, mounted from
`./secrets`). Missing keys = boot failure. `just ensure-oidc-keys` now generates
them (added this session).

### 3.8 The OIDC direction is in transition (read this carefully)
There are currently **two issuers** in play and the wiring is mid-migration:
- `bunyip-api` IS an OIDC issuer (`OIDC_ISSUER=:4401`, serves `/oauth2/*` +
  `/.well-known/*`) and owns its own `/v1/auth/*` (email+password register/login).
- yet `bunyip-web` is still configured as a **client of mokosh-server**
  (`BUNYIP_OIDC_ISSUER=https://<user>-mokosh-api.a8n.run` + the
  `register-bunyip-client` flow above).

So the dev-sso SSO bridge points the SPA at mokosh-server as IdP, even though
bunyip can now be its own IdP. `dev-docs/bunyip-on-dunite-scaffold.md` step 8
explicitly flags this as "reversed OIDC wiring" to fix: bunyip-web should
eventually consume Bunyip's own issuer. Until that converges, the
`register-bunyip-client` + `BUNYIP_OIDC_*` dance is the supported dev-sso path.

## 4. Spin-up procedure (the happy path, once a box is set up)

On **desktop-02**, in dependency order:

```nu
# 1. IdP first
cd /home/long/mokosh-server; just dev-sso

# 2. Register bunyip-web as an OIDC client (ONE TIME; prints a UUID)
just register-bunyip-client
#    -> paste the UUID into /home/long/bunyip/.env as BUNYIP_OIDC_CLIENT_ID

# 3. The client SPA
cd /home/long/mokosh-apps; just dev-sso

# 4. The hub
cd /home/long/bunyip; just dev-sso
```

bunyip `.env` must have (resolve `${USER}` to your username):
```
BUNYIP_OIDC_ISSUER=https://long-mokosh-api.a8n.run
BUNYIP_OIDC_CLIENT_ID=<uuid from step 2>
BUNYIP_OIDC_REDIRECT_URI=https://long-bunyip.a8n.run/auth/callback
```

Optionally, to also serve the distribution proxy (member downloads + the OCI
registry on `<user>-bunyip-registry.a8n.run`), add the Forgejo service
credentials; see section 9.

On your **Mac** (one time), point the dev hostnames at desktop-02's Nebula IP:
```bash
# remove any stale 127.0.0.1 mapping for these first (it wins; see 6.5)
sudo sed -i '' '/^127\.0\.0\.1.*a8n\.run/d' /etc/hosts
echo "172.30.0.11  long-bunyip.a8n.run long-mokosh-api.a8n.run long-mokosh.a8n.run" | sudo tee -a /etc/hosts
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
```
Then open `https://long-bunyip.a8n.run`.

## 5. Client-side access from the Mac (over Nebula)

- **/etc/hosts override is mandatory**: DNS sends you to dev-01; you must force the
  dev hostnames to desktop-02's Nebula IP `172.30.0.11`.
- **Chrome Secure DNS (DoH) bypasses /etc/hosts.** If `curl`/`ping` resolve right
  but Chrome still fails, turn off `chrome://settings/security` -> "Use secure DNS"
  and fully quit Chrome. (Alternative for a throwaway test: launch Chrome with
  `--host-resolver-rules="MAP long-bunyip.a8n.run 172.30.0.11, ..."` and a separate
  `--user-data-dir`.)
- **Mailpit is LAN-only** on desktop-02 (`127.0.0.1:8025`), so signup/reset emails
  are not reachable over Nebula. Tunnel it: `ssh -L 8025:127.0.0.1:8025 long@desktop-02`,
  then open `http://localhost:8025`.

## 6. Every obstacle hit, with root cause and fix

Grouped by era. Some early ones are now historical (the pre-rebuild Dioxus SPA),
kept for context.

### 6.1 (historical) Plain `just dev` signup -> 405
Pre-rebuild, the SPA auth pages called the OIDC issuer URL; in LAN mode there was
no issuer, so the POST hit the `dx serve` static server -> 405. **Resolved by the
rebuild**: bunyip-api now serves real `/v1/auth/register` (email+password), and
dev-sso provides the issuer. Historical.

### 6.2 "This site can't be reached" from the Mac (the big one)
Symptom: browser cannot load `long-bunyip.a8n.run` while the stack is clearly up.
Root cause was a **stack** of issues, peeled one at a time:
1. DNS `*.a8n.run` -> dev-01, not desktop-02 (section 2).
2. Routers bound to `web-secure` (LAN-only), unreachable over Nebula.
3. Stale `127.0.0.1` line in the Mac `/etc/hosts` winning over the correct one.
4. Chrome Secure DNS bypassing `/etc/hosts`.
Fix: bind routers to `nebula-secure` (6.4), `/etc/hosts` -> `172.30.0.11` (6.5),
Chrome DoH off (section 5).

### 6.3 Self-signed / default Traefik cert
Probing `:443` from the wrong vantage (the LAN IP, or before issuance) returned the
`TRAEFIK DEFAULT CERT`. Real full-chain Let's Encrypt certs are served once the
`cert-cloudflare` resolver provisions and you hit the right entrypoint/host. Not a
real problem once `nebula-secure` + the host override are correct.

### 6.4 Routers on the wrong entrypoint (web-secure vs nebula-secure)
Symptom: 404 over Nebula for every `long-*` host. Cause: dev-sso overlays pinned
`entrypoints: web-secure` (LAN-only). Fix: switch to `nebula-secure` (and to
list-syntax labels, 6.8). mokosh-server already had this; bunyip + mokosh-apps got
`fix/dev-sso-nebula-secure-list`. Assumes dev-01 also serves on `nebula-secure`.

### 6.5 Stale `127.0.0.1` host entry -> ERR_CONNECTION_REFUSED
Symptom: refused in ~1ms while `curl --resolve ... 172.30.0.11` worked. Cause: an
old `127.0.0.1 long-*.a8n.run` line earlier in `/etc/hosts` won (first match), so
the browser hit localhost:443 with nothing listening. Fix: delete the stale line,
keep only the `172.30.0.11` mapping, flush DNS.

### 6.6 compose network label conflict (post-rebuild regression)
Symptom: `network dev-bunyip-private-${USER} ... incorrect label
com.docker.compose.network set to '' (expected: private)`. Cause: the dunite
rewrite dropped `external: true` from `compose.dev.yml` while the recipe still
pre-creates the network. Fix: restore `external: true`
(`fix/dev-sso-private-network-external`). See 3.4.

### 6.7 Container crash-loop "can't cd to /app/bunyip-web" (post-rebuild regression)
Symptom: api + web restart forever; Traefik returns 404 (no healthy backend).
Cause: the justfile exported `UID`/`GID`, but compose reads `HOST_UID`/`HOST_GID`,
so they fell back to 1000; the container ran as 1000 and could not read the 0700
repo owned by uid 10002. Fix: `export HOST_UID`/`HOST_GID`
(`fix/dev-host-uid-mapping`). See 3.6.

### 6.8 `${USER}` literal in router name (map vs list labels)
Symptom: default cert + 404 even with a correct rule. Cause: map-syntax labels left
`${USER}` un-interpolated in the router **key**. Fix: list-syntax labels (3.5),
folded into `fix/dev-sso-nebula-secure-list`.

### 6.9 Register page "error sending request ... /v1/auth/register"
Symptom: web SSR could not reach `api:4401`. Cause: the api **crash-looped on
config** - the `.env` was the **old-architecture** one (missing ~20 new keys), so
`TOTP_ENCRYPTION_KEY`/`STRIPE_ENCRYPTION_KEY` were empty (must be 32-byte hex) and
the api panicked; plus `secrets/` had no Ed25519 OIDC keys. Fix: regenerate `.env`
from the new template (generated secret keys, kept the registered client_id + uid),
generate `secrets/dev-2026.pem`, recreate the api. Durable fix: `ensure-oidc-keys`
recipe (`feat/dev-ensure-oidc-keys`) + the existing `ensure-env` key generation.
See 3.7.

## 7. Troubleshooting quick-reference

| Symptom | Most likely cause | Where |
| --- | --- | --- |
| signup 405 | on plain `just dev` (no issuer), not dev-sso | 6.1 |
| "can't be reached" / 404 from Mac | router on `web-secure` not `nebula-secure`, or DNS to dev-01 | 6.2 / 6.4 |
| ERR_CONNECTION_REFUSED from Mac | stale `127.0.0.1` line in `/etc/hosts` | 6.5 |
| curl works, browser does not | Chrome Secure DNS (DoH) bypassing hosts | sec 5 |
| default cert / "not private" | wrong entrypoint/host, or pre-issuance | 6.3 |
| compose "incorrect label ... network" | missing `external: true` | 6.6 |
| containers restart, 404 backend | HOST_UID fell back to 1000 (0700 repo) | 6.7 |
| api panics "must be 32 bytes" | stale `.env` missing the new secret keys | 6.9 |
| api panics on OIDC key | `secrets/dev-2026.pem` missing | 3.7 / 6.9 |
| `${USER}` literal in `docker inspect` labels | map-syntax labels | 6.8 |

## 8. Open / transitional items

- **Reversed OIDC wiring** (3.8): bunyip-web is a client of mokosh-server while
  bunyip-api is its own issuer. Converge per scaffold step 8.
- **dev-01 must serve on `nebula-secure`** for the entrypoint change to be correct
  there too; confirm with the foundation owner (the work was done on desktop-02).
- **Open PRs** from this session: `fix/dev-sso-nebula-secure-list` (bunyip +
  mokosh-apps), `fix/dev-sso-private-network-external`, `feat/dev-ensure-oidc-keys`;
  mokosh-server already carries the nebula-secure change.
- The `milestone-1-handoff.md` and `bunyip-on-dunite-scaffold.md` docs predate the
  rebuild landing and are stale on "mock backend / don't persist in bunyip-api".

## 9. OCI registry subdomain (distribution proxy, BUNYIP-32)

The dev-sso overlay routes the bunyip OCI registry through Traefik on its own
per-developer hostname, `<user>-bunyip-registry.a8n.run`, with a real
certificate. Members (or you, testing) docker-login with bunyip credentials;
bunyip fetches the actual images from the private Forgejo with a server-side
service token. Procedures and configuration rules live in
`dev-docs/oci-registry-verification.md` (which has a dedicated dev-sso
section); this section covers only the dev-sso-specific wiring.

### Required .env additions

The same distribution block documented in `.env.example` (Forgejo base URL,
service token, `OCI_REGISTRY_ENABLED=true`). Do NOT set
`OCI_REGISTRY_SERVICE` / `OCI_REGISTRY_REALM` for dev-sso: the overlay pins the
service to `<user>-bunyip-registry.a8n.run` and clears the realm so it derives
to `https://<service>/auth/token` (TLS via Traefik).

The single api container serves both access paths at once: Traefik routes the
registry hostname to it AND its localhost port stays published, so
`localhost:18081` keeps working. (This is one container reachable two ways,
not two stacks; a separate plain `just dev` cannot run concurrently with
dev-sso - same container names and host ports.)

### How it is wired

- `compose.dev-sso.yml` adds Traefik labels to the `api` service:
  router `bunyip-registry-<user>` on entrypoints `web-secure,nebula-secure`,
  certresolver `cert-cloudflare`, forwarding to container port 18081.
- The router binds BOTH secure entrypoints because the dev boxes differ
  (verified on dev-01, 2026-06-02): on dev-01 the public :443 maps to Traefik's
  `web-secure` entrypoint, while on desktop-02 the Nebula-published :443 is
  `nebula-secure`. A router bound to only one of them 404s on the other box.
  This is the same split behind the section 8 open item about bunyip-web's
  entrypoint.
- Both `/v2/*` and `/auth/token` ride the same hostname, which is exactly what
  Docker's auth flow expects.

### Smoke test (on the dev box)

Run `just verify-oci` first (covers the full matrix against `localhost:18081`,
which the same container also serves). Then confirm the Traefik path:

```nu
# A member user + application row must exist; `just verify-oci` seeds them.
let user_name = (^whoami | str trim)
let registry = $"($user_name)-bunyip-registry.a8n.run"

# 1. Challenge advertises the Traefik hostname + https realm
^curl --silent --include $"https://($registry)/v2/" | lines | where $it =~ "www-authenticate"
# expect: Bearer realm="https://<user>-bunyip-registry.a8n.run/auth/token",service="..."

# 2. Login + pull through Traefik (login prompts for the password; pipe it via
#    --password-stdin when scripting)
^docker login $registry --username admin@bunyip.local
^docker pull $"($registry)/bunyip-api:v0.1.1"
```

The rest of the matrix (denials, cache hits, rate limits) is identical to the
localhost procedure in `dev-docs/oci-registry-verification.md`. The binary
download proxy rides the api with no extra routing; exercise it via the web UI
/downloads page or `/v1/downloads` with a bearer token.

### Mac access

Add the registry hostname to the same `/etc/hosts` line as the other dev
hostnames (section 4): `<nebula-ip>  <user>-bunyip-registry.a8n.run`. Docker
Desktop on macOS resolves through the host's `/etc/hosts`.

## 10. Distribution e2e smoke test (BUNYIP-35)

The full customer-flow verification matrix, first executed 2026-06-02 against
the local dev stack (`just dev-detach`, registry on `localhost:18081`). The
Traefik-hostname variant of the OCI flow is section 9's smoke test; everything
below exercises the same containers and code paths. Full results live as a
comment on BUNYIP-35.

### Prerequisites

- Stack up via `just dev-detach` (NEVER raw `docker compose`; the justfile owns
  the HOST_UID/volume wiring).
- `.env` has a valid `FORGEJO_BASE_URL` + `FORGEJO_API_TOKEN` (read:package
  scope) and `OCI_REGISTRY_ENABLED=true`.
- Two test users (the BUNYIP-35 run created these in the dev DB):
  - Member: `test-member-b34@bunyip.local` (lifetime_member = TRUE)
  - Non-member: `test-nonmember-b34@bunyip.local`
  Recreate with `POST /v1/auth/register` + `UPDATE users SET lifetime_member =
  TRUE, email_verified = TRUE WHERE email = '...'` in psql.

### Matrix A: functional flows (no restarts)

| # | Test | Command sketch | Expected |
| --- | --- | --- | --- |
| A1 | Member docker login | `docker login localhost:18081` with member creds | `Login Succeeded` |
| A2 | Bad password | same, wrong password | `unauthorized` |
| A3 | Non-member login | same, non-member creds | `unauthorized` (entitlement gate) |
| A4 | Entitled pull | `docker pull localhost:18081/mokosh-server:v0.2.0` | succeeds; multi-arch index served (check with `Accept: ...image.index.v1+json`) |
| A5 | Nonexistent repo | `docker pull localhost:18081/no-such-product:v1` | `name unknown` OCI envelope, not 500 |
| A6 | Unpinned tag | `docker pull localhost:18081/mokosh-server:latest` | `manifest unknown` envelope (pinned-tag enforcement) |
| A7 | Blob cache hit | `docker rmi` + re-pull; grep api logs for upstream blob fetches | zero upstream fetches on re-pull |
| A8 | Downloads listing | `GET /v1/downloads` with member cookie | products with assets and/or `oci` blocks |
| A9 | Binary integrity | download binary + `.sha256` asset; compare; also sha256 the same file fetched from Forgejo directly | all three digests identical |
| A10 | Non-member denial | `GET /v1/downloads` + asset URL with non-member cookie | 403 with clean FORBIDDEN envelope |

Caveat for A4-A7: space pulls ~15 s apart or the token endpoint's 5/min/email
rate limit (BUNYIP-40) fires before the limit you are actually testing.

### Matrix B: limit enforcement

The limit env vars are not yet passed through by the compose files
(BUNYIP-42), so until that lands this requires a temporary compose override
layered onto the just-managed stack. With limits set low (e.g. pulls 3/day,
downloads 3/day, download concurrency 1):

| # | Test | Expected |
| --- | --- | --- |
| B1 | Pull past the daily cap | 429 on `/v2/{slug}/manifests/...` with `retry_after` = seconds until midnight UTC. NOTE: one multi-arch docker pull = 3 counted requests (BUNYIP-43) |
| B2 | 4th download with cap 3 | 429, error code `download_daily_limit`, `retry_after` to midnight UTC |
| B3 | 3 parallel downloads, concurrency 1 | exactly one 200, rest 429 |

Reset counters between runs: `DELETE FROM oci_pull_daily_counts; DELETE FROM
download_daily_counts;` in psql.

### Matrix C: failure modes

| # | Test | Procedure | Expected |
| --- | --- | --- | --- |
| C1 | Forgejo unreachable | `docker exec --user root dev-bunyip-api-<user> sh -c 'echo "127.0.0.2 dev.a8n.run" >> /etc/hosts'` (revert after) | Warm caches keep serving; after cache invalidation `/v1/downloads` stays 200 and drops the affected product; asset download = 502 UPSTREAM_ERROR; `docker pull` = 502 with OCI envelope; container never crash-loops |
| C2 | Forgejo token revoked | swap `FORGEJO_API_TOKEN` in `.env` for garbage, `just dev-detach`; restore + `just dev-detach` after | Customer sees generic "upstream service temporarily unavailable"; api log carries the actionable line `upstream Forgejo rejected the registry service credentials; verify FORGEJO_API_TOKEN is valid and has the read:package scope`; no token value in any response |

### Known gaps and defects (as of 2026-06-02)

- No live releases-backed product exists (all binaries publish to the Forgejo
  generic package registry), so the `artifact_source = 'release'` path is
  covered only by wiremock integration tests in
  `bunyip-api/src/handlers/download.rs`, not by this live matrix.
- BUNYIP-40: token endpoint shares the 5/min login rate limit; multi-image
  pulls can 429.
- BUNYIP-41: blob cache LRU eviction silently fails (pool exhaustion) during
  concurrent pulls.
- BUNYIP-42: compose files missing limit/TTL env passthrough.
- BUNYIP-43: daily pull counter counts manifest requests (3+ per docker pull).
