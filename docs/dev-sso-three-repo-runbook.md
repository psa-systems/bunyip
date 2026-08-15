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
`./secrets/oidc`). Missing keys = boot failure. `just ensure-oidc-keys` now generates
them (added this session).

### 3.8 The OIDC direction (cutover landed: bunyip-api IS the OP)
The reversed wiring scaffold step 8 flagged is now converged in dev-sso. There is ONE issuer: `bunyip-api` (`OIDC_ISSUER=https://<user>-bunyip-api.a8n.run`, serves `/oauth2/*` + `/.well-known/*` + its own `/v1/auth/*` email+password login). Both relying parties consume it:
- `bunyip-web` (the hub): `BUNYIP_OIDC_ISSUER=https://<user>-bunyip-api.a8n.run`, client `bunyip-web-dev`.
- the mokosh SPA: `MOKOSH_OIDC_ISSUER=https://<user>-bunyip-api.a8n.run`, client `mokosh-apps-dev`.

`mokosh-server` is a **Resource Server**: its auth middleware's BunyipVerifier (`src/modules/auth/oidc_rs.rs`) validates the at+jwt bunyip mints by fetching bunyip's discovery + JWKS and JIT-provisioning the user, activated by `OIDC_ISSUER` + `OIDC_AUDIENCE`. Because the issuer host resolves to dev-01's public edge (self-signed + 404 on the OP path) from inside the container, mokosh-server's compose pins it to the LOCAL Traefik via `extra_hosts` (`<user>-bunyip-api.a8n.run:${BUNYIP_OP_TRAEFIK_IP:-172.30.0.11}`), which serves the OP with a valid Let's Encrypt cert.

bunyip-api's OP is exposed on its own Traefik host `<user>-bunyip-api.a8n.run` (port 4401); register the two dev clients with `just register-dev-clients`. The old `register-bunyip-client` (mokosh-server) flow is retired.

## 4. Spin-up procedure (the happy path, once a box is set up)

On **desktop-02**, in dependency order:

```nu
# 1. The OP (bunyip-api) + hub first
cd /home/long/bunyip; just dev-sso

# 2. Register the two dev OIDC clients in bunyip-api (idempotent; prints UUIDs)
just register-dev-clients
#    -> hub UUID  -> /home/long/bunyip/.env as BUNYIP_OIDC_CLIENT_ID
#    -> SPA UUID  -> /home/long/mokosh-apps/.env as MOKOSH_OIDC_CLIENT_ID

# 3. The Resource Server (mokosh-server)
cd /home/long/mokosh-server; just dev-sso

# 4. The client SPA
cd /home/long/mokosh-apps; just dev-sso

# 5. Re-up the hub so it reads the client_id you just set
cd /home/long/bunyip; just dev-sso
```

bunyip `.env` must have (resolve `${USER}` to your username):
```
BUNYIP_OIDC_ISSUER=https://long-bunyip-api.a8n.run
BUNYIP_OIDC_CLIENT_ID=b0000000-0000-4000-8000-0000000000d1
BUNYIP_OIDC_REDIRECT_URI=https://long-bunyip.a8n.run/auth/callback
```
mokosh-apps `.env` needs `MOKOSH_OIDC_CLIENT_ID=b0000000-0000-4000-8000-0000000000d2`; mokosh-server reads the RS env from its compose overlay (`OIDC_ISSUER` + `OIDC_AUDIENCE` + the `extra_hosts` pin).

Optionally, to also serve the distribution proxy (member downloads + the OCI
registry on `<user>-bunyip-registry.a8n.run`), add the Forgejo service
credentials; see section 9.

Optionally, to enable **account backup/restore** (BUNYIP-356 - the Backup add-on
under Integrations captures the account's Mokosh tenant data), set
`MOKOSH_BACKUP_API_URL=https://<user>-mokosh-api.a8n.run` in bunyip's `.env`
(same mokosh host as `MOKOSH_WEBHOOK_URL`) and re-up bunyip-api. Left unset,
bunyip mints nothing and the Backup add-on records Mokosh as "unavailable" - so
this is opt-in per box. bunyip mints a short-lived Mokosh-audience `at+jwt` for
the acting admin and calls Mokosh `/api/v1/data/{export,import}`. Backup/export
works immediately; **restore is gated on mokosh-server PMS-648** (its tenant
data import is still WIP), so a restore round-trip is not reliable until that
lands.

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
`APP_ENCRYPTION_KEY` was empty (must be 32-byte hex) and the api refused to
start (since BUNYIP-537 it reports every unusable variable as a startup
configuration `ERROR` and exits 1; before that it panicked); plus
`secrets/oidc/` had no Ed25519 OIDC keys. Fix: regenerate `.env`
from the new template (generated secret keys, kept the registered client_id + uid),
generate `secrets/oidc/dev-2026.pem`, recreate the api. Durable fix: `ensure-oidc-keys`
recipe (`feat/dev-ensure-oidc-keys`) + the existing `ensure-env` key generation.
See 3.7.

### 6.10 Audit log / access log shows a Docker IP, not the real client (BUNYIP-476)
Symptom: an audited login's `actor_ip_address` (or the access-log IP) is a
`172.x` / `10.x` container address, not the browser's public IP. Cause: the
client IP travels the two-hop BFF path (Traefik -> bunyip-web -> bunyip-api), and
each hop honours `X-Forwarded-For` only from a peer inside its trusted-proxy
list. If bunyip-api's `TRUSTED_PROXY_CIDR` does not contain bunyip-web's
container address (or bunyip-web's `WEB_TRUSTED_PROXY_CIDR` does not contain
Traefik's), the forwarded IP is dropped and the socket peer (bunyip-web) is
recorded instead. It is a config/topology condition, not a resolver bug:
auto-ban's single-hop direct-to-API endpoints still resolve correctly, which is
why they can disagree. Fix: keep the compose defaults
(`172.16.0.0/12,10.0.0.0/8,192.168.0.0/16` on both), which already span the
Docker/Traefik ranges; if you narrow them, keep bunyip-web's address in
bunyip-api's `TRUSTED_PROXY_CIDR`. bunyip-api logs its posture once at boot (a
`WARN` when `TRUSTED_PROXY_CIDR` is empty). Full walkthrough:
`docs/client-ip-forwarding.md` (section "The audited-login path").

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
| api exits 1, "APP_ENCRYPTION_KEY ... not the required 32" | stale `.env` missing the new secret keys | 6.9 |
| api fails to load the OIDC key set | `secrets/oidc/dev-2026.pem` missing | 3.7 / 6.9 |
| `${USER}` literal in `docker inspect` labels | map-syntax labels | 6.8 |

## 8. Open / transitional items

- ~~**Reversed OIDC wiring** (3.8): bunyip-web is a client of mokosh-server while
  bunyip-api is its own issuer.~~ DONE: bunyip-api is now the sole OP; bunyip-web
  and the mokosh SPA are its clients; mokosh-server is a Resource Server (see 3.8).
- **dev-01 must serve on `nebula-secure`** for the entrypoint change to be correct
  there too; confirm with the foundation owner (the work was done on desktop-02).
- **Open PRs** from this session: `fix/dev-sso-nebula-secure-list` (bunyip +
  mokosh-apps), `fix/dev-sso-private-network-external`, `feat/dev-ensure-oidc-keys`;
  mokosh-server already carries the nebula-secure change.
- The milestone-1 handoff (now distilled into `docs/dev-docs/CHANGELOG.md`) and
  `docs/dev-docs/bunyip-on-dunite-scaffold.md` predate the rebuild landing and are
  stale on "mock backend / don't persist in bunyip-api".

## 9. OCI registry subdomain (distribution proxy, BUNYIP-32)

The dev-sso overlay routes the bunyip OCI registry through Traefik on its own
per-developer hostname, `<user>-bunyip-registry.a8n.run`, with a real
certificate. Members (or you, testing) docker-login with bunyip credentials;
bunyip fetches the actual images from the private Forgejo with a server-side
service token. Procedures and configuration rules live in
`docs/oci-registry-verification.md` (which has a dedicated dev-sso
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
localhost procedure in `docs/oci-registry-verification.md`. The binary
download proxy rides the api with no extra routing; exercise it via the web UI
/downloads page or `/v1/downloads` with a bearer token.

### Mac access

Add the registry hostname to the same `/etc/hosts` line as the other dev
hostnames (section 4): `<nebula-ip>  <user>-bunyip-registry.a8n.run`. Docker
Desktop on macOS resolves through the host's `/etc/hosts`.

## 10. Distribution e2e smoke test (BUNYIP-35)

The full customer-flow verification matrix, first executed 2026-06-02 against
the local dev stack. Full pass/fail results live as a comment on BUNYIP-35.

This section does NOT repeat what is already automated or documented
elsewhere:

- **OCI basics** (auth challenge, admin docker login, entitled pull,
  pinned-tag enforcement): run `just verify-oci` - it checks all of them with
  pass/fail output. The manual procedure behind it is
  `docs/oci-registry-verification.md` (the BUNYIP-31 runbook).
- **Traefik-hostname routing**: section 9 above.

What this section adds: the credential matrix (including non-member denials),
a definitive cache proof, binary download integrity, limit enforcement, and
Forgejo failure modes.

### Prerequisites

- Stack up via `just dev-detach` (NEVER raw `docker compose`; the justfile
  owns the HOST_UID/volume wiring).
- `.env` has a valid `FORGEJO_BASE_URL` + `FORGEJO_API_TOKEN` (read:package
  scope) and `OCI_REGISTRY_ENABLED=true`.
- Two dedicated test users. `just verify-oci` uses the admin
  (`SETUP_DEFAULT_ADMIN`); this matrix needs a separate MEMBER (so results
  don't depend on admin state) and a NON-MEMBER (for the denial tests, which
  verify-oci cannot cover). Create them:

```nu
# Member + non-member accounts (register sets no entitlement).
^curl --silent --request POST http://localhost:4401/v1/auth/register --header "Content-Type: application/json" --data '{"email": "test-member@bunyip.local", "password": "<pick-a-password>"}'
^curl --silent --request POST http://localhost:4401/v1/auth/register --header "Content-Type: application/json" --data '{"email": "test-nonmember@bunyip.local", "password": "<pick-a-password>"}'

# Entitle ONLY the member. lifetime_member is one of the access paths checked
# by has_member_access() (role/lifetime/trial/active|grace all work);
# oci-registry-verification.md uses membership_status = 'active' instead -
# either is fine, lifetime_member never expires.
let user_name = (^whoami | str trim)
^docker exec $"dev-bunyip-postgres-($user_name)" psql --username bunyip --dbname bunyip --command "UPDATE users SET lifetime_member = TRUE, email_verified = TRUE WHERE email = 'test-member@bunyip.local';" --command "UPDATE users SET email_verified = TRUE WHERE email = 'test-nonmember@bunyip.local';"
```

- API auth for `/v1/*` is an HttpOnly `access_token` cookie (NOT a bearer
  header). Capture it with a cookie jar:

```nu
# Login and store cookies; reuse $jar on every later /v1 request.
let jar = (^mktemp | str trim)
^curl --silent --cookie-jar $jar --request POST http://localhost:4401/v1/auth/login --header "Content-Type: application/json" --data '{"email": "test-member@bunyip.local", "password": "<password>"}'
# Authenticated request:
^curl --silent --cookie $jar http://localhost:4401/v1/downloads
```

### Matrix A: functional flows (no restarts)

Run `just verify-oci` first; everything below assumes it passed.

| # | Test | Command sketch | Expected |
| --- | --- | --- | --- |
| A1 | Bad password | `docker login localhost:18081` with member email, wrong password | docker: `unauthorized`; HTTP 401 from `/auth/token` |
| A2 | Non-member docker login | `docker login` with non-member creds | `unauthorized` (entitlement gate; verify-oci only tests the happy path) |
| A3 | Multi-arch index | `curl --header "Authorization: Bearer <token>" --header "Accept: application/vnd.oci.image.index.v1+json" http://localhost:18081/v2/mokosh-server/manifests/v0.2.0` (token from `/auth/token` with the pull scope) | JSON body `mediaType: application/vnd.oci.image.index.v1+json` with a `linux/amd64` entry |
| A4 | Nonexistent repo | `docker pull localhost:18081/no-such-product:v1` | HTTP 404; JSON envelope code `NAME_UNKNOWN`; docker CLI prints `name unknown: repository name not known` |
| A5 | Unpinned tag | `docker pull localhost:18081/mokosh-server:latest` | HTTP 404; JSON envelope code `MANIFEST_UNKNOWN`; docker CLI prints `manifest unknown: manifest not known` |
| A6 | Cache proof (definitive) | see below | re-pull succeeds with Forgejo unreachable |
| A7 | Downloads listing | `GET /v1/downloads` with member cookie jar | groups with `assets` and/or `oci` blocks |
| A8 | Binary integrity | download binary + `.sha256` asset via the proxy; `sha256sum` the binary; also sha256 the same file fetched from Forgejo directly | all three digests identical |
| A9 | Non-member denial | `GET /v1/downloads` + an asset URL with the NON-member cookie jar | HTTP 403, envelope code `FORBIDDEN`, no asset bytes |

Caveat: space docker operations ~15 s apart or the token endpoint's
5/min/email rate limit (BUNYIP-40) fires before whatever you are actually
testing.

**A6 cache proof.** "Grep the logs" does NOT work here: the blob path logs
nothing on an upstream fetch, so absence of log lines proves nothing. The
definitive method is a re-pull with the upstream dead - it can only succeed if
every manifest and blob byte comes from bunyip's caches:

```nu
let user_name = (^whoami | str trim)
let api = $"dev-bunyip-api-($user_name)"
# 1. Warm the caches.
^docker pull localhost:18081/mokosh-server:v0.2.0
# 2. Make Forgejo unreachable inside the api container (backup first).
^docker exec --user root $api sh -c 'cp /etc/hosts /etc/hosts.bak && echo "127.0.0.2 dev.a8n.run" >> /etc/hosts'
# 3. Re-pull within the manifest-cache TTL (60 s default). Success = proof.
^docker rmi localhost:18081/mokosh-server:v0.2.0
^docker pull localhost:18081/mokosh-server:v0.2.0
# 4. ALWAYS restore, even if step 3 failed.
^docker exec --user root $api sh -c 'cp /etc/hosts.bak /etc/hosts && rm /etc/hosts.bak'
```

### Matrix B: limit enforcement

Blocked on BUNYIP-42 for a clean procedure: compose.dev.yml does not pass the
limit env vars through, so `.env` values are ignored. Until that lands, the
interim method is a compose override layered on top of the just-managed stack
(this is the one sanctioned exception to "never raw compose" - it keeps
compose.dev.yml first so all just-managed wiring stays identical, and HOST_UID
/ HOST_GID must be exported exactly as the justfile does):

```nu
# Override file with low limits (save errors if a leftover exists; remove it first).
if ("/tmp/compose.limits.yml" | path exists) { ^rm /tmp/compose.limits.yml }
"services:
  api:
    environment:
      OCI_PULLS_PER_USER_PER_DAY: \"3\"
      DOWNLOAD_DAILY_LIMIT_PER_USER: \"3\"
      DOWNLOAD_CONCURRENCY_PER_USER: \"1\"
" | save /tmp/compose.limits.yml
$env.HOST_UID = (^id --user | str trim); $env.HOST_GID = (^id --group | str trim)
^docker compose -f compose.dev.yml -f /tmp/compose.limits.yml up --detach api
# ... run B1-B3 ...
# Restore the normal stack when done:
just dev-detach
^rm /tmp/compose.limits.yml
```

| # | Test | Expected |
| --- | --- | --- |
| B1 | Pull past the daily cap | HTTP 429 on `/v2/{slug}/manifests/...`; the wait time is the `Retry-After` HTTP HEADER (the OCI 429 body has no retry field); value = seconds until midnight UTC. NOTE: one multi-arch docker pull = 3 counted requests (BUNYIP-43), so with cap 3 the SECOND pull is denied |
| B2 | 4th download with cap 3 | HTTP 429; JSON body code `download_daily_limit` with `details.retry_after` (seconds to midnight UTC) - unlike B1 this one IS in the body |
| B3 | 3 parallel downloads, concurrency 1 | exactly one 200, rest 429 |

Reset counters between runs:

```nu
let user_name = (^whoami | str trim)
^docker exec $"dev-bunyip-postgres-($user_name)" psql --username bunyip --dbname bunyip --command "DELETE FROM oci_pull_daily_counts;" --command "DELETE FROM download_daily_counts;"
```

### Matrix C: failure modes

| # | Test | Procedure | Expected |
| --- | --- | --- | --- |
| C1 | Forgejo unreachable | Same hosts block/restore as A6 steps 2 and 4 (ALWAYS restore) | Warm caches keep serving; after cache expiry/invalidation `/v1/downloads` stays 200 and drops the affected product; asset download = 502 with API envelope code `UPSTREAM_ERROR`; `docker pull` = 502 with OCI envelope code `UNKNOWN`, message `upstream error`; container never crash-loops |
| C2 | Forgejo token revoked | `cp .env /tmp/env-backup` FIRST. Then swap the token (`sed -i 's/^FORGEJO_API_TOKEN=.*/FORGEJO_API_TOKEN=invalid-test/' .env`), `just dev-detach`, run the checks, then `cp /tmp/env-backup .env && just dev-detach` | Customer sees generic "upstream service temporarily unavailable"; api log carries the actionable line `upstream Forgejo rejected the registry service credentials; verify FORGEJO_API_TOKEN is valid and has the read:package scope`; the token value never appears in any response |

### Known gaps and defects (as of 2026-06-02)

- No live releases-backed product exists (all binaries publish to the Forgejo
  generic package registry), so the `artifact_source = 'release'` path is
  covered only by wiremock integration tests in
  `bunyip-api/src/handlers/download.rs`, not by this live matrix.
- Blob cache hits/misses are not observable in logs (why A6 needs the
  dead-upstream method); the only blob-cache log lines are the eviction
  failures of BUNYIP-41.
- BUNYIP-40: token endpoint shares the 5/min login rate limit; multi-image
  pulls can 429.
- BUNYIP-41: blob cache LRU eviction silently fails (pool exhaustion) during
  concurrent pulls.
- BUNYIP-42: compose files missing limit/TTL env passthrough.
- BUNYIP-43: daily pull counter counts manifest requests (3+ per docker pull).
