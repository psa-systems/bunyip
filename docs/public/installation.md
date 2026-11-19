# Installation

For a deployment operator putting bunyip on a real host. `compose.yml` is the reference deployment; it runs the published `bunyip-api` and `bunyip-web` OCI images plus PostgreSQL. No build from source, no sidecar agents.

## Topology

A Traefik edge terminates TLS and routes two public names at the host:

- `${BUNYIP_HOST}` (the apex, e.g. `bunyip.example.com`) is `bunyip-web`, the front-end.
- `api.${BUNYIP_HOST}` is `bunyip-api`, which is also the OIDC issuer. Discovery lives at `api.${BUNYIP_HOST}/.well-known/openid-configuration` and the OAuth 2.1 endpoints at `/oauth2/*`.

`bunyip-web` reaches `bunyip-api` server-side over the internal Compose network via `BUNYIP_API_URL` (default `http://api:4401`). The browser only ever hits the two public names above. `BUNYIP_API_PUBLIC_ORIGIN` (e.g. `https://api.${BUNYIP_HOST}`) is the browser-facing origin the front-end and Stripe redirects use.

Client IP travels Traefik to `bunyip-web` to `bunyip-api` and is honoured only from a trusted-proxy CIDR. The two forwarding knobs are `TRUSTED_PROXY_CIDR` on the api side and `WEB_TRUSTED_PROXY_CIDR` on the web side. See the Client IP section of [Configuration](configuration.md).

## Deploy

The images live in the private `dev.a8n.run/psa-systems-private` registry. Authenticate the host once:

```
docker login dev.a8n.run
```

Copy `.env.production.example` to `.env` and pin the image tags plus the browser-facing origin:

```
cp .env.production.example .env
# Set BUNYIP_API_IMAGE, BUNYIP_WEB_IMAGE to the same release tag, e.g.
#   dev.a8n.run/psa-systems-private/bunyip-api:v0.4.1
# Set BUNYIP_API_PUBLIC_ORIGIN=https://api.${BUNYIP_HOST}
# Set TRUSTED_PROXY_CIDR and WEB_TRUSTED_PROXY_CIDR to match your edge.
# Set OIDC_JWT_PRIVATE_KEY_PATH and OIDC_JWT_ACTIVE_KID per secrets.md.
```

Place Group-1 secrets under `./secrets/`. For a bootstrap, `just init-secrets` generates throwaway values. A real deployment supplies them from a SOPS-encrypted `compose-secrets.yml` kept per host; see the [docker repo](https://dev.a8n.run/NiceGuyIT/docker) convention.

Start it:

```
docker compose up --detach
```

`BUNYIP_API_IMAGE` and `BUNYIP_WEB_IMAGE` are required; Compose refuses to start without them. Pin both to the same release tag so a rolling restart never serves two different builds.

## Migrations apply automatically

The api runs migrations on start, in order, against the connection it opens with `DATABASE_URL`. Committed migrations are immutable: a release never rewrites a migration that already shipped. An operator only sees one of three outcomes on boot:

- Up to date: no rows written, api begins serving.
- Behind: new migrations apply in order, then the api begins serving. The container log names each file as it runs.
- Ahead: the deployed image is older than the database. The api refuses to serve. Roll the image forward to the version whose migrations include every one the database has.

## Health and first sign-in

`GET /health` on the api returns `{"status":"ok"}` when it is ready. Hit the discovery URL to confirm the OP side: `https://api.${BUNYIP_HOST}/.well-known/openid-configuration`. Then open the front-end at `https://${BUNYIP_HOST}/` and sign in with the seeded default from `SETUP_DEFAULT_ADMIN`. Change the password on the account page before you wire any RP against this deployment.

## What is NOT installed by this stack

- No DNS, no TLS certificates, no reverse proxy. Traefik fronts bunyip; this stack does not provision it.
- No log aggregation. `docker compose logs` is the source of truth; ship to your platform of choice.
- No metrics server. The api exposes application metrics but needs a Prometheus scrape target wired to the deployment.

Everything above is a deliberate split: bunyip assumes it runs inside an existing fleet with these layers already present.

## Updating

Pull a newer release tag, bump `BUNYIP_API_IMAGE` and `BUNYIP_WEB_IMAGE` to the same new tag in `.env`, then `docker compose up --detach`. The api runs any new migrations on its first start. See [Upgrades](operations/upgrades.md) for the operator-facing rollout flow.
