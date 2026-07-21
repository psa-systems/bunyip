-- PMS-678: public setup documentation for Mokosh, delivered as bunyip per-app
-- docs for the mokosh-server application (rendered at /apps/mokosh-server/docs/*).
-- Covers running Mokosh locally with Docker Compose, the image registry + login
-- model (including suspended/deactivated-account behaviour, verified against
-- bunyip-oci's oci_auth flow), and splitting the server and web across hosts.
-- Idempotent via ON CONFLICT so a re-run is safe.

-- Running Mokosh with Docker Compose.
INSERT INTO application_docs (application_id, slug, title, body, sort_order)
SELECT id, 'docker-compose', 'Running with Docker Compose', $md$
# Running Mokosh with Docker Compose

Mokosh ships as container images you pull from Bunyip's registry and run with Docker Compose. This gets a working instance on one machine.

## What you are running

- **Mokosh Server** (`mokosh-server`) - the REST API backend, listening on port 8080. It applies its own database migrations on start.
- **PostgreSQL** - the database the server uses.
- **Mokosh Web** (`mokosh-www`) - the browser frontend. Optional for an API-only setup; see [Splitting the server and web](/apps/mokosh-server/docs/split-deployment).

By default the server and web run together on one host; you can split them later.

## Prerequisites

- Docker with the Compose v2 plugin (`docker compose version`).
- A Bunyip account with access, used both to sign in to the image registry and as Mokosh's single sign-on. See [The image registry and signing in](/apps/mokosh-server/docs/registry-login).

## 1. Sign in and pull

```
docker login oci.a8n.systems
docker pull oci.a8n.systems/mokosh-server:<tag>
```

Use the tag shown on this app's page in Bunyip, and sign in with your a8n.systems credentials.

## 2. A Compose file

Save the following as `compose.yml`. It is a minimal single-host setup; fill the `CHANGE_ME` and `<...>` placeholders. See [Configuration](/apps/mokosh-server/docs/configuration) for every variable the server accepts.

```
name: mokosh
services:
  server:
    image: oci.a8n.systems/mokosh-server:<tag>
    restart: unless-stopped
    environment:
      HOST: 0.0.0.0
      PORT: "8080"
      RUN_MIGRATIONS: "true"
      DATABASE_URL: postgres://mokosh:CHANGE_ME@postgres:5432/mokosh
      OIDC_ISSUER: <your Bunyip issuer, e.g. https://api.a8n.systems>
      OIDC_AUDIENCE: <the audience Mokosh accepts>
      ENCRYPTION_KEY: <32 bytes, raw or 64 hex chars>
      CORS_ORIGIN: http://localhost:8080
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
  postgres:
    image: docker.io/postgres:18-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: mokosh
      POSTGRES_PASSWORD: CHANGE_ME
      POSTGRES_DB: mokosh
    volumes:
      - mokosh-postgres:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $$POSTGRES_USER -d $$POSTGRES_DB"]
      interval: 10s
      timeout: 5s
      retries: 5
volumes:
  mokosh-postgres:
```

## 3. Start it

```
docker compose up -d
```

The server applies migrations on first start (`RUN_MIGRATIONS=true`) and serves the API at `http://localhost:8080/api/v1/health`.
$md$, 2
FROM applications WHERE slug = 'mokosh-server'
ON CONFLICT (application_id, slug) DO NOTHING;

-- The image registry and signing in.
INSERT INTO application_docs (application_id, slug, title, body, sort_order)
SELECT id, 'registry-login', 'The image registry and signing in', $md$
# The image registry and signing in

Mokosh's images live in Bunyip's container registry at `oci.a8n.systems`. It is an authenticated proxy in front of the private package registry: there is no anonymous access, so you sign in before pulling.

## Signing in

```
docker login oci.a8n.systems
```

Use your **a8n.systems account** - the same email and password you sign in to Bunyip with. Docker stores the login, so later pulls just work.

## What access requires

Sign-in succeeds only for an account that is allowed to use the registry: an admin, a lifetime member, an active trial, or an active membership. An allowed, signed-in account can pull the Mokosh images.

## Suspended or deactivated accounts

If your account is **suspended or deactivated**, registry sign-in stops working: `docker login` is rejected as unauthorized, and you can no longer pull. Re-activating the account restores access. Losing membership access (a trial expiring, a cancelled membership) likewise blocks new sign-ins and pulls.

Images you have already pulled keep working locally; the registry only gates fetching new images or tags.
$md$, 3
FROM applications WHERE slug = 'mokosh-server'
ON CONFLICT (application_id, slug) DO NOTHING;

-- Splitting the server and web across hosts.
INSERT INTO application_docs (application_id, slug, title, body, sort_order)
SELECT id, 'split-deployment', 'Splitting the server and web across hosts', $md$
# Splitting the server and web across hosts

By default Mokosh Server and Mokosh Web run together on a single host. For larger deployments you can run them on separate hosts.

## The two pieces

- **Mokosh Server** (`mokosh-server`) - the API backend plus its PostgreSQL database. This is the stateful core.
- **Mokosh Web** (`mokosh-www`) - the browser frontend. It is stateless and talks to the server over its REST API.

## Splitting them

Run each on its own host with its own Compose file:

- On the **backend host**: the `server` and `postgres` services, as in [Running with Docker Compose](/apps/mokosh-server/docs/docker-compose). Expose the API to the frontend host, directly or behind a reverse proxy.
- On the **frontend host**: the `mokosh-www` container, pointed at the backend host's API URL.

The frontend must reach the server's API, and both sign users in through the same Bunyip issuer, so the server's `OIDC_ISSUER` / `OIDC_AUDIENCE` and the web's API target have to line up across the two hosts.
$md$, 4
FROM applications WHERE slug = 'mokosh-server'
ON CONFLICT (application_id, slug) DO NOTHING;
