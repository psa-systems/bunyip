-- BUNYIP-388: per-application documentation.
--
-- Bunyip's catalog apps (applications table) had no place for product docs of
-- their own; the only docs surface was the global /docs. This table holds
-- multiple admin-authored markdown pages per application, read publicly and
-- rendered by bunyip-web through the same markdown pipeline as /docs. Pages are
-- ordered by sort_order then title, and identified per app by slug.
CREATE TABLE application_docs (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID        NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    slug           TEXT        NOT NULL,
    title          TEXT        NOT NULL,
    body           TEXT        NOT NULL,
    sort_order     INT         NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (application_id, slug)
);

CREATE INDEX idx_application_docs_app ON application_docs (application_id, sort_order);

-- Seed: Mokosh Server and Mokosh Web start with documentation; every other app
-- starts with none. Bodies are grounded in mokosh-server's real configuration
-- and the server/web split. Idempotent via ON CONFLICT so a re-run is safe.

-- Mokosh Server: getting started.
INSERT INTO application_docs (application_id, slug, title, body, sort_order)
SELECT id, 'getting-started', 'Getting Started', $md$
# Getting started with Mokosh Server

Mokosh Server is the self-hosted PSA (Professional Services Automation) API backend for MSPs. It exposes the REST API that the Mokosh web frontend and integrations talk to.

## Get it

Mokosh Server ships as a container image. From this app in Bunyip, copy the pull command and run:

```
docker login <registry>
docker pull <registry>/mokosh-server:<tag>
```

See [Downloading apps](/docs/downloading-apps) for the general download and pull flow.

## Run it

Run the image with your configuration supplied as environment variables (see the Configuration page). Point a PostgreSQL database at it and let it apply its migrations on start.
$md$, 0
FROM applications WHERE slug = 'mokosh-server'
ON CONFLICT (application_id, slug) DO NOTHING;

-- Mokosh Server: configuration.
INSERT INTO application_docs (application_id, slug, title, body, sort_order)
SELECT id, 'configuration', 'Configuration', $md$
# Configuring Mokosh Server

Mokosh Server is configured entirely through environment variables. The essentials:

## Database

- `DATABASE_URL` - PostgreSQL connection string. Required.
- `RUN_MIGRATIONS` - apply schema migrations on start. Defaults to `true`.

## Single sign-on

Mokosh Server verifies Bunyip-issued access tokens as an OpenID Connect resource server:

- `OIDC_ISSUER` - the Bunyip issuer URL.
- `OIDC_AUDIENCE` - the audience Mokosh Server accepts.

## Security

- `ENCRYPTION_KEY` - 32 bytes (raw, or 64 hex characters), used for at-rest encryption of per-tenant secrets. Required.
- `CORS_ORIGIN` - comma-separated list of allowed origins.

## Email

- `SMTP_HOST` - when set, outbound email uses SMTP; otherwise email is logged. When `SMTP_USERNAME` is set, `SMTP_PASSWORD` is required.
$md$, 1
FROM applications WHERE slug = 'mokosh-server'
ON CONFLICT (application_id, slug) DO NOTHING;

-- Mokosh Web: getting started.
INSERT INTO application_docs (application_id, slug, title, body, sort_order)
SELECT id, 'getting-started', 'Getting Started', $md$
# Getting started with Mokosh Web

Mokosh Web is the browser frontend for the Mokosh PSA platform. It talks to a running Mokosh Server over its REST API and signs users in through Bunyip.

## Get it

Mokosh Web ships as a container image. From this app in Bunyip, copy the pull command and run it. See [Downloading apps](/docs/downloading-apps) for the general flow.

## Run it

Run the container alongside a reachable Mokosh Server and point it at that server. Users sign in once through Bunyip and land in the Mokosh Web interface.
$md$, 0
FROM applications WHERE slug = 'mokosh-www'
ON CONFLICT (application_id, slug) DO NOTHING;
