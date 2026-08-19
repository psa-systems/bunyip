# Self-hosting Bunyip

`compose.yml` is the reference deployment. It runs the published `bunyip-api` and `bunyip-web` OCI images plus PostgreSQL; no build from source. This guide covers the topology, the deploy, and how updates are checked and applied. For every configuration variable see [configuration.md](configuration.md); for secret sourcing and rotation see [secrets-infisical.md](secrets-infisical.md).

## Topology

A Traefik edge terminates TLS and routes two public names at the host:

- `${BUNYIP_HOST}` (the apex, e.g. `bunyip.example.com`) - the `bunyip-web` front-end.
- `api.${BUNYIP_HOST}` (e.g. `api.bunyip.example.com`) - `bunyip-api`, which is also the OIDC issuer, so relying parties reach `/.well-known/openid-configuration` and `/oauth2/*` there.

`bunyip-web` reaches `bunyip-api` server-side over the internal Compose network (`BUNYIP_API_URL`, default `http://api:4401`); the browser only ever talks to the two public names above. `BUNYIP_API_PUBLIC_ORIGIN` (e.g. `https://api.${BUNYIP_HOST}`) is the browser-facing origin the front-end and Stripe use for redirects and webhooks.

Client IP travels a two-hop chain, Traefik -> `bunyip-web` -> `bunyip-api`, honoured only from trusted proxies (`TRUSTED_PROXY_CIDR` / `WEB_TRUSTED_PROXY_CIDR`); see [client-ip-forwarding.md](client-ip-forwarding.md).

## Deploy

The images live in the private `dev.a8n.run/psa-systems-private` registry, so authenticate first:

```nu
docker login dev.a8n.run
cp .env.example .env
# Edit .env: pin BUNYIP_API_IMAGE / BUNYIP_WEB_IMAGE, set BUNYIP_API_PUBLIC_ORIGIN and the trusted-proxy CIDRs.
just init-secrets            # dev throwaways; production supplies ./secrets via the SOPS compose-secrets.yml
docker compose up --detach
```

`BUNYIP_API_IMAGE` and `BUNYIP_WEB_IMAGE` are **required** (BUNYIP-237): Compose refuses to start without them. Pin both to the same release tag, e.g. `dev.a8n.run/psa-systems-private/bunyip-api:v0.4.1`, so a rolling restart never serves two different builds.

Group-1 startup secrets (postgres, `DATABASE_URL`, `APP_ENCRYPTION_KEY`, `JWT_SECRET`, ...) are files, never environment variables: `compose.yml` mounts each from `./secrets/<name>` at `/run/secrets/<name>` and the api reads it through the `{NAME}_FILE` convention, so `docker inspect` never shows a value. `just init-secrets` ([`scripts/init-secrets.nu`](../scripts/init-secrets.nu)) generates them locally, which is right for a self-host that keeps its own values; the PSA deployments supply the same files from the SOPS `compose-secrets.yml`. Group-2 integration secrets (the SMTP password and the two Stripe secrets) come from the ONE store the deployment declares in `SECRETS_STORAGE=environment|database|infisical`, and only from that store. Full detail: [secrets-infisical.md](secrets-infisical.md).

`bunyip-api` and `bunyip-web` are released as a **matched pair**: both carry the same workspace version and are promoted together. Since BUNYIP-506 the response models tolerate one release of skew (an unknown field or enum value degrades to a neutral render instead of failing the decode), which is what makes a rolling restart safe; two or more releases apart is not supported. Bump both image tags to the same release in the same operator action.

## Update checking

The instance reports its running version and whether a newer release is published:

```nu
http get https://api.${BUNYIP_HOST}/version
```

```json
{
  "version": "0.15.0",
  "revision": "<git sha>",
  "update": {
    "enabled": true,
    "current": "0.15.0",
    "latest": "0.16.0",
    "update_available": true,
    "checked_at": "2026-08-19T12:00:00+00:00"
  }
}
```

The check polls `BUNYIP_UPDATE_CHECK_URL` (the public Forgejo `releases/latest` endpoint by default) at most once an hour and caches the result. Set it to an empty string to disable checking (`update.enabled` becomes `false`). A private release feed needs a read token in `BUNYIP_UPDATE_CHECK_TOKEN` (via `BUNYIP_UPDATE_CHECK_TOKEN_FILE`).

## Applying an update

Updates are never automatic; the operator decides when to apply one. Bump both image tags in `.env` to the new release, then:

```nu
docker compose pull
docker compose up --detach
```

Database migrations run on `bunyip-api` startup. Committed migrations are immutable, so a downgrade is not a supported path; restore from a backup instead.
