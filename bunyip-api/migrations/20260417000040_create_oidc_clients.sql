-- OAuth 2.0 / OIDC client registrations
--
-- Dynamic registration (RFC 7591) is disabled; clients are seeded here.
-- require_pkce is always TRUE — no exceptions.

CREATE TABLE IF NOT EXISTS oauth_clients (
    id                          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id                   UUID        NOT NULL UNIQUE,
    -- Argon2id hash; NULL for public clients
    client_secret_hash          TEXT,
    client_type                 TEXT        NOT NULL CHECK (client_type IN ('public', 'confidential')),
    name                        TEXT        NOT NULL,
    -- Exact-match redirect URIs (array, no wildcards)
    redirect_uris               TEXT[]      NOT NULL,
    post_logout_redirect_uris   TEXT[]      NOT NULL DEFAULT '{}',
    backchannel_logout_uri      TEXT,
    lifecycle_event_uri         TEXT,
    allowed_scopes              TEXT[]      NOT NULL,
    -- Subset of { authorization_code, refresh_token }
    allowed_grant_types         TEXT[]      NOT NULL,
    token_endpoint_auth_method  TEXT        NOT NULL CHECK (
        token_endpoint_auth_method IN ('none', 'client_secret_basic', 'private_key_jwt')
    ),
    require_pkce                BOOLEAN     NOT NULL DEFAULT TRUE,
    -- Access token TTL: 60–900 s
    access_token_ttl_seconds    INT         NOT NULL DEFAULT 600
        CHECK (access_token_ttl_seconds BETWEEN 60 AND 900),
    -- Refresh token absolute TTL: 1h–90d
    refresh_token_ttl_seconds   INT         NOT NULL DEFAULT 2592000
        CHECK (refresh_token_ttl_seconds BETWEEN 3600 AND 7776000),
    -- Refresh idle TTL
    refresh_idle_ttl_seconds    INT         NOT NULL DEFAULT 1209600,
    -- Audience for access tokens issued to this client
    audience                    TEXT        NOT NULL,
    dpop_bound                  BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by                  UUID        REFERENCES users(id),
    disabled_at                 TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS oauth_clients_active ON oauth_clients(client_id)
    WHERE disabled_at IS NULL;

-- No client seeds here. Bunyip registers its own relying parties (the
-- bunyip-web SPA, mokosh-server, etc.) via a separate seed migration once their
-- client_ids / redirect_uris / secrets are known. See BUNYIP-26.
