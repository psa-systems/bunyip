-- IdP-side sessions (server-side; allows back-channel revocation)
CREATE TABLE IF NOT EXISTS op_sessions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Opaque value stored in the browser cookie
    sid             TEXT        NOT NULL UNIQUE,
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    user_agent      TEXT,
    ip              INET,
    -- Authentication context / methods
    acr             TEXT,
    amr             TEXT[]
);

CREATE INDEX IF NOT EXISTS op_sessions_user_active
    ON op_sessions(user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS op_sessions_sid
    ON op_sessions(sid) WHERE revoked_at IS NULL;

-- Authorization codes (hashed; single-use; 60 s TTL)
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code_hash               BYTEA       PRIMARY KEY,
    client_id               UUID        NOT NULL REFERENCES oauth_clients(client_id),
    user_id                 UUID        NOT NULL REFERENCES users(id),
    op_session_id           UUID        NOT NULL REFERENCES op_sessions(id),
    redirect_uri            TEXT        NOT NULL,
    scope                   TEXT[]      NOT NULL,
    code_challenge          TEXT        NOT NULL,
    code_challenge_method   TEXT        NOT NULL CHECK (code_challenge_method = 'S256'),
    nonce                   TEXT        NOT NULL,
    auth_time               TIMESTAMPTZ NOT NULL,
    acr                     TEXT,
    amr                     TEXT[],
    issued_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ NOT NULL,
    consumed_at             TIMESTAMPTZ,
    revoked_at              TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS oauth_codes_expires ON oauth_authorization_codes(expires_at);

-- Per-user, per-application entitlement.
-- Token and authorization endpoints refuse to issue tokens for a (user, client)
-- pair without an active row here.  Default at migration time: grant all
-- existing users access to the seeded clients (preserves current behavior).
CREATE TABLE IF NOT EXISTS user_application_access (
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id       UUID        NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    granted_scopes  TEXT[]      NOT NULL,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by      UUID        REFERENCES users(id),
    revoked_at      TIMESTAMPTZ,
    PRIMARY KEY (user_id, client_id)
);

CREATE INDEX IF NOT EXISTS user_application_access_active
    ON user_application_access(user_id) WHERE revoked_at IS NULL;

-- Backfill access rows for the (user x client) pairs that exist AT THIS POINT
-- in the migration chain. NOTE: no clients are seeded yet - oauth_clients
-- (20260417000040) ships with zero rows and the relying-party seeds
-- (20260502000048 onward) run LATER - so on a fresh database this CROSS JOIN
-- matches zero clients and inserts zero rows. It is retained only to grant
-- access to any clients an operator inserted manually before this migration.
-- The authoritative grant paths are: per-client seed migrations (which insert
-- their own access rows) and JIT provisioning at login for new users. This is
-- deliberately NOT a no-op error: it is correct for the manual-insert case and
-- harmless (zero rows) otherwise.
INSERT INTO user_application_access (user_id, client_id, granted_scopes, granted_at)
SELECT
    u.id,
    c.client_id,
    c.allowed_scopes,
    NOW()
FROM users u
CROSS JOIN oauth_clients c
WHERE u.deleted_at IS NULL
ON CONFLICT (user_id, client_id) DO NOTHING;
