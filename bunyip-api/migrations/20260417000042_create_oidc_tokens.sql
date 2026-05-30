-- Refresh-token families (one per login session / code exchange)
CREATE TABLE IF NOT EXISTS refresh_token_families (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       UUID        NOT NULL REFERENCES oauth_clients(client_id),
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    op_session_id   UUID        NOT NULL REFERENCES op_sessions(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,
    revoke_reason   TEXT
);

CREATE INDEX IF NOT EXISTS refresh_token_families_user
    ON refresh_token_families(user_id) WHERE revoked_at IS NULL;

-- Refresh tokens — rotated on every use; hashed; opaque to clients
CREATE TABLE IF NOT EXISTS refresh_tokens_v2 (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash          BYTEA       NOT NULL UNIQUE,   -- SHA-256 of raw token
    family_id           UUID        NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE,
    parent_id           UUID        REFERENCES refresh_tokens_v2(id),
    client_id           UUID        NOT NULL REFERENCES oauth_clients(client_id),
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope               TEXT[]      NOT NULL,
    -- DPoP JWK thumbprint (nullable; Phase 2)
    cnf_jkt             TEXT,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at             TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    idle_expires_at     TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    ip                  INET,
    user_agent          TEXT
);

CREATE INDEX IF NOT EXISTS refresh_tokens_family
    ON refresh_tokens_v2(family_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_active_user
    ON refresh_tokens_v2(user_id)
    WHERE revoked_at IS NULL AND used_at IS NULL;

-- Optional JTI blocklist for access tokens.
-- Populated only for explicitly revoked tokens (password change, admin revoke).
-- RSes consult via a short-lived in-process cache.
CREATE TABLE IF NOT EXISTS access_token_blocklist (
    jti         TEXT        PRIMARY KEY,
    exp         TIMESTAMPTZ NOT NULL,
    reason      TEXT        NOT NULL,
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS access_token_blocklist_exp ON access_token_blocklist(exp);

-- Lifecycle event outbox for back-channel user-state notifications (§7.5).
-- Inserted in the same transaction as the user-state change.
CREATE TABLE IF NOT EXISTS lifecycle_event_outbox (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  TEXT        NOT NULL CHECK (event_type IN (
        'user.suspended', 'user.unsuspended', 'user.deleted',
        'entitlement.granted', 'entitlement.revoked'
    )),
    user_id     UUID        NOT NULL,
    payload     JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One delivery attempt row per (event, target client)
CREATE TABLE IF NOT EXISTS lifecycle_event_delivery (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID        NOT NULL REFERENCES lifecycle_event_outbox(id) ON DELETE CASCADE,
    client_id       UUID        NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    delivery_url    TEXT        NOT NULL,
    -- Stable jti across retries so receiver can be idempotent
    jti             UUID        NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    attempts        INT         NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_attempt_at TIMESTAMPTZ,
    delivered_at    TIMESTAMPTZ,
    failed_at       TIMESTAMPTZ,
    last_error      TEXT
);

CREATE INDEX IF NOT EXISTS lifecycle_event_delivery_pending
    ON lifecycle_event_delivery(next_attempt_at)
    WHERE delivered_at IS NULL AND failed_at IS NULL;
