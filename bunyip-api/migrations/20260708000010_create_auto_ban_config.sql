-- BUNYIP-351: singleton table for auto-ban configuration (admin-configurable).
-- NULL columns fall back to environment variable defaults at runtime, matching
-- the `tier_config` / `stripe_config` DB-overrides-env pattern.
CREATE TABLE auto_ban_config (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    enabled           BOOLEAN,
    threshold         BIGINT,
    window_secs       BIGINT,
    ban_duration_secs BIGINT,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by        UUID REFERENCES users(id)
);

INSERT INTO auto_ban_config (id) VALUES (1);
