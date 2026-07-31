-- BUNYIP-413: super-admin flag + persisted rate-limit configuration.
--
-- Super admin
-- -----------
-- The "first setup account": the bootstrap admin (BOOTSTRAP_ADMIN_EMAIL) on a
-- fresh install, the earliest-created admin on an existing one. Only this
-- account may manage rate limits and IP bans, because either can lock the
-- platform out for everybody.
ALTER TABLE users ADD COLUMN is_super_admin BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill: existing deployments already have their bootstrap admin, so the
-- sign-in promotion path (`ensure_bootstrap_admin`) is inert there and would
-- never set the flag. Seed it from the earliest-created admin instead.
UPDATE users
SET is_super_admin = TRUE
WHERE id = (
    SELECT id FROM users
    WHERE role = 'admin' AND deleted_at IS NULL
    ORDER BY created_at ASC
    LIMIT 1
);

-- Persisted rate-limit configuration
-- ----------------------------------
-- One optional row per known `RateLimitConfig` action. Absent = use the
-- bootstrap default (the compile-time const, itself overridable by the
-- RATE_LIMIT_{ACTION}_MAX_REQUESTS / _WINDOW_SECONDS env vars). Present =
-- override the cap/window for that action everywhere it is enforced.
CREATE TABLE rate_limit_configs (
    action VARCHAR(64) PRIMARY KEY,
    max_requests INTEGER NOT NULL CHECK (max_requests > 0),
    window_seconds BIGINT NOT NULL CHECK (window_seconds > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES users (id) ON DELETE SET NULL
);
