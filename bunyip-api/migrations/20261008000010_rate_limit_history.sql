-- Rate-limit history: one durable row per throttle event.
--
-- Record the fact that a rate limit was breached so the admin page can still
-- show it after the window elapses. The `rate_limits` row's count/window pair
-- are overwritten on the next window, so a 429 that fired forty minutes ago
-- cannot be read back from there; this table carries fired_at and expires_at
-- that stay stable through the window reset.
--
-- Insert is gated on the under-cap to over-cap transition in
-- `RateLimitRepository::check_and_increment`, so a burst of 20 refused
-- requests inside one window produces one history row rather than 20.
--
-- Retention is 24 hours, enforced by a background sweep in
-- `bunyip-api/src/main.rs` beside the existing rate-limit cleanup task.
-- Older rows are not useful for the "has a rate limit fired recently"
-- question the admin page answers.

CREATE TABLE rate_limit_history (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    action     TEXT        NOT NULL,
    key        TEXT        NOT NULL,
    fired_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX rate_limit_history_fired_at_idx
    ON rate_limit_history (fired_at DESC);

CREATE INDEX rate_limit_history_action_fired_at_idx
    ON rate_limit_history (action, fired_at DESC);

COMMENT ON TABLE rate_limit_history IS
    'Durable record of past rate-limit breaches, read by the admin page.';
COMMENT ON COLUMN rate_limit_history.key IS
    'The rate-limit key as it is stored on `rate_limits.key`: email, user id, IP, or oauth client id, as the action''s KeyKind interprets it.';
COMMENT ON COLUMN rate_limit_history.fired_at IS
    'When the throttle first crossed the under-cap to over-cap boundary.';
COMMENT ON COLUMN rate_limit_history.expires_at IS
    'When the throttle''s window would have ended (fired_at + window_seconds).';

GRANT SELECT, INSERT, DELETE ON rate_limit_history TO bunyip_app;
