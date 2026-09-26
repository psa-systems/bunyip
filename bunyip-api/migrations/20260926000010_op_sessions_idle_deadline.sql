-- BUNYIP-636 PR 1 of 5: `op_sessions` gains a sliding idle deadline.
--
-- Today the row carries one deadline (`expires_at`) set once at creation to
-- NOW() + 7 days regardless of "remember me" or activity, plus a
-- `last_active_at` column that is written at INSERT and never rolled forward.
-- So an OP session's clock is a fixed 7-day countdown that neither activity nor
-- absence of activity can move, and the OIDC refresh grant runs its own idle
-- clock beside it (`refresh_tokens_v2.idle_expires_at`, 14 days). Idle-then-
-- return leaves the two clocks disagreeing: the hub tab reads signed out on the
-- fixed OP deadline while an RP silently renews on its longer idle budget.
--
-- Two follow-up migrations plus code changes make the pair one clock. This
-- migration is the schema half: `expires_at` becomes the absolute ceiling,
-- `idle_expires_at` becomes the sliding deadline every liveness check reads.
-- Both are NOT NULL and both carry a DEFAULT so existing rows keep working
-- until the code half (PR 2) starts sliding the new column. The DEFAULT for
-- `idle_expires_at` is the row's own `expires_at`, so a legacy row that has
-- never been read behaves exactly as it did before (it dies on the absolute
-- deadline; the idle deadline is at the same instant so it never fires first).
--
-- The pre-existing 7-day `expires_at` DEFAULT stays for the same reason: PR 2
-- lands the code that reads `remember` at login and sets both deadlines from
-- the two `SESSION_IDLE_TTL_*_SECONDS` config keys.

ALTER TABLE op_sessions
    ADD COLUMN idle_expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days');

-- Backfill NOT NULL for existing rows to the SAME instant the row already dies
-- on the absolute deadline. Zero live-clock movement for any session in flight
-- when the migration lands.
UPDATE op_sessions SET idle_expires_at = expires_at WHERE idle_expires_at > expires_at;

-- The liveness read is `revoked_at IS NULL AND expires_at > NOW() AND
-- idle_expires_at > NOW()` and answers "load the session by sid" plus every
-- future rotation guard. `expires_at` is already indexed as part of `sid`
-- lookups the `revoked_at IS NULL` partial index above serves, so an
-- additional index on the new column is not warranted at this size.
COMMENT ON COLUMN op_sessions.idle_expires_at IS
    'Sliding idle deadline (BUNYIP-636): the session dies when either this or `expires_at` passes. Rolled forward by any refresh rotation from PR 2 onward; DEFAULT matches the row''s own `expires_at` so a session created before PR 2 lands has no different behaviour.';
