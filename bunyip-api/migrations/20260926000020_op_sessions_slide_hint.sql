-- BUNYIP-636 PR 2 of 5: record the idle-TTL policy each op_session was
-- created under, so a refresh rotation can slide `idle_expires_at` by the
-- SAME window the session was minted with (a "remember me" session slides
-- by `SESSION_IDLE_TTL_REMEMBER_SECONDS`, an ordinary one by
-- `SESSION_IDLE_TTL_SECONDS`).
--
-- Without this hint, PR 2 would have to either guess the policy from the
-- absolute deadline's width (fragile: the two absolute deadlines are hard
-- constants and moving them would silently reclassify every session that
-- crossed the boundary), or slide every session by the same window (wrong:
-- a remember-me session that stays active would die on the short idle
-- window instead of the long one). Storing the number the row was created
-- with keeps the slide honest across a config change: the row keeps its
-- original policy until the next login re-creates it.
--
-- The column is NOT NULL with a DEFAULT of 28800 (8 h, the non-remember
-- default from `SESSION_IDLE_TTL_SECONDS`); the backfill leaves the value
-- at the DEFAULT for every session created before PR 2, which is the
-- conservative fallback (any of those pre-PR-2 sessions were the fixed
-- 7-day-absolute shape and will die on their absolute deadline sooner
-- than an 8-hour idle would matter in practice).

ALTER TABLE op_sessions
    ADD COLUMN idle_ttl_seconds INT NOT NULL DEFAULT 28800;

COMMENT ON COLUMN op_sessions.idle_ttl_seconds IS
    'BUNYIP-636: the number of seconds `create_op_session` set as the initial idle window for this session, so a refresh rotation slides `idle_expires_at` by the SAME window it was minted with. Not read by any liveness check; only by the slide half of `rotate_refresh_token`.';
