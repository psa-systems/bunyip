-- BUNYIP-1042: the earlier BUNYIP-636 PR 1 migration
-- (`20260926000010_op_sessions_idle_deadline.sql`) carried a COMMENT ON COLUMN
-- claiming the DEFAULT matches the row's own `expires_at`, while the column
-- DEFAULT is literally `NOW() + INTERVAL '7 days'`. The migration's own UPDATE
-- immediately after the ADD COLUMN backfilled existing rows to `expires_at` so
-- live rows at migration time were in fact aligned, but any subsequent INSERT
-- that omits `idle_expires_at` picks up the 7-day literal, which diverges from
-- `expires_at` when the caller computed that differently (e.g. the
-- "remember me" paths from BUNYIP-636 PR 2).
--
-- Migrations are immutable (CLAUDE.md invariants build-ci.md), so this is a
-- fix-forward: restate the COMMENT to describe what the column actually is.
-- The DEFAULT itself is kept: PR 2's code sets both deadlines explicitly on
-- every write, so the literal is only load-bearing for the ADD COLUMN moment,
-- which has already passed.

COMMENT ON COLUMN op_sessions.idle_expires_at IS
    'Sliding idle deadline (BUNYIP-636): the session dies when either this or `expires_at` passes. Written explicitly by code paths from BUNYIP-636 PR 2 onward (both the login and the refresh-rotation path set it). The column DEFAULT is `NOW() + INTERVAL ''7 days''`, which only applied during the original ADD COLUMN; existing rows were immediately backfilled to `expires_at` by the same migration, and later rows carry an explicit value, so the literal does not reach live traffic. (BUNYIP-1042 doc correction.)';
