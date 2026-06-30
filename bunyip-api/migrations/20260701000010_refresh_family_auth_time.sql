-- BUNYIP-262: persist `auth_time` on `refresh_token_families` so a
-- rotated at+jwt carries the authentication time of the ORIGINAL login,
-- not the time of the most recent refresh.
--
-- The previous behaviour reset `auth_time = Utc::now()` at every
-- rotation, which violates OIDC Core §2 ("the time when the End-User
-- authentication occurred"). A stale family that's been refreshed every
-- hour for a year appeared "freshly authenticated" to any RP doing
-- step-up auth on auth_time, defeating risk-based session rules. The
-- audit named this medium-severity.
--
-- The new column lands on the family (not on each refresh_tokens_v2
-- row) because auth_time is a per-session invariant: it never changes
-- across rotations within the same login.
--
-- Existing rows are backfilled with NOW(): we cannot recover the
-- original auth_time, but stamping the migration time is more correct
-- than the rotation time (the family at least existed at NOW() by
-- definition) and the next rotation reads this value instead of
-- Utc::now() so the lie stops growing.

ALTER TABLE refresh_token_families
    ADD COLUMN auth_time TIMESTAMPTZ NOT NULL DEFAULT NOW();
