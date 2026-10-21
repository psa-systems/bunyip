-- BUNYIP-933: rate-limit whitelist.
--
-- Admins add a (kind, value) pair to this table. The rate limiter checks
-- the pair against the current request's resolved principal before it
-- increments any counter; a match short-circuits to Allow without touching
-- rate_limits.
--
-- `kind` is one of `user`, `email`, `ip`. The rate-limit key the limiter
-- builds encodes one of these three forms (`email:foo@bar.com`,
-- `ip:1.2.3.4`, `user:<uuid>`), so a whitelist row names what to match in
-- the same vocabulary.
--
-- `reason` is a free-text note (why this principal is exempt) rendered
-- next to the row in the admin UI so a drive-by admin can see WHY the
-- rule was added before deciding to remove it.
--
-- `added_by` references the admin user id that created the row; a NULL
-- means the admin was deleted since.

CREATE TABLE IF NOT EXISTS rate_limit_whitelist (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK (kind IN ('user', 'email', 'ip')),
    value text NOT NULL,
    reason text NOT NULL DEFAULT '',
    added_by uuid REFERENCES users(id) ON DELETE SET NULL,
    added_at timestamptz NOT NULL DEFAULT NOW()
);

-- One row per (kind, value): adding the same (ip, 1.2.3.4) twice from the
-- admin UI is a no-op, not a quiet duplicate.
CREATE UNIQUE INDEX IF NOT EXISTS rate_limit_whitelist_kind_value_uq
    ON rate_limit_whitelist (kind, value);

-- The limiter looks up by key prefix (`email:` / `ip:` / `user:`) plus the
-- value exactly, so a composite index on both columns stays index-covered
-- without a seq scan.
CREATE INDEX IF NOT EXISTS rate_limit_whitelist_lookup_idx
    ON rate_limit_whitelist (kind, value);
