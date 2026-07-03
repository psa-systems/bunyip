-- BUNYIP-330: soft-deleted emails are permanently reserved. Replace the
-- partial `users_email_unique_active` (which only enforced uniqueness among
-- non-deleted rows so a deleted account's email could be re-registered) with
-- a plain case-insensitive UNIQUE index that spans active + soft-deleted
-- rows. Combined with the service-layer swap from `email_exists`/`find_by_email`
-- to `email_reserved` on the register / magic-link-signup / email-change /
-- invite-accept paths, this locks a deleted user's email out of every future
-- signup surface with a DB-level guarantee in addition to the application
-- check.

-- Rename any pre-existing lower-case collisions before creating the strict
-- index (a deleted-then-re-registered pair, still allowed under the old
-- partial index, would fail the CREATE UNIQUE INDEX below). The rename
-- suffixes each duplicate with its uuid so the new value is guaranteed
-- unique; the earliest-created row keeps the original email. In practice
-- production is expected to have zero collisions, since this pattern was
-- only exercisable via the flow BUNYIP-330 is closing.
WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (PARTITION BY LOWER(email) ORDER BY created_at) AS rn
    FROM users
)
UPDATE users
SET email = email || '.dup-' || id::text
WHERE id IN (SELECT id FROM ranked WHERE rn > 1);

DROP INDEX IF EXISTS users_email_unique_active;

CREATE UNIQUE INDEX users_email_unique ON users (LOWER(email));
