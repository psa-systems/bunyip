-- BUNYIP-325: backfill existing user emails to lowercase. Historically emails
-- were stored verbatim, so a mixed-case signup ("Nice.Guy@Example.COM") landed
-- a mixed-case row. Lookups have always compared with LOWER(email), so login
-- still worked, but the stored address (and the address outbound verification /
-- welcome mail is sent to, and the OIDC email claim) diverged in case from what
-- case-sensitive downstream consumers (e.g. the mokosh Next.js auth store)
-- expect, so the verification mail was never reconciled and the account stayed
-- stuck unverified.
--
-- Going forward normalize_email() lowercases at the two write paths
-- (UserRepository::create / update_email); this one-shot backfill fixes the rows
-- written before that.
--
-- Collision-safe: the BUNYIP-330 index users_email_unique is already
-- CREATE UNIQUE INDEX ... ON users (LOWER(email)), so no two rows (active OR
-- soft-deleted) can already share a lowercased email; lowercasing therefore
-- cannot violate uniqueness. Idempotent: the WHERE guard touches only rows that
-- are not already lowercase, so a re-run is a no-op.
UPDATE users
SET email = LOWER(email)
WHERE email <> LOWER(email);
