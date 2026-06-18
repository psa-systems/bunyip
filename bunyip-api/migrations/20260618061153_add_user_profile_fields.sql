-- BUNYIP-139 (slice A of BUNYIP-103): add nullable first_name + last_name +
-- phone columns to users. Slice B (BUNYIP-140) is what wires these into the
-- OIDC `profile` + `phone` scope claims; this migration is storage-only and
-- ships independently of the consent / claim work.
--
-- All three columns nullable; legacy rows have nothing to back-fill from
-- (email local-parts make poor names, e.g. "joe.smith" -> "Joe.Smith").
-- A user fills the columns from the Settings page; mokosh-apps' existing
-- /onboarding/profile screen continues to catch new users until slice C
-- swings the JIT path over to the at+jwt claims.
--
-- Per-column CHECK (length <= 64) so a pathological string can't blow up
-- render paths downstream. 64 chars covers every real-world name + phone
-- format (longest documented surname is ~33 chars, longest E.164 phone is
-- 15 chars plus optional formatting).
ALTER TABLE users
    ADD COLUMN first_name TEXT CHECK (first_name IS NULL OR length(first_name) <= 64),
    ADD COLUMN last_name  TEXT CHECK (last_name  IS NULL OR length(last_name)  <= 64),
    ADD COLUMN phone      TEXT CHECK (phone      IS NULL OR length(phone)      <= 64);
