-- BUNYIP-248: oauth_authorization_codes.user_id referenced users(id) WITHOUT a
-- cascade (migration 20260417000041), so hard-deleting a user FK-blocked once
-- the user had a pending authorization code. A pending code is the user's own
-- ephemeral OIDC artifact, so it should disappear with the user. Recreate the FK
-- as ON DELETE CASCADE.
--
-- The hard-delete path is non-production only (the e2e ?purge flag, the
-- disposable reaper, bunyip-e2e-bootstrap); production never hard-deletes a user
-- (DELETE /v1/users/me soft-deletes), so the CASCADE never fires there and this
-- is a behavior-preserving change for production.
--
-- The constraint name is Postgres's default for an inline FK on
-- oauth_authorization_codes(user_id). DROP ... IF EXISTS keeps the migration
-- idempotent if it is ever re-applied against a recreated table.
ALTER TABLE oauth_authorization_codes
    DROP CONSTRAINT IF EXISTS oauth_authorization_codes_user_id_fkey;

ALTER TABLE oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
