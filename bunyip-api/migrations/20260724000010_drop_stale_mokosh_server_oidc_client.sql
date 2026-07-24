-- Drop the stale mokosh-server confidential OIDC client registration.
--
-- 20260502000048_register_mokosh_oidc_client.sql registered mokosh-server
-- (client_id b0000000-0000-4000-8000-000000000001) as a confidential client
-- back when it was planned to run its own browser flow. The bunyip-as-OP
-- cutover made mokosh-server a Resource Server only, so that row is unused; it
-- was left in place as a soft-delete (disabled_at set) for one release. This is
-- the documented follow-up (noted in 20260603000010 and
-- docs/new-auth/mokosh/03-mokosh-server-rs-cutover.md section 3.5) that drops it.
--
-- The real relying-party seeds (mokosh-apps ...0002, drillmark ...0003) in
-- 20260603000010 are unaffected. Idempotent: a DELETE of an absent row is a
-- no-op, so this is safe on any database regardless of the soft-deleted row's
-- current state.

DELETE FROM oauth_clients
WHERE client_id = 'b0000000-0000-4000-8000-000000000001';
