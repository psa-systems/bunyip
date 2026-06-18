-- BUNYIP-140 (slice B of BUNYIP-103): add `profile` and `phone` to the
-- allowed_scopes set for the three relying parties seeded so far. Future
-- RPs declare these in their own seeds.
--
-- ARRAY append + ON CONFLICT not needed: we only add to existing rows.
-- The `array_append` chain is idempotent because of the `NOT (... && ...)`
-- guard (no-op if both scopes are already present).
UPDATE oauth_clients
SET allowed_scopes = array_append(array_append(allowed_scopes, 'profile'), 'phone')
WHERE client_id IN (
    'b0000000-0000-4000-8000-000000000002'::uuid,  -- mokosh-apps
    'b0000000-0000-4000-8000-000000000003'::uuid,  -- drillmark
    'b0000000-0000-4000-8000-00000000000c'::uuid   -- lets-chat-psa
)
AND NOT (allowed_scopes @> ARRAY['profile', 'phone']);
