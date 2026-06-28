-- BUNYIP-140: retroactively strip `profile` and `phone` from any existing
-- `user_application_access.granted_scopes` array so existing users re-
-- consent the first time an RP asks for those scopes after deploy.
--
-- Without this strip, the prior JIT path (`grant_entitlement(user, client,
-- client.allowed_scopes)`) would have copied the new `profile` / `phone`
-- entries into every existing grant row the moment the previous migration
-- ran, defeating the consent posture for every pre-existing user.
--
-- The subquery `array(SELECT unnest(...) EXCEPT SELECT unnest(...))` removes
-- the two scopes if present and is a no-op if absent. PostgreSQL preserves
-- nothing about array order here, which is fine: the OIDC scope comparison
-- treats granted_scopes as a set.
UPDATE user_application_access
SET granted_scopes = ARRAY(
    SELECT unnest(granted_scopes)
    EXCEPT
    SELECT unnest(ARRAY['profile', 'phone'])
)
WHERE granted_scopes && ARRAY['profile', 'phone'];
