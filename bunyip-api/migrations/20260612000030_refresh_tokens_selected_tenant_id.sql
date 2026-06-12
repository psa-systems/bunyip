-- BUNYIP-63: refresh tokens carry the originally-selected tenant id.
--
-- /authorize (BUNYIP-62) persists `selected_tenant_id` on the auth-code
-- row. When /token consumes that code it mints (a) a fresh
-- refresh_tokens_v2 row, and (b) an at+jwt + id_token that emit the
-- tenant claim. The refresh row needs to carry the tenant_id forward
-- so that on the NEXT /token grant_type=refresh_token exchange we mint
-- the rotated at+jwt + id_token with the same tenant claim - bunyip
-- never re-derives the tenant inside the refresh-token flow because
-- the user is not present to re-pick.
--
-- Nullable for back-compat: clients with NULL `tenant_claim_name` still
-- mint refresh tokens with this column NULL, and the mint path emits
-- no tenant claim. Tenant switching is a fresh /authorize round-trip,
-- not a refresh - by design.

ALTER TABLE refresh_tokens_v2
    ADD COLUMN IF NOT EXISTS selected_tenant_id UUID;

COMMENT ON COLUMN refresh_tokens_v2.selected_tenant_id IS
    'For clients with a non-null oauth_clients.tenant_claim_name, the tenant_id this refresh-token family is bound to. Mirrored from oauth_authorization_codes.selected_tenant_id at exchange time and carried forward through every rotation. NULL means the client emits no tenant claim (legacy behaviour).';
