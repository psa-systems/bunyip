-- BUNYIP-62: persist the user's selected tenant on the auth-code row.
--
-- The /authorize handler (this PR) gates on `oauth_client_user_tenants`
-- when the client's `tenant_claim_name` is non-null. When the user has
-- exactly one assignment we auto-select; when they have more than one
-- we render a picker and persist the choice here. /token (BUNYIP-63)
-- reads this column when minting at+jwt and id_token so the tenant
-- claim emitted matches the user's pick.
--
-- Nullable because (a) existing seeded clients still have
-- tenant_claim_name = NULL and never select anything, and (b) the
-- column needs to be set in two passes for picker rounds (insert at
-- code creation, UPDATE after picker submit) when the picker UI was
-- not yet integrated into the initial auth code creation. v1 sets it
-- in one shot in both branches; the column shape stays nullable for
-- back-compat.

ALTER TABLE oauth_authorization_codes
    ADD COLUMN IF NOT EXISTS selected_tenant_id UUID;

COMMENT ON COLUMN oauth_authorization_codes.selected_tenant_id IS
    'For clients with a non-null oauth_clients.tenant_claim_name, the tenant_id the user chose (auto-selected if they had exactly one assignment, picker-chosen if multiple). /token reads this and emits the tenant claim on the at+jwt + id_token. NULL means the client does not enforce tenant assignments.';
