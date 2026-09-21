-- BUNYIP-780: the original column comment on oauth_clients.allowed_grant_types
-- (20260417000040_create_oidc_clients.sql) undercounts the legal values as
-- "Subset of { authorization_code, refresh_token }". client_credentials is a
-- third legal value (crates/bunyip-oidc/src/services/oidc_provider.rs), used
-- by the machine-client path (crates/bunyip-oidc/src/machine_client.rs,
-- bunyip-api/src/machine_client.rs). The migration that introduced the wrong
-- comment is already applied and immutable, so this corrects it in place
-- rather than editing that file.
COMMENT ON COLUMN oauth_clients.allowed_grant_types IS
    'Subset of { authorization_code, refresh_token, client_credentials }.';
