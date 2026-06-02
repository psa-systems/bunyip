-- Register the browser SPAs that consume bunyip-api as their OIDC issuer.
-- Both are PUBLIC PKCE clients (no client_secret, S256 challenge required).
-- Companion to docs/new-auth/mokosh/02-bunyip-prerequisites.md §2.2.
--
-- Audience is intentionally the Resource Server's URL (not the SPA's host),
-- so the at+jwt minted for each client carries an `aud` that the RS can pin
-- and verify against its own canonical host.
--
-- The older 20260502000048_register_mokosh_oidc_client.sql row registered
-- mokosh-server itself as a confidential client back when mokosh-server was
-- planned to do its own browser flow. After this cutover mokosh-server is a
-- Resource Server only and that row is unused; leave it in place for one
-- release as a soft-delete, drop it (and the schema) in a follow-up migration
-- per docs/new-auth/mokosh/03-mokosh-server-rs-cutover.md §3.5.

INSERT INTO oauth_clients (
    client_id, client_type, name,
    redirect_uris, post_logout_redirect_uris,
    allowed_scopes, allowed_grant_types,
    token_endpoint_auth_method, require_pkce,
    audience, access_token_ttl_seconds
) VALUES (
    'b0000000-0000-4000-8000-000000000002',
    'public',
    'mokosh-apps',
    ARRAY['https://msp.a8n.systems/auth/callback'],
    ARRAY['https://msp.a8n.systems'],
    ARRAY['openid', 'email', 'offline_access'],
    ARRAY['authorization_code', 'refresh_token'],
    'none', TRUE,
    'https://api.msp.a8n.systems',
    600
)
ON CONFLICT (client_id) DO NOTHING;

INSERT INTO oauth_clients (
    client_id, client_type, name,
    redirect_uris, post_logout_redirect_uris,
    allowed_scopes, allowed_grant_types,
    token_endpoint_auth_method, require_pkce,
    audience, access_token_ttl_seconds
) VALUES (
    'b0000000-0000-4000-8000-000000000003',
    'public',
    'drillmark',
    ARRAY['https://drillmark.a8n.systems/auth/callback'],
    ARRAY['https://drillmark.a8n.systems'],
    ARRAY['openid', 'email', 'offline_access'],
    ARRAY['authorization_code', 'refresh_token'],
    'none', TRUE,
    'https://api.drillmark.a8n.systems',
    600
)
ON CONFLICT (client_id) DO NOTHING;
