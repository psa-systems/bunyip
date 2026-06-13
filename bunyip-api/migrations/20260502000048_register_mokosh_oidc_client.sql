-- Register mokosh-server as a confidential OIDC client of Bunyip's OpenID
-- Provider. Bunyip is the issuer; mokosh-server is the relying party that SSOs
-- its users against Bunyip. This mirrors the a8n.tools client-seed pattern.
--
-- The redirect URIs below are dev/staging placeholders following the
-- msp-api.<host> topology. Replace them with mokosh-server's real OAuth2
-- callback before first use, and set the client secret:
--
--   Generate a plaintext secret:  openssl rand -hex 32
--   Hash it (Argon2id m=65536 t=3 p=4, matching PasswordService) and store it
--   in client_secret_hash; put the plaintext in mokosh-server's OIDC_CLIENT_SECRET.
--   Until the hash is set, the confidential token-endpoint auth will reject this
--   client (intentional - no usable secret ships in the repo).
--
-- Additional relying parties (e.g. the mokosh-clients SPA as a public PKCE
-- client) follow this same INSERT shape in their own seed migrations.
--
-- SOFT-DELETED: this registration was never completed (placeholder redirect
-- URIs, NULL client_secret_hash) and was superseded by the real relying-party
-- seeds in 20260603000010_register_mokosh_apps_and_drillmark_oidc_clients.sql
-- (client_ids ...0002 / ...0003). The documented follow-up to finish it never
-- landed, so the row is inserted already-disabled (disabled_at set) to keep it
-- out of the oauth_clients_active partial index and stop it from appearing as
-- an active client. Re-enable by clearing disabled_at and setting a real
-- secret/redirect URIs if mokosh-server is ever onboarded under this id.

INSERT INTO oauth_clients (
    client_id, client_type, name,
    redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, lifecycle_event_uri,
    allowed_scopes, allowed_grant_types,
    token_endpoint_auth_method, require_pkce,
    client_secret_hash,
    audience,
    disabled_at
) VALUES (
    'b0000000-0000-4000-8000-000000000001',
    'confidential',
    'mokosh-server',
    ARRAY[
        'https://msp-api.localhost/oauth2/callback',
        'http://localhost:4501/oauth2/callback'
    ],
    ARRAY[
        'https://msp-api.localhost/',
        'http://localhost:4501/'
    ],
    'https://msp-api.localhost/oauth2/backchannel-logout',
    'https://msp-api.localhost/oauth2/lifecycle-event',
    ARRAY['openid', 'email', 'offline_access'],
    ARRAY['authorization_code', 'refresh_token'],
    'client_secret_basic', TRUE,
    NULL,
    'https://msp-api.localhost/api',
    NOW()
)
ON CONFLICT (client_id) DO NOTHING;
