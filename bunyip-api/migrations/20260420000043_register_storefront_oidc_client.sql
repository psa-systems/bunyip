-- Register the storefront CMS as a confidential OIDC client.
-- The client_secret_hash must be updated with a real Argon2id hash before deploying.
-- Generate the plaintext secret with: openssl rand -hex 32
-- Then hash it and store it here: argon2-hash <secret>
-- The plaintext secret goes into OIDC_CLIENT_SECRET in the storefront environment.

INSERT INTO oauth_clients (
    client_id, client_type, name,
    redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, lifecycle_event_uri,
    allowed_scopes, allowed_grant_types,
    token_endpoint_auth_method, require_pkce,
    client_secret_hash,
    audience
) VALUES (
    'a8000000-0000-0000-0000-000000000004',
    'confidential',
    'storefront-web-bff',
    ARRAY[
        'https://storefront.a8n.run/oauth2/callback',
        'http://localhost:4020/oauth2/callback'
    ],
    ARRAY[
        'https://storefront.a8n.run/',
        'http://localhost:4020/'
    ],
    'https://storefront.a8n.run/oauth2/backchannel-logout',
    'https://storefront.a8n.run/oauth2/lifecycle-event',
    ARRAY['openid', 'email', 'offline_access'],
    ARRAY['authorization_code', 'refresh_token'],
    'client_secret_basic', TRUE,
    NULL,
    'https://storefront.a8n.run/api'
)
ON CONFLICT (client_id) DO NOTHING;
