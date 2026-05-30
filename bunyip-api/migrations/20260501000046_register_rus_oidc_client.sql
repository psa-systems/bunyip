-- Register RUS (rust URL shortener) as a confidential OIDC client.
-- Per-developer redirect URIs are listed below; add yours when onboarding.
-- The plaintext secret is stored in the rus repo's .env.saas as OIDC_CLIENT_SECRET.
--
-- Generate a fresh plaintext secret with: openssl rand -hex 32
-- Then hash it (Argon2id m=65536 t=3 p=4, matching PasswordService) with:
--   python3 -c "from argon2 import PasswordHasher, Type; print(PasswordHasher(type=Type.ID, memory_cost=65536, time_cost=3, parallelism=4).hash('<secret>'))"

INSERT INTO oauth_clients (
    client_id, client_type, name,
    redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, lifecycle_event_uri,
    allowed_scopes, allowed_grant_types,
    token_endpoint_auth_method, require_pkce,
    client_secret_hash,
    audience
) VALUES (
    'a8000000-0000-0000-0000-000000000007',
    'confidential',
    'rus-web-bff',
    ARRAY[
        'https://a contributor-rus.a8n.run/oauth2/callback',
        'http://localhost:4001/oauth2/callback'
    ],
    ARRAY[
        'https://a contributor-rus.a8n.run/',
        'http://localhost:4001/'
    ],
    'https://a contributor-rus.a8n.run/oauth2/backchannel-logout',
    'https://a contributor-rus.a8n.run/oauth2/lifecycle-event',
    ARRAY['openid', 'email', 'offline_access'],
    ARRAY['authorization_code', 'refresh_token'],
    'client_secret_basic', TRUE,
    '$argon2id$v=19$m=65536,t=3,p=4$xkTYbS5tLxQYqS4xoXi/EQ$4glJuJ18G2aMNXKWQy26f4x25I+nko2I10U4rvc+sKQ',
    'https://a contributor-rus.a8n.run/api'
)
ON CONFLICT (client_id) DO NOTHING;
