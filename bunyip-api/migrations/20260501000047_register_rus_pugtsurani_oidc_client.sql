-- Register RUS (rust URL shortener) for the pugtsurani staging instance.
-- Separate client from the a8n.run instance because the audience differs.
-- Plaintext secret lives in docker/server/hc-01/a8n-tools-go/compose-secrets.yml.
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
    'a8000000-0000-0000-0000-000000000008',
    'confidential',
    'rus-pugtsurani-bff',
    ARRAY[
        'https://go.pugtsurani.net/oauth2/callback'
    ],
    ARRAY[
        'https://go.pugtsurani.net/'
    ],
    'https://go.pugtsurani.net/oauth2/backchannel-logout',
    'https://go.pugtsurani.net/oauth2/lifecycle-event',
    ARRAY['openid', 'email', 'offline_access'],
    ARRAY['authorization_code', 'refresh_token'],
    'client_secret_basic', TRUE,
    '$argon2id$v=19$m=65536,t=3,p=4$TPe2kWZtwWFdjuBofuBjnQ$9LDMlCibq3d03FzTfbLvbZAz7kFJezTjUDjTH1jcxgo',
    'https://go.pugtsurani.net/api'
)
ON CONFLICT (client_id) DO NOTHING;
