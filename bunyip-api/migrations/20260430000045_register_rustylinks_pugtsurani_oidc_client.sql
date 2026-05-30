-- Register rusty-links (links.pugtsurani.net) as a confidential OIDC client.
-- This is a separate client from the a8n.run instance because the audience differs.
-- Secret generated with: python3 -c "import secrets; print(secrets.token_hex(32))"
-- Hash generated with argon2id m=65536, t=3, p=4 (matches PasswordService parameters).
INSERT INTO oauth_clients (
    client_id, client_type, name,
    redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, lifecycle_event_uri,
    allowed_scopes, allowed_grant_types,
    token_endpoint_auth_method, require_pkce,
    client_secret_hash,
    audience
) VALUES (
    'a8000000-0000-0000-0000-000000000006',
    'confidential',
    'rustylinks-pugtsurani-bff',
    ARRAY[
        'https://links.pugtsurani.net/oauth2/callback'
    ],
    ARRAY[
        'https://links.pugtsurani.net/'
    ],
    'https://links.pugtsurani.net/oauth2/backchannel-logout',
    'https://links.pugtsurani.net/oauth2/lifecycle-event',
    ARRAY['openid', 'email', 'offline_access'],
    ARRAY['authorization_code', 'refresh_token'],
    'client_secret_basic', TRUE,
    '$argon2id$v=19$m=65536,t=3,p=4$GWFql9ifzZ1mAytmAkaZ8g$L67YbzKFAgTDb8cC29yCmUr0xjdPh70WEQIhipnEkKU',
    'https://links.pugtsurani.net/api'
)
ON CONFLICT (client_id) DO NOTHING;
