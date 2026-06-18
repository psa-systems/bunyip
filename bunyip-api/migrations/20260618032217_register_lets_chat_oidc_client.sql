-- Register lets-chat (chat.a8n.systems) as a confidential OIDC client of
-- bunyip-api. Companion to docs/lets-chat/sso/bunyip-only/02-bunyip-
-- prerequisites.md §2.1 and the lets-chat pure-RP cutover at LC-22.
--
-- Confidential client because lets-chat is a server-side Axum backend
-- (token-endpoint POST is server-to-server, no browser); secret is sent
-- via client_secret_basic and PKCE is still applied on top per bunyip's
-- schema-wide require_pkce.
--
-- Scopes are deliberately narrow: openid + email only. No offline_access
-- (lets-chat's 30-day session cookie covers session length and lets-chat
-- never calls bunyip-api on the user's behalf, so a refresh token has no
-- consumer). access_token_ttl_seconds matches mokosh-apps + drillmark.
--
-- post_logout_redirect_uris is pre-seeded for the v2 RP-initiated logout
-- follow-up; v1 only drops the local session.
--
-- The plaintext client_secret is delivered out-of-band to the operator
-- and lands in lets-chat's `LETS_CHAT_BUNYIP_SSO_CLIENT_SECRET` env var.
-- client_secret_hash below is Argon2id(m=65536, t=3, p=4) of that
-- plaintext.
--
-- client_id slot picks the next free 'c' position to match the
-- pre-existing docs cross-references (the spec quotes ...0000000c).
INSERT INTO oauth_clients (
    client_id,
    client_type,
    name,
    redirect_uris,
    post_logout_redirect_uris,
    allowed_scopes,
    allowed_grant_types,
    token_endpoint_auth_method,
    require_pkce,
    client_secret_hash,
    audience,
    access_token_ttl_seconds
) VALUES (
    'b0000000-0000-4000-8000-00000000000c',
    'confidential',
    'lets-chat-psa',
    ARRAY['https://chat.a8n.systems/auth/bunyip/callback'],
    ARRAY['https://chat.a8n.systems'],
    ARRAY['openid', 'email'],
    ARRAY['authorization_code'],
    'client_secret_basic',
    TRUE,
    '$argon2id$v=19$m=65536,t=3,p=4$gLBGXD23tryNkzHo142zRA$zO6k3LxNcC8xqyO+J844UySGuyfW8xPjNXLnTixoiI4',
    'https://chat.a8n.systems',
    600
)
ON CONFLICT (client_id) DO NOTHING;
