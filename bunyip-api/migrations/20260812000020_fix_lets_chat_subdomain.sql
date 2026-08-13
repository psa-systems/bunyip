-- BUNYIP-533: the footer / hub "Let's Chat" launch link resolved to
-- https://lets-chat.{app_domain} because the lets-chat application row had no
-- subdomain set, so bunyip-web's `app_link()` fell back to the slug
-- ("lets-chat"). The product is served at the "chat" subdomain
-- (chat.a8n.systems on staging, chat.spa.systems on production - the domain half
-- comes from BUNYIP_APP_DOMAIN, so one subdomain value is correct for every
-- environment). Set the subdomain to "chat" so the link resolves to
-- https://chat.{app_domain}.
--
-- Targeted UPDATE, not a seed: the lets-chat application row is admin-created on
-- real deployments (migration 20241230000017 deliberately left subdomains to the
-- admin API), so a fresh database that has no such row simply matches nothing.
-- The guard only touches the states that produce the wrong link (unset, empty,
-- or the slug echoed back as the subdomain), so a deliberate admin override is
-- left alone. Idempotent: re-running lands on the same value. Companion to the
-- OIDC-client registration in 20260618032217_register_lets_chat_oidc_client.sql,
-- whose header already names chat.a8n.systems as the canonical host.

UPDATE applications
SET subdomain = 'chat'
WHERE slug = 'lets-chat'
  AND (subdomain IS NULL OR subdomain = '' OR subdomain = 'lets-chat');
