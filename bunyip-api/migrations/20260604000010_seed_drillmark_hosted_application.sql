-- Seed Drillmark as a HOSTED application so the hub dashboard renders a
-- launcher tile for it. Companion to docs/new-auth/drillmark in the docs repo,
-- and the second-product mirror of 20260603000020_seed_mokosh_hosted_application.sql.
--
-- subdomain = 'drillmark' so dashboard.rs computes app_url =
-- `drillmark.{base_domain}` -> https://drillmark.a8n.systems/dashboard on c-01
-- (the /dashboard suffix is appended by the launcher tile template).
--
-- container_name is required NOT NULL but functionally meaningless for hosted
-- apps that bunyip doesn't run inside its own Compose; reuse the docker-repo
-- service name so a future health-check column can target it.
--
-- sort_order = 20 puts Drillmark after Mokosh (10) in the hub grid. Self-hosters
-- who don't run Drillmark can flip is_active = FALSE.

INSERT INTO applications
    (name, slug, display_name, description, container_name,
     subdomain, is_active, is_hosted, sort_order)
VALUES
    ('drillmark', 'drillmark', 'Drillmark',
     'DMARC report aggregation, parsing, and forensics for MSPs.',
     'dmarc-reporter-frontend',
     'drillmark', TRUE, TRUE, 20)
ON CONFLICT (slug) DO NOTHING;
