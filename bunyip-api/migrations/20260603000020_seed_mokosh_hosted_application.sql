-- Seed Mokosh as a HOSTED application so the hub dashboard renders a launcher
-- tile for it. Companion to docs/new-auth/mokosh: with the bunyip-as-OP cutover
-- the hub is where members land after sign-in, and Mokosh (the PSA SPA at
-- msp.<apex>) needs to be reachable from a launcher click.
--
-- Distinct from the catalog rows in 20260602000050 (mokosh-server / mokosh-api
-- / mokosh-www are OCI catalog products, NOT hosted apps - is_hosted = FALSE
-- there). This row is the hub-side launch tile: is_hosted = TRUE, subdomain =
-- 'msp' so dashboard.rs computes app_url = `msp.{base_domain}` (matching the
-- mokosh-apps host on c-01: msp.a8n.systems).
--
-- container_name is required NOT NULL but functionally meaningless for hosted
-- apps that bunyip doesn't run inside its own Compose; reuse the 'mokosh-apps'
-- service name from the docker-repo deploy so a future health-check column
-- can target it. Self-hosters who don't run Mokosh can flip is_active = FALSE.

INSERT INTO applications
    (name, slug, display_name, description, container_name,
     subdomain, is_active, is_hosted, sort_order)
VALUES
    ('mokosh', 'mokosh', 'Mokosh',
     'PSA platform for MSPs: tickets, contracts, time tracking, billing, RMM.',
     'mokosh-apps',
     'msp', TRUE, TRUE, 10)
ON CONFLICT (slug) DO NOTHING;
