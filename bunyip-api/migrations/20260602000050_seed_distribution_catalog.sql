-- Seed the Mokosh product distribution catalog (BUNYIP-33).
--
-- These are the products bunyip distributes to entitled members, pointing at
-- real artifacts in the private Forgejo registry (psa-systems-private).
-- Idempotent: ON CONFLICT (slug) DO NOTHING, so operator edits made through
-- the admin API are never overwritten by re-running migrations.
--
-- Entitlement model (M1): any user with member access (admin, lifetime,
-- active trial, or active/grace membership) can pull/download every active
-- product. Per-product entitlements are a post-M1 concern.
--
-- container_name is required-but-unused for catalog-only products ('catalog'
-- sentinel): these rows exist for distribution, not for the hosted-app
-- health/maintenance machinery.

-- Mokosh Server: the self-hosted PSA platform (OCI image).
INSERT INTO applications
    (name, slug, display_name, description, container_name, is_active,
     oci_image_owner, oci_image_name, pinned_image_tag)
VALUES
    ('mokosh-server', 'mokosh-server', 'Mokosh Server',
     'The Mokosh PSA platform server. Pull and run with Docker Compose; see the deployment guide.',
     'catalog', TRUE,
     'psa-systems-private', 'mokosh-server', 'v0.2.0')
ON CONFLICT (slug) DO NOTHING;

-- Mokosh API: the platform API container (OCI image).
INSERT INTO applications
    (name, slug, display_name, description, container_name, is_active,
     oci_image_owner, oci_image_name, pinned_image_tag)
VALUES
    ('mokosh-api', 'mokosh-api', 'Mokosh API',
     'The Mokosh platform API service container.',
     'catalog', TRUE,
     'psa-systems-private', 'mokosh-api', 'v0.2.0')
ON CONFLICT (slug) DO NOTHING;

-- Mokosh Web: the platform web frontend container (OCI image).
INSERT INTO applications
    (name, slug, display_name, description, container_name, is_active,
     oci_image_owner, oci_image_name, pinned_image_tag)
VALUES
    ('mokosh-www', 'mokosh-www', 'Mokosh Web',
     'The Mokosh platform web frontend container.',
     'catalog', TRUE,
     'psa-systems-private', 'mokosh-www', 'v0.2.0')
ON CONFLICT (slug) DO NOTHING;

-- Vervain Agent: endpoint agent binaries (Forgejo generic package registry).
INSERT INTO applications
    (name, slug, display_name, description, container_name, is_active,
     forgejo_owner, forgejo_package, pinned_release_tag, artifact_source)
VALUES
    ('vervain-agent', 'vervain-agent', 'Vervain Agent',
     'The Vervain endpoint agent. Download the binary for your platform.',
     'catalog', TRUE,
     'psa-systems-private', 'vervain-agent', '0.1.0-6-g7ecf9c3', 'generic_package')
ON CONFLICT (slug) DO NOTHING;
