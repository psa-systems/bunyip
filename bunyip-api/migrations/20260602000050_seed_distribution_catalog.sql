-- Distribution catalog: hosted/catalog discriminator + Mokosh product seeds (BUNYIP-33).
--
-- WHAT THIS SEEDS
--   The products bunyip distributes to entitled members, pointing at real
--   artifacts in the private Forgejo registry (psa-systems-private). The
--   pinned versions are the LAUNCH versions; admins maintain the pins through
--   the admin API afterward (this migration never overwrites admin edits:
--   ON CONFLICT (slug) DO NOTHING).
--
-- ENTITLEMENT MODEL (M1)
--   Any user with member access (admin, lifetime, active trial, or
--   active/grace membership) can pull/download every active product.
--   Per-product entitlements are a post-M1 concern (tracked as BUNYIP-39).
--
-- SELF-HOSTER NOTE
--   These rows describe the PSA SaaS catalog. A self-hosted deployment whose
--   FORGEJO_API_TOKEN cannot access psa-systems-private should deactivate or
--   repoint them, e.g.:
--     UPDATE applications SET is_active = FALSE WHERE container_name = 'catalog';
--   The rows are inert (clean denials, no crashes) when the distribution
--   proxy is disabled or the upstream is unreachable.
--
-- HOSTED vs CATALOG
--   Catalog-only products are NOT hosted apps: they must not appear as launch
--   tiles in the application hub. The is_hosted flag added below is the
--   discriminator; the hub lists WHERE is_hosted, while the downloads/OCI
--   surfaces list all active applications. container_name uses the 'catalog'
--   sentinel because the column is NOT NULL but meaningless for catalog rows.

-- Discriminator between hosted apps (hub launch tiles) and catalog-only
-- products (downloads / OCI registry surfaces).
ALTER TABLE applications
    ADD COLUMN is_hosted BOOLEAN NOT NULL DEFAULT TRUE;

-- Plain (non-partial) index: the hub lists WHERE is_hosted, but the downloads
-- and OCI surfaces list catalog rows WHERE NOT is_hosted. A partial index on
-- TRUE only would leave the catalog-side queries unindexed, so index the whole
-- boolean and serve both predicates.
CREATE INDEX idx_applications_is_hosted ON applications(is_hosted);

-- Mokosh Server: the self-hosted PSA platform (OCI image).
INSERT INTO applications
    (name, slug, display_name, description, container_name, is_active, is_hosted,
     oci_image_owner, oci_image_name, pinned_image_tag)
VALUES
    ('mokosh-server', 'mokosh-server', 'Mokosh Server',
     'The Mokosh PSA platform server. Pull and run with Docker Compose; see the deployment guide.',
     'catalog', TRUE, FALSE,
     'psa-systems-private', 'mokosh-server', 'v0.2.0')
ON CONFLICT (slug) DO NOTHING;

-- Mokosh API: the platform API container (OCI image).
INSERT INTO applications
    (name, slug, display_name, description, container_name, is_active, is_hosted,
     oci_image_owner, oci_image_name, pinned_image_tag)
VALUES
    ('mokosh-api', 'mokosh-api', 'Mokosh API',
     'The Mokosh platform API service container.',
     'catalog', TRUE, FALSE,
     'psa-systems-private', 'mokosh-api', 'v0.2.0')
ON CONFLICT (slug) DO NOTHING;

-- Mokosh Web: the platform web frontend container (OCI image).
INSERT INTO applications
    (name, slug, display_name, description, container_name, is_active, is_hosted,
     oci_image_owner, oci_image_name, pinned_image_tag)
VALUES
    ('mokosh-www', 'mokosh-www', 'Mokosh Web',
     'The Mokosh platform web frontend container.',
     'catalog', TRUE, FALSE,
     'psa-systems-private', 'mokosh-www', 'v0.2.0')
ON CONFLICT (slug) DO NOTHING;

-- Vervain Agent: endpoint agent binaries (Forgejo generic package registry).
INSERT INTO applications
    (name, slug, display_name, description, container_name, is_active, is_hosted,
     forgejo_owner, forgejo_package, pinned_release_tag, artifact_source)
VALUES
    ('vervain-agent', 'vervain-agent', 'Vervain Agent',
     'The Vervain endpoint agent. Download the binary for your platform.',
     'catalog', TRUE, FALSE,
     'psa-systems-private', 'vervain-agent', '0.1.0-6-g7ecf9c3', 'generic_package')
ON CONFLICT (slug) DO NOTHING;
