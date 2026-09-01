-- BUNYIP-493: enable switch for the organizations and teams feature.
-- Defaults to false so the feature stays dark everywhere until an admin turns
-- it on, including in the environment the work is being built in.
ALTER TABLE tier_config
    ADD COLUMN orgs_enabled BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN tier_config.orgs_enabled IS
    'Admin switch (Pricing tiers page): when false every organizations and teams route 404s and no nav entry for it is rendered.';
