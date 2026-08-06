-- BUNYIP-487: publish switch for the public /pricing page.
-- Defaults to false so an unconfigured deployment does not publish pricing.
ALTER TABLE tier_config
    ADD COLUMN pricing_enabled BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN tier_config.pricing_enabled IS
    'Admin switch (Pricing tiers page): when false the public /pricing page 404s and every link to it is hidden.';
