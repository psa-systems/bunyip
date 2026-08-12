-- BUNYIP-527: per-tier visibility on the public /pricing page. Each mapped tier
-- can be shown or hidden independently, underneath the global pricing_enabled
-- switch. NOT NULL with a `true` default, so every existing mapped tier keeps
-- showing until an admin hides it.
ALTER TABLE tier_config
    ADD COLUMN IF NOT EXISTS lifetime_visible      boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS early_adopter_visible boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS standard_visible      boolean NOT NULL DEFAULT true;
