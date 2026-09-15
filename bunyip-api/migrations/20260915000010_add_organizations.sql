-- BUNYIP-672 [BUNYIP-626 child 1]: an organization owned by a Bunyip user.
--
-- The organization is the identity layer above per-user Mokosh accounts;
-- teams (next migration) live under it, and cross-account grants
-- (BUNYIP-673) will point at rows in this table. v1 is one org per user by
-- construction (`UNIQUE(owner_bunyip_user_id)`), which is the parent epic's
-- settled contract; a later migration relaxes that when the product asks.
--
-- The whole surface is gated on `tier_config.orgs_enabled` (BUNYIP-493).
-- This migration lands the schema regardless of the flag - a table nobody
-- reads costs less than a rollout coordination between the migration and
-- the flag flip.
CREATE TABLE organizations (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_bunyip_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                 TEXT        NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (owner_bunyip_user_id)
);

COMMENT ON TABLE organizations IS
    'BUNYIP-672: the identity layer above per-user Mokosh accounts. One row per owning Bunyip user (v1); cross-account grants (BUNYIP-673) will reference these rows.';
COMMENT ON COLUMN organizations.owner_bunyip_user_id IS
    'The Bunyip user who owns and administers this organization. UNIQUE per user is the v1 contract; relax when the product asks.';
