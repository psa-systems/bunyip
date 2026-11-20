-- organizations: Bunyip-side identity layer owning teams of Bunyip users.
-- One organization per owner for v1 (parent BUNYIP-626 settled contract);
-- additive extension to many-per-user is a later migration if the product
-- needs it. Gated at the service layer on tier_config.orgs_enabled (BUNYIP-493)
-- so a flag-off deployment keeps the table empty and every route 404s.

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_bunyip_user_id UUID NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (owner_bunyip_user_id)
);

CREATE INDEX idx_organizations_owner ON organizations (owner_bunyip_user_id);

COMMENT ON TABLE organizations IS
    'Bunyip-side organization owning teams. One per owner (v1).';
COMMENT ON COLUMN organizations.owner_bunyip_user_id IS
    'The Bunyip user that owns this organization; UNIQUE enforces one org per owner.';
