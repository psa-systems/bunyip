-- BUNYIP-692 [BUNYIP-626 followup]: global org-tier pricing catalogue.
--
-- Admin edits a set of org tiers on the Pricing page (name, per-seat Stripe
-- price, included seats, cap, visibility). Every org picks one through the
-- BUNYIP-691 admin surface. The seat-based subscription that bills against
-- these prices is BUNYIP-693 (separate migration on `organizations`).
--
-- Separate table from the existing per-user `pricing` because the two shapes
-- carry different columns: `included_seats` / `seat_cap` here have no user
-- analogue, and user tiers carry `annual_price_id` that has no org analogue.
-- One table with a `kind` column would grow nullable columns per kind and
-- every reader would have to branch on `kind`.
--
-- Gated on `tier_config.orgs_enabled` (BUNYIP-493) at the service and
-- route layers, not on the migration: an empty catalogue costs less than a
-- rollout coordination between this migration and the flag flip.
CREATE TABLE org_pricing_tiers (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT        NOT NULL,
    stripe_price_id  TEXT        NOT NULL,
    included_seats   INT         NOT NULL DEFAULT 0,
    seat_cap         INT,
    visibility       TEXT        NOT NULL DEFAULT 'public',
    sort_order       INT         NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (stripe_price_id),
    CHECK (visibility IN ('public', 'hidden')),
    CHECK (included_seats >= 0),
    CHECK (seat_cap IS NULL OR seat_cap >= included_seats)
);

CREATE INDEX org_pricing_tiers_sort_order_idx ON org_pricing_tiers (sort_order);

COMMENT ON TABLE org_pricing_tiers IS
    'BUNYIP-692: admin-editable catalogue of org tiers. Every org picks one; the seat-based subscription in BUNYIP-693 bills against stripe_price_id.';
COMMENT ON COLUMN org_pricing_tiers.stripe_price_id IS
    'The $/seat/month Stripe price the seat-based subscription bills against. UNIQUE so two rows cannot bill against the same Stripe price.';
COMMENT ON COLUMN org_pricing_tiers.included_seats IS
    'Seats included in the base fee; usage above bills through stripe_price_id per seat.';
COMMENT ON COLUMN org_pricing_tiers.seat_cap IS
    'Upper bound on seats. NULL means unlimited (mirrors how user tiers treat NULL).';
COMMENT ON COLUMN org_pricing_tiers.visibility IS
    'public means the public catalogue lists it; hidden means an admin can still assign it to an existing org but new signups do not see it.';

-- Per-org tier assignment (BUNYIP-672's organizations table). NULL means the
-- owner has not picked a tier yet, which is also the state a brand-new org
-- lands in; the seat-based subscription in BUNYIP-693 refuses to subscribe
-- against a NULL org_tier_id.
ALTER TABLE organizations
    ADD COLUMN org_tier_id UUID REFERENCES org_pricing_tiers(id);

COMMENT ON COLUMN organizations.org_tier_id IS
    'BUNYIP-692: the org_pricing_tiers row the owner picked. NULL when no tier is chosen yet; BUNYIP-693 subscription refuses NULL.';
