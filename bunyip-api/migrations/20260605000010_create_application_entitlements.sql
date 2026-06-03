-- Per-product entitlements (BUNYIP-39).
--
-- M1 shipped a single-plan model: any member (admin, lifetime, active trial,
-- or active/grace membership) could pull and download EVERY active product.
-- This migration adds per-product access control on top of that membership
-- gate, without changing the default behaviour of any existing product.
--
-- Model (chosen in BUNYIP-39):
--   access(user, app) = user.is_access_allowed()                      -- membership gate
--                       AND ( NOT app.requires_entitlement            -- product is open, OR
--                             OR user is admin                        -- admins bypass, OR
--                             OR an active entitlement row exists )    -- explicitly granted
-- A product with requires_entitlement = FALSE behaves exactly as before
-- (open to every member). Flip the flag to TRUE to sell it as a tiered add-on.

-- 1. Per-product opt-in flag. Defaults FALSE so every existing product stays
--    open to all members; no behaviour change on deploy.
ALTER TABLE applications
    ADD COLUMN requires_entitlement BOOLEAN NOT NULL DEFAULT FALSE;

-- 2. The entitlement grants themselves. One row per (user, product); revoked
--    grants are kept (revoked_at set) for audit rather than deleted.
CREATE TABLE application_entitlements (
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    application_id UUID        NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    granted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL for system-issued grants (Stripe webhook, backfill); the admin's
    -- user id for manually granted entitlements.
    granted_by     UUID        REFERENCES users(id) ON DELETE SET NULL,
    -- Provenance so a Stripe-driven revoke never clobbers an admin grant and
    -- vice versa: 'admin' | 'stripe' | 'backfill'.
    source         TEXT        NOT NULL,
    -- NULL = active. Set on revoke; a later grant clears it (UPSERT below).
    revoked_at     TIMESTAMPTZ,
    PRIMARY KEY (user_id, application_id)
);

-- Hot path: "does this user have an active entitlement for this product".
CREATE INDEX idx_application_entitlements_active
    ON application_entitlements (user_id, application_id)
    WHERE revoked_at IS NULL;

-- Reverse lookup for the admin "who can access product X" view.
CREATE INDEX idx_application_entitlements_by_app
    ON application_entitlements (application_id)
    WHERE revoked_at IS NULL;

-- 3. Stripe price -> product mapping. A subscription carrying one of these
--    price ids grants (on the webhook) entitlements to the mapped products.
--    Many-to-many: a bundle price maps to several products; a product can be
--    sold under several prices.
CREATE TABLE stripe_price_entitlements (
    stripe_price_id TEXT        NOT NULL,
    application_id  UUID        NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (stripe_price_id, application_id)
);

CREATE INDEX idx_stripe_price_entitlements_by_price
    ON stripe_price_entitlements (stripe_price_id);

-- 4. Preserve current access (BUNYIP-39 decision): snapshot every member who
--    has access today and grant them every currently-active product, so that
--    flipping a product to requires_entitlement = TRUE later does not
--    retroactively cut off existing members. The predicate mirrors
--    User::is_access_allowed() exactly. Admins are intentionally skipped: they
--    bypass the entitlement check in code, so a row would be noise.
INSERT INTO application_entitlements (user_id, application_id, granted_by, source)
SELECT u.id, a.id, NULL, 'backfill'
FROM users u
CROSS JOIN applications a
WHERE a.is_active = TRUE
  AND u.deleted_at IS NULL
  AND u.role <> 'admin'
  AND (
        u.lifetime_member = TRUE
        OR (u.trial_ends_at IS NOT NULL AND u.trial_ends_at > now())
        OR u.subscription_status IN ('active', 'grace_period')
  )
ON CONFLICT (user_id, application_id) DO NOTHING;
