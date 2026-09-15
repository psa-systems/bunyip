-- BUNYIP-693 [BUNYIP-626 followup]: seat-based org billing state on the
-- organizations row.
--
-- `stripe_subscription_id` holds the owner's own Stripe subscription id
-- for the org's per-seat charge (distinct from `users.stripe_subscription_id`
-- for their INDIVIDUAL membership; both can coexist because Stripe
-- customers can hold several subscriptions on separate prices).
--
-- `subscription_status` is the mirror of the Stripe status the webhook
-- keeps up to date. NULL when no subscription exists. Statuses match
-- Stripe's own vocabulary; a CHECK constraint names the closed set so a
-- typo in the webhook consumer surfaces at write time.
--
-- `seat_count` is the last quantity we told Stripe about. The service
-- writes it in the same UPDATE as the Stripe call so the two are always
-- read together; the nightly reconciliation worker (follow-up) uses it
-- to detect drift.
ALTER TABLE organizations
    ADD COLUMN stripe_subscription_id TEXT,
    ADD COLUMN subscription_status TEXT,
    ADD COLUMN seat_count INT NOT NULL DEFAULT 0,
    ADD COLUMN subscription_updated_at TIMESTAMPTZ;

ALTER TABLE organizations
    ADD CONSTRAINT organizations_subscription_status_valid
    CHECK (
        subscription_status IS NULL
        OR subscription_status IN (
            'incomplete', 'incomplete_expired', 'trialing', 'active',
            'past_due', 'canceled', 'unpaid', 'paused'
        )
    );

ALTER TABLE organizations
    ADD CONSTRAINT organizations_seat_count_nonneg
    CHECK (seat_count >= 0);

CREATE INDEX organizations_stripe_subscription_id_idx
    ON organizations (stripe_subscription_id);

COMMENT ON COLUMN organizations.stripe_subscription_id IS
    'BUNYIP-693: the org owner subscription in Stripe. Distinct from users.stripe_subscription_id.';
COMMENT ON COLUMN organizations.subscription_status IS
    'Mirror of the Stripe subscription status. NULL when no subscription exists.';
COMMENT ON COLUMN organizations.seat_count IS
    'Last quantity told to Stripe. Reconciliation compares against a live team_members COUNT.';
