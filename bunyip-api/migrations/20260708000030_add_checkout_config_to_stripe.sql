-- BUNYIP-351 (phase 3): move the non-secret Stripe checkout knobs into the
-- singleton stripe_config row so an admin can tune them from the Stripe settings
-- page without a redeploy. NULL columns fall back to the env defaults
-- (STRIPE_SUCCESS_URL / STRIPE_CANCEL_URL / BUNYIP_BILLING_TRIAL_PERIOD_DAYS) at
-- load time, matching the DB-overrides-env pattern. free_price_id is NOT added
-- here: it is already admin-configurable via tier_config (Tier Settings page).
ALTER TABLE stripe_config
    ADD COLUMN success_url        TEXT,
    ADD COLUMN cancel_url         TEXT,
    ADD COLUMN trial_period_days  INTEGER;
