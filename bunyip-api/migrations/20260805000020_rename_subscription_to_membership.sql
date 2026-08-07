-- BUNYIP-488: PSA Systems sells a membership, not a subscription. "Subscription"
-- is Stripe's noun and stays only at the Stripe boundary (stripe_subscription_id,
-- customer.subscription.* events). Rename, not recreate: the tier string values
-- ('lifetime', 'free', 'early_adopter', 'standard') are unchanged, so no data moves.
ALTER TABLE users RENAME COLUMN subscription_status TO membership_status;
ALTER TABLE users RENAME COLUMN subscription_tier TO membership_tier;
ALTER TABLE users RENAME COLUMN subscription_override_by TO membership_override_by;

ALTER INDEX idx_users_subscription_status RENAME TO idx_users_membership_status;
