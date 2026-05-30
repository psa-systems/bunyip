-- Fix accounts where membership was revoked but tier/slot was never freed.
-- These users have subscription_status = 'canceled' but still hold a
-- lifetime or early_adopter slot, preventing new users from claiming it.

UPDATE users
SET subscription_tier = 'standard',
    lifetime_member = FALSE,
    trial_ends_at = NULL,
    subscription_override_by = NULL,
    updated_at = NOW()
WHERE subscription_status = 'canceled'
  AND subscription_tier IN ('lifetime', 'early_adopter', 'free')
  AND deleted_at IS NULL;
