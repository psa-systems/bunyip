-- Fix users who were assigned a subscription tier during email verification
-- but never had their subscription_status set to 'active'.
UPDATE users
SET subscription_status = 'active',
    updated_at = NOW()
WHERE subscription_status = 'none'
  AND deleted_at IS NULL
  AND email_verified = TRUE
  AND (
    lifetime_member = TRUE
    OR trial_ends_at IS NOT NULL
  );
