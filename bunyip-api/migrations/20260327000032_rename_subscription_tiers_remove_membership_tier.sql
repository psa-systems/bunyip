-- Rename subscription tier values: trial_3m -> early_adopter, trial_1m -> standard
UPDATE users SET subscription_tier = 'early_adopter' WHERE subscription_tier = 'trial_3m';
UPDATE users SET subscription_tier = 'standard' WHERE subscription_tier = 'trial_1m';

-- Change default from 'trial_1m' to 'standard'
ALTER TABLE users ALTER COLUMN subscription_tier SET DEFAULT 'standard';

-- Drop the membership_tier column (Business tier moves to a separate application)
DROP INDEX IF EXISTS idx_users_membership_tier;
ALTER TABLE users DROP COLUMN IF EXISTS membership_tier;
