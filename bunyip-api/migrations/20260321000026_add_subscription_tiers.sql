-- Add tiered subscription model
-- subscription_tier: lifetime | trial_3m | trial_1m
-- Assigned atomically at email verification time based on verified user count.
ALTER TABLE users
    ADD COLUMN subscription_tier VARCHAR(50) NOT NULL DEFAULT 'trial_1m',
    ADD COLUMN trial_ends_at TIMESTAMPTZ,
    ADD COLUMN lifetime_member BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN subscription_override_by UUID REFERENCES users(id);

CREATE INDEX idx_users_lifetime_member ON users(lifetime_member);
CREATE INDEX idx_users_trial_ends_at ON users(trial_ends_at) WHERE trial_ends_at IS NOT NULL;
