-- Add membership_tier column to users table
ALTER TABLE users ADD COLUMN membership_tier VARCHAR(50) DEFAULT 'personal';

-- Add index for filtering by tier
CREATE INDEX idx_users_membership_tier ON users(membership_tier);
