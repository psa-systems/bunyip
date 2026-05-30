-- Add key_version to track which encryption key version encrypted each record.
-- All existing rows are version 1 (the original key).
ALTER TABLE user_totp ADD COLUMN key_version SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE stripe_config ADD COLUMN key_version SMALLINT NOT NULL DEFAULT 1;
