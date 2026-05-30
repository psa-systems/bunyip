-- Encrypt Stripe secrets at rest: replace TEXT columns with BYTEA + nonce columns.
-- The singleton row has NULL values so dropping and re-adding is safe.
ALTER TABLE stripe_config
    DROP COLUMN secret_key,
    DROP COLUMN webhook_secret,
    ADD COLUMN secret_key BYTEA,
    ADD COLUMN secret_key_nonce BYTEA,
    ADD COLUMN webhook_secret BYTEA,
    ADD COLUMN webhook_secret_nonce BYTEA;
