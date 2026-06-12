-- Encrypt Stripe secrets at rest: replace TEXT columns with BYTEA + nonce columns.
-- The singleton row is expected to hold NULL values so dropping and re-adding is
-- safe. Fail closed if that assumption is wrong: dropping a populated column
-- would silently discard a live Stripe secret/webhook secret with no way to
-- recover the plaintext, so refuse to run rather than destroy data.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM stripe_config
        WHERE secret_key IS NOT NULL OR webhook_secret IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'stripe_config holds non-NULL secret_key/webhook_secret; refusing to DROP them. Clear or migrate the plaintext secrets before applying this migration.';
    END IF;
END $$;

ALTER TABLE stripe_config
    DROP COLUMN secret_key,
    DROP COLUMN webhook_secret,
    ADD COLUMN secret_key BYTEA,
    ADD COLUMN secret_key_nonce BYTEA,
    ADD COLUMN webhook_secret BYTEA,
    ADD COLUMN webhook_secret_nonce BYTEA;
