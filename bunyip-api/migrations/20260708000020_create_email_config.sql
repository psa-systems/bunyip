-- BUNYIP-351: singleton table for email / SMTP configuration (admin-configurable).
-- NULL columns fall back to environment variable defaults at runtime, matching
-- the tier_config / stripe_config DB-overrides-env pattern. The SMTP password is
-- a secret and is encrypted at rest (BYTEA ciphertext + nonce) with the same
-- EncryptionKeySet as the Stripe secrets (STRIPE_ENCRYPTION_KEY), so it is never
-- stored or returned in plaintext.
CREATE TABLE email_config (
    id                        INTEGER PRIMARY KEY CHECK (id = 1),
    enabled                   BOOLEAN,
    smtp_host                 TEXT,
    smtp_port                 INTEGER,
    smtp_tls                  TEXT,
    smtp_username             TEXT,
    smtp_password             BYTEA,
    smtp_password_nonce       BYTEA,
    key_version               SMALLINT NOT NULL DEFAULT 1,
    from_email                TEXT,
    from_name                 TEXT,
    admin_notification_emails TEXT,
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by                UUID REFERENCES users(id)
);

INSERT INTO email_config (id) VALUES (1);
