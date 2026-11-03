-- BUNYIP-997: singleton table for the Mirzam newsletter integration.
-- The Mirzam site address, the product-updates and notices list slugs and the
-- on/off switch are admin-managed settings. The API token is the governed
-- secret MIRZAM_API_TOKEN: these ciphertext columns are its `database`
-- provider, encrypted under APP_ENCRYPTION_KEY like the Stripe and SMTP
-- secrets, and are never stored or returned in plaintext.
CREATE TABLE mirzam_config (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    base_url        TEXT NOT NULL DEFAULT '',
    updates_list    TEXT NOT NULL DEFAULT '',
    notices_list    TEXT NOT NULL DEFAULT '',
    api_token       BYTEA,
    api_token_nonce BYTEA,
    key_version     SMALLINT NOT NULL DEFAULT 1,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      UUID REFERENCES users (id) ON DELETE SET NULL
);

INSERT INTO mirzam_config (id) VALUES (1);

GRANT SELECT, UPDATE ON mirzam_config TO bunyip_app;
