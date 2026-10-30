-- BUNYIP-983: serve one host secret to a registered calling app, and keep the
-- Mokosh Google OAuth client pair that is the first of them.
--
-- A hosted Mokosh needs the suite's Google OAuth client to sync contacts, and
-- until now an operator pasted the pair into Mokosh's own secret store by hand
-- (PMS-1430). Bunyip already holds the suite's shared facts, so the pair is set
-- here once and read over `GET /v1/host/secrets/{KEY}`.
--
-- `allowed_secret_keys` is the per-client allow-list that route reads. Default
-- empty and NOT NULL, so every registration that exists today, and every one
-- made without naming a key, can read nothing: default-deny is the only safe
-- default for a route whose job is handing out secrets. The column is on
-- `oauth_clients` rather than a join table because the entitlement is a
-- property of the registration and a second table would be a second place for
-- the two to disagree.
--
-- Deliberately NOT reusing `allowed_scopes`: scopes are what a USER consents to
-- on the authorize screen, this is what a MACHINE may read with its own
-- credential, and collapsing them would let a consent screen widen a secret
-- entitlement.
ALTER TABLE oauth_clients
    ADD COLUMN allowed_secret_keys TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN oauth_clients.allowed_secret_keys IS
    'BUNYIP-983: host-secret keys this registration may read at GET /v1/host/secrets/{KEY}. Empty means none, which is every registration that does not name one.';

-- The Mokosh host settings bunyip holds on the suite's behalf. Singleton, the
-- `mirzam_config` shape (BUNYIP-997): one row, admin-managed, with the secret
-- half in ciphertext columns that are the `database` provider of a governed
-- secret.
--
-- The pair is split by what it is, not by where it is read. `google_client_id`
-- is public by nature: it travels in every OAuth redirect the browser makes, so
-- it is an ordinary setting and the admin page shows it. The secret is
-- `MOKOSH_GOOGLE_CLIENT_SECRET`, governed by `SECRETS_STORAGE` like every other
-- Group-2 secret, and these columns are its database home, encrypted under
-- `APP_ENCRYPTION_KEY` and never returned in plaintext by any admin read.
CREATE TABLE mokosh_config (
    id                          INTEGER PRIMARY KEY CHECK (id = 1),
    google_client_id            TEXT NOT NULL DEFAULT '',
    google_client_secret        BYTEA,
    google_client_secret_nonce  BYTEA,
    key_version                 SMALLINT NOT NULL DEFAULT 1,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by                  UUID REFERENCES users (id) ON DELETE SET NULL
);

INSERT INTO mokosh_config (id) VALUES (1);

GRANT SELECT, UPDATE ON mokosh_config TO bunyip_app;
