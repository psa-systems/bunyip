-- BUNYIP-571 slice 3a: inbound IMAP settings on the singleton mail-config row.
-- The password is a governed secret (SECRETS_STORAGE), encrypted like
-- smtp_password and sharing the row's key_version; host/port/username/mailbox/
-- enabled are regular config (env bootstrap, admin override). The poller
-- (slice 3b) consumes these; the admin form fields land alongside.
ALTER TABLE email_config
    ADD COLUMN imap_host           TEXT,
    ADD COLUMN imap_port           INTEGER,
    ADD COLUMN imap_username       TEXT,
    ADD COLUMN imap_password       BYTEA,
    ADD COLUMN imap_password_nonce BYTEA,
    ADD COLUMN imap_mailbox        TEXT,
    ADD COLUMN imap_enabled        BOOLEAN;
