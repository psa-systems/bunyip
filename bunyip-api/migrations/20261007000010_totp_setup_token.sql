-- BUNYIP-886: one-time token that ties a two-factor setup to the password check
-- that started it. Only the SHA-256 (hex) is stored, with a 15-minute expiry;
-- confirm and resume require the token, and a successful confirm clears both.
-- NULL means no setup is in progress.
ALTER TABLE user_totp
    ADD COLUMN setup_token_hash TEXT,
    ADD COLUMN setup_token_expires_at TIMESTAMPTZ;
