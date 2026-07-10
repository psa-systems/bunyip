-- BUNYIP-355: stage a re-keyed authenticator secret in pending_* columns so the
-- currently-active TOTP secret keeps working until the user confirms the new
-- one. All nullable; all-NULL means no re-key is in progress. begin_rekey writes
-- these; confirm_rekey promotes them into the active columns and clears them.
ALTER TABLE user_totp
    ADD COLUMN pending_encrypted_secret BYTEA,
    ADD COLUMN pending_nonce BYTEA,
    ADD COLUMN pending_key_version SMALLINT,
    ADD COLUMN pending_created_at TIMESTAMPTZ;
