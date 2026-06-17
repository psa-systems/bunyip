-- Trusted devices for the "remember this device, skip TOTP" feature
-- (BUNYIP-138). A row represents one device a SUBSCRIBER has marked trusted at
-- 2FA time. The opaque cookie secret is never stored; only its SHA-256 hash is
-- kept (same scheme as refresh_tokens.token_hash), so possession of the secret
-- is the proof and the row stays revocable. Admins never get rows here.
CREATE TABLE trusted_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    -- User-Agent at creation, for display in the settings panel only. Never
    -- used to gate the skip (it is spoofable and changes on browser updates).
    label VARCHAR(500),
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    -- Absolute deadline set at creation (now + 30 days); using the device does
    -- not extend it.
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_trusted_devices_user_id ON trusted_devices(user_id);
CREATE INDEX idx_trusted_devices_token_hash ON trusted_devices(token_hash);
