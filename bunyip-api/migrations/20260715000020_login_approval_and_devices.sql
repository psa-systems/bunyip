-- BUNYIP-373: suspicious-login notify-and-approve gate.
--
-- login_approval_codes: the pending "approve this sign-in" challenge. A login
-- flagged as suspicious (new country and/or new device) does NOT mint tokens;
-- instead a single-use 6-digit code is emailed and one row is stored here, bound
-- to the pending login by a short-lived "login_approval" challenge JWT. The user
-- re-submits {challenge_token, code} to complete, mirroring the 2FA flow. Only
-- the SHA-256 hash of the code is stored. Not RLS-scoped: like magic_link_tokens
-- and password_reset_tokens, these rows are written PRE-auth (mid-login, before
-- any user session / app.current_user_id GUC exists), so they rely on app-level
-- WHERE user_id scoping instead.

CREATE TABLE login_approval_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    -- Context of the flagged attempt, for the approval email and audit.
    country VARCHAR(64),
    ip_address INET,
    device_hash VARCHAR(255),
    device_info TEXT,
    -- Wrong-code attempts against this challenge; capped by the service.
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_login_approval_codes_user ON login_approval_codes(user_id);
CREATE INDEX idx_login_approval_codes_expires_at ON login_approval_codes(expires_at);

-- login_devices: per-user set of known login devices. A device is identified by
-- a client-supplied stable device_id (generated + persisted by the client);
-- only its SHA-256 hash is stored. A login from a device_hash not in this table
-- is a "new device" signal, but only once the user already has >= 1 known device
-- (the first device is baseline, mirroring the first-login country being
-- recorded rather than alerted). Absent device_id = no device signal
-- (country-only), so the gate degrades gracefully for clients that do not send
-- one. Not RLS-scoped for the same pre-auth reason as above.

CREATE TABLE login_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_hash VARCHAR(255) NOT NULL,
    user_agent TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, device_hash)
);

CREATE INDEX idx_login_devices_user ON login_devices(user_id);
