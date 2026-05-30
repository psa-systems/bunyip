-- Auto-ban: IP bans table for tracking banned IPs from suspicious request patterns
CREATE TABLE ip_bans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address INET NOT NULL,
    reason VARCHAR(255) NOT NULL,
    strikes INTEGER NOT NULL DEFAULT 1,
    banned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT unique_ip_ban UNIQUE (ip_address)
);

CREATE INDEX idx_ip_bans_expires ON ip_bans (expires_at);
