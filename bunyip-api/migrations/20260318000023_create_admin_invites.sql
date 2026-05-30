CREATE TABLE admin_invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    invited_by UUID NOT NULL REFERENCES users(id),
    role TEXT NOT NULL DEFAULT 'admin',
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_admin_invites_email ON admin_invites (email);
CREATE INDEX idx_admin_invites_token_hash ON admin_invites (token_hash);
CREATE INDEX idx_admin_invites_invited_by ON admin_invites (invited_by);
