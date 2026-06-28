-- Email change requests table
CREATE TABLE email_change_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    new_email VARCHAR(255) NOT NULL,
    -- UNIQUE so a token hash maps to at most one request, matching the other
    -- single-use token tables (refresh_tokens, password_reset_tokens). The
    -- redundant non-unique idx_..._token_hash below is kept only for lookups
    -- that predate this constraint; the UNIQUE index covers equality lookups.
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    confirmed_at TIMESTAMPTZ,
    canceled_at TIMESTAMPTZ,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_change_requests_user_id ON email_change_requests(user_id);
CREATE INDEX idx_email_change_requests_token_hash ON email_change_requests(token_hash);
CREATE INDEX idx_email_change_requests_expires_at ON email_change_requests(expires_at);
