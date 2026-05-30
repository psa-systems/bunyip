-- Create rate limits table
CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_rate_limit UNIQUE (key, action)
);

CREATE INDEX idx_rate_limits_key_action ON rate_limits(key, action);
CREATE INDEX idx_rate_limits_window_start ON rate_limits(window_start);
