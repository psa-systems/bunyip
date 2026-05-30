-- Create users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'subscriber',
    stripe_customer_id VARCHAR(255) UNIQUE,
    subscription_status VARCHAR(50) NOT NULL DEFAULT 'none',
    price_locked BOOLEAN NOT NULL DEFAULT FALSE,
    locked_price_id VARCHAR(255),
    locked_price_amount INTEGER,
    grace_period_start TIMESTAMPTZ,
    grace_period_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_stripe_customer_id ON users(stripe_customer_id);
CREATE INDEX idx_users_subscription_status ON users(subscription_status);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
