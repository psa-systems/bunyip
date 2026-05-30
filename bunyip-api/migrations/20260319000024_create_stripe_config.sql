CREATE TABLE stripe_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    secret_key TEXT,
    webhook_secret TEXT,
    price_id_personal TEXT,
    price_id_business TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);

-- Singleton row; all updates use UPDATE WHERE id = 1
INSERT INTO stripe_config (id) VALUES (1);
