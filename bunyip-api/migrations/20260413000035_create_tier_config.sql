-- Singleton table for tier configuration (admin-configurable).
-- NULL columns fall back to environment variable defaults at runtime.
CREATE TABLE tier_config (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    lifetime_slots          BIGINT,
    early_adopter_slots     BIGINT,
    early_adopter_trial_days BIGINT,
    standard_trial_days     BIGINT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  UUID REFERENCES users(id)
);

INSERT INTO tier_config (id) VALUES (1);
