-- BUNYIP-840: admin feature toggles, keyed by the `Feature` variants in crates/bunyip-domain/src/feature_toggles.rs.
-- A missing row reads as OFF and an unknown key is ignored; `tier_config` is untouched.
CREATE TABLE feature_toggles (
    key        TEXT        PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*$'),
    enabled    BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID        REFERENCES users (id) ON DELETE SET NULL
);

COMMENT ON TABLE feature_toggles IS
    'Admin switches (admin page: Feature Toggles). Off means invisible: the feature''s routes 404 and its nav entries are not rendered.';
