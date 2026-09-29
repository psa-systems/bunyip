-- BUNYIP-840: one registry of admin-managed feature toggles, replacing a
-- `tier_config` column per flag.
--
-- The keys are the `Feature` variants in
-- crates/bunyip-domain/src/feature_toggles.rs. A missing row reads as OFF, and a
-- row whose key no variant matches is ignored, so adding a feature needs no
-- migration.
CREATE TABLE feature_toggles (
    key        TEXT        PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*$'),
    enabled    BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID        REFERENCES users (id) ON DELETE SET NULL
);

COMMENT ON TABLE feature_toggles IS
    'Admin switches (admin page: Feature Toggles). Off means invisible: the feature''s routes 404 and its nav entries are not rendered.';

-- The organizations switch (BUNYIP-493) moves in with its current value, so a
-- deployment that had it on keeps it on. The column goes in the same migration:
-- one source of truth, never two that can disagree.
INSERT INTO feature_toggles (key, enabled, updated_at, updated_by)
SELECT 'organizations', orgs_enabled, updated_at, updated_by
FROM tier_config
WHERE id = 1;

ALTER TABLE tier_config DROP COLUMN orgs_enabled;
