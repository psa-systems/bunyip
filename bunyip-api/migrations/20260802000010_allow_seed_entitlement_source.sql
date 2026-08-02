-- PMS-709: allow 'seed' as an entitlement source.
--
-- The demo-seed loader (`bunyip-api/src/seed.rs`, PSA-55) grants each demo
-- user their entitlements with source 'seed', but the original constraint from
-- 20260605000010_create_application_entitlements.sql only permitted
-- 'admin' | 'stripe' | 'backfill'. Every demo-msp / minimal template load
-- therefore failed at the entitlements step with a check-constraint violation
-- (SQLSTATE 23514), which the shared `AppError` collapses to the generic
-- "A database error occurred" - so the admin "Load <template>" button appeared
-- to do nothing. Groups, applications and users had already been written
-- (the loader is not transactional), leaving a partial seed and no entitlements.
--
-- Widen the constraint to include 'seed' so the loader's deliberate provenance
-- value is accepted and demo entitlements load. Non-destructive: every existing
-- row already carries one of the four now-permitted values, so re-adding the
-- constraint validates cleanly. The constraint name is preserved.
ALTER TABLE application_entitlements
    DROP CONSTRAINT application_entitlements_source_check;

ALTER TABLE application_entitlements
    ADD CONSTRAINT application_entitlements_source_check
    CHECK (source IN ('admin', 'stripe', 'backfill', 'seed'));
