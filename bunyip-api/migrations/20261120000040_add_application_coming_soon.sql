-- applications.coming_soon (BUNYIP-797 slice 1 of 3)
-- When TRUE, the dashboard renders a coming-soon pill on the tile and the
-- tile remains visible even without a reachability signal. The periodic
-- URL-health work (slice 2) still owes the reachability column; slice 3
-- combines the two into the `is_active AND (reachable OR coming_soon)` filter.
-- Defaulting FALSE preserves today's behaviour for every existing entry.

ALTER TABLE applications
    ADD COLUMN coming_soon BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN applications.coming_soon IS
    'When TRUE, the entry renders a coming-soon pill and stays visible even without a reachability signal.';
