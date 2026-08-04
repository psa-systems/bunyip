-- BUNYIP-473: densify applications.sort_order to distinct sequential positions.
--
-- Applications created through the admin form never set sort_order, so they all
-- took the column default 0. The old reorder control swapped two rows'
-- sort_order values, and swapping 0 with 0 moved nothing, so reordering
-- appeared broken. The new control assigns explicit positions, but existing
-- rows still share 0; this backfill gives every row a distinct position.
--
-- The ordering key is (sort_order, display_name) - exactly the list's own sort -
-- so the visible order is preserved; only the ties are broken. Safe to run on an
-- already-densified database (it just re-numbers to the same sequence).
WITH ranked AS (
    SELECT id, ROW_NUMBER() OVER (ORDER BY sort_order ASC, display_name ASC) AS rn
    FROM applications
)
UPDATE applications SET sort_order = ranked.rn
FROM ranked WHERE applications.id = ranked.id;
