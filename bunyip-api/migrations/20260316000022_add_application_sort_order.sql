-- Add sort_order column to applications for manual ordering
ALTER TABLE applications ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0;

-- Set initial sort_order based on current display_name order
WITH ranked AS (
    SELECT id, ROW_NUMBER() OVER (ORDER BY display_name ASC) AS rn
    FROM applications
)
UPDATE applications SET sort_order = ranked.rn
FROM ranked WHERE applications.id = ranked.id;
