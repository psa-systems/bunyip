-- Add subdomain column to applications table
-- This allows admins to configure a custom subdomain (e.g., 'go' instead of 'rus')
ALTER TABLE applications ADD COLUMN subdomain VARCHAR(100);

-- NOTE: the original 'rus'/'rustylinks' subdomain backfills were removed. They
-- targeted slugs seeded by 20241230000008_seed_applications.sql, which was
-- deleted (see the position-8 gap documented in README.md). With no seed
-- migration creating those rows, the UPDATEs matched zero rows on every fresh
-- database. Admins set the subdomain through the admin API instead.
