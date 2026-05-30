-- Add subdomain column to applications table
-- This allows admins to configure a custom subdomain (e.g., 'go' instead of 'rus')
ALTER TABLE applications ADD COLUMN subdomain VARCHAR(100);

-- Seed existing applications with their known subdomains
UPDATE applications SET subdomain = 'go' WHERE slug = 'rus';
UPDATE applications SET subdomain = 'links' WHERE slug = 'rustylinks';
