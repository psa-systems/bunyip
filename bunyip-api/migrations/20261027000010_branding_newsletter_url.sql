-- MIRZAM-217: the newsletter signup on the landing page posts to a Mirzam
-- list's subscribe endpoint. The address lives on the admin-managed branding
-- record with the rest of the marketing page, so an admin sets it on the
-- Branding page instead of a deployment variable. Empty hides the signup.
ALTER TABLE branding ADD COLUMN newsletter_url TEXT NOT NULL DEFAULT '';
