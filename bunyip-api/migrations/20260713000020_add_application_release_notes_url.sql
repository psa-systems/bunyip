-- BUNYIP-343: per-application release-notes link, surfaced in the applications
-- view so users can see what changed. Admin-editable (mirrors source_code_url),
-- and seeded here for the known hosted apps with their canonical public Forgejo
-- releases page. These seed values are best-effort defaults: an operator can
-- correct any of them from the admin applications UI without a new migration,
-- and the column is nullable so an app with no release notes simply shows no
-- link.

ALTER TABLE applications ADD COLUMN release_notes_url TEXT;

-- Seed the known hosted launch tiles. Guarded on IS NULL so a value an admin
-- has already set is never overwritten by a later re-run of the seed logic.
UPDATE applications
    SET release_notes_url = 'https://dev.a8n.run/psa-systems/mokosh-server/releases'
    WHERE slug = 'mokosh' AND release_notes_url IS NULL;

UPDATE applications
    SET release_notes_url = 'https://dev.a8n.run/psa-systems/drillmark/releases'
    WHERE slug = 'drillmark' AND release_notes_url IS NULL;
