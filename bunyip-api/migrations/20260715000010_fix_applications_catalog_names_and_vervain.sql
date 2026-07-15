-- BUNYIP-374 (PMS-667): correct stale application display names and disable
-- vervain-agent by default.
--
-- The distribution-catalog seed (20260602000050_seed_distribution_catalog.sql)
-- inserts these apps with the canonical "Mokosh" spelling and is_active = TRUE
-- via INSERT ... ON CONFLICT (slug) DO NOTHING, so it can never correct rows
-- that already exist. Staging's long-lived database still carries the old
-- "Mokash" / "mokash" display names (from an out-of-band seed or a manual admin
-- edit, none of which are in source) and an active vervain-agent. This one-time
-- correction fixes those existing rows. On a fresh database it runs AFTER the
-- seed, so the name updates are a no-op (already canonical) while vervain-agent
-- is still disabled.
--
-- The name updates are scoped `AND display_name <> '<canonical>'` so
-- already-correct rows are left untouched. vervain-agent is disabled EVERYWHERE
-- by default (PMS-667 decision, not a staging-only gate); a deployment enables
-- it in the admin UI when it ships, and that enable persists because this
-- migration runs only once per database.

UPDATE applications
   SET display_name = 'Mokosh Server'
 WHERE slug = 'mokosh-server' AND display_name <> 'Mokosh Server';

UPDATE applications
   SET display_name = 'Mokosh API'
 WHERE slug = 'mokosh-api' AND display_name <> 'Mokosh API';

UPDATE applications
   SET display_name = 'Mokosh Web'
 WHERE slug = 'mokosh-www' AND display_name <> 'Mokosh Web';

UPDATE applications
   SET is_active = FALSE
 WHERE slug = 'vervain-agent' AND is_active <> FALSE;
