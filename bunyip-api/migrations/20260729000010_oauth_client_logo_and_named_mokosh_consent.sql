-- BUNYIP-406: name (and, where set, show the icon of) the requesting application
-- on the OAuth consent screen.
--
-- Two changes:
--   1. A nullable logo_uri on oauth_clients. The consent screen renders it next
--      to the client name; NULL degrades to a name-initial badge. Threaded to
--      bunyip-web through the consent redirect the same way client_name already
--      is (BUNYIP-342).
--   2. The mokosh-apps client (the app users authorize from) was registered
--      first-party, which SKIPS the consent screen entirely. Per BUNYIP-406 it
--      should instead show a NAMED consent, so first_party is cleared, and its
--      display name is set to the user-facing "Mokosh" (was the internal
--      "mokosh-apps"). Consent only appears when there are un-consented scopes,
--      so users who already granted are not re-prompted.
ALTER TABLE oauth_clients
    ADD COLUMN logo_uri TEXT;

-- logo_uri points at Mokosh's brand mark, self-hosted by bunyip-web
-- (bunyip-web/assets/mokosh-logo.png, copied from mokosh-apps) so the consent
-- icon is same-origin: it always loads, needs no cross-origin/CORS, and matches
-- the consent page CSP ('self'), rather than depending on the Mokosh origin's
-- asset paths or uptime.
UPDATE oauth_clients
    SET first_party = FALSE,
        name = 'Mokosh',
        logo_uri = '/assets/mokosh-logo.png'
    WHERE client_id = 'b0000000-0000-4000-8000-000000000002';
