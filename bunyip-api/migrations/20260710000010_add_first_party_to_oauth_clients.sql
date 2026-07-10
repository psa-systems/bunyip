-- BUNYIP-342: mark first-party OAuth clients (Mokosh and other apps under the
-- Bunyip platform) so /oauth2/authorize can skip the consent screen for them,
-- the way Google Workspace does not re-prompt for its own core apps. Genuinely
-- third-party integrations still get a named consent screen.
ALTER TABLE oauth_clients
    ADD COLUMN first_party BOOLEAN NOT NULL DEFAULT FALSE;

-- mokosh-apps (the PSA client SPA) is first-party under Bunyip.
UPDATE oauth_clients
    SET first_party = TRUE
    WHERE client_id = 'b0000000-0000-4000-8000-000000000002';
