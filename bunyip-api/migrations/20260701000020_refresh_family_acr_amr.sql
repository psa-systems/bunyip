-- BUNYIP-257: persist `acr` and `amr` on `refresh_token_families` so a
-- rotated at+jwt carries the authentication-method-reference of the
-- ORIGINAL login, not a hardcoded `pwd` fallback that lies about MFA /
-- magic-link auth.
--
-- The previous behaviour stamped `acr = "urn:bunyip:loa:pwd"`,
-- `amr = ["pwd"]` on every rotated token regardless of the actual
-- factor set. RPs that gate admin actions on `amr` contains `mfa` /
-- `otp` were misled; step-up auth on those claims was impossible. The
-- audit named this medium-severity and the same fix shape as the
-- BUNYIP-262 `auth_time` column (persist on the family, carry forward
-- on every rotation, read at remint).
--
-- Existing families backfill to the legacy defaults so a rolling deploy
-- does not change the wire shape of in-flight rotations; the truthful
-- values land on every NEW family created post-migration.

ALTER TABLE refresh_token_families
    ADD COLUMN acr TEXT NOT NULL DEFAULT 'urn:bunyip:loa:pwd';

ALTER TABLE refresh_token_families
    ADD COLUMN amr TEXT[] NOT NULL DEFAULT ARRAY['pwd'];
