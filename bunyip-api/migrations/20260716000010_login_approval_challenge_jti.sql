-- BUNYIP-375: bind each login-approval challenge to its own code row.
--
-- BUNYIP-373 completed a withheld login by matching the emailed code against
-- the user's LATEST valid login_approval_codes row, ignoring which challenge
-- token was presented. With two concurrent gated logins for one user, only the
-- newest emitted code worked; the earlier login could not complete even with
-- its correct code. Persist the challenge JWT's jti on the row so completion
-- resolves the exact row the presented challenge token was minted for.
--
-- Nullable because it is added after the table exists; every row written by the
-- service sets it (the feature ships off by default, so no live rows predate
-- this). Indexed by (user_id, challenge_jti) for the completion lookup.

ALTER TABLE login_approval_codes ADD COLUMN challenge_jti VARCHAR(255);

CREATE INDEX idx_login_approval_codes_challenge_jti
    ON login_approval_codes (user_id, challenge_jti);
