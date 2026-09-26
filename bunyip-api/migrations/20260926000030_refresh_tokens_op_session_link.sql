-- BUNYIP-636 PR 3b of 5: bind hub `refresh_tokens` rows to their owning
-- op-session so `AuthService::refresh_tokens` (the hub refresh path)
-- reads and slides the same clock the RP families already do (PR 2).
--
-- The column is NULL for rows minted before PR 3b, plus for a mint whose
-- op-session provider is not configured; a NULL op_session_id falls back
-- to the legacy behaviour (deadline carried across rotation by
-- `refresh_absolute_ttl`) so the migration itself changes no live
-- session. From PR 3b's login handlers onwards, every new hub refresh
-- token that has an op-session available is linked to it, and its
-- rotation goes through the same check-and-slide gate the RP path takes.
--
-- ON DELETE CASCADE mirrors the shape `refresh_token_families.op_session_id`
-- already uses (migration `20260417000042_create_oidc_tokens.sql`): when
-- an op-session is deleted, its hub refresh tokens die with it, matching
-- the RP families.

ALTER TABLE refresh_tokens
    ADD COLUMN op_session_id UUID NULL REFERENCES op_sessions(id) ON DELETE CASCADE;

-- The refresh path looks the row up by `token_hash` and then reads
-- op_session_id off it, so the existing token_hash index is enough for
-- the lookup; a bare index on op_session_id would only help a "list every
-- hub token under this session" query, which does not exist today.

COMMENT ON COLUMN refresh_tokens.op_session_id IS
    'BUNYIP-636: the OP session that authorised this hub refresh token. NULL for pre-PR-3b rows and for tokens minted without an op-session provider; a rotation with NULL falls back to the legacy `refresh_absolute_ttl` behaviour and does not touch op_sessions.';
