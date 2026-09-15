-- BUNYIP-673 [BUNYIP-626 child 2]: cross-account Mokosh grants.
--
-- A Bunyip user grants another Bunyip user scoped access to their own
-- Mokosh account. Distinct from BUNYIP-672's teams: teams collect Bunyip
-- users on ONE Mokosh account into working groups; grants let one Bunyip
-- user see another's Mokosh account under a scoped role.
--
-- The FK to `users(id)` on both sides is the portal-contact separation
-- guarantee at the Bunyip level (BUNYIP-675's shape): portal contacts
-- are a Mokosh-side concept and never appear in `users`, so a portal
-- contact can neither be a grantor nor a grantee by construction.
--
-- `role` uses the app-level RBAC vocabulary settled in PMS-1162; the
-- CHECK constraint names the closed set so a typo in the caller (or in
-- an admin-console script) surfaces at write time rather than silently
-- persisting a role the mokosh RS will not recognise.
--
-- `mokosh_account_id` is the Mokosh tenant slug the owner controls. Kept
-- as TEXT (not a FK) because the Mokosh tenants live in a different
-- deployment; the mokosh RS is what validates the value on read (the
-- `at+jwt` claim), and a stale row here becomes an inert grant once the
-- tenant is gone.
--
-- `revoked_at` NULL means the grant is active. The partial UNIQUE below
-- keeps one active grant per (owner, grantee, mokosh_account) triple;
-- multiple revoked rows for the same triple accumulate as an audit
-- trail, so revoking and re-granting the same access reads as two
-- distinct events in the history table.
CREATE TABLE mokosh_account_grants (
    id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_bunyip_user_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantee_bunyip_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mokosh_account_id      TEXT        NOT NULL,
    role                   TEXT        NOT NULL,
    granted_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at             TIMESTAMPTZ,
    CHECK (role IN ('admin', 'manager', 'technician', 'finance', 'read_only')),
    CHECK (owner_bunyip_user_id <> grantee_bunyip_user_id)
);

CREATE UNIQUE INDEX mokosh_account_grants_active_unique
    ON mokosh_account_grants (owner_bunyip_user_id, grantee_bunyip_user_id, mokosh_account_id)
    WHERE revoked_at IS NULL;

CREATE INDEX mokosh_account_grants_grantee_idx
    ON mokosh_account_grants (grantee_bunyip_user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX mokosh_account_grants_owner_idx
    ON mokosh_account_grants (owner_bunyip_user_id)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE mokosh_account_grants IS
    'BUNYIP-673: a Bunyip user grants another Bunyip user scoped access to their Mokosh account. Portal-contact separation is enforced by the FK to users(id) on both sides (BUNYIP-675).';
COMMENT ON COLUMN mokosh_account_grants.mokosh_account_id IS
    'The Mokosh tenant slug the owner controls. Kept as TEXT because Mokosh tenants live in a different deployment; the mokosh RS validates the value on read.';
COMMENT ON COLUMN mokosh_account_grants.role IS
    'App-level RBAC role from PMS-1162: admin | manager | technician | finance | read_only.';
