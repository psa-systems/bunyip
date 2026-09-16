-- BUNYIP-626 follow-up (redo): my earlier migration
-- 20260916000010_mokosh_tenant_claim_name.sql set tenant_claim_name on
-- a client_id that no longer exists in the schema.
-- Migration 20260724000010_drop_stale_mokosh_server_oidc_client.sql
-- had deleted b0000000-0000-4000-8000-000000000001 (the retired
-- confidential mokosh-server OP registration) when the bunyip-as-OP
-- cutover made mokosh-server a Resource Server only. The UPDATE
-- matched zero rows, committed, and recorded success in
-- `_sqlx_migrations` - the exact silent-no-op class mokosh's PMS-1117
-- migration convention exists to prevent. Bunyip has no equivalent
-- GET DIAGNOSTICS guard, so nothing caught it.
--
-- The LIVE mokosh client on this deployment is
-- b0000000-0000-4000-8000-000000000002 (mokosh-apps: the SPA users
-- authorize from). That is the client the grant-token flow is meant
-- to serve, so it is the row that needs `tenant_claim_name =
-- 'mokosh_tenant_id'` to unblock POST /v1/grants/{id}/access-token.
--
-- Two rules kept:
--
--   1. Idempotent: the WHERE clause reads `tenant_claim_name IS NULL`,
--      so a row that already has a non-null value (from any future
--      opt-in path) is untouched.
--
--   2. Hard fail on zero rows. The `DO $$` block captures
--      GET DIAGNOSTICS ROW_COUNT and RAISEs when the UPDATE matched
--      nothing AND no row is already opted in - the shape mokosh's
--      `mokosh_assert_content_rows_matched` helper enforces. This is
--      what would have caught 20260916000010's silent no-op at
--      migration time.
--
-- Migration 20260916000010 stays in place as an applied no-op so
-- databases that ran it stay valid; editing it is a checksum
-- violation (see BUNYIP-293).

DO $$
DECLARE
    updated_count INTEGER;
    existing_count INTEGER;
BEGIN
    UPDATE oauth_clients
    SET tenant_claim_name = 'mokosh_tenant_id'
    WHERE client_id = 'b0000000-0000-4000-8000-000000000002'
      AND tenant_claim_name IS NULL;

    GET DIAGNOSTICS updated_count = ROW_COUNT;

    SELECT COUNT(*) INTO existing_count
    FROM oauth_clients
    WHERE client_id = 'b0000000-0000-4000-8000-000000000002'
      AND tenant_claim_name = 'mokosh_tenant_id';

    IF updated_count = 0 AND existing_count = 0 THEN
        RAISE EXCEPTION
            'BUNYIP-626 migration: no oauth_clients row for client_id '
            'b0000000-0000-4000-8000-000000000002. This deployment has '
            'no live mokosh-apps client registered; the grant-token flow '
            'cannot be enabled. Register the mokosh-apps client first '
            '(see 20260603000010_register_mokosh_apps_and_drillmark_oidc_clients.sql).';
    END IF;
END $$;
