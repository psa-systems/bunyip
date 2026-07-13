-- BUNYIP-344: fail-closed per-user row level security on the self-service tables.
--
-- Background
-- ----------
-- bunyip-api has isolated user data with application-level `WHERE user_id = $1`
-- filters only. This adds a DB-level backstop on the strictly self-service
-- tables (the ones a logged-in user reads/writes about only themselves), keyed
-- on the transaction-local GUC `app.current_user_id`. It mirrors the Mokosh
-- tenant pattern (`mokosh-server/migrations/038_rls_fail_closed.sql`), swapping
-- `tenant_id`/`app.current_tenant` for `user_id`/`app.current_user_id`.
--
-- Scope (this slice, BUNYIP-344 phase 1)
-- --------------------------------------
-- Only tables that carry a NOT NULL `user_id` FK to `users` AND whose access is
-- purely self-service:
--   trusted_devices, user_totp, recovery_codes,
--   application_entitlements, email_change_requests
-- Deliberately EXCLUDED (pre-auth / cross-user / admin access, would fail-close
-- auth): `users` itself, all token tables (refresh_tokens, magic_link_tokens,
-- password_reset_tokens, email_verification_tokens), the OIDC session/code/token
-- tables, subscriptions/payment_history (Stripe-webhook-written without a user
-- session), and every global/admin/catalog table. Those keep relying on
-- application-level filters. See the BUNYIP-344 ticket comment for the full
-- enumeration and rationale.
--
-- Fail-closed form
-- ----------------
--   USING      (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
--   WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
-- With the GUC unset, `current_setting(.., true)` -> NULL, `NULLIF(NULL,'')` ->
-- NULL, `NULL::uuid` -> NULL, and `user_id = NULL` is never true: a read returns
-- zero rows and a write is rejected. An empty-string GUC takes the same NULL
-- path instead of raising an invalid-uuid cast error. The GUC is set
-- transaction-locally by `begin_with_user` (bunyip-api/src/db.rs).
--
-- DB role posture (safe to land now)
-- ----------------------------------
-- `FORCE ROW LEVEL SECURITY` makes the policy bind the table owner too, but NOT
-- superusers or roles with BYPASSRLS - those always bypass RLS. Therefore:
--   * The MIGRATION / owner role MUST bypass RLS so migrations and admin/system
--     paths keep operating across all users.
--   * The APPLICATION role that serves self-service reads MUST be NOBYPASSRLS so
--     the policy actually constrains those queries.
-- Roles are cluster-global and environment-specific, so this migration does NOT
-- create or alter them (that would collide across databases sharing a cluster);
-- provisioning the unprivileged `bunyip_app` role and pointing `APP_DATABASE_URL`
-- at it is a deployment step (tracked separately). Until that role exists and the
-- self-service paths are routed through `begin_with_user`, the running app
-- connects as the bypassing role, so this flip is a NO-OP at runtime and safe to
-- land now. The regression in `bunyip-api/tests/rls_isolation.rs` proves the
-- fail-closed behaviour against an explicitly NOBYPASSRLS role.

DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT unnest(ARRAY[
            'trusted_devices',
            'user_totp',
            'recovery_codes',
            'application_entitlements',
            'email_change_requests'
        ])
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS user_isolation ON %I', t);
        EXECUTE format('
            CREATE POLICY user_isolation ON %I
            USING (
                user_id = NULLIF(current_setting(''app.current_user_id'', true), '''')::uuid
            )
            WITH CHECK (
                user_id = NULLIF(current_setting(''app.current_user_id'', true), '''')::uuid
            )
        ', t);
    END LOOP;
END $$;
