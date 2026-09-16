-- BUNYIP-626 follow-up: opt the Mokosh oauth_clients row into
-- tenant-scoped claims so `POST /v1/grants/{id}/access-token` can
-- actually mint a grant-scoped at+jwt for it.
--
-- Background. BUNYIP-61 added `oauth_clients.tenant_claim_name`
-- (migration 20260612000010) and left every existing row at NULL:
-- the cutover to non-null was declared a separate deploy step gated
-- on the assignment table being backfilled. Nothing has run that
-- step for Mokosh since. Meanwhile BUNYIP-626 (the orgs / teams /
-- grants epic) mints grant-scoped tokens that key the resource-
-- server's tenant scoping ON `tenant_claim_name`, so the endpoint
-- refuses every registered client with "Client is not configured
-- with a tenant_claim_name".
--
-- Setting `mokosh_tenant_id` here is the deferred cutover for the
-- Mokosh client: it turns on tenant-scoped claim emission on the
-- id_token and at+jwt AND makes the /authorize path start reading
-- `oauth_client_user_tenants`. The assignment table is populated
-- for Mokosh already (that is what SaaS-mode login has been doing
-- since BUNYIP-61 shipped), so the guard is satisfied.
--
-- Idempotent: the guard reads NULL to skip a row already opted in
-- via any other future path. The mokosh-server client_id is the
-- fixed UUID from migration 20260502000048.

UPDATE oauth_clients
SET tenant_claim_name = 'mokosh_tenant_id'
WHERE client_id = 'b0000000-0000-4000-8000-000000000001'
  AND tenant_claim_name IS NULL;
