-- BUNYIP-61: per-RP tenant assignment for OIDC users.
--
-- Bunyip is the OIDC issuer; relying parties (mokosh-server today,
-- drillmark / future RPs tomorrow) want to filter their data by
-- tenant_id. Today bunyip mints at+jwt with only the standard OIDC
-- claims and the RPs fall back to OIDC_DEFAULT_TENANT_ID, which means
-- every user authenticated through bunyip lands in tenant id 1 and
-- sees every other user's data. This table closes that gap.
--
-- Shape: one row per (oauth_client, user, tenant) assignment. A user
-- may legitimately have multiple tenants on a single RP (MSP
-- consultants, parent/child orgs), so the unique key is the triple.
--
-- `tenant_id` is OPAQUE to bunyip: the RP defines what the UUID means
-- and registers the relevant tenant UUIDs against the client. Bunyip
-- never resolves it.
--
-- `role` is RP-specific scratch space (owner / member / admin / ...).
-- v1 stores it but does not interpret it; persisting now avoids a
-- second migration once RPs start consuming the column.
--
-- Companion column `tenant_claim_name` lands on `oauth_clients` in the
-- same migration so per-client claim namespacing is configured at the
-- same boundary as the assignments themselves. Existing seeded clients
-- get NULL, which means "no tenant claim emitted, no assignment
-- enforcement, identical to pre-BUNYIP-61 behaviour" - the new
-- behaviour is opt-in per client.

CREATE TABLE IF NOT EXISTS oauth_client_user_tenants (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    oauth_client_id UUID        NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id       UUID        NOT NULL,
    role            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID        REFERENCES users(id),
    UNIQUE (oauth_client_id, user_id, tenant_id)
);

-- Hot path for `/authorize`: load every assignment for (client, user)
-- so the handler can branch on the count (0 -> deny, 1 -> auto, N ->
-- picker). Covering both columns lets the planner skip a sort on the
-- common "list this user's tenants on this app" query.
CREATE INDEX IF NOT EXISTS oauth_client_user_tenants_by_user
    ON oauth_client_user_tenants(oauth_client_id, user_id);

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS tenant_claim_name TEXT;

COMMENT ON COLUMN oauth_clients.tenant_claim_name IS
    'When non-null, /authorize gates on oauth_client_user_tenants and the token mints emit the selected tenant_id under this claim name (e.g. mokosh_tenant_id). NULL = no tenant claim, no assignment enforcement, legacy single-tenant behaviour. The cutover from NULL to non-null is a separate deploy step gated on the assignment table being backfilled.';
