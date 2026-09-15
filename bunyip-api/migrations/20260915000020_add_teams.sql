-- BUNYIP-672 [BUNYIP-626 child 1]: teams within an organization.
--
-- A team is a container for `team_members` (next migration). Cascade delete
-- from `organizations` because a team without an org is nonsense; the same
-- reasoning is why `team_members` cascades from teams.
--
-- `UNIQUE(organization_id, name)` is per-org: two different orgs can each
-- have a team called "Ops" without collision.
CREATE TABLE teams (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, name)
);

CREATE INDEX teams_organization_id_idx ON teams (organization_id);

COMMENT ON TABLE teams IS
    'BUNYIP-672: a team within an organization. Contains team_members; deleted when its org is deleted.';
