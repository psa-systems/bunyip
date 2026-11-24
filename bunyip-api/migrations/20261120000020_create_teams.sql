-- teams: a sub-grouping inside an organization. Cascade on parent delete so a
-- removed organization leaves no orphaned teams or members (team_members
-- cascades off teams in the next migration). UNIQUE (organization_id, name)
-- gives two orgs independent naming while preventing duplicates inside one.

CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, name)
);

CREATE INDEX idx_teams_organization ON teams (organization_id);

COMMENT ON TABLE teams IS
    'Teams inside an organization; cascades with the parent org.';
