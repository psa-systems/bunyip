-- team_members: which Bunyip users belong to which team, with a role string.
-- role is free text (default 'member') so the PMS-1162 projection-from-app-role
-- model can add roles without a migration; constrain at the service layer.
-- Composite PK prevents double-adding a user to the same team; cascade off the
-- team drops memberships when the team drops.

CREATE TABLE team_members (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    bunyip_user_id UUID NOT NULL REFERENCES users(id),
    role TEXT NOT NULL DEFAULT 'member',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, bunyip_user_id)
);

CREATE INDEX idx_team_members_user ON team_members (bunyip_user_id);

COMMENT ON TABLE team_members IS
    'Bunyip-user membership in a team; cascades with the parent team.';
