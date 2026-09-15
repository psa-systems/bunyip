-- BUNYIP-672 [BUNYIP-626 child 1]: membership of a Bunyip user in a team.
--
-- Composite primary key `(team_id, bunyip_user_id)` is the natural
-- de-duplication: the same user cannot be added to the same team twice.
-- Cascade delete from `teams` matches the shape teams uses for
-- `organizations` - a member row without a team is nonsense.
--
-- `role` is a two-value string (`member` / `leader`) that stays a
-- display + notification axis rather than a permission axis, per the
-- projection model settled in PMS-1162's parent PMS-804 epic. Permission
-- checks that involve a team read the caller's app-level role instead of
-- projecting this column into an authority level.
CREATE TABLE team_members (
    team_id        UUID        NOT NULL REFERENCES teams(id)  ON DELETE CASCADE,
    bunyip_user_id UUID        NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    role           TEXT        NOT NULL DEFAULT 'member',
    joined_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, bunyip_user_id),
    CHECK (role IN ('member', 'leader'))
);

CREATE INDEX team_members_bunyip_user_id_idx ON team_members (bunyip_user_id);

COMMENT ON TABLE team_members IS
    'BUNYIP-672: membership of a Bunyip user in a team. role is a display + notification axis per PMS-1162 projection model; permission checks read the caller''s app-level role, not this column.';
