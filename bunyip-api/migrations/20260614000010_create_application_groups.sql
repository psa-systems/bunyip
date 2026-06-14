-- BUNYIP-100: application groups.
--
-- Some products are really several applications (e.g. Mokosh = mokosh-server
-- + mokosh-apps + ...). This table lets an admin group those apps under one
-- user-facing heading. Membership is one group per app: applications.group_id
-- is a nullable FK; NULL means "ungrouped" and renders standalone as before.
-- ON DELETE SET NULL keeps the apps when a group is removed.

CREATE TABLE IF NOT EXISTS application_groups (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT        NOT NULL UNIQUE,
    slug         TEXT        NOT NULL UNIQUE,
    display_name TEXT        NOT NULL,
    description  TEXT,
    icon_url     TEXT,
    sort_order   INTEGER     NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS group_id UUID REFERENCES application_groups(id) ON DELETE SET NULL;

-- Hot path: the user Applications page groups apps by group_id, and admin
-- group deletion reassigns members; both want a quick lookup by group_id.
CREATE INDEX IF NOT EXISTS idx_applications_group_id ON applications(group_id);
