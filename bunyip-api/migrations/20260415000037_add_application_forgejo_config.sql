-- Add Forgejo release proxy configuration to applications.
-- When all three columns are non-null, the application is "downloadable".

ALTER TABLE applications
    ADD COLUMN forgejo_owner       TEXT,
    ADD COLUMN forgejo_repo        TEXT,
    ADD COLUMN pinned_release_tag  TEXT;

CREATE INDEX applications_downloadable_idx
    ON applications (id)
    WHERE forgejo_owner IS NOT NULL
      AND forgejo_repo IS NOT NULL
      AND pinned_release_tag IS NOT NULL;
