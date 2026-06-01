-- Align the download proxy schema with the dunite-download engine (BUNYIP-30).

-- The cached value is a release tag OR a generic-package version, so the
-- engine names it `version`. Renaming preserves the UNIQUE constraint and
-- existing rows.
ALTER TABLE download_cache RENAME COLUMN release_tag TO version;

-- Per-application artifact source selection: which Forgejo API serves this
-- application's binaries.
ALTER TABLE applications
    ADD COLUMN artifact_source TEXT NOT NULL DEFAULT 'release'
        CHECK (artifact_source IN ('release', 'generic_package')),
    ADD COLUMN forgejo_package TEXT;

COMMENT ON COLUMN applications.artifact_source IS
    'Forgejo artifact API for downloads: release (release attachments) or generic_package (generic package registry)';
COMMENT ON COLUMN applications.forgejo_package IS
    'Generic-package name when artifact_source = generic_package; falls back to forgejo_repo when NULL';
