-- BUNYIP-386: version history for distributed applications (OCI images AND binaries).
--
-- Bunyip's proxies previously served only the single current pin: `pinned_image_tag`
-- for the OCI registry and `pinned_release_tag` for the Forgejo release/package download
-- path. An admin bump (v0.7 -> v0.8) overwrote the pin and made v0.7 unreachable through
-- Bunyip. This table records every version tag an application has published, so a bump
-- ADDS a version rather than replacing it. It doubles as each proxy's tag allow-list: a
-- tag is servable when it is the current pin OR a non-yanked row here. `version_tag` holds
-- the OCI image tag for image-distributed apps and the release/package tag for
-- binary-distributed apps (an app uses one distribution mechanism, so the tag is
-- unambiguous); the pin columns stay as the current/default pointer.
CREATE TABLE application_versions (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id    UUID        NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version_tag       TEXT        NOT NULL,
    -- OCI content digest, resolved lazily; NULL until the manifest is first fetched and
    -- always NULL for binary (release/package) versions, which have no single digest.
    artifact_digest   TEXT,
    published_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    release_notes_url TEXT,
    -- An admin can pull a bad/insecure version out of circulation without deleting
    -- the append-only history; the serve checks refuse yanked versions.
    yanked            BOOLEAN     NOT NULL DEFAULT false,
    UNIQUE (application_id, version_tag)
);

CREATE INDEX idx_application_versions_app ON application_versions (application_id);

-- Backfill: the current pins become each app's first recorded version, so history starts
-- from today's state. Both distribution paths are covered via UNION; an app sets at most
-- one of the pin columns, but the UNION is safe either way. Versions bumped BEFORE this
-- migration are already lost from Bunyip and are not recovered here (a one-time
-- upstream-registry tag scan could reintroduce them later).
INSERT INTO application_versions (application_id, version_tag)
SELECT id, pinned_image_tag FROM applications WHERE pinned_image_tag IS NOT NULL
UNION
SELECT id, pinned_release_tag FROM applications WHERE pinned_release_tag IS NOT NULL
ON CONFLICT (application_id, version_tag) DO NOTHING;
