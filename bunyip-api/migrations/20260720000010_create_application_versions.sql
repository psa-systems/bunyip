-- BUNYIP-386: version history for distributed applications.
--
-- Bunyip's OCI proxy previously served only the single `applications.pinned_image_tag`,
-- so an admin bump (v0.7 -> v0.8) overwrote the pin and made v0.7 unpullable through
-- Bunyip. This table records every image tag an application has published, so a bump
-- ADDS a version rather than replacing it. It doubles as the OCI proxy's tag allow-list:
-- a tag is pullable when it is the pinned tag OR a non-yanked row here. `pinned_image_tag`
-- stays as the current/default pointer.

CREATE TABLE application_versions (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id    UUID        NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    image_tag         TEXT        NOT NULL,
    -- Resolved lazily; NULL until the manifest is first fetched.
    image_digest      TEXT,
    published_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    release_notes_url TEXT,
    -- An admin can pull a bad/insecure version out of circulation without deleting
    -- the append-only history; the OCI serve check refuses yanked versions.
    yanked            BOOLEAN     NOT NULL DEFAULT false,
    UNIQUE (application_id, image_tag)
);

CREATE INDEX idx_application_versions_app ON application_versions (application_id);

-- Backfill: the current pin becomes each app's first recorded version, so history
-- starts from today's state. Versions bumped BEFORE this migration are already lost
-- from Bunyip and are not recovered here (a one-time upstream-registry tag scan could
-- reintroduce them later).
INSERT INTO application_versions (application_id, image_tag)
SELECT id, pinned_image_tag
FROM applications
WHERE pinned_image_tag IS NOT NULL
ON CONFLICT (application_id, image_tag) DO NOTHING;
