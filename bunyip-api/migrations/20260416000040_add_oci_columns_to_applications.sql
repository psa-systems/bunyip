-- Add OCI registry proxy configuration to applications.
-- When all three columns are non-null, the application is "pullable".

ALTER TABLE applications
    ADD COLUMN oci_image_owner    TEXT,
    ADD COLUMN oci_image_name     TEXT,
    ADD COLUMN pinned_image_tag   TEXT;

CREATE INDEX applications_pullable_idx
    ON applications (id)
    WHERE oci_image_owner IS NOT NULL
      AND oci_image_name IS NOT NULL
      AND pinned_image_tag IS NOT NULL;
