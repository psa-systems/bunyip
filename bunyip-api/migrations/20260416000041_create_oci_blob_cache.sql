-- Tracks every OCI blob we have cached on disk.
-- Filename on disk = content_digest (full sha256:<hex> string stored).
CREATE TABLE oci_blob_cache (
    content_digest    TEXT PRIMARY KEY,
    size_bytes        BIGINT NOT NULL,
    media_type        TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX oci_blob_cache_lru_idx ON oci_blob_cache (last_accessed_at);
