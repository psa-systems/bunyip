-- Create download_cache table: metadata for on-disk cached Forgejo release assets.
-- Files are stored on disk under DOWNLOAD_CACHE_DIR keyed by content_sha256.
CREATE TABLE download_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    release_tag TEXT NOT NULL,
    asset_name TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    content_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (application_id, release_tag, asset_name)
);

CREATE INDEX download_cache_last_accessed_at_idx ON download_cache(last_accessed_at);
CREATE INDEX download_cache_content_sha256_idx ON download_cache(content_sha256);
