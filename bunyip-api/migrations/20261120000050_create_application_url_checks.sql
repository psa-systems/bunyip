-- application_url_checks (BUNYIP-1089): one row per URL health probe the
-- UrlHealthWorker writes. Cascade on parent delete so a removed application
-- leaves no orphan history. CHECK constraint ties `status` to the five values
-- the worker emits; schema stays byte-immutable (BUNYIP-293), so a new value
-- goes through a new migration.

CREATE TABLE application_url_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL CHECK (status IN ('ok','http_error','screen_refused','timeout','network_error')),
    http_status SMALLINT,
    latency_ms INTEGER,
    error_detail TEXT
);

-- DESC index for the "most recent check for this app" lookup the admin list
-- uses and the retention worker reads.
CREATE INDEX idx_application_url_checks_app_recent
    ON application_url_checks (application_id, checked_at DESC);

COMMENT ON TABLE application_url_checks IS
    'Health-check history written by UrlHealthWorker (BUNYIP-1089); retained 7 days.';
