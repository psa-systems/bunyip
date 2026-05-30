-- Archive table for closed feedback purged after 90 days.
-- Stores a JSONB snapshot of the full feedback row; enough context to restore if needed.
-- PostgreSQL TOAST-compresses large JSONB values automatically.
CREATE TABLE feedback_archive (
    id          UUID        PRIMARY KEY,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data        JSONB       NOT NULL
);

CREATE INDEX idx_feedback_archive_archived_at ON feedback_archive (archived_at DESC);
