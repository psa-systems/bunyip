CREATE TABLE feedback_attachments (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    feedback_id UUID        NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
    filename    TEXT        NOT NULL,
    mime_type   TEXT        NOT NULL,
    size_bytes  INTEGER     NOT NULL,
    data        BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_feedback_attachments_feedback_id ON feedback_attachments(feedback_id);
