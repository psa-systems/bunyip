CREATE TABLE feedback_attachments (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    feedback_id UUID        NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
    filename    TEXT        NOT NULL,
    mime_type   TEXT        NOT NULL,
    -- Bounded to 5 MiB, matching MAX_ATTACHMENT_SIZE in
    -- bunyip-api/src/handlers/feedback.rs so a bypassed app-layer check can
    -- never store an unbounded blob.
    size_bytes  INTEGER     NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 5242880),
    data        BYTEA       NOT NULL,
    -- Keep the stored payload size in lock-step with the recorded size_bytes;
    -- this also caps the BYTEA itself at 5 MiB.
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT feedback_attachments_data_size CHECK (octet_length(data) = size_bytes)
);

CREATE INDEX idx_feedback_attachments_feedback_id ON feedback_attachments(feedback_id);
