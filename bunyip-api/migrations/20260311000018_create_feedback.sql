-- Create feedback table
CREATE TABLE feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100),
    email VARCHAR(255),
    subject VARCHAR(200),
    message TEXT NOT NULL,
    page_path VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'new',
    admin_response TEXT,
    responded_by UUID REFERENCES users(id),
    responded_at TIMESTAMPTZ,
    is_spam BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_feedback_status ON feedback(status);
CREATE INDEX idx_feedback_created_at ON feedback(created_at DESC);
CREATE INDEX idx_feedback_responded_by ON feedback(responded_by);
