ALTER TABLE feedback
ADD COLUMN tags TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX idx_feedback_tags ON feedback USING GIN(tags);
