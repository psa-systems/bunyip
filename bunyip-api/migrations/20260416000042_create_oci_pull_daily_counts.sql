-- Per-user daily pull counter. UTC day boundary.
-- Counted once per manifest pull; blob fetches don't increment.
CREATE TABLE oci_pull_daily_counts (
    user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day_utc  DATE NOT NULL,
    count    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day_utc)
);
