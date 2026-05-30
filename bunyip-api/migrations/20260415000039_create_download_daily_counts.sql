-- Per-user daily download counter (UTC day boundary).
-- Used by the download rate limiter; rows are upserted atomically via
-- INSERT ... ON CONFLICT (user_id, day) DO UPDATE SET count = count + 1.
CREATE TABLE download_daily_counts (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
);
