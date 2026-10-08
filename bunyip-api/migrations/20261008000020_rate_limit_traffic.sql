-- Rate-limit traffic rollup, feeding the admin page's per-bucket sparkline.
--
-- The `rate_limits` table carries only the current window's count per
-- (key, action) and overwrites `window_start` on every reset, so it cannot
-- answer "how many requests landed on this action between 10:00 and 10:15
-- yesterday". A naive implementation would log one row per request and
-- aggregate on read; the parent ticket's goal line rules out a full
-- monitoring stack, so the aggregation lives here as a cheap counter per
-- 15-minute bucket per (action, key_hash).
--
-- The admin page reads one row per bucket in the selected range (max 1 day),
-- rolled up across all key_hashes for the action. Pre-aggregated at write
-- time, so the read is a single range scan on the (action, bucket_start)
-- index.
--
-- `key_hash` is a sha256 of the raw rate-limit key (email, user id, IP, or
-- oauth client id) computed on the write side and passed as a bytea. The
-- raw key is NOT stored here: the "which IP/account is close to the limit"
-- view in the admin page reads `rate_limits` for the current window (the
-- raw key is still there), and keeping the hash means a GDPR deletion of a
-- user leaves the aggregate traffic record intact.
--
-- Retention: 24 hours, swept by the background task in `bunyip-api/main.rs`.
-- The admin page's maximum window is 1 day, so anything older is unused.

CREATE TABLE rate_limit_traffic (
    action       TEXT        NOT NULL,
    key_hash     BYTEA       NOT NULL,
    bucket_start TIMESTAMPTZ NOT NULL,
    count        INTEGER     NOT NULL DEFAULT 0,
    PRIMARY KEY (action, key_hash, bucket_start)
);

CREATE INDEX rate_limit_traffic_action_bucket_idx
    ON rate_limit_traffic (action, bucket_start DESC);

COMMENT ON TABLE rate_limit_traffic IS
    'Per-15-minute-bucket request counts, feeding the admin sparkline.';
COMMENT ON COLUMN rate_limit_traffic.key_hash IS
    'sha256 of the raw rate-limit key, computed on the Rust side.';
COMMENT ON COLUMN rate_limit_traffic.bucket_start IS
    'Start of the 15-minute window this row aggregates, truncated.';

GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limit_traffic TO bunyip_app;
