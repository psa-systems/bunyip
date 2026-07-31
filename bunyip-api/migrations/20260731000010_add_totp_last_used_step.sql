-- BUNYIP-428: record the last TOTP step consumed by a successful verification
-- so an accepted code can never be accepted again (RFC 6238 section 5.2). The
-- counter is per user (not per secret) and monotonic: a verification at step S
-- claims it with a guarded UPDATE that only fires when last_used_step is NULL
-- or < S, so a replay or a concurrent double-submit updates zero rows and is
-- treated as a failed verification. NULL for existing rows = nothing consumed
-- yet.
ALTER TABLE user_totp
    ADD COLUMN last_used_step BIGINT;
