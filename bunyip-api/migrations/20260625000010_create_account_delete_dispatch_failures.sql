-- BUNYIP-211: capture account-delete webhook dispatches that exhausted their
-- retries so ops can replay them.
--
-- When a bunyip account is deleted the delete handler fans an `account_deleted`
-- webhook out to every active application with a `webhook_url` (mokosh and any
-- other connected PSA app). The dispatch retries with backoff, but the upstream
-- delete is irreversible: if a receiver is still unreachable after the final
-- attempt we must not silently lose the fact that its copy of the user was
-- never purged. Each exhausted (user_id, app) pair lands here as a replayable
-- record; the admin replay endpoint re-fires a single app's webhook and the row
-- documents what is still outstanding until it does.
--
-- No FK to `applications`: the app could be archived/removed after the failure,
-- and the row must survive as an audit of the unresolved delete. `app_slug` is
-- the stable human/replay key. No FK to `users` either: the user is gone by
-- design once the soft delete commits.
CREATE TABLE account_delete_dispatch_failures (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL,
    app_slug     TEXT        NOT NULL,
    last_error   TEXT        NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Ops queries filter by the deleted user when reconciling a single delete.
CREATE INDEX idx_account_delete_dispatch_failures_user_id
    ON account_delete_dispatch_failures (user_id);
