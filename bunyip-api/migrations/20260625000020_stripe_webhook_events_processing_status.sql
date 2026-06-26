-- BUNYIP-210: make the BUNYIP-89 idempotency fence safe against handler
-- failures.
--
-- The original fence recorded `event.id` BEFORE running the matched handler
-- (and on a separate connection from it). A handler error therefore left the
-- event permanently marked "processed": Stripe's retry hit ON CONFLICT, the
-- webhook returned 200, and the handler never ran again. The membership
-- activation and per-product entitlement grants were lost with no recovery
-- short of manual DB surgery plus a dashboard replay.
--
-- Introduce a processing lifecycle so an event counts as "already handled"
-- only once its handler actually succeeded:
--   * a delivery CLAIMS the event by writing status 'processing';
--   * on success it is promoted to 'done';
--   * on failure the claim is released (row deleted) so the retry reprocesses.
-- A 'processing' claim whose owner crashed before releasing it is reclaimable
-- after a lease window (the handler re-runs; its DB writes and entitlement
-- sync are idempotent, being status updates and revoke-all-then-grant).
--
-- Existing rows predate the lifecycle and were only ever recorded by the old
-- code, which ran handlers inline; treat them as already-done so they are
-- never reprocessed.
ALTER TABLE stripe_webhook_events
    ADD COLUMN status TEXT NOT NULL DEFAULT 'done';

-- Claims read "is this row done, or a stale processing claim?" by status and
-- age; keep that lookup cheap as the table grows.
CREATE INDEX idx_stripe_webhook_events_status
    ON stripe_webhook_events (status, received_at);
