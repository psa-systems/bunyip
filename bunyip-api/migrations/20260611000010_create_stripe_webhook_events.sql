-- BUNYIP-89: Stripe webhook idempotency on `event.id`.
--
-- Stripe delivers webhooks at-least-once. Every retry (network drop,
-- non-2xx, slow response) re-runs whatever side effect the handler had:
-- duplicate emails on `customer.subscription.deleted`, duplicate audit-
-- log rows on `checkout.session.completed`, duplicate payment receipts
-- on `invoice.payment_succeeded`. The fix is one fence in front of the
-- handler routing: record `event.id` on first sight, short-circuit on
-- duplicate.
--
-- Stripe event IDs are stable (`evt_xxx`) so the PK is sufficient
-- enforcement; no SELECT FOR UPDATE needed. `ON CONFLICT (event_id) DO
-- NOTHING` in the webhook handler resolves the race between concurrent
-- retries cleanly: the second to commit sees `rows_affected = 0` and
-- returns 200 without re-running.
--
-- No retention policy here; ops can prune `received_at < NOW() - INTERVAL
-- '90 days'` later if the table grows. Stripe stops retrying after a few
-- days, so anything older than that is purely historical.
CREATE TABLE stripe_webhook_events (
    event_id    TEXT        PRIMARY KEY,
    event_type  TEXT        NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
