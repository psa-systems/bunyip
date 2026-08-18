# Reconciling duplicate active Stripe prices (BUNYIP-562)

A Stripe price is immutable, so changing what a plan costs is a REPLACE
(BUNYIP-511): create a new price, repoint bunyip's references, then archive the
old price. The archive is deliberately last, because a stranded reference breaks
checkout while a duplicate does not. If that final archive fails, the product is
left with two active prices sharing the same currency and interval: the new
price (which the tier columns and entitlements now point at) and the old price
(still active, no longer pointed at).

BUNYIP-514 refuses CREATING that state and warns about it on `/admin/stripe`,
but it cannot clean a duplicate that already exists. `reconcile-duplicate-prices`
does.

## What it does

Groups the active app-tagged prices by `(product_id, currency,
recurring_interval, recurring_interval_count)` and, in each group of two or more,
archives only the prices that nothing references, and only when a referenced
price remains as the keeper.

A price is REFERENCED when any of these hold:

- it sits in a `tier_config` price column (`free_price_id`,
  `early_adopter_price_id`, `standard_price_id`);
- it has a `stripe_price_entitlements` row (an application maps to it);
- it has members: someone is on its mapped tier, or is locked to it via
  `users.locked_price_id`.

Decisions per duplicate group:

- one or more referenced, one or more unreferenced: archive the unreferenced
  orphans, keep the referenced price(s). This is the failed-replace case.
- none referenced: SKIP and report. Choosing which of two unmapped prices
  survives (for example a manual `$9.00` and `$3.00` on one product) is a
  business decision no rule can make. Resolve it by hand from `/admin/stripe`.
- all referenced: SKIP and report. Migrate the references off one price first,
  then archive it by hand.

It never archives a price anything points at or anyone is on, never removes the
last price of a key, and never picks a winner among equals. The `subscriptions`
table is not consulted (live subscription state lives only in Stripe, and a
member on a live subscription is already counted).

## Running it

It is a `bunyip-api` subcommand, run inside the api container. Read-only by
default; pass `--apply` to archive.

```nu
# Dry run: print the plan, change nothing.
docker compose exec bunyip-api bunyip-api reconcile-duplicate-prices

# Apply: archive the orphans and write an audit log for each.
docker compose exec bunyip-api bunyip-api reconcile-duplicate-prices --apply
```

Dry-run output names, per product, the price it would archive and the keeper,
and every group it skips with the reason. `--apply` archives via Stripe and
records each archive in the audit log with `source = "reconcile-duplicate-prices"`
and the archived and kept price ids. It is idempotent: a second `--apply` finds
nothing to do. When Stripe is not configured it prints "nothing to reconcile"
and exits cleanly.
