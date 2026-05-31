# M1 Stripe billing: acceptance-criteria gap matrix (audit, not a build plan)

Snapshot: 2026-05-31. Deliverable for the M1 "Stripe-backed subscription billing
for SaaS access" ticket. This is an **audit** of the billing vertical that was
ported from menkent into the current actix/dunite backend. **No billing logic was
changed to produce this.**

## Decisions already locked (do not re-litigate)

- **Q1: per-user.** A paying MSP is one owner-user account for M1 (confirmed with
  Vas + `For AI/bunyip-mokosh-boundaries.md`). No org-level billing or seats; that
  stays deferred to multi-tenant work. The `user_id`-based data model
  (`users.stripe_customer_id`, `subscriptions.user_id`) is therefore **correct**.
- Consequently **"MSP-misfit" means a8n.tools-consumer-model misfit**, NOT
  user-vs-org misfit: the scarcity/growth-hack semantics (lifetime slots,
  early-adopter slots, price-lock-for-life, `tier_config`,
  `resolve_tier_for_product`) that do not fit a B2B SaaS plan. The ticket wants
  "single plan to start, structure for more."

## Verification caveat: Stripe is not configured in this dev env

`stripe_config` has 1 row with `secret_key = NULL`; the dashboard renders a disabled
"Payment is not configured" button (`bunyip-web/src/handlers/dashboard.rs:222`). So
rows whose behavior depends on live Stripe calls are **statically** audited only;
each is tagged **[needs test keys]** with exactly what to verify once a Stripe
**test-mode** secret + webhook secret are loaded into `stripe_config` (via the admin
Stripe UI / `admin_stripe.rs`) or env.

## Status legend

`satisfied` = present and fits M1 as-is. `partial` = present but incomplete.
`missing` = not implemented. `misfit` = present and working but encodes the
a8n.tools consumer model that must be reshaped for PSA/MSP.

## Matrix

### 1. Stripe customer + subscription creation - `satisfied (plumbing) / misfit (semantics)` [needs test keys]

| | |
| --- | --- |
| Existing code | Customer: `services/stripe.rs:738 create_customer`. Checkout: `:767 create_checkout_session`. Free sub: `:825 create_free_subscription`. SetupIntent ($0 card auth at signup): `:1018 create_setup_intent` + `handlers/billing.rs:34 create_setup_intent`. Subscribe entry points: `handlers/membership.rs:93 create_checkout`, `:413 subscribe`. |
| Status | Plumbing is complete and idiomatic (`async-stripe 0.37`). |
| What needs to change | (a) Decide whether the **SetupIntent-at-signup $0-auth** path stays for MSPs or is dropped in favor of plain Checkout. (b) The flow is coupled to the consumer tier/price-lock model (see rows 2 and 7) - decouple. (c) Verify the customer->checkout->subscription round-trip with test keys. |

### 2. Plan/tier definitions (single plan, structure for more) - `misfit`

| | |
| --- | --- |
| Existing code | Tier config singleton: `migrations/20260413000035_create_tier_config.sql` (`lifetime_slots`, `early_adopter_slots`, `*_trial_days`) + `..._45_add_price_ids` / `..._46_add_product_ids`. Tier enum + naming: `migrations/20260321000026_add_subscription_tiers.sql`, `..._32_rename_subscription_tiers...`. Admin plan CRUD (the "structure for more" mechanism): `handlers/admin_stripe.rs:62-178` over `services/stripe.rs:156-452` (products/prices list/create/update/archive). |
| Status | The *mechanism* for "structure for more" exists (admin defines Stripe products/prices). The *opinion* baked on top is the consumer model. |
| What needs to change | Collapse the three named tiers (`Lifetime`/`EarlyAdopter`/`Standard`) and the scarcity columns (`lifetime_slots`, `early_adopter_slots`, trial-day knobs) down to **one PSA SaaS plan**, keeping the product/price admin CRUD as the extension point. Replace `resolve_tier_for_product` (row 3) accordingly. Migration work: a new migration to neutralize `tier_config`/tier enum; do NOT mutate the per-user shape. |

### 3. Webhook handling for lifecycle events - `satisfied / misfit (+2 correctness bugs, rows 6-7)`

| | |
| --- | --- |
| Existing code | `handlers/webhook.rs:20 stripe_webhook` routes: `checkout.session.completed:84`, `customer.subscription.{created:143,updated:209,deleted:290}`, `invoice.payment_{succeeded:352,failed:420}`. Signature verification: `services/stripe.rs:957 verify_webhook_signature`. Webhook-endpoint self-registration with Stripe: `services/stripe.rs:603-706` + `admin_stripe.rs`. |
| Status | All the lifecycle events the ticket lists are handled, with signature verification, audit logs, and emails. |
| What needs to change | Fix the two correctness bugs (rows 6-7); re-point `resolve_tier_for_product` (`webhook.rs:496`) to the new single-plan model; add idempotency (row 6). [needs test keys] Replay each event from the Stripe CLI / test dashboard and confirm the resulting `users.*` state. |

### 4. Account state reflects subscription state (active / past_due / cancelled) - `satisfied (status) / partial (detail)`

| | |
| --- | --- |
| Existing code | `models/user.rs:46 enum MembershipStatus { None, Active, PastDue, Canceled, GracePeriod }`. Webhook handlers map Stripe status -> `MembershipStatus` and call `UserRepository::update_membership_status` (`webhook.rs:240-245` etc.). UI reflects it: `dashboard.rs:145 badge(... "No Membership")`. |
| Status | active/past_due/cancelled are all represented (plus an extra `GracePeriod` consumer state). Coarse status is correct. |
| What needs to change | The canonical **`subscriptions` table (`migrations/20241230000005_create_subscriptions.sql`) is dead schema** - no INSERT/SELECT anywhere in `bunyip-api/src` or `bunyip-domain/src`. State is denormalized onto `users.*`, so renewal date / `cancel_at_period_end` / `stripe_subscription_id` are not persisted. Decide for M1: (a) accept the denormalized `users.*` columns (cheapest), or (b) populate/read the `subscriptions` table for a real renewal-date / cancel-at-period-end UI. Also decide keep/drop `GracePeriod` (a8n.tools addition). |

### 5. Self-service plan management from the account UI - `partial / misfit` [needs test keys]

| | |
| --- | --- |
| Existing code | UI seam: `bunyip-web/src/handlers/dashboard.rs` Membership card ("Subscribe Now" `:73,:78,:220,:406`; "No Membership" `:145`; Stripe-config gate `:222`), `/membership` route. Client types: `bunyip-web/src/api/types.rs:126` (payments), `:137` (invoices). Backend endpoints: `handlers/membership.rs` (`get_membership:52`, `create_checkout:93`, `cancel:163`, `cancel_immediate:237`, `reactivate:302`, `billing_portal:339`, `payment_history:363`), `handlers/billing.rs` (`list_invoices:79`, `download_invoice:102`). Billing Portal session: `services/stripe.rs:932`. |
| Status | The management surface exists (subscribe, Billing Portal, cancel/reactivate, invoices, payment history). It is **gated off** when Stripe is unconfigured, and its copy/tiers are consumer-model. |
| What needs to change | Confirm the `/membership` page itself renders the (single) plan and a working Subscribe + Billing Portal path (its handler was not read in this pass). Reskin consumer copy to PSA/MSP. [needs test keys] Verify the Subscribe -> Checkout -> active, and Billing Portal -> cancel/reactivate round-trips. |

### 6. (correctness) Webhook idempotency - `missing`

| | |
| --- | --- |
| Existing code | None. Checked all 48 files in `bunyip-api/migrations/`; no processed-event/dedup table. The only event tables, `lifecycle_event_outbox` / `lifecycle_event_delivery` (`migrations/20260417000042_create_oidc_tokens.sql:55,67`), are for **OIDC outbound** delivery, not Stripe inbound. `handlers/webhook.rs` reads no event id, has no `ON CONFLICT`, no dedup. |
| Status | Stripe webhook processing is **not idempotent** at the event level. |
| Impact | On Stripe redelivery (any timeout/5xx triggers retries): `update_membership_status`/`lock_price` are idempotent; grace-start is guarded by `if user.grace_period_start.is_none()` (`webhook.rs:456`); but **audit-log rows duplicate** and **emails resend** (welcome, payment receipt, cancellation) per redelivery. |
| What needs to change | Add a `stripe_events` table keyed on Stripe event id; insert-once at the top of `stripe_webhook` and skip if already seen (or make each side-effecting handler idempotent). Small migration + a guard in `webhook.rs:20`. |

### 7. (correctness) `checkout.session.completed` amount default + price mis-parse - `bug`

| | |
| --- | --- |
| Existing code | `handlers/webhook.rs` ~100-118 (`handle_checkout_completed`). |
| Bug A | `amount` falls back to **300** (a8n.tools $3.00, in cents) when `amount_total` is missing - a wrong magic default for PSA. |
| Bug B | `price_id` is read from `session["subscription"]`, which is the **subscription id** (`sub_...`), not a price id; it is then stored via `UserRepository::lock_price(..., &price_id, amount)` as the "price_id", falling back to the literal `"price_default"`. The price-lock record persists a subscription id mislabeled as a price id. |
| What needs to change | Both live inside the **price-lock-for-life** path, which is consumer-model (row 2) and likely removed for MSP. If any of it survives: read the price id from the subscription's line items (a Stripe fetch) rather than `session["subscription"]`, and remove the `300` magic default (fail loudly or fetch the real amount). |

## Suggested order of work (for when build starts; not part of this audit)

1. Reshape tiers -> single PSA plan (rows 2, 3-tier-resolution, 7-price-lock). Largest, gates the rest.
2. Decide the `subscriptions`-table question (row 4) and `GracePeriod` keep/drop.
3. Add webhook idempotency (row 6) - independent, low-risk, do early.
4. Reskin the self-service UI copy (row 5); confirm the `/membership` handler.
5. Load Stripe **test-mode** keys and run the [needs test keys] verifications end to end.

## Files cited (quick index)

- `crates/bunyip-domain/src/services/stripe.rs` - Stripe client (customer/checkout/portal/products/prices/webhook-verify).
- `bunyip-api/src/handlers/webhook.rs` - lifecycle event handlers (rows 3, 6, 7).
- `bunyip-api/src/handlers/membership.rs` - subscribe/cancel/reactivate/portal/payments.
- `bunyip-api/src/handlers/billing.rs` - setup-intent + invoices.
- `bunyip-api/src/handlers/admin_stripe.rs` - admin product/price/webhook CRUD.
- `crates/bunyip-domain/src/models/user.rs` - `MembershipStatus`.
- `bunyip-web/src/handlers/dashboard.rs` - the UI seam.
- `bunyip-api/migrations/` - 48 migrations; billing-relevant ones listed in rows 2, 4, 6.
