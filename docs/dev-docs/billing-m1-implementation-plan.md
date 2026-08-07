# M1 Stripe billing: sequenced implementation plan

Snapshot: 2026-05-31. Built on the locked scoping decisions below. This is a
**plan, not a build** - no billing logic was changed to produce it. Companion to
`docs/dev-docs/billing-m1-gap-matrix.md` (the audit it sequences). Per-user data model
stays; no migration touches the `user_id` relationships.

## Locked decisions (do not re-litigate)

1. **Single plan.** Collapse to one recurring PSA SaaS plan. Delete the consumer
   tiers (Lifetime/EarlyAdopter/Standard), the scarcity columns
   (`lifetime_slots`, `early_adopter_slots`, trial-day knobs), and
   `resolve_tier_for_product`. Keep the product/price admin CRUD as the extension
   point. The price-lock-for-life path is deleted with it (that removes both row-7
   bugs rather than fixing them in place).
2. **Real renewal/cancel date.** Bring the dead `subscriptions` table to life:
   write on `customer.subscription.{created,updated,deleted}`, read it in the
   membership UI for renewal date / "cancels at period end."
3. **Trial month, card-on-file.** 1-month free trial. Keep the
   SetupIntent-$0-auth-at-signup path (card-on-file then bill). Reshape `trial_1m`
   into a plain 1-month trial on the single plan. Add a `Trialing`
   `MembershipStatus` and the trial->active transition on first charge.
4. **GracePeriod kept.** No change.

## Prerequisite GATE (not a phase): Stripe test-mode keys

Stripe is currently **unconfigured** in dev (`stripe_config.secret_key = NULL`;
dashboard shows the disabled "Payment is not configured" button at
`bunyip-web/src/handlers/dashboard.rs:222`). The five `[needs test keys]` rows in
the matrix cannot be verified end to end until a **test-mode secret key + webhook
signing secret** are loaded into `stripe_config` (via the admin Stripe UI /
`handlers/admin_stripe.rs`) or env. **Action for the human (likely source from Vas
/ secrets): provision Stripe test-mode keys + a test webhook endpoint before the
verification steps in phases 1, 3, 4, 5 can pass.** Code and migrations in every
phase can be written and compiled without keys; only end-to-end verification is
gated.

## Confirmation of the decision-1 blast radius (flagged per your ask)

The row-7 bug removal is clean, but "delete the consumer tiers" is a cross-cutting
refactor, not a local delete. `MembershipTier` / `lifetime_member` /
`price_locked` are referenced outside the lock path and each must be handled in
phase 2:

- Registration / email-verify tier assignment: `crates/bunyip-domain/src/services/auth.rs:987-1032`, `bunyip-api/src/handlers/user.rs:290`, `crates/bunyip-domain/src/repositories/user.rs:521-553`.
- Cancel / revoke flows call `reset_membership_tier`: `bunyip-api/src/handlers/membership.rs:199,272`, `bunyip-api/src/handlers/admin.rs:349`.
- JWT claims bake `price_locked` + `price_id`: `crates/bunyip-domain/src/services/jwt.rs:25,112-113` (changing this changes the token claim shape - existing tokens carry the old fields until re-issued).
- Access control (load-bearing): `crates/bunyip-domain/src/models/user.rs:212-224 is_access_allowed()` (admin OR `lifetime_member` OR `trial_ends_at > now` OR `membership_status.has_access()`).
- Web client: `bunyip-web/src/util.rs:45-46`, `bunyip-web/src/api/types.rs:47-49,90-91`, `bunyip-api/src/handlers/membership.rs:81-82` (MembershipResponse still returns price_locked).
- Admin comp lever: `grant_lifetime_membership` (`bunyip-api/src/routes/admin.rs:42`, `crates/bunyip-domain/src/repositories/user.rs:586`).

**RESOLVED sub-decision:** `lifetime_member` is **kept as a decoupled admin comp
flag** ("comp this MSP / free-forever for a partner"). Decouple it from the deleted
`Lifetime` *tier*, but keep the boolean, the `is_access_allowed()` branch, and the
`grant_lifetime_membership` admin endpoint (`bunyip-api/src/routes/admin.rs:42`,
`crates/bunyip-domain/src/repositories/user.rs:586`). Phase 2c therefore reduces
`is_access_allowed()` to: `admin OR lifetime_member OR trial-not-expired OR
membership_status.has_access()`.

## Phases

### Phase 1 - Webhook idempotency (decision-independent; do FIRST)

Customer-facing (duplicate emails + audit rows on Stripe redelivery), low-risk,
survives every later change, depends on nothing.

- **Changes:** add a dedup guard at the top of `bunyip-api/src/handlers/webhook.rs:20 stripe_webhook` - after signature verification and event-id extraction, INSERT the Stripe event id into a new table; if it already exists, return `200 OK` without processing. New repository method (e.g. `StripeEventRepository::mark_seen -> bool`).
- **Migration:** new `stripe_events` table (`event_id TEXT PRIMARY KEY, type TEXT, received_at TIMESTAMPTZ DEFAULT now()`). Additive; no `user_id`-shape change.
- **Done:** a redelivered event id is a no-op (no second audit-log row, no second email). Unit-testable with a synthetic duplicate without Stripe keys. `[needs test keys]` only for the live Stripe-CLI replay confirmation.

### Phase 2 - Single-plan reshape (the gate for 3, 7, and most of 5)

Largest and riskiest; everything keys off it. Removes the consumer tier model and,
with it, the price-lock path and both row-7 bugs.

- **2a - delete the price-lock path (removes row-7 Bug A + Bug B):** drop the `amount`/`price_id`/`lock_price` block in `handle_checkout_completed` (`webhook.rs:~100-118`). Keep the membership-activation + welcome-email + audit. This is the clean part.
- **2b - de-tier the webhook:** remove `resolve_tier_for_product` (`webhook.rs:493-507`) and the `upgrade_membership_tier`/`reset_membership_tier` calls in `handle_subscription_{created,updated,deleted}` (`webhook.rs:181,252,319`). Subscription state no longer mutates a tier; only `membership_status` (and, in phase 4, the `subscriptions` row).
- **2c - de-tier registration + access + claims:** replace the tier-assignment logic in `services/auth.rs:987-1032` + `repositories/user.rs:521-553` with the single plan (a new user is on the one plan; trial handled in phase 3). Update `handlers/user.rs:290`. Stop **writing** `price_locked`/`price_id` to the JWT claims (`services/jwt.rs:112-113`), the `MembershipResponse` (`handlers/membership.rs:81-82`), and web types (`bunyip-web/src/api/types.rs:47-49,90-91`). **Do this the non-breaking way (RESOLVED):** keep tolerating the fields' absence on read and let existing tokens age out naturally. Do NOT do a hard removal that assumes the new claim shape, because live sessions carry the old tokens until reissue and `is_access_allowed` is the access gate; serde defaults / `Option` on read are enough, no deprecation-window engineering. Keep `is_access_allowed()` working: it reduces to `admin OR lifetime_member OR trial-not-expired OR membership_status.has_access()`.
- **2d - migration:** neutralize `tier_config` (drop `lifetime_slots`, `early_adopter_slots`, the trial-day columns; keep/repoint the product/price-id columns to the single plan) and collapse the `membership_tier`/`lifetime_member` columns per the sub-decision above. DDL only; no `user_id`-shape change.
- **Files:** `webhook.rs`, `services/auth.rs`, `repositories/user.rs`, `models/user.rs` (`MembershipTier` enum), `models/mod.rs`, `handlers/user.rs`, `handlers/membership.rs`, `services/jwt.rs`, `handlers/admin.rs` (reset/grant), `bunyip-web/src/{util.rs,api/types.rs}`, plus the migration + `.sqlx` regen (bunyip-oidc query! cache - see CLAUDE.md sqlx note; here the queries live in bunyip-domain via `query`, confirm whether any `query!` is touched).
- **Done:** a new signup lands on the single plan; the webhook never resolves a tier or locks a price; `cargo build`/`clippy` green; JWT + MembershipResponse no longer carry price-lock; `is_access_allowed` verified (admin, trial, active, grace, cancelled all gate correctly). End-to-end subscribe verification is `[needs test keys]`.

### Phase 3 - Trial state + trial->active transition (depends on phase 2)

- **Changes:** add `MembershipStatus::Trialing` (`models/user.rs:46`); map Stripe `"trialing"` -> `Trialing` in the webhook status match (`webhook.rs:240-245`) instead of defaulting to `Active`; configure the single plan's subscription with a **1-month Stripe trial** on the SetupIntent-then-subscription path (`services/stripe.rs:767 create_checkout_session` / `:825 create_free_subscription` / `:1018 create_setup_intent`; trial via `subscription_data` / `trial_period_days`). Handle trialing->active on first charge: `customer.subscription.updated` (status flips trialing->active) and/or `invoice.payment_succeeded` clears `trial_ends_at` (`repositories/user.rs:278,293` already have the clear logic) and sets `Active`. UI shows "trialing / X days left" from `trial_ends_at`.
- **Migration:** none required if `membership_status` is a text column (verify); `Trialing` is a new enum value, not a schema change.
- **Done:** signup -> card-on-file -> 1-month trial (`MembershipStatus::Trialing`, dashboard shows days left) -> first successful charge flips to `Active` and clears `trial_ends_at`. `[needs test keys]` for the live trial->charge cycle (Stripe test clock can fast-forward the trial).

### Phase 4 - Bring the `subscriptions` table to life (decision 2; depends on 2/3)

This is the main net-new build. Note: `get_membership` (`handlers/membership.rs:65-75`)
currently fetches renewal/cancel **live from Stripe per request**; this phase
persists that state and reads from the DB instead.

- **Changes:** add a `SubscriptionRepository` (none exists today) with upsert keyed on `stripe_subscription_id`. In `handle_subscription_{created,updated,deleted}` (`webhook.rs`), upsert the row (`user_id`, `stripe_subscription_id`, `stripe_price_id`, `status`, `current_period_start/end`, `cancel_at_period_end`, `amount`, `currency`; soft-state on deleted). Switch `get_membership` to read renewal date / `cancel_at_period_end` from the `subscriptions` row instead of the live `stripe.get_customer_subscription` call.
- **Migration:** none for the table (it exists: `bunyip-api/migrations/20241230000005_create_subscriptions.sql`); possibly an index or a `trial_end` column if the UI needs it.
- **Done:** the `subscriptions` table is populated by the webhooks; `get_membership` no longer makes a live Stripe call per load; renewal date and "cancels at period end" render from the DB and survive Stripe being briefly unreachable. `[needs test keys]` to drive the create/update/delete events that populate it.

### Phase 5 - Self-service UI reskin (depends on 2/3/4)

- **Changes:** confirm the `/membership` page handler renders the single plan and a working Subscribe + Billing Portal path (that handler was not read in the audit pass - read it first). Reskin a8n.tools consumer copy (lifetime/early-adopter/price-lock language) to PSA/MSP single-plan copy. Surface the new states: Trialing (days left), Active (renewal date), PastDue/GracePeriod, "cancels at period end." Files: `bunyip-web/src/handlers/dashboard.rs` (Membership card `:73,:78,:145,:220,:406`), the `/membership` handler, `bunyip-web/src/api/types.rs`.
- **Migration:** none.
- **Done:** in the browser, signup -> trial -> active -> manage (Billing Portal, cancel/reactivate) round-trips with correct copy and states. Fully `[needs test keys]`.

## Dependency graph

```
Phase 1 (idempotency) ── independent, do first
Phase 2 (single plan) ── gates 3, 4-semantics, 5; removes row-7 bugs
   └─> Phase 3 (trial + Trialing state)
          └─> Phase 4 (subscriptions table persist + read)
                 └─> Phase 5 (UI reskin + end-to-end)
GATE: Stripe test keys ── blocks end-to-end verification of 1, 3, 4, 5
```

## What stays untouched

- The per-user data model (`users.stripe_customer_id`, `subscriptions.user_id`).
  No phase changes the `user_id` shape.
- `GracePeriod` (decision 4) and its grace-start guard (`webhook.rs:456`).
- The Stripe client plumbing in `services/stripe.rs` (customer/checkout/portal/
  product-price CRUD/webhook-verify) - reused, not rebuilt.
- The OCI/OIDC verticals and the dev-sso infra.

## Open items for you before build

1. **`lifetime_member`** - RESOLVED: keep as a decoupled admin comp flag (see phase 2c + the blast-radius note above).
2. **`MembershipResponse`/JWT dropping `price_locked`** - RESOLVED: non-breaking. Stop writing the fields; tolerate their absence on read; let old tokens age out. No deprecation-window engineering (phase 2c).
3. **Stripe test-mode keys + test webhook endpoint** - STILL OPEN (the gate). Likely source from Vas / secrets. Blocks end-to-end verification in phases 1, 3, 4, 5.

This plan is now decision-complete except for the Stripe-key gate (item 3).
