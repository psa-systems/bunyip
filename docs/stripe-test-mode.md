# Stripe test mode: local subscription testing (BUNYIP-175)

How to exercise the full membership-subscription lifecycle on a dev box with
zero real money and no separate sandbox environment. Stripe's built-in **test
mode** is the sandbox: test cards authorize only against test-mode keys and are
rejected in live mode, so nothing here can move real money.

## What is being verified

```
browser checkout ──card 4242...──> Stripe (test mode)
                                      │  fires webhook events
                                      ▼
stripe CLI (stripe listen) ──forward──> bunyip-api POST /v1/webhooks/stripe (:4401)
                                      │  Stripe-Signature verified vs STRIPE_WEBHOOK_SECRET
                                      │  deduped on event.id (stripe_webhook_events)
                                      └──> membership status / entitlements / emails
```

The webhook endpoint is `POST /v1/webhooks/stripe`, served by `stripe_webhook`
in `bunyip-api/src/handlers/webhook.rs` and mounted under the `/v1` scope
(`bunyip-api/src/routes/webhook.rs:9`, `bunyip-api/src/routes/mod.rs:24`). The
api listens on `APP_PORT=4401`. Handled event types:

- `checkout.session.completed` activates membership, locks the price, and (BUNYIP-209) burns the one-time signup trial by setting `users.has_used_trial = TRUE` when the session was issued with a trial.
- `customer.subscription.created` sets status Active, resolves tier from the product id, grants per-product entitlements (BUNYIP-39).
- `customer.subscription.updated` maps Stripe status to membership status and re-syncs / revokes entitlements.
- `customer.subscription.deleted` cancels membership, resets tier, revokes Stripe-sourced entitlements.
- `invoice.payment_succeeded` clears any grace period and emails a receipt.
- `invoice.payment_failed` starts the 30-day grace period and emails the failure.

## Prerequisites

1. A Stripe account with access to **Test mode** (the dashboard toggle, top right).
2. The Stripe CLI installed and logged in: `stripe login` (opens a browser to pair the CLI with your account). Install docs: <https://docs.stripe.com/stripe-cli>.

## Step 1 - load test-mode keys

Keys can be loaded two ways; the DB value wins per-field when set, otherwise the
env var is used. Both honour the `{NAME}_FILE` compose-secret convention.

- **Env (simplest for `just dev`).** In the Stripe Dashboard switch to Test mode, open Developers -> API keys, copy the **Secret key** (`sk_test_...`), and set it in `.env`:

  ```
  STRIPE_SECRET_KEY=sk_test_...
  ```

  Also set `STRIPE_ENCRYPTION_KEY` to any 32-byte hex value (`openssl rand -hex 32`); it encrypts secrets at rest. `STRIPE_WEBHOOK_SECRET` is filled in step 2.

- **Admin Stripe UI.** Alternatively, paste the same `sk_test_...` key into the in-app admin Stripe settings, which writes the encrypted value to the `stripe_config` table (`bunyip-api/src/handlers/admin_stripe.rs`). This overrides the env var.

Until a secret key is present the dashboard renders the disabled "Payment is not
configured" button (`bunyip-web/src/handlers/dashboard.rs`).

## Step 2 - forward webhooks with the Stripe CLI

In a dedicated terminal, run the listener and forward to the local api:

```nu
stripe listen --forward-to http://localhost:4401/v1/webhooks/stripe
```

On startup it prints a signing secret:

```
> Ready! Your webhook signing secret is whsec_xxxxxxxxxxxx (^C to quit)
```

This `whsec_...` is specific to the `stripe listen` session and differs from a
dashboard endpoint secret. Set it as the webhook secret and restart the api so
it picks up the value:

```
STRIPE_WEBHOOK_SECRET=whsec_...
```

(or paste it into the admin Stripe UI). Leave `stripe listen` running for the
rest of the session; it relays every test-mode event to the local endpoint.

## Step 3 - create a membership product + price (REQUIRED for checkout)

Checkout will not work until at least one **app-tagged** product with an active
recurring price exists. When the Subscribe button posts to
`POST /v1/memberships/checkout` with no explicit price, the api selects the first
active price whose **product carries the metadata `app=<STRIPE_APP_TAG>`**
(default `app=bunyip`); see `list_prices` / `list_products` in
`crates/bunyip-domain/src/services/stripe.rs`. Untagged products are filtered
out, so a brand-new test account (or one whose products predate the tag) fails
checkout with `400 price_id: No active price configured`, and the web silently
redirects back to `/membership` with no error.

Create the tagged product + price either way:

- **Admin Stripe UI (preferred).** Use the in-app admin product CRUD; the api's `create_product` auto-injects `metadata.app = STRIPE_APP_TAG`, so anything created there is tagged correctly.
- **Stripe CLI.** Tag the product explicitly, then add a recurring price:

  ```nu
  stripe products create --name "Bunyip Membership" -d "metadata[app]=bunyip"
  # -> prod_xxx
  stripe prices create --product prod_xxx --unit-amount 300 --currency usd -d "recurring[interval]=month"
  ```

Verify the api can see it: a logged-in Subscribe click should now redirect to
`checkout.stripe.com` instead of bouncing back.

## Step 3b (operator action) - mirror the signup trial on the product (BUNYIP-209)

New users get a one-time 30-day free trial on their first checkout. The code
path is the source of truth: `create_checkout_session`
(`crates/bunyip-domain/src/services/stripe.rs`) sets
`subscription_data.trial_period_days` and
`payment_method_collection = if_required` whenever the user's
`users.has_used_trial` is `FALSE`, and the `checkout.session.completed` webhook
flips that flag so a later subscribe never re-grants the trial. The trial length
is `BUNYIP_BILLING_TRIAL_PERIOD_DAYS` (default `30`).

As defense in depth, configure the same 30-day trial on the membership
**product** in the Stripe Dashboard (Product -> the recurring price -> Free
trial -> 30 days). This is belt-and-suspenders only: if anyone ever creates a
subscription bypassing our checkout helper, the dashboard default still applies a
matching trial rather than billing immediately. Keep the two values in sync - if
ops changes `BUNYIP_BILLING_TRIAL_PERIOD_DAYS`, update the dashboard trial to
match.

## Step 4 (optional) - map product ids to tiers

Map the tagged product's **id** into the tier config (lifetime / early-adopter /
standard) so `resolve_tier_for_product` (`bunyip-api/src/handlers/webhook.rs`)
resolves a tier; otherwise a created subscription still activates membership but
leaves the tier unchanged (the webhook logs `resolved_tier=None`). Note the M1
billing plan (`docs/dev-docs/billing-m1-implementation-plan.md`, decision 1) collapses
to a single plan and removes the tiers, so this step may be retired.

## Step 5 - drive the lifecycle

- **Subscribe (happy path).** In the app's checkout, pay with the canonical test card below. The subscription activates through `checkout.session.completed` + `customer.subscription.created`; the dashboard shows the membership as Active.
- **Failure / grace path.** A bare `stripe trigger invoice.payment_failed` will NOT exercise a real member: the fixture invents its own customer, so the handler logs `User not found for failed payment` and does nothing. To drive the grace cycle for an existing subscriber, send an event scoped to that customer. The simplest deterministic way is a locally-signed event (the signature is real - HMAC-SHA256 over `<timestamp>.<payload>` with `STRIPE_WEBHOOK_SECRET`):

  ```nu
  let secret = (^docker exec dev-bunyip-api-($env.USER) printenv STRIPE_WEBHOOK_SECRET | str trim)
  let cus = "cus_..."                       # the member's stripe_customer_id
  let ts = (date now | format date "%s")
  let payload = $'{"id":"evt_local_fail","object":"event","type":"invoice.payment_failed","data":{"object":{"object":"invoice","customer":"($cus)","amount_due":300}}}'
  let sig = ($"($ts).($payload)" | openssl dgst -sha256 -hmac $secret -hex | split row "= " | last)
  curl --silent -X POST http://localhost:4401/v1/webhooks/stripe --header $"Stripe-Signature: t=($ts),v1=($sig)" --header "Content-Type: application/json" --data $payload
  ```

  `invoice.payment_failed` moves the member to `grace_period` (30-day window); resending with `type=invoice.payment_succeeded` and `amount_paid` clears it back to `active`. Cancel / plan-change can be driven from the dashboard or via `stripe trigger customer.subscription.{updated,deleted}` with a customer override.

### Test cards

Any future expiry, any CVC, any postal code. Full list:
<https://docs.stripe.com/testing>.

| Card number          | Behaviour                                   |
| -------------------- | ------------------------------------------- |
| 4242 4242 4242 4242  | Visa, succeeds (happy-path subscribe)       |
| 4000 0000 0000 9995  | Declined: insufficient funds                |
| 4000 0000 0000 0341  | Attaches, then the charge fails             |
| 4000 0000 0000 0002  | Declined: generic card decline              |

There is no "all 9s" success card; the 9s appear in the decline cards above.

## Cleanup

- Stop the listener with `Ctrl-C`; the `whsec_...` it issued is invalidated, so clear `STRIPE_WEBHOOK_SECRET` (a stale value makes every delivery fail signature verification).
- Test-mode data (customers, subscriptions, events) lives only in Test mode and never touches live data; delete test customers from the dashboard if you want a clean slate.

## Verification status (BUNYIP-175)

Verified end to end on the dev-sso stack with provisioned test-mode keys:

- A `4242` checkout activates membership (`subscription_status=active`, `price_locked=true`) via `checkout.session.completed` + `customer.subscription.created`.
- The grace cycle works: a customer-scoped `invoice.payment_failed` moves the member to `grace_period` (30-day window), and `invoice.payment_succeeded` clears it back to `active`.

Outstanding: tier resolution from a mapped product (Step 4) is intentionally not
wired, since the M1 plan removes the tiers
(`docs/dev-docs/billing-m1-implementation-plan.md`, decision 1). Revisit only if the
single-plan collapse is abandoned.
