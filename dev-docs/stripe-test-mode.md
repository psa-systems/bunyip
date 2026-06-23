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

- `checkout.session.completed` activates membership and locks the price.
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

## Step 3 - map test-mode products to tiers

Create test-mode Products and Prices (Dashboard -> Product catalog, in Test
mode) and map their **product ids** into the tier config (lifetime /
early-adopter / standard) so `resolve_tier_for_product`
(`bunyip-api/src/handlers/webhook.rs`) resolves a tier. Without a mapping a
created subscription still activates membership but leaves the tier unchanged.

## Step 4 - drive the lifecycle

- **Subscribe (happy path).** In the app's checkout, pay with the canonical test card below. The subscription activates through `checkout.session.completed` + `customer.subscription.created`; the dashboard shows the membership as Active.
- **Failure / grace path.** `stripe trigger invoice.payment_failed` starts the 30-day grace period; `stripe trigger invoice.payment_succeeded` clears it. Cancel / plan-change can be driven from the dashboard or via the matching `stripe trigger customer.subscription.{updated,deleted}` events.

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

## What still needs a live test account

Steps 3-5 of the BUNYIP-175 acceptance criteria (a real subscribe activating
membership, the trigger-driven grace cycle, and tier resolution from a mapped
product) are end-to-end checks that require provisioned Stripe test-mode keys.
They are the same `[needs test keys]` items the M1 plan gates
(`dev-docs/billing-m1-implementation-plan.md`).
