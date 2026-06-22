import { existsSync } from 'node:fs';
import { TOKEN_FILE } from '../lib/auth-state';
import { env } from '../lib/env';
import { isOwnedByThisRun, isStale } from '../lib/run';

// Global teardown: best-effort cleanup of records THIS run created plus stale
// e2e residue from earlier failed runs. Best-effort BY DESIGN - a teardown
// failure must never mask a green/red test result, so EVERYTHING here is wrapped
// and nothing throws.
//
// Unlike the mokosh suite (which creates companies/contacts/tickets/...), bunyip
// specs mostly read or mutate the existing E2E account, so there is little to
// sweep on the API side. The one externally-created resource is a test-mode
// Stripe subscription the billing specs may create; cancel those here when a
// Stripe TEST key is configured. Everything else is a no-op until those specs
// land.

// Stripe REST. Hit directly with fetch (no Stripe SDK dependency in e2e).
const STRIPE_API = 'https://api.stripe.com/v1';
const STRIPE_TEST_KEY_PREFIX = 'sk_test_';

interface StripeSubscription {
  id: string;
  description?: string | null;
  metadata?: Record<string, string> | null;
}

interface StripeList<T> {
  data?: T[];
}

// A subscription is ours to cancel when any text it carries (its description or
// any metadata value) matches this run's tag or is stale e2e residue.
function subscriptionIsSweepable(sub: StripeSubscription, now: number): boolean {
  const texts: string[] = [];
  if (sub.description) texts.push(sub.description);
  if (sub.metadata) texts.push(...Object.values(sub.metadata));
  return texts.some((t) => isOwnedByThisRun(t) || isStale(t, now));
}

// Cancel test-mode Stripe subscriptions the billing specs created. Skipped
// entirely unless a Stripe TEST key (`sk_test_...`) is configured - the common
// case until staging Stripe is provisioned. Never throws.
async function sweepStripeSubscriptions(now: number): Promise<string> {
  const key = env.stripeSecretKey;
  if (!key) {
    return 'stripe skipped (no E2E_STRIPE_SECRET_KEY)';
  }
  if (!key.startsWith(STRIPE_TEST_KEY_PREFIX)) {
    // Guard against ever touching live data: only test-mode keys are swept.
    return `stripe skipped (key is not ${STRIPE_TEST_KEY_PREFIX}*; live keys are never swept)`;
  }

  const authHeader = { Authorization: `Bearer ${key}` };
  let subs: StripeSubscription[] = [];
  try {
    const res = await fetch(`${STRIPE_API}/subscriptions?status=active&limit=100`, {
      headers: authHeader,
    });
    if (!res.ok) {
      return `stripe list failed: ${res.status}`;
    }
    const body = (await res.json()) as StripeList<StripeSubscription>;
    subs = body.data ?? [];
  } catch (err) {
    return `stripe list threw: ${String(err)}`;
  }

  let cancelled = 0;
  let failed = 0;
  for (const sub of subs) {
    if (!subscriptionIsSweepable(sub, now)) continue;
    try {
      // DELETE /v1/subscriptions/<id> cancels the subscription immediately.
      const res = await fetch(`${STRIPE_API}/subscriptions/${sub.id}`, {
        method: 'DELETE',
        headers: authHeader,
      });
      if (res.ok) cancelled += 1;
      else {
        failed += 1;
        console.warn(`[teardown] stripe cancel ${sub.id} -> ${res.status}`);
      }
    } catch (err) {
      failed += 1;
      console.warn(`[teardown] stripe cancel ${sub.id} threw: ${String(err)}`);
    }
  }
  return `stripe cancelled=${cancelled} failed=${failed} (of ${subs.length} active)`;
}

export default async function globalTeardown(): Promise<void> {
  // No bearer on disk means setup never completed; there is nothing this run
  // created, so skip cleanup entirely.
  if (!existsSync(TOKEN_FILE)) {
    console.warn('[teardown] no bearer token on disk; skipping cleanup (setup likely failed)');
    return;
  }

  const now = Date.now();
  const summary: string[] = [];
  try {
    summary.push(await sweepStripeSubscriptions(now));
  } catch (err) {
    // sweepStripeSubscriptions already swallows its own errors; this is a final
    // belt-and-braces guard so teardown can never throw.
    console.warn(`[teardown] stripe sweep threw unexpectedly: ${String(err)}`);
  }

  const meaningful = summary.filter((s) => s && !/cancelled=0 failed=0/.test(s) && !/skipped/.test(s));
  if (meaningful.length === 0) {
    console.log(`[teardown] nothing to sweep (${summary.join('; ') || 'no actions'})`);
  } else {
    console.log(`[teardown] ${summary.join('; ')}`);
  }
}
