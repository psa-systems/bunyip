// Centralised env-var access for the bunyip E2E suite. Required vars fail loud
// so a misconfigured CI run dies with a clear message instead of a confusing
// mid-test 401/redirect.

import { config as loadEnv } from 'dotenv';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Load e2e/.env BEFORE reading process.env so dotenv-only values are visible
// to every consumer. CI injects the same vars from Forgejo secrets, so a
// missing file is fine (override:false keeps real env winning).
const here = dirname(fileURLToPath(import.meta.url));
loadEnv({ path: resolve(here, '..', '.env'), override: false });

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') {
    throw new Error(
      `Missing required env var ${name}. Set it in e2e/.env (local) or as a ` +
        `Forgejo Actions secret (CI). See e2e/README.md.`,
    );
  }
  return value.trim();
}

function optional(name: string): string | undefined {
  const value = process.env[name];
  return value === undefined || value.trim() === '' ? undefined : value.trim();
}

// Derive the OP/API host from the hub-web host by prepending `api.`. bunyip's
// canonical staging deploy serves the hub at `a8n.systems` and the API/OP at
// `api.a8n.systems` (prod: `psa.systems` -> `api.psa.systems`). Returns null
// when the hub host is already prefixed or the URL cannot be parsed.
function deriveApiBase(hubUrl: string): string | null {
  try {
    const u = new URL(hubUrl);
    if (u.hostname.startsWith('api.')) return null;
    return `${u.protocol}//api.${u.hostname}`;
  } catch {
    return null;
  }
}

// Required: no domain is ever hardcoded as a fallback. The hub host differs
// per environment (staging `https://a8n.systems`, prod `https://psa.systems`),
// so the operator must inject it explicitly.
// Strip a trailing slash so `${base}${route}` (e.g. in discoverOidc) never
// produces a double slash like `https://api.a8n.systems//v1/...`, mirroring the
// gate scripts' own normalisation.
const stripTrailingSlash = (u: string): string => u.replace(/\/+$/, '');

const hubBaseURL = stripTrailingSlash(required('E2E_BASE_URL'));
const derivedApi = deriveApiBase(hubBaseURL);
// The OIDC OP and the `/v1/*` JSON API are the SAME host on bunyip (bunyip-api
// serves both under `api.<tld>`). E2E_OP_BASE_URL is supplied explicitly in CI
// (= OIDC_ISSUER_*); locally it falls back to `api.<hub host>`.
const opBaseURL = stripTrailingSlash(optional('E2E_OP_BASE_URL') ?? derivedApi ?? hubBaseURL);
const apiBaseURL = stripTrailingSlash(optional('E2E_API_BASE_URL') ?? opBaseURL);

// Whether the hub host is the production apex. Billing write specs skip on
// production so a manual prod dispatch never creates a live subscription.
function isProductionApex(hubUrl: string): boolean {
  try {
    return new URL(hubUrl).hostname === 'psa.systems';
  } catch {
    return false;
  }
}

export const env = {
  // Where a human browser hits bunyip-web (login form, /settings, /membership).
  // The `ui` project navigates here.
  baseURL: hubBaseURL,
  // Where bunyip-api serves the `/v1/*` JSON API. The `api` project and
  // teardown hit this host. Same host as the OP on bunyip.
  apiBaseURL,
  // Where the OIDC OP (authorize / token / userinfo / discovery) lives.
  opBaseURL,
  // True when targeting the production apex; gates billing write specs.
  isProductionApex: isProductionApex(hubBaseURL),
  get email() {
    return required('E2E_EMAIL');
  },
  get password() {
    return required('E2E_PASSWORD');
  },
  get tenantId() {
    return required('E2E_TENANT_ID');
  },
  get oidcClientId() {
    return required('E2E_OIDC_CLIENT_ID');
  },
  get oidcRedirectUri() {
    // Required: OIDC clients are registered with specific callback paths.
    // Defaulting to the bare deployment root produces invalid_redirect_uri
    // at /oauth2/authorize or /oauth2/token. Force an explicit registered URI.
    return required('E2E_OIDC_REDIRECT_URI');
  },
  get totpSecret() {
    // Required: the E2E account is expected to have 2FA on, mirroring the
    // production hardening posture. Setup drives the second factor by
    // generating a TOTP code from this base32 secret. See lib/login.ts.
    return required('E2E_TOTP_SECRET');
  },
  // Optional: a Stripe test-mode secret key (`sk_test_...`) used ONLY by
  // teardown to cancel test-mode subscriptions the billing specs create.
  stripeSecretKey: optional('E2E_STRIPE_SECRET_KEY'),
  // Optional: the staging mail-sink JMAP base URL with the E2E mailbox's
  // credentials embedded as basicAuth userinfo, e.g.
  // `https://nate%40a8n.run:password@mail.a8n.run` (Stalwart). The email-driven
  // specs read token-links from this mailbox over JMAP and address unique
  // plus-subaddresses of it. STAGING ONLY - production has no sink, so the
  // password-reset / magic-link / change-email specs skip when this is unset
  // (BUNYIP-150).
  mailSinkURL: optional('E2E_MAIL_SINK_URL'),
} as const;

// All env vars the suite cannot run without, in the order an operator would
// reasonably fill them in. Each entry pairs the var name with a one-line
// purpose so the aggregated error names what each missing value is for.
const REQUIRED: Array<{ name: string; purpose: string }> = [
  {
    name: 'E2E_BASE_URL',
    purpose: 'hub-web host the suite navigates to (e.g. https://a8n.systems); no default',
  },
  { name: 'E2E_EMAIL', purpose: 'login email of the dedicated E2E account' },
  { name: 'E2E_PASSWORD', purpose: 'password for E2E_EMAIL' },
  { name: 'E2E_TENANT_ID', purpose: 'UUID of the dedicated E2E tenant' },
  { name: 'E2E_OIDC_CLIENT_ID', purpose: 'public PKCE client id for the OP token-flow test' },
  {
    name: 'E2E_OIDC_REDIRECT_URI',
    purpose: 'redirect_uri registered for E2E_OIDC_CLIENT_ID (must match exactly)',
  },
  {
    name: 'E2E_TOTP_SECRET',
    purpose: 'base32 TOTP secret for the E2E account, used to compute the second factor',
  },
];

/// Verify every required env var is present and non-empty. Aggregates ALL
/// missing names into a single error so the operator sees the full
/// configuration gap in one round trip instead of fixing-and-rerunning once
/// per missing key. Called from the `preflight` setup project so it runs
/// before any other project's tests.
export function preflightRequiredEnv(): void {
  const missing = REQUIRED.filter(({ name }) => {
    const value = process.env[name];
    return value === undefined || value.trim() === '';
  });
  if (missing.length === 0) return;
  const lines = missing.map(({ name, purpose }) => `  - ${name}: ${purpose}`);
  throw new Error(
    `Missing ${missing.length} required env var(s). Set in e2e/.env (local) or as ` +
      `Forgejo Actions secrets (CI). See e2e/README.md.\n${lines.join('\n')}`,
  );
}
