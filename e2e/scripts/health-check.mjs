#!/usr/bin/env node
// PR-mode reachability check: a PR's SHA never deploys, so the
// wait-for-deploy.mjs `/v1/version` SHA gate would always time out for PRs.
// Replace it with a one-shot `GET /health` that just confirms the deployment
// is up and the suite has something to talk to. The actual coverage gate is
// the Playwright suite that runs after this script.
//
// `/health` is a root-level endpoint on the OP/API host (returns
// `{status,version}`), distinct from the `/v1/*` JSON API. On bunyip the
// OIDC OP and the `/v1/*` API share one host (api.<tld>); resolve it the same
// way the deploy-sync gate does.

function pick(...values) {
  for (const v of values) {
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
  }
  return '';
}

function deriveOpBase(hubUrl) {
  try {
    const u = new URL(hubUrl);
    if (u.hostname.startsWith('api.')) return '';
    return `${u.protocol}//api.${u.hostname}`;
  } catch {
    return '';
  }
}

// Required: no domain is hardcoded as a fallback. Inject the per-environment
// hub host (staging `https://a8n.systems`, prod `https://psa.systems`).
const hubBaseURL = pick(process.env.E2E_BASE_URL);
if (!hubBaseURL) {
  console.error('E2E_BASE_URL is unset; set it to the hub host (see e2e/.env.example). Aborting.');
  process.exit(1);
}
const opBaseURL = pick(
  process.env.E2E_OP_BASE_URL,
  deriveOpBase(hubBaseURL),
  hubBaseURL,
).replace(/\/+$/, '');

const healthUrl = `${opBaseURL}/health`;
const TIMEOUT_MS = 30_000;

console.log(`PR mode: probing ${healthUrl} (timeout ${TIMEOUT_MS / 1000}s)...`);

const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

try {
  const res = await fetch(healthUrl, {
    headers: { accept: 'application/json' },
    signal: controller.signal,
  });
  if (!res.ok) {
    console.error(`Deployment /health returned HTTP ${res.status}.`);
    process.exit(1);
  }
  console.log(`Deployment /health -> ${res.status} ok. Proceeding.`);
} catch (err) {
  console.error(`Could not reach ${healthUrl}: ${String(err)}`);
  process.exit(1);
} finally {
  clearTimeout(timer);
}
