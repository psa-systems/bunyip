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
// Hub liveness (BUNYIP-149): bunyip-web's /healthz, the SSR app the browser
// specs actually drive. The API /health above only proves the OP/API host is
// up, not the hub - so probe both before the suite runs.
const hubHealthzUrl = `${hubBaseURL.replace(/\/+$/, '')}/healthz`;
const TIMEOUT_MS = 30_000;

// `soft` tolerates a non-2xx response (warns and continues) but still treats a
// network-level failure (host unreachable) as fatal. Used for the hub /healthz
// during its rollout: PR SHAs never deploy, so on the PR that ADDS /healthz the
// live staging hub does not serve it yet, and a hard 404 here would deadlock the
// very PR introducing it (BUNYIP-149, same deploy-transition shape as
// BUNYIP-183). Tighten to a hard check once /healthz is deployed everywhere.
async function probe(url, { soft = false } = {}) {
  console.log(`PR mode: probing ${url} (timeout ${TIMEOUT_MS / 1000}s)...`);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
    if (!res.ok) {
      if (soft) {
        console.warn(`${url} -> HTTP ${res.status} (not deployed yet?); continuing.`);
        return;
      }
      console.error(`${url} returned HTTP ${res.status}.`);
      process.exit(1);
    }
    console.log(`${url} -> ${res.status} ok.`);
  } catch (err) {
    console.error(`Could not reach ${url}: ${String(err)}`);
    process.exit(1);
  } finally {
    clearTimeout(timer);
  }
}

// API/OP host is the hard gate (its /health already exists everywhere).
await probe(healthUrl);
// Hub /healthz is additive + soft until universally deployed (see above).
await probe(hubHealthzUrl, { soft: true });
console.log('Reachability checks complete. Proceeding.');
