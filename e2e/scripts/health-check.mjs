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

// Production apex host. TEMPORARY (BUNYIP-185): until psa.systems serves the
// real /healthz, the hub probe stays SOFT there; everywhere else (staging) it is
// a hard, body-validating check. Remove this carve-out + the `soft` branch in
// probeHub once prod serves /healthz.
const PROD_APEX_HOST = 'psa.systems';

const hubIsProdApex = (() => {
  try {
    return new URL(hubBaseURL).hostname === PROD_APEX_HOST;
  } catch {
    return false;
  }
})();

// Hard probe for the API /health host (status-only: /health is JSON
// `{status,version}` and exists everywhere, so a 200 is sufficient).
async function probe(url) {
  console.log(`PR mode: probing ${url} (timeout ${TIMEOUT_MS / 1000}s)...`);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
    if (!res.ok) {
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

// Hub /healthz probe. bunyip-web returns a soft-404 fallback (HTTP 200 + HTML)
// for unknown paths, so a 200 alone does NOT prove /healthz is the real endpoint
// - require the JSON liveness body `{"status":"ok"}`. `soft` downgrades a
// missing/blank endpoint to a warning; a network failure is always fatal.
//
// Two callers set `soft: true` today:
// - `hubIsProdApex` (BUNYIP-185): psa.systems does not yet serve /healthz.
// - `E2E_HUB_SOFT` env var (BUNYIP-301): set by the PR gate,
//   `.forgejo/workflows/e2e-pr.yml`. A PR's own SHA never deploys, so a broken
//   staging deploy is not a signal about THIS PR's quality; downgrading to a
//   warning stops staging outages from deadlocking outage-fix PRs. The push
//   (post-merge deploy) path uses `wait-for-deploy.mjs` instead of this
//   script, so post-merge staging-broken alerting is unchanged. A production
//   `workflow_dispatch` stays hard: it does not set E2E_HUB_SOFT.
async function probeHub(url, { soft = false } = {}) {
  console.log(`PR mode: probing ${url} (timeout ${TIMEOUT_MS / 1000}s)...`);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
    let body = null;
    if (res.ok) {
      try {
        body = await res.json();
      } catch {
        body = null;
      }
    }
    const live = res.ok && body && body.status === 'ok';
    if (!live) {
      const ct = res.headers.get('content-type') || '';
      const detail = res.ok
        ? `200 but not the /healthz JSON {"status":"ok"} (ct=${ct}); a soft-404 fallback is masking a missing endpoint`
        : `HTTP ${res.status}`;
      if (soft) {
        console.warn(`${url} -> ${detail}; hub probe soft (prod-apex carve-out or E2E_HUB_SOFT), continuing.`);
        return false;
      }
      console.error(`${url} -> ${detail}.`);
      process.exit(1);
    }
    console.log(`${url} -> 200 {"status":"ok"} ok.`);
    return true;
  } catch (err) {
    console.error(`Could not reach ${url}: ${String(err)}`);
    process.exit(1);
  } finally {
    clearTimeout(timer);
  }
}

// API/OP host is a hard gate (its /health exists everywhere).
await probe(healthUrl);
// Hub /healthz: hard + body-validating, except the prod apex stays soft until
// psa.systems serves it (BUNYIP-185) OR the caller sets E2E_HUB_SOFT=true
// (BUNYIP-301: set by e2e-pr.yml so a broken staging deploy does not deadlock
// outage-fix PRs). See probeHub docstring for the full contract.
const hubSoft = hubIsProdApex || process.env.E2E_HUB_SOFT === 'true';
await probeHub(hubHealthzUrl, { soft: hubSoft });
console.log('Reachability checks complete. Proceeding.');
