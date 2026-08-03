#!/usr/bin/env node
// Deploy-sync gate: block the E2E run until the deployed bunyip instance is
// actually serving a commit at-or-newer than the most recent one that would
// have produced an OCI image.
//
// The build-api.yml and build-web.yml workflows only fire when one of a fixed
// set of paths changes (see BUILD_TRIGGER_PATHS below). A commit to main that
// touches only docs/tests/CI never republishes an image, so the deployment
// keeps serving the PREVIOUS build. Polling for GITHUB_SHA in that case times
// out on a hash the deployment can never report.
//
// Resolve the expected SHA the same way the build trigger does: walk
// `git log` from GITHUB_SHA backwards, find the most recent commit that
// touched a build-trigger path, and poll for THAT hash. When the current
// commit IS build-relevant, the result equals GITHUB_SHA. When it isn't, the
// result is the latest commit that actually produced an image, which is
// exactly what the deployment is running.
//
// The script polls <op>/v1/version every 15s for up to 10 minutes and
// compares the reported `commit` (the SHORT git hash baked from the
// GIT_COMMIT build arg, `git rev-parse --short HEAD`) against the resolved
// expected SHA via GITHUB_SHA.startsWith(commit). We use /v1/version, NOT
// the root /version: /version's `.revision` reads BUNYIP_GIT_SHA, which the
// Dockerfile never sets, so it is always empty.
//
// On bunyip the OIDC OP and the `/v1/*` JSON API share one host (api.<tld>).
// Prefer an explicit E2E_OP_BASE_URL; otherwise prepend `api.` to
// E2E_BASE_URL; otherwise fall back to E2E_BASE_URL (same-origin only).

import { execFileSync } from 'node:child_process';

// Keep in lock-step with the union of on.push.paths across build-api.yml and
// build-web.yml. A path here that neither build workflow lists will make the
// gate poll for a SHA the deployment never serves; a path a build lists that
// this misses will make the gate accept a stale deploy. Audit all three
// together. `migrations/` is deliberately absent: there is no top-level
// migrations dir (migrations live under bunyip-api/migrations/), so the
// `bunyip-api` entry already covers them.
const BUILD_TRIGGER_PATHS = [
  'bunyip-api', // build-api.yml: bunyip-api/**
  'bunyip-web', // build-web.yml: bunyip-web/**
  'crates', // build-api.yml: crates/**
  'Cargo.toml', // build-api.yml + build-web.yml
  'Cargo.lock', // build-api.yml + build-web.yml
  '.sqlx', // build-api.yml: .sqlx/**
  'oci-build', // build-api.yml + build-web.yml: oci-build/**
  '.forgejo/workflows/build-api.yml', // build-api.yml self-trigger
  '.forgejo/workflows/build-web.yml', // build-web.yml self-trigger
];

// Forgejo Actions passes the literal empty string for secrets that are not
// configured, so `??` alone would not fall back. Treat empty/whitespace as
// missing, matching e2e/lib/env.ts.
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

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8' }).trim();
}

function isShallow() {
  try {
    return git(['rev-parse', '--is-shallow-repository']) === 'true';
  } catch {
    return false;
  }
}

function tryUnshallow() {
  try {
    console.log('  clone is shallow; running `git fetch --unshallow origin` ...');
    execFileSync('git', ['fetch', '--unshallow', 'origin'], { stdio: 'inherit' });
    return true;
  } catch (err) {
    console.warn(`  unshallow attempt failed: ${String(err)}`);
    return false;
  }
}

// Forgejo's actions/checkout has been observed to clone with --filter=blob:none
// or --filter=tree:0 even when fetch-depth: 0 is set, leaving the local clone
// without the tree objects `git log -- <path>` needs to test path membership.
// The query then silently returns zero matches even though the commits are
// present. `git fetch --refetch origin` repopulates the missing objects.
function tryRefetch() {
  try {
    console.log('  refetching objects without filter (`git fetch --refetch origin`) ...');
    execFileSync('git', ['fetch', '--refetch', 'origin'], { stdio: 'inherit' });
    return true;
  } catch (err) {
    console.warn(`  refetch attempt failed: ${String(err)}`);
    return false;
  }
}

function buildShaQuery(headSha) {
  return git(['log', '-1', '--format=%H', headSha, '--', ...BUILD_TRIGGER_PATHS]);
}

// Return the most recent commit at-or-before `headSha` that touched any
// BUILD_TRIGGER_PATHS entry. The Forgejo runner's actions/checkout has been
// observed to honour fetch-depth: 0 inconsistently AND to apply object
// filters that strip the trees `git log -- <path>` needs, so self-heal in
// two stages: unshallow first if the clone is shallow, then refetch
// without filter if the path query still finds nothing.
function resolveBuildSha(headSha) {
  let sha = buildShaQuery(headSha);
  if (sha) return sha;

  if (isShallow() && tryUnshallow()) {
    sha = buildShaQuery(headSha);
    if (sha) return sha;
  }

  if (tryRefetch()) {
    sha = buildShaQuery(headSha);
    if (sha) return sha;
  }

  const depth = (() => {
    try {
      return git(['rev-list', '--count', headSha]);
    } catch {
      return '?';
    }
  })();
  throw new Error(
    `No commit at-or-before ${headSha} touches any build-trigger path ` +
      `(clone depth=${depth}, shallow=${isShallow()}). Check that ` +
      `BUILD_TRIGGER_PATHS in this script matches the build-oci-image ` +
      `workflow's on.push.paths.`,
  );
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
const headSha = pick(process.env.GITHUB_SHA, process.env.E2E_EXPECT_SHA);

const INTERVAL_MS = 15_000;
const TIMEOUT_MS = 10 * 60 * 1000;
const versionUrl = `${opBaseURL}/v1/version`;

if (!headSha) {
  console.error('GITHUB_SHA is unset; cannot verify the deployed commit. Aborting.');
  process.exit(1);
}

let expectedSha;
try {
  expectedSha = resolveBuildSha(headSha);
} catch (err) {
  // All self-heal attempts failed (probably a runner clone we cannot fix
  // from inside the job). Falling back to GITHUB_SHA on a doc/test-only
  // commit re-creates the very problem this gate is meant to avoid -
  // polling for 10m on a SHA the deployment never serves. Skip the gate
  // entirely with a loud warning and let the suite run against whatever the
  // deployment is currently serving. Record that served commit (BUNYIP-448)
  // so the run log always states exactly what was tested, not merely that the
  // gate skipped. fetchCommit is a hoisted function declaration (defined
  // below); versionUrl is already assigned by the time this catch runs.
  const served = await fetchCommit();
  const servedDesc = served.ok ? `commit=${served.commit || '(empty)'}` : served.detail;
  console.warn('============================================================');
  console.warn(`SKIPPING deploy-sync gate: ${String(err)}`);
  console.warn(`Deployment is currently serving: ${servedDesc}`);
  console.warn('Tests will run against that commit.');
  console.warn('============================================================');
  process.exit(0);
}

if (expectedSha === headSha) {
  console.log(`Head commit ${headSha} is build-relevant; expecting the deployment to serve it.`);
} else {
  console.log(
    `Head commit ${headSha} did not touch any build-trigger path; ` +
      `expecting the deployment to serve ${expectedSha} instead (last build-relevant commit).`,
  );
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchCommit() {
  try {
    const res = await fetch(versionUrl, { headers: { accept: 'application/json' } });
    if (!res.ok) return { ok: false, detail: `HTTP ${res.status}` };
    const body = await res.json();
    return { ok: true, commit: String(body.commit ?? '') };
  } catch (err) {
    return { ok: false, detail: String(err) };
  }
}

const deadline = Date.now() + TIMEOUT_MS;
console.log(`Waiting for ${versionUrl} to report ${expectedSha} (timeout 10m)...`);

let lastSeen = '';
while (Date.now() < deadline) {
  const result = await fetchCommit();
  if (result.ok && result.commit && expectedSha.startsWith(result.commit)) {
    console.log(`Deployment is serving ${result.commit} (matches ${expectedSha}). Proceeding.`);
    process.exit(0);
  }
  const seen = result.ok ? `commit=${result.commit || '(empty)'}` : result.detail;
  if (seen !== lastSeen) {
    console.log(`  not yet (${seen}); polling every ${INTERVAL_MS / 1000}s`);
    lastSeen = seen;
  }
  await sleep(INTERVAL_MS);
}

console.error(`Timed out after 10m: the deployment never picked up ${expectedSha}.`);
process.exit(1);
