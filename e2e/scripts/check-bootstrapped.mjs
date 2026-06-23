#!/usr/bin/env node
// E2E seed readiness gate (BUNYIP-163).
//
// Probes the deployed bunyip-api's `GET /e2e-bootstrapped` and writes
// `bootstrapped=<true|false>` to `$GITHUB_OUTPUT`, so e2e.yml can SKIP the
// Playwright suite (with the job still succeeding) when staging is not seeded.
// That lets `e2e` be a REQUIRED check without a merge lockout: a missing or
// removed E2E seed skips coverage instead of blocking every PR.
//
// Fail-open by design: any non-200 / parse / network error yields
// `bootstrapped=false` (skip, never block), and the script always exits 0.

import { appendFileSync } from 'node:fs';

function pick(...values) {
  for (const v of values) {
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
  }
  return '';
}

// The endpoint lives at the OP/API host root (api.<tld>/e2e-bootstrapped),
// resolved the same way the deploy-sync and reachability gates resolve it.
function deriveOpBase(hubUrl) {
  try {
    const u = new URL(hubUrl);
    if (u.hostname.startsWith('api.')) return '';
    return `${u.protocol}//api.${u.hostname}`;
  } catch {
    return '';
  }
}

function setOutput(bootstrapped) {
  const out = process.env.GITHUB_OUTPUT;
  if (out) appendFileSync(out, `bootstrapped=${bootstrapped}\n`);
  console.log(`bootstrapped=${bootstrapped}`);
}

const hubBaseURL = pick(process.env.E2E_BASE_URL);
const opBaseURL = pick(process.env.E2E_OP_BASE_URL, deriveOpBase(hubBaseURL), hubBaseURL).replace(
  /\/+$/,
  '',
);

if (!opBaseURL) {
  console.warn('No E2E_OP_BASE_URL / E2E_BASE_URL set; treating staging as not bootstrapped.');
  setOutput(false);
  process.exit(0);
}

const url = `${opBaseURL}/e2e-bootstrapped`;
const TIMEOUT_MS = 15_000;
const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

try {
  const res = await fetch(url, {
    headers: { accept: 'application/json' },
    signal: controller.signal,
  });
  if (!res.ok) {
    console.warn(`${url} -> HTTP ${res.status}; treating as not bootstrapped.`);
    setOutput(false);
    process.exit(0);
  }
  const body = await res.json();
  const bootstrapped = body?.bootstrapped === true;
  console.log(`${url} -> bootstrapped=${bootstrapped}`);
  setOutput(bootstrapped);
} catch (err) {
  console.warn(`Could not reach ${url}: ${String(err)}; treating as not bootstrapped.`);
  setOutput(false);
} finally {
  clearTimeout(timer);
}

process.exit(0);
