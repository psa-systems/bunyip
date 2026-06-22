import { test as setup } from '@playwright/test';
import { logResolvedConfig, preflightRequiredEnv } from '../lib/env';

// Runs before every other project. Aggregates every missing required env var
// into one error so a misconfigured CI run names the full configuration gap in
// a single round trip instead of failing one key at a time.
setup('verify required env vars are present', () => {
  preflightRequiredEnv();
  // BUNYIP-167 (temporary): dump the resolved host / email / credential
  // fingerprint so a failing run shows exactly which inputs the suite used.
  // Remove once the login mismatch it was added for is resolved.
  logResolvedConfig();
});
