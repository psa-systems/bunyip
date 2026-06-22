import { test as setup } from '@playwright/test';
import { preflightRequiredEnv } from '../lib/env';

// Runs before every other project. Aggregates every missing required env var
// into one error so a misconfigured CI run names the full configuration gap in
// a single round trip instead of failing one key at a time.
setup('verify required env vars are present', () => {
  preflightRequiredEnv();
});
