import { defineConfig, devices } from '@playwright/test';
// `lib/env` self-loads e2e/.env (dotenv) on first import so consumers see the
// populated process.env, and exposes the hub-vs-OP host split used below.
import { env } from './lib/env';

// Path the setup project writes its authenticated browser storageState to, and
// the authenticated UI project replays. Reusing one login keeps the suite under
// bunyip's 5-logins-per-minute-per-email rate limit: a fresh login per spec
// would trip it within a handful of specs.
const HUB_STORAGE_STATE = './.auth/hub-state.json';

export default defineConfig({
  testDir: './tests',
  // Teardown deletes this run's records and sweeps stale residue.
  globalTeardown: './tests/global.teardown.ts',
  // Serial: tests share one E2E account + tenant; parallel mutation invites
  // cross-test interference, and concurrent logins would trip the rate limit.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [['list'], ['html', { open: 'never' }]],
  // No top-level baseURL: the hub web and the OP/API live on different hosts
  // (a8n.systems vs api.a8n.systems). Each project picks the right one.
  use: {
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    // 0. Aggregate-all-missing env-var check. Runs first so a misconfigured CI
    //    names every gap in one round trip instead of dying at the first key.
    {
      name: 'preflight',
      testMatch: /preflight\.setup\.ts$/,
    },
    // 1. Log in once via the hub-web form, capture the bearer + OP cookies +
    //    full browser storageState, and drive the OIDC consent Allow so the OP
    //    session carries granted scopes. Persists artifacts under .auth/.
    {
      name: 'setup',
      testMatch: /global\.setup\.ts$/,
      dependencies: ['preflight'],
      use: { ...devices['Desktop Chrome'], baseURL: env.baseURL },
    },
    // 2. Browser-driven auth/session coverage. Starts ANONYMOUS (no
    //    storageState) and does its own login, so its logout assertion never
    //    invalidates the shared session. Depends only on `preflight`. These are
    //    the only specs that consume the login rate limit, so login-bearing
    //    flows are combined and the rest are test.fixme.
    {
      name: 'auth-ui',
      testMatch: /tests\/auth\/.*\.spec\.ts$/,
      dependencies: ['preflight'],
      use: { ...devices['Desktop Chrome'], baseURL: env.baseURL },
    },
    // 3. Authenticated browser coverage (account, memberships, billing). Loads
    //    the storageState `setup` saved, so every spec starts logged in WITHOUT
    //    a fresh login (rate-limit safe).
    {
      name: 'account-ui',
      testMatch: /tests\/(account|memberships|billing)\/.*\.spec\.ts$/,
      dependencies: ['setup'],
      use: { ...devices['Desktop Chrome'], baseURL: env.baseURL, storageState: HUB_STORAGE_STATE },
    },
    // 4. Request-context OIDC OP coverage. The fixtures in lib/fixtures.ts load
    //    the bearer (`test`) or replay the OP cookies (`oidcTest`). Uses the OP
    //    host, not the hub host.
    {
      name: 'api',
      testMatch: /tests\/oidc\/.*\.spec\.ts$/,
      dependencies: ['setup'],
      use: { baseURL: env.opBaseURL },
    },
  ],
});
