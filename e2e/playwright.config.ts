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
    // Run the FULL chromium build, not the default stripped
    // `chromium-headless-shell`. PW 1.60 picks headless-shell for headless runs;
    // it dies on heavier pages (e.g. /settings, which renders profile + email +
    // password + 2FA + sessions + trusted-device forms) with "Target page,
    // context or browser has been closed" and NO page-level crash event, while
    // the lighter /membership survives. The full chromium (installed by
    // `playwright install chromium`) handles the same page. BUNYIP-148.
    channel: 'chromium',
    // --disable-dev-shm-usage: containers (the CI runner) give chromium a tiny
    // /dev/shm, so heavier pages can OOM the browser process. Backing shared
    // memory with /tmp instead avoids that. Kept alongside the full-chromium
    // switch as defense in depth (BUNYIP-148).
    launchOptions: { args: ['--disable-dev-shm-usage'] },
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
      // No retries: this project logs in, and bunyip rate-limits login to
      // 5/min/email. Retrying a rate-limited login just burns more of that
      // budget and cascades one blip into several failures. Fail once instead.
      retries: 0,
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
      // No retries, same reason as `setup`: these specs log in, and a retry of a
      // rate-limited login only deepens the 5/min hole. account-ui / api below
      // keep the global retries (they do not log in).
      retries: 0,
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
    //
    // `dependencies: ['account-ui']` forces the api project to wait for every
    // account-ui spec to finish before any api spec starts. Without this, the
    // workers:1 scheduler interleaves tests across the two projects: a single
    // account-ui spec (memberships) runs, the worker closes its chromium and
    // launches a fresh non-storageState chromium for the api specs, then later
    // tries to relaunch a storageState-loaded chromium for the next account-ui
    // spec (profile / sessions). The second account-ui browser launch is what
    // fails with "Target page, context or browser has been closed" - chromium
    // process pid=1306 closes with exitCode=0 mid-run (DEBUG=pw:browser
    // confirmed it is a clean playwright-initiated close, not a crash), and
    // the relaunch attempt never produces a usable page. Serialising the two
    // projects keeps the storageState chromium alive for one continuous
    // memberships+account+billing pass; the api chromium then runs once and
    // exits. One launch per project = no relaunch-after-close failure mode.
    //
    // Trade-off: total wall-clock is the sum of the two projects' runtimes
    // instead of an interleaved overlap. Since workers:1 already serialises
    // execution there is no real cost; the interleaving was wall-clock-neutral
    // but introduced the relaunch fault. (BUNYIP-148.)
    {
      name: 'api',
      testMatch: /tests\/oidc\/.*\.spec\.ts$/,
      dependencies: ['setup', 'account-ui'],
      use: { baseURL: env.opBaseURL },
    },
  ],
});
