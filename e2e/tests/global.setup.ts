import { expect, test as setup, type Request as PwRequest, type Response as PwResponse } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { OP_STORAGE_STATE_FILE, TOKEN_FILE } from '../lib/auth-state';
import { env } from '../lib/env';
import { loginViaHub } from '../lib/login';
import { makePkce, randomToken } from '../lib/api';

// Runs once (project `setup`) after `preflight`. Drives the bunyip-web hub login
// in a real browser and persists four artifacts under e2e/.auth/:
//
//  - token.txt        : the bunyip access_token, for the bearer-auth `api`/oidc
//                       fixtures and teardown.
//  - hub-state.json   : the FULL authenticated browser storageState, replayed by
//                       the `account-ui` project so its specs start logged in
//                       without a fresh login. bunyip allows only 5 logins per
//                       minute per email, so re-login-per-spec would trip the
//                       limit; one shared login keeps the suite under it.
//  - op-state.json    : a Playwright storageState-shaped JSON of the OP-session
//                       cookies, replayed by the OIDC specs so `/oauth2/authorize`
//                       sees a server-validated session and mints a `code`.
//
// bunyip-web is server-rendered (NOT a WASM SPA), so the access_token is normally
// available straight off the `access_token` cookie that login sets. Two response/
// request sniffers are attached BEFORE login as fallbacks (a `/oauth2/token`
// response body and an `Authorization: Bearer` request header) so a markup/flow
// change that stops setting the cookie still yields a token instead of a blind
// timeout. The rich URL-trail diagnostic is kept from the mokosh template so a
// failure names exactly which capture paths were tried.

// The legacy bearer cookie bunyip sets on hub login. Primary capture path.
const ACCESS_TOKEN_COOKIE = 'access_token';

// The OP-session cookie `/oauth2/authorize` gates on (bunyip-domain OP_SESSION
// cookie). Scoped by the OP's COOKIE_DOMAIN env: on the OP host, possibly the
// parent apex. Missing it means authorize 302s to /login and the OIDC specs fail.
const OP_SESSION_COOKIE = 'bunyip_op_session';

// bunyip's OIDC token endpoint. Matched path-only so a host move does not break
// the fallback capture - any host exposing POST `/oauth2/token` counts.
const TOKEN_ENDPOINT_RE = /\/oauth2\/token(?:\?|$)/;

// Cap on URL samples in the timeout diagnostic: enough to see the traffic
// pattern, low enough to keep the error readable.
const URL_SAMPLE_CAP = 30;

// e2e/ root, derived from this file's location, for resolving .auth paths.
const here = dirname(fileURLToPath(import.meta.url));
const HUB_STATE_FILE = resolve(here, '..', '.auth', 'hub-state.json');

setup('capture bearer + OP cookies from the hub login', async ({ page }) => {
  let token: string | null = null;
  let tokenSourceUrl: string | null = null;
  const allRequestUrls: string[] = [];
  const bearerRequestUrls: string[] = [];
  // Token-endpoint responses observed (url + status), for the timeout
  // diagnostic. Empty when OIDC token exchange never fired.
  const tokenEndpointResponses: Array<{ url: string; status: number }> = [];

  // FALLBACK 1: first request carrying an `Authorization: Bearer` header.
  page.on('request', (req: PwRequest) => {
    const url = req.url();
    allRequestUrls.push(url);
    const auth = req.headers()['authorization'];
    if (!auth || !auth.toLowerCase().startsWith('bearer ')) return;
    bearerRequestUrls.push(url);
    if (token) return;
    token = auth.slice('bearer '.length).trim();
    tokenSourceUrl = url;
  });

  // FALLBACK 2: read the access_token out of the first OK `/oauth2/token`
  // response body. Survives a flow that gets the token but never re-sends it as
  // a bearer header. Ignores failed exchanges and non-JSON bodies.
  const tryCaptureFromTokenResponse = async (resp: PwResponse) => {
    const url = resp.url();
    if (!TOKEN_ENDPOINT_RE.test(url)) return;
    tokenEndpointResponses.push({ url, status: resp.status() });
    if (token) return;
    if (!resp.ok()) return;
    let body: unknown;
    try {
      body = await resp.json();
    } catch {
      return;
    }
    if (typeof body !== 'object' || body === null) return;
    const at = (body as Record<string, unknown>)['access_token'];
    if (typeof at !== 'string' || at.length === 0) return;
    token = at;
    tokenSourceUrl = url;
  };
  page.on('response', (resp: PwResponse) => {
    void tryCaptureFromTokenResponse(resp);
  });

  // Track every top-frame navigation. On failure we dump the trail to see
  // whether login bounced through /login -> /login/2fa -> landing correctly.
  const urlTrail: string[] = [];
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) urlTrail.push(frame.url());
  });

  await loginViaHub(page);
  const postLoginUrl = page.url();

  // PRIMARY capture: the `access_token` cookie bunyip sets on a successful hub
  // login. This is the normal server-rendered path; the request/response
  // sniffers above only matter if this cookie ever stops being set.
  const readAccessTokenCookie = async (): Promise<string | null> => {
    const cookies = await page.context().cookies();
    const c = cookies.find((x) => x.name === ACCESS_TOKEN_COOKIE && x.value);
    return c ? c.value : null;
  };

  try {
    await expect
      .poll(
        async () => {
          if (token) return token;
          const cookieToken = await readAccessTokenCookie();
          if (cookieToken) {
            token = cookieToken;
            tokenSourceUrl = `cookie:${ACCESS_TOKEN_COOKIE}`;
          }
          return token;
        },
        {
          timeout: 30_000,
          message:
            `no access_token captured from the ${ACCESS_TOKEN_COOKIE} cookie, a ` +
            `/oauth2/token response, or a Bearer header`,
        },
      )
      .not.toBeNull();
  } catch (err) {
    // expect.poll's `message` is static, so rebuild the dynamic diagnostic on
    // the way out: did login complete, did any request fly, did any carry a
    // bearer, did the token exchange even happen.
    const sample = (arr: string[]) =>
      arr.length === 0 ? '(none)' : arr.slice(-URL_SAMPLE_CAP).join('\n    ');
    const finalUrl = page.url();
    const tokenExchanges =
      tokenEndpointResponses.length === 0
        ? '(none observed; OIDC token exchange never fired)'
        : tokenEndpointResponses
            .slice(-URL_SAMPLE_CAP)
            .map((r) => `${r.status} ${r.url}`)
            .join('\n    ');
    const cookieNames = (await page.context().cookies())
      .map((c) => `${c.domain}#${c.name}`)
      .join(', ');
    throw new Error(
      [
        'No access_token captured after hub login completed (30s timeout).',
        '  Tried capture paths: ' +
          `cookie:${ACCESS_TOKEN_COOKIE}, /oauth2/token response body, Authorization: Bearer header.`,
        `  postLoginUrl=${postLoginUrl}`,
        `  finalUrl=${finalUrl}`,
        `  cookies present: ${cookieNames || '(none)'}`,
        `  /oauth2/token responses (status + url, last ${URL_SAMPLE_CAP}):\n    ${tokenExchanges}`,
        `  urlTrail (last ${URL_SAMPLE_CAP}):\n    ${sample(urlTrail)}`,
        `  Bearer-carrying requests (last ${URL_SAMPLE_CAP}):\n    ${sample(bearerRequestUrls)}`,
        `  ALL requests (last ${URL_SAMPLE_CAP}):\n    ${sample(allRequestUrls)}`,
        `  underlying: ${String(err)}`,
      ].join('\n'),
    );
  }

  console.log(`[setup] captured bearer from ${tokenSourceUrl}`);
  mkdirSync(dirname(TOKEN_FILE), { recursive: true });
  writeFileSync(TOKEN_FILE, token!);

  // Persist the full authenticated browser storageState BEFORE consent so the
  // `account-ui` project can start logged in even if the consent drive below
  // fails. Re-saved after consent so the persisted session carries the grant.
  await page.context().storageState({ path: HUB_STATE_FILE });
  console.log(`[setup] persisted hub storageState to ${HUB_STATE_FILE}`);

  // Capture OP-session cookies for the OIDC specs. Filter to the OP host and its
  // parent apex: on bunyip-as-OP the OP-session cookie lives on the OP host
  // (e.g. api.a8n.systems) while hub access/refresh cookies live on the apex
  // (a8n.systems). Both are kept; unrelated cookies (CDNs, analytics) are dropped.
  await persistOpCookies(page);

  // Drive OIDC consent once so granted scopes exist for the later token-flow
  // specs. Best-effort: the post-consent redirect to the registered redirect_uri
  // is an app callback that may 404 in this context, so the whole thing is
  // wrapped and never fails setup.
  await driveConsent(page);

  // Re-save AFTER consent so the granted-scope session is what gets persisted.
  await page.context().storageState({ path: HUB_STATE_FILE });
  await persistOpCookies(page);
  console.log('[setup] re-persisted hub storageState + OP cookies after consent');
});

// Filter the browser's cookies to the OP host + parent apex and write a
// Playwright storageState-shaped JSON to OP_STORAGE_STATE_FILE. Logs a full
// kept/dropped inventory by name, WARNs if the OP-session cookie is missing, and
// throws if zero OP cookies matched at all.
async function persistOpCookies(page: import('@playwright/test').Page): Promise<void> {
  const opCookieDomains = computeOpCookieDomains(env.opBaseURL);
  const allCookies = await page.context().cookies();
  const opCookies = allCookies.filter((c) => {
    const d = c.domain.startsWith('.') ? c.domain.slice(1) : c.domain;
    return opCookieDomains.has(d);
  });

  // KEEP/drop inventory by name+domain+path (no values - keep secrets out of
  // logs). Makes "captured set non-empty but missing bunyip_op_session because
  // it was set on a host outside the filter" diagnosable from run output alone.
  const keptKeys = new Set(opCookies.map((c) => `${c.domain}${c.path}#${c.name}`));
  const cookieInventory = allCookies
    .map((c) => {
      const key = `${c.domain}${c.path}#${c.name}`;
      return `${keptKeys.has(key) ? 'KEEP' : 'drop'} ${c.domain}#${c.name}`;
    })
    .join('\n    ');
  console.log(
    `[setup] OP cookie inventory (KEEP = matched ${[...opCookieDomains].join('/')}):\n    ${
      cookieInventory || '(no cookies)'
    }`,
  );

  if (!opCookies.some((c) => c.name === OP_SESSION_COOKIE)) {
    const onAnyHost = allCookies.some((c) => c.name === OP_SESSION_COOKIE);
    console.warn(
      `[setup] WARNING: ${OP_SESSION_COOKIE} not in the persisted OP set` +
        `${
          onAnyHost
            ? ' (present in the browser but on a domain outside the filter - check COOKIE_DOMAIN vs opBaseURL)'
            : ' (not set by login at all - check the OP login/SSO step)'
        }.` +
        ` OIDC authorize will 302 to /login.`,
    );
  }
  if (opCookies.length === 0) {
    throw new Error(
      `No OP cookies matched ${[...opCookieDomains].join(', ')} after login. ` +
        `Browser had ${allCookies.length} cookie(s) total: ` +
        `${allCookies.map((c) => `${c.domain}${c.path}#${c.name}`).join(', ') || '(none)'}.`,
    );
  }

  // Playwright already returns sameSite as 'Strict' | 'Lax' | 'None', the exact
  // shape OpStorageState expects, so the cookies pass through unchanged.
  writeFileSync(
    OP_STORAGE_STATE_FILE,
    JSON.stringify({ cookies: opCookies, origins: [] }, null, 2),
  );
  console.log(
    `[setup] persisted ${opCookies.length} OP cookie(s) [${opCookies
      .map((c) => c.name)
      .join(', ')}] (${[...opCookieDomains].join(', ')}) to ${OP_STORAGE_STATE_FILE}`,
  );
}

// Drive the OIDC authorize -> consent Allow flow once so the OP session carries
// granted scopes. Entirely best-effort: wrapped so nothing here fails setup.
async function driveConsent(page: import('@playwright/test').Page): Promise<void> {
  try {
    const pkce = makePkce();
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: env.oidcClientId,
      redirect_uri: env.oidcRedirectUri,
      scope: 'openid email offline_access',
      state: randomToken(),
      nonce: randomToken(),
      code_challenge: pkce.challenge,
      code_challenge_method: pkce.method,
    });
    const authorizeUrl = `${env.opBaseURL}/oauth2/authorize?${params.toString()}`;
    await page.goto(authorizeUrl, { waitUntil: 'domcontentloaded' }).catch(() => {});

    // bunyip 302s authorize -> /oauth2/consent when the client has un-granted
    // scopes. Click Allow to grant them.
    if (/\/oauth2\/consent/.test(new URL(page.url()).pathname)) {
      const allow = page
        .locator('button[name="action"][value="allow"]')
        .or(page.getByRole('button', { name: /allow|authorize|approve/i }))
        .first();
      await allow.click({ timeout: 10_000 }).catch(() => {});
      // The post-consent redirect targets the registered redirect_uri, an app
      // callback that may 404 here. Tolerate any landing.
      await page.waitForLoadState('domcontentloaded', { timeout: 10_000 }).catch(() => {});
      console.log('[setup] drove OIDC consent Allow (granted scopes for token-flow specs)');
    } else {
      console.log(
        `[setup] no consent screen reached (landed on ${page.url()}); scopes may already be granted`,
      );
    }
  } catch (err) {
    console.warn(`[setup] OIDC consent drive failed (non-fatal): ${String(err)}`);
  }
}

// Cookie-domain values the OIDC specs care about given the OP base URL: the OP
// host plus its immediate parent (so `api.a8n.systems` yields both
// `api.a8n.systems` and `a8n.systems`). Single-label hosts (`localhost`) and IP
// literals return just themselves - stripping a label off `127.0.0.1` produces a
// bogus `0.0.1` that matches nothing but clutters the diagnostic. We do NOT walk
// to a TLD: that would admit cookies the OP and hub do not share with us.
function computeOpCookieDomains(opUrl: string): Set<string> {
  const host = new URL(opUrl).hostname;
  const domains = new Set<string>([host]);
  if (isIP(host) === 0) {
    const parts = host.split('.');
    if (parts.length > 2) domains.add(parts.slice(1).join('.'));
  }
  return domains;
}
