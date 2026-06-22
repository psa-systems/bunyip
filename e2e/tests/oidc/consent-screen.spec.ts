import { expect, oidcTest as test } from '../../lib/fixtures';
import { discoverOidc, makePkce, randomToken } from '../../lib/api';
import { env } from '../../lib/env';

// OIDC consent-surface coverage (BUNYIP-149). Runs in the `api` project with the
// `oidcTest` fixture (replayed OP session cookies, no bearer).
//
// Design constraint: global.setup already drove the consent Allow for the E2E
// account + client, so a NORMAL authorize will NOT re-prompt - it goes straight
// to a `code`. We therefore cannot assert the consent screen by replaying the
// pre-granted authorize flow. Instead this hits GET /oauth2/consent directly
// with a well-formed authorize query (the shape bunyip would forward into the
// consent handler) and asserts the OP responds coherently: either it renders
// the consent form (HTML + an Allow/Deny control) for a session that still has
// an un-granted scope, OR - because scopes are pre-granted - it redirects
// straight back toward the authorize continuation. Both are valid; a 4xx/5xx is
// not. This keeps a real assertion against the consent route without depending
// on forcing a fresh prompt against the shared pre-granted account.
//
// If bunyip ever stops serving GET /oauth2/consent outside an in-flight
// authorize (e.g. it requires a server-side consent ticket), convert this to
// `test.fixme` and provision a throwaway client/scope so a genuine first-time
// consent screen can be forced (the only fully reliable way to assert the
// rendered form).
test.describe('OIDC consent surface', () => {
  test('the consent route responds coherently', async ({ request }) => {
    const oidc = await discoverOidc(request, env.opBaseURL);
    const pkce = makePkce();

    const consentQuery = new URLSearchParams({
      response_type: 'code',
      client_id: env.oidcClientId,
      redirect_uri: env.oidcRedirectUri,
      scope: 'openid email offline_access',
      state: randomToken(),
      nonce: randomToken(),
      code_challenge: pkce.challenge,
      code_challenge_method: pkce.method,
    });
    const consentUrl = `${env.opBaseURL}/oauth2/consent?${consentQuery.toString()}`;

    // Do not auto-follow: a redirect back into the authorize continuation is a
    // valid outcome we want to observe rather than chase.
    const res = await request.get(consentUrl, { maxRedirects: 0 });

    const REDIRECT_STATUSES = [301, 302, 303, 307, 308];
    if (REDIRECT_STATUSES.includes(res.status())) {
      // Pre-granted: the OP short-circuits consent and redirects on. Assert it
      // is not redirecting to an OP error page.
      const location = res.headers()['location'] ?? '';
      const target = new URL(location, env.opBaseURL);
      expect(
        target.searchParams.get('error'),
        `consent redirect carried error=${target.searchParams.get('error')}`,
      ).toBeNull();
      return;
    }

    // Otherwise the consent form should render: a 200 HTML page carrying an
    // Allow/Deny (or scope) control.
    expect(res.status(), `consent GET -> ${res.status()}: ${await res.text()}`).toBe(200);
    const body = await res.text();
    expect(
      /name=["']action["']|allow|consent|authorize|approve|scope/i.test(body),
      'consent response did not look like a consent form (no Allow/scope markup)',
    ).toBe(true);
  });
});
