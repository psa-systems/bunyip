import { expect, oidcTest as test } from '../../lib/fixtures';
import { discoverOidc, makePkce, randomToken } from '../../lib/api';
import { env } from '../../lib/env';

// OIDC authorize-redirect coverage (BUNYIP-149). Runs in the `api` project with
// the `oidcTest` fixture: a request context that replays the OP session cookies
// `setup` persisted (notably `bunyip_op_session`) and attaches NO bearer header.
// bunyip's /oauth2/authorize reads the OP session from the cookie, so this
// proves authorize issues a `code` for an already-authenticated session WITHOUT
// following the redirect to the app callback.
//
// Consent is pre-granted by global.setup (it drives the consent Allow once), so
// a fresh authorize should return a `code` rather than bouncing to /consent.
test.describe('OIDC authorize redirect', () => {
  test('authorize returns a code to the registered redirect host', async ({ request }) => {
    const oidc = await discoverOidc(request, env.opBaseURL);
    const pkce = makePkce();
    const state = randomToken();
    const nonce = randomToken();

    const authorizeUrl = new URL(oidc.authorization_endpoint);
    authorizeUrl.search = new URLSearchParams({
      response_type: 'code',
      client_id: env.oidcClientId,
      redirect_uri: env.oidcRedirectUri,
      // offline_access so the grant carries a refresh token; matches the scope
      // set the token-flow spec exchanges and the consent set setup granted.
      scope: 'openid email offline_access',
      state,
      nonce,
      code_challenge: pkce.challenge,
      code_challenge_method: pkce.method,
    }).toString();

    // Do not follow the redirect; read the Location header directly.
    const authRes = await request.get(authorizeUrl.toString(), { maxRedirects: 0 });
    const REDIRECT_STATUSES = [301, 302, 303, 307, 308];
    expect(
      REDIRECT_STATUSES,
      `authorize should 3xx-redirect; got ${authRes.status()}`,
    ).toContain(authRes.status());

    const location = authRes.headers()['location'];
    expect(location, 'authorize 3xx had no Location header').toBeTruthy();
    const redirected = new URL(location, env.opBaseURL);

    // When authorize 3xx-redirects WITHOUT a `code`, it bounced to an
    // interstitial (login or consent) instead of the registered redirect_uri.
    // A /login and a /consent bounce share the same top-level signature (state,
    // code, and error all absent because the originals are nested inside
    // return_to), so the bare assertions below cannot tell them apart. Name the
    // destination here. Surface path + param KEYS only; values are redacted
    // because the nested return_to echoes state/nonce.
    //   - /login   => bunyip rejected the bunyip_op_session cookie (session
    //                 missing / expired / scoped to the wrong host).
    //   - /consent => session is valid, but a requested scope is not granted for
    //                 this (user, client); setup's consent drive did not stick.
    if (!redirected.searchParams.get('code')) {
      const paramKeys = [...redirected.searchParams.keys()].join(',') || '(none)';
      throw new Error(
        `authorize did not return an authorization code; it redirected to ` +
          `${redirected.origin}${redirected.pathname} ` +
          `(param keys: ${paramKeys}; error=${redirected.searchParams.get('error') ?? 'none'}). ` +
          `A /login target => the bunyip_op_session cookie was not accepted; a /consent target => ` +
          `the session is valid but a requested scope is not granted for this client (BUNYIP-146).`,
      );
    }

    expect(
      redirected.searchParams.get('error'),
      `authorize returned error=${redirected.searchParams.get('error')}`,
    ).toBeNull();
    expect(redirected.searchParams.get('state'), 'state mismatch').toBe(state);

    // The code must come back on the REGISTERED redirect host, not some other
    // origin. Compare against the configured redirect_uri's host.
    const expectedHost = new URL(env.oidcRedirectUri).host;
    expect(
      redirected.host,
      `code returned to ${redirected.host}, expected the registered ${expectedHost}`,
    ).toBe(expectedHost);
    expect(redirected.searchParams.get('code'), 'no authorization code in redirect').toBeTruthy();
  });
});
