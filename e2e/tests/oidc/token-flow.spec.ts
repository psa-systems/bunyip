import { expect, oidcTest as test } from '../../lib/fixtures';
import { discoverOidc, makePkce, randomToken } from '../../lib/api';
import { env } from '../../lib/env';

// Full OIDC PKCE token-flow coverage (BUNYIP-149). Runs in the `api` project
// with the `oidcTest` fixture: a request context that replays the OP session
// cookies `setup` persisted (notably `bunyip_op_session`), no bearer header.
// Exercises the complete OP contract end to end:
//   authorize -> code -> token (authorization_code) -> userinfo -> token (refresh).
//
// Consent is pre-granted by global.setup, so authorize yields a code. bunyip's
// token endpoint is form-encoded (application/x-www-form-urlencoded).
test.describe('OIDC token flow', () => {
  test('authorize -> token -> userinfo -> refresh', async ({ request }) => {
    const oidc = await discoverOidc(request, env.opBaseURL);
    const pkce = makePkce();
    const state = randomToken();
    const nonce = randomToken();

    // 1. /oauth2/authorize: do not follow the redirect; read `code` from Location.
    const authorizeUrl = new URL(oidc.authorization_endpoint);
    authorizeUrl.search = new URLSearchParams({
      response_type: 'code',
      client_id: env.oidcClientId,
      redirect_uri: env.oidcRedirectUri,
      // offline_access is required for the OP to mint a refresh_token (the last
      // leg of this test).
      scope: 'openid email offline_access',
      state,
      nonce,
      code_challenge: pkce.challenge,
      code_challenge_method: pkce.method,
    }).toString();

    const authRes = await request.get(authorizeUrl.toString(), { maxRedirects: 0 });
    const REDIRECT_STATUSES = [301, 302, 303, 307, 308];
    expect(
      REDIRECT_STATUSES,
      `authorize should 3xx-redirect with a code; got ${authRes.status()}`,
    ).toContain(authRes.status());

    const location = authRes.headers()['location'];
    expect(location, 'authorize 3xx had no Location header').toBeTruthy();
    const redirected = new URL(location, env.opBaseURL);

    // Same no-code diagnostic as authorize-redirect.spec.ts: name /login vs
    // /consent so a bounce is diagnosable instead of failing as a bare "state
    // mismatch". Param keys only; values redacted (return_to echoes state/nonce).
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
    expect(redirected.searchParams.get('state'), 'state mismatch').toBe(state);
    const code = redirected.searchParams.get('code');
    expect(code, 'no authorization code in redirect Location').toBeTruthy();

    // 2. /oauth2/token: authorization_code grant (form-encoded).
    const tokenRes = await request.post(oidc.token_endpoint, {
      form: {
        grant_type: 'authorization_code',
        code: code!,
        redirect_uri: env.oidcRedirectUri,
        client_id: env.oidcClientId,
        code_verifier: pkce.verifier,
      },
    });
    expect(tokenRes.status(), `token exchange failed: ${await tokenRes.text()}`).toBe(200);
    const tokens = (await tokenRes.json()) as {
      access_token: string;
      refresh_token?: string;
      token_type: string;
    };
    expect(tokens.access_token, 'no access_token').toBeTruthy();
    expect(tokens.token_type.toLowerCase()).toBe('bearer');

    // 3. /oauth2/userinfo: bearer-authenticated claims.
    const userinfoRes = await request.get(oidc.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfoRes.status(), `userinfo failed: ${await userinfoRes.text()}`).toBe(200);
    const claims = (await userinfoRes.json()) as { sub?: string };
    expect(claims.sub, 'userinfo missing sub claim').toBeTruthy();

    // 4. /oauth2/token: refresh_token grant (form-encoded).
    expect(tokens.refresh_token, 'no refresh_token issued (need offline_access?)').toBeTruthy();
    const refreshRes = await request.post(oidc.token_endpoint, {
      form: {
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token!,
        client_id: env.oidcClientId,
      },
    });
    expect(refreshRes.status(), `refresh failed: ${await refreshRes.text()}`).toBe(200);
    const refreshed = (await refreshRes.json()) as { access_token?: string };
    expect(refreshed.access_token, 'refresh returned no access_token').toBeTruthy();
  });
});
