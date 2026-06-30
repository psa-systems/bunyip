// BUNYIP-287: shared CSRF posture for bunyip-web POSTs over `page.request`.
//
// BUNYIP-259 added an Origin / Referer CSRF middleware on bunyip-web
// (`bunyip-web/src/csrf.rs`). Every state-changing POST that is NOT under
// `/oauth2/*` must carry an `Origin` (or `Referer`) header whose host matches
// the request `Host`. A real browser submitting a form sends `Origin`
// automatically; Playwright's `page.request.post(...)` sends none by default,
// so a spec driving a form submission over the request context must add the
// header itself to faithfully replicate the browser submission it replaces.
//
// First seen in BUNYIP-284 (account/profile.spec.ts), where the header was
// inlined per call site. Centralised here so a future bunyip-web POST spec
// picks up the right header from one place, and so a future Origin-rule
// change (e.g. the synchronizer-token follow-up parked in BUNYIP-259's
// description) is a one-file diff in the suite.
//
// Scope: bunyip-web only. POSTs to bunyip-api have no CSRF middleware (the
// /oauth2/* endpoints authenticate via PKCE + state + nonce + client
// credentials) so specs that target `env.apiBaseURL` need none of this.

import { env } from './env';

/**
 * Headers a `page.request.post(...)` call against bunyip-web must carry to
 * pass the BUNYIP-259 Origin / Referer check. Returns a plain bag so callers
 * can spread it alongside their own headers without losing either.
 *
 * Reads `env.baseURL` at call time so a test that swaps `BASE_URL` mid-run
 * still picks up the right value.
 */
export function bunyipWebPostHeaders(): Record<string, string> {
  return { Origin: new URL(env.baseURL).origin };
}
