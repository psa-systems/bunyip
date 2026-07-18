// Shared API helpers: route constants, PKCE primitives, and OIDC discovery.
//
// bunyip-api serves its JSON API under `/v1` (NOT `/api/v1`); the OIDC OP
// surface is mounted at the deployment root (`/oauth2/*`,
// `/.well-known/openid-configuration`) - see crates/bunyip-oidc/src/routes.
// The `api` Playwright project picks up a Bearer token from the setup project
// (see lib/auth-state.ts) and the custom `test` fixture in lib/fixtures.ts
// attaches it as the `Authorization` header on every request.

import { createHash, randomBytes } from 'node:crypto';
import type { APIRequestContext } from '@playwright/test';

export const API_V1 = '/v1';

export const routes = {
  // Health / version. `version` is the deploy-sync gate target: its `commit`
  // field carries the short git hash baked in via the GIT_COMMIT build arg.
  version: `${API_V1}/version`,
  health: '/health',
  healthV1: `${API_V1}/health`,
  rootStatus: '/',

  // Auth / session surface (bunyip-api).
  memberships: `${API_V1}/auth/memberships`,
  userSessions: `${API_V1}/users/me/sessions`,
  userConsents: `${API_V1}/users/me/consents`,

  // Account lifecycle + email-driven flows (BUNYIP-150). Used by the disposable
  // account helpers (lib/accounts.ts) and the mail-sink specs.
  authRegister: `${API_V1}/auth/register`,
  // BUNYIP-377 signup bot guard: the timing-challenge token the register form is
  // rendered with; registerDisposable (lib/accounts.ts) fetches it before POSTing.
  registerChallenge: `${API_V1}/auth/register-challenge`,
  authLogin: `${API_V1}/auth/login`,
  authMagicLink: `${API_V1}/auth/magic-link`,
  authMagicLinkVerify: `${API_V1}/auth/magic-link/verify`,
  authPasswordReset: `${API_V1}/auth/password-reset`,
  authPasswordResetConfirm: `${API_V1}/auth/password-reset/confirm`,
  userMe: `${API_V1}/users/me`,
  userEmail: `${API_V1}/users/me/email`,
  userEmailConfirm: `${API_V1}/users/me/email/confirm`,
  userEmailVerify: `${API_V1}/users/me/email/verify`,
  userEmailVerifyConfirm: `${API_V1}/users/me/email/verify/confirm`,

  // OIDC OP discovery (root-mounted).
  oidcDiscovery: '/.well-known/openid-configuration',
  jwks: '/.well-known/jwks.json',
} as const;

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export interface Pkce {
  verifier: string;
  challenge: string;
  method: 'S256';
}

// RFC 7636 PKCE pair (S256). Verifier is 43-128 chars of base64url.
export function makePkce(): Pkce {
  const verifier = base64url(randomBytes(48));
  const challenge = base64url(createHash('sha256').update(verifier).digest());
  return { verifier, challenge, method: 'S256' };
}

export interface OidcEndpoints {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  issuer: string;
}

// Fetch the live discovery document so the token-flow test targets whatever
// endpoints the deployment actually advertises rather than hard-coded paths.
export async function discoverOidc(
  request: APIRequestContext,
  baseURL: string,
): Promise<OidcEndpoints> {
  const res = await request.get(`${baseURL}${routes.oidcDiscovery}`);
  if (!res.ok()) {
    throw new Error(`OIDC discovery failed: GET ${routes.oidcDiscovery} -> ${res.status()}`);
  }
  return (await res.json()) as OidcEndpoints;
}

// A throwaway base64url token suitable for `state` / `nonce`.
export function randomToken(): string {
  return base64url(randomBytes(16));
}
