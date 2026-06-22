// Persisted bearer token + OP cookies from the setup project, consumed by API
// tests and global teardown.
//
// Two artifacts live in `.auth/`:
//
// - `token.txt`: the bunyip-issued access_token captured during the hub-web
//   login. The `api` project's request fixture (lib/fixtures.ts) injects it as
//   `Authorization: Bearer`. bunyip's `/oauth2/token` response and the legacy
//   `access_token` cookie both carry it; setup captures whichever it sees.
//
// - `op-state.json`: a Playwright `storageState`-shaped JSON containing the
//   cookies the OP needs to recognise the user's session (notably
//   `bunyip_op_session`). The OIDC specs replay these via
//   `request.newContext({ storageState })` so `/oauth2/authorize` sees a
//   server-validated OP session and issues a `code` rather than bouncing to
//   the hub login screen. No bearer is attached on that path: bunyip's
//   authorize handler reads the session from the cookie, and a foreign-audience
//   bearer would just be noise.
//
// Setup writes both files in one pass after a successful login; teardown reads
// `token.txt` only.

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync, existsSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));

export const TOKEN_FILE = resolve(here, '..', '.auth', 'token.txt');
export const OP_STORAGE_STATE_FILE = resolve(here, '..', '.auth', 'op-state.json');

export function readToken(): string {
  if (!existsSync(TOKEN_FILE)) {
    throw new Error(
      `Missing ${TOKEN_FILE}. The setup project must run before tests that read ` +
        `the token; check that this project declares dependencies: ['setup'].`,
    );
  }
  const token = readFileSync(TOKEN_FILE, 'utf-8').trim();
  if (!token) {
    throw new Error(`Empty token in ${TOKEN_FILE}; setup project probably failed`);
  }
  return token;
}

// Shape Playwright's `request.newContext({ storageState })` expects when passed
// as an object literal. We only populate `cookies`; `origins` (which would
// carry localStorage entries) is left empty because the OP session lives
// entirely in cookies. Re-declared here rather than imported from Playwright so
// the file type-checks under a `node` lib without pulling the
// `@playwright/test` typings into shared code.
export interface OpStorageState {
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    expires: number;
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'Strict' | 'Lax' | 'None';
  }>;
  origins: never[];
}

export function readOpStorageState(): OpStorageState {
  if (!existsSync(OP_STORAGE_STATE_FILE)) {
    throw new Error(
      `Missing ${OP_STORAGE_STATE_FILE}. The setup project must run before ` +
        `tests that read OP cookies; check that this project declares ` +
        `dependencies: ['setup'].`,
    );
  }
  const raw = readFileSync(OP_STORAGE_STATE_FILE, 'utf-8');
  const parsed = JSON.parse(raw) as OpStorageState;
  if (!Array.isArray(parsed.cookies) || parsed.cookies.length === 0) {
    throw new Error(
      `${OP_STORAGE_STATE_FILE} has no cookies; setup probably ran before the ` +
        `login established an OP session, or the OP hostname filter excluded ` +
        `everything. Check setup's diagnostic output.`,
    );
  }
  return parsed;
}
