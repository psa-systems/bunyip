// Read token-links out of the staging Mailpit test mail sink (BUNYIP-150).
//
// On staging, bunyip-api delivers all outbound mail to Mailpit instead of a
// real relay (see the c-01 bunyip-mailpit deployment). Mailpit exposes an HTTP
// API the suite reads to extract the password-reset / magic-link / email-change
// token-links that would otherwise only arrive in a human's inbox.
//
// The sink base URL (with embedded basicAuth credentials) comes from
// E2E_MAIL_SINK_URL. Specs guard on `env.mailSinkURL` with `test.skip` before
// calling anything here, so these helpers assume it is set.

import { request as requestFactory, type APIRequestContext } from '@playwright/test';
import { env } from './env';

// Absolute-URL matchers for each flow's token-link. The token is base64url /
// hex (`[\w.-]`); the host is whatever APP_URL the deployment renders into the
// email body (staging `https://a8n.systems`). `match[0]` is the full URL, from
// which the caller pulls `?token=` via `new URL(...)`.
export const MAGIC_LINK_RE = /https?:\/\/[^\s"'<>]+\/magic-link\?token=[\w.-]+/;
export const PASSWORD_RESET_RE = /https?:\/\/[^\s"'<>]+\/password-reset\/confirm\?token=[\w.-]+/;
export const EMAIL_CHANGE_RE = /https?:\/\/[^\s"'<>]+\/settings\/confirm-email\?token=[\w.-]+/;

interface SinkConnection {
  base: string;
  headers: Record<string, string>;
}

// Split E2E_MAIL_SINK_URL into a credential-free base URL plus a Basic auth
// header. Embedding the credentials in the URL keeps it to a single secret, but
// we send them as an explicit header rather than relying on fetch/undici
// userinfo handling.
function sinkConnection(): SinkConnection {
  const raw = env.mailSinkURL;
  if (!raw) {
    throw new Error('E2E_MAIL_SINK_URL is not set (guard specs with test.skip on env.mailSinkURL)');
  }
  const u = new URL(raw);
  const headers: Record<string, string> = {};
  if (u.username) {
    const user = decodeURIComponent(u.username);
    const pass = decodeURIComponent(u.password);
    headers.Authorization = `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
    u.username = '';
    u.password = '';
  }
  return { base: u.toString().replace(/\/+$/, ''), headers };
}

async function sinkContext(): Promise<APIRequestContext> {
  const { base, headers } = sinkConnection();
  return requestFactory.newContext({ baseURL: base, extraHTTPHeaders: headers });
}

// Delete every captured message. The suite runs serially (workers: 1), so
// clearing the sink immediately BEFORE triggering an email removes any chance
// of matching a stale message from an earlier step or run.
export async function clearMailbox(): Promise<void> {
  const ctx = await sinkContext();
  try {
    await ctx.delete('/api/v1/messages');
  } finally {
    await ctx.dispose();
  }
}

interface MailpitMessageSummary {
  ID: string;
}

interface MailpitSearchResult {
  messages?: MailpitMessageSummary[];
}

interface MailpitMessage {
  Text?: string;
  HTML?: string;
}

export interface WaitForLinkOptions {
  timeoutMs?: number;
  intervalMs?: number;
}

// Poll the sink for a message to `toAddress` whose body contains a link matching
// `linkRe`, and return the full matched URL. Filtering by the link pattern (not
// just the recipient) means the async `send_account_created` welcome mail that
// also lands for a freshly-registered address is ignored. Throws on timeout so
// a never-delivered mail fails the spec with a clear message rather than hanging.
export async function waitForLink(
  toAddress: string,
  linkRe: RegExp,
  opts: WaitForLinkOptions = {},
): Promise<string> {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const intervalMs = opts.intervalMs ?? 1_000;
  const ctx = await sinkContext();
  const query = encodeURIComponent(`to:${toAddress}`);
  try {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const search = await ctx.get(`/api/v1/search?query=${query}`);
      if (search.ok()) {
        const result = (await search.json()) as MailpitSearchResult;
        for (const summary of result.messages ?? []) {
          const msgRes = await ctx.get(`/api/v1/message/${summary.ID}`);
          if (!msgRes.ok()) continue;
          const msg = (await msgRes.json()) as MailpitMessage;
          const haystack = `${msg.Text ?? ''}\n${msg.HTML ?? ''}`;
          const match = linkRe.exec(haystack);
          if (match) return match[0];
        }
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    throw new Error(
      `waitForLink: no mail to ${toAddress} matched ${linkRe} within ${timeoutMs}ms`,
    );
  } finally {
    await ctx.dispose();
  }
}

// Pull the `token` query param out of a matched token-link URL.
export function tokenFromLink(link: string): string {
  const token = new URL(link).searchParams.get('token');
  if (!token) throw new Error(`no ?token= in mail link: ${link}`);
  return token;
}
