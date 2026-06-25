// Read token-links out of the staging mail sink via Stalwart's JMAP API
// (BUNYIP-150).
//
// Staging bunyip-api delivers its outbound mail through the existing Stalwart
// relay (mail.a8n.run). A mailbox there (currently nate@a8n.run; a dedicated
// e2e@a8n.run later) receives the E2E mail; the email-driven specs address a
// unique plus-subaddress per run (e.g. nate+<tag>@a8n.run), which Stalwart
// delivers into that one mailbox, and read it back over JMAP. Reading by the
// unique recipient means no mailbox clearing is needed; each matched message is
// destroyed after it is read, and ONLY the exact subaddress is ever matched or
// destroyed (see addressedTo) so a shared mailbox's real mail is never touched.
//
// E2E_MAIL_SINK_URL carries the JMAP host plus the mailbox credentials as
// basicAuth userinfo, e.g. `https://nate%40a8n.run:password@mail.a8n.run`.
// Specs guard on `env.mailSinkURL` with `test.skip` before calling anything
// here, so these helpers assume it is set.

import { request as requestFactory, type APIRequestContext } from '@playwright/test';
import { env } from './env';

// Absolute-URL matchers for each flow's token-link. The token is base64url /
// hex (`[\w.-]`); the host is whatever APP_URL the deployment renders into the
// email body (staging `https://a8n.systems`). `match[0]` is the full URL, from
// which the caller pulls `?token=` via `new URL(...)`.
export const MAGIC_LINK_RE = /https?:\/\/[^\s"'<>]+\/magic-link\?token=[\w.-]+/;
export const PASSWORD_RESET_RE = /https?:\/\/[^\s"'<>]+\/password-reset\/confirm\?token=[\w.-]+/;
export const EMAIL_CHANGE_RE = /https?:\/\/[^\s"'<>]+\/settings\/confirm-email\?token=[\w.-]+/;

const JMAP_MAIL_CAPABILITIES = [
  'urn:ietf:params:jmap:core',
  'urn:ietf:params:jmap:mail',
];
const JMAP_MAIL_ACCOUNT = 'urn:ietf:params:jmap:mail';

interface SinkConnection {
  base: string;
  mailbox: string;
  headers: Record<string, string>;
}

// Split E2E_MAIL_SINK_URL into a credential-free base URL, the mailbox address
// (the basicAuth username, e.g. e2e@a8n.run), and a Basic auth header.
function sinkConnection(): SinkConnection {
  const raw = env.mailSinkURL;
  if (!raw) {
    throw new Error('E2E_MAIL_SINK_URL is not set (guard specs with test.skip on env.mailSinkURL)');
  }
  const u = new URL(raw);
  const mailbox = decodeURIComponent(u.username);
  const password = decodeURIComponent(u.password);
  if (!mailbox) {
    throw new Error('E2E_MAIL_SINK_URL must embed the mailbox credentials (user:pass@host)');
  }
  const headers: Record<string, string> = {
    Authorization: `Basic ${Buffer.from(`${mailbox}:${password}`).toString('base64')}`,
    'Content-Type': 'application/json',
  };
  u.username = '';
  u.password = '';
  return { base: u.toString().replace(/\/+$/, ''), mailbox, headers };
}

// Build a plus-subaddress of the sink mailbox, e.g. mailbox `e2e@a8n.run` +
// tag `e2e-...-1` -> `e2e+e2e-...-1@a8n.run`. Stalwart delivers this into the
// mailbox, and the unique tag isolates one test's mail from every other's.
export function subaddress(tag: string): string {
  const { mailbox } = sinkConnection();
  const at = mailbox.lastIndexOf('@');
  const local = mailbox.slice(0, at);
  const domain = mailbox.slice(at + 1);
  return `${local}+${tag}@${domain}`;
}

async function sinkContext(): Promise<APIRequestContext> {
  const { base, headers } = sinkConnection();
  return requestFactory.newContext({ baseURL: base, extraHTTPHeaders: headers });
}

interface JmapSession {
  apiUrl: string;
  primaryAccounts?: Record<string, string>;
}

// Fetch the JMAP session document and resolve the primary mail account id.
async function jmapSession(ctx: APIRequestContext): Promise<{ apiUrl: string; accountId: string }> {
  const res = await ctx.get('/.well-known/jmap');
  if (!res.ok()) {
    throw new Error(`JMAP session GET /.well-known/jmap -> ${res.status()}: ${await res.text()}`);
  }
  const session = (await res.json()) as JmapSession;
  const accountId = session.primaryAccounts?.[JMAP_MAIL_ACCOUNT];
  if (!accountId) {
    throw new Error('JMAP session has no primary mail account');
  }
  // Stalwart advertises apiUrl as its internal address (e.g.
  // http://mail.a8n.run:8080/jmap/), which the CI runner cannot reach. The
  // `.well-known/jmap` GET above already succeeded over the public TLS host, so
  // keep only the apiUrl PATH and force the origin back to the configured sink
  // base (https://mail.a8n.run via Traefik on 443).
  const { base } = sinkConnection();
  const path = new URL(session.apiUrl, base);
  return { apiUrl: `${base}${path.pathname}${path.search}`, accountId };
}

interface JmapResponse {
  methodResponses?: Array<[string, Record<string, unknown>, string]>;
}

async function jmapCall(
  ctx: APIRequestContext,
  apiUrl: string,
  methodCalls: unknown[],
): Promise<JmapResponse> {
  const res = await ctx.post(apiUrl, { data: { using: JMAP_MAIL_CAPABILITIES, methodCalls } });
  if (!res.ok()) {
    throw new Error(`JMAP POST ${apiUrl} -> ${res.status()}: ${await res.text()}`);
  }
  return (await res.json()) as JmapResponse;
}

interface JmapBodyPart {
  partId?: string;
}
interface JmapEmail {
  id: string;
  to?: Array<{ email?: string }>;
  textBody?: JmapBodyPart[];
  htmlBody?: JmapBodyPart[];
  bodyValues?: Record<string, { value?: string }>;
}

// The sink mailbox may be a shared/personal mailbox (e.g. nate@a8n.run), so a
// message is only ever a match - and only ever destroyed - when its To header
// carries the EXACT unique plus-subaddress this test used. This guards against
// a JMAP `to` filter that normalises the subaddress to the base mailbox: real
// mail addressed to the plain mailbox can never match or be deleted.
function addressedTo(email: JmapEmail, toAddress: string): boolean {
  const want = toAddress.toLowerCase();
  return (email.to ?? []).some((a) => (a.email ?? '').toLowerCase() === want);
}

// Concatenate every text + HTML body part's decoded value (JMAP returns part
// references in textBody/htmlBody and the decoded strings in bodyValues).
function bodyText(email: JmapEmail): string {
  const parts = [...(email.textBody ?? []), ...(email.htmlBody ?? [])];
  const values = email.bodyValues ?? {};
  return parts
    .map((part) => (part.partId ? values[part.partId]?.value ?? '' : ''))
    .join('\n');
}

export interface WaitForLinkOptions {
  timeoutMs?: number;
  intervalMs?: number;
}

// Poll the sink mailbox over JMAP for a message addressed to `toAddress` whose
// body contains a link matching `linkRe`, return the full matched URL, and
// destroy that message. Filtering by the link pattern ignores the async
// `send_account_created` welcome mail that also arrives for the address. Throws
// on timeout so a never-delivered mail fails the spec clearly.
export async function waitForLink(
  toAddress: string,
  linkRe: RegExp,
  opts: WaitForLinkOptions = {},
): Promise<string> {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const intervalMs = opts.intervalMs ?? 2_000;
  const ctx = await sinkContext();
  try {
    const { apiUrl, accountId } = await jmapSession(ctx);
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const resp = await jmapCall(ctx, apiUrl, [
        [
          'Email/query',
          {
            accountId,
            filter: { to: toAddress },
            sort: [{ property: 'receivedAt', isAscending: false }],
            limit: 20,
          },
          'q',
        ],
        [
          'Email/get',
          {
            accountId,
            '#ids': { resultOf: 'q', name: 'Email/query', path: '/ids' },
            properties: ['id', 'to', 'textBody', 'htmlBody', 'bodyValues'],
            fetchTextBodyValues: true,
            fetchHTMLBodyValues: true,
          },
          'g',
        ],
      ]);
      const get = resp.methodResponses?.find((m) => m[0] === 'Email/get');
      const emails = (get?.[1]?.list as JmapEmail[] | undefined) ?? [];
      for (const email of emails) {
        // Only this test's own subaddressed mail, never the base mailbox.
        if (!addressedTo(email, toAddress)) continue;
        const match = linkRe.exec(bodyText(email));
        if (match) {
          // Best-effort cleanup so the shared mailbox does not accumulate.
          await jmapCall(ctx, apiUrl, [
            ['Email/set', { accountId, destroy: [email.id] }, 'd'],
          ]).catch(() => {});
          return match[0];
        }
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    throw new Error(`waitForLink: no JMAP mail to ${toAddress} matched ${linkRe} within ${timeoutMs}ms`);
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
