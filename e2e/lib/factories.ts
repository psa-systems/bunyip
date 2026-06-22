import { expect, type APIRequestContext } from '@playwright/test';
import { routes } from './api';
import { runSuffix } from './run';

// Minimal factories for the bunyip E2E suite. bunyip specs mostly read or mutate
// the existing E2E account rather than create heavy record graphs (unlike the
// mokosh suite), so this stays small: a date helper, a memberships reader, and a
// run-unique name tagger for the rare record a spec must name uniquely.

// Today's date as a YYYY-MM-DD string (the date-only wire format the API expects
// for date fields).
export function today(): string {
  return new Date().toISOString().slice(0, 10);
}

// The authenticated user's memberships, including `active_tenant_id`. The tenant
// scope is implied by the session; a spec reads this to learn which tenant it is
// acting in.
export async function getMemberships(
  request: APIRequestContext,
): Promise<{ active_tenant_id: string; [key: string]: unknown }> {
  const res = await request.get(routes.memberships);
  expect(res.status(), `GET ${routes.memberships} -> ${res.status()}: ${await res.text()}`).toBe(
    200,
  );
  return (await res.json()) as { active_tenant_id: string; [key: string]: unknown };
}

// A run-unique name for any record a spec needs to create and later identify, so
// teardown's name-based sweep (and this run's owned-record match) can find it.
export function tagged(prefix: string): string {
  return `${prefix}-${runSuffix()}`;
}
