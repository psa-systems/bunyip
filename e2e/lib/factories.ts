import { runSuffix } from './run';

// Minimal factories for the bunyip E2E suite. bunyip specs mostly read or mutate
// the existing E2E account rather than create heavy record graphs (unlike the
// mokosh suite), so this stays small: a date helper and a run-unique name tagger
// for the rare record a spec must name uniquely.

// Today's date as a YYYY-MM-DD string (the date-only wire format the API expects
// for date fields).
export function today(): string {
  return new Date().toISOString().slice(0, 10);
}

// A run-unique name for any record a spec needs to create and later identify, so
// teardown's name-based sweep (and this run's owned-record match) can find it.
export function tagged(prefix: string): string {
  return `${prefix}-${runSuffix()}`;
}
