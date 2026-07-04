#!/usr/bin/env bash
# Purge accumulated seeded / manual test accounts from a NON-PRODUCTION
# bunyip database (BUNYIP-273).
#
# Why this exists: the admin "delete user" endpoint (DELETE /admin/users/{id})
# is a SOFT delete, which would leave soft-delete residue and eventually clash
# with the BUNYIP-161 partial unique index on (email) WHERE deleted_at IS NULL.
# This script instead performs a HARD delete that mirrors, statement for
# statement, the supported BUNYIP-246 path
# `UserRepository::clear_deps_and_delete_users`
# (crates/bunyip-domain/src/repositories/user.rs): clear the non-cascade
# dependents (audit_logs.actor_id, admin_notifications.user_id / .read_by),
# then DELETE FROM users. Every other dependent row is removed by its FK
# ON DELETE CASCADE, exactly as in the Rust path.
#
# It does NOT touch encryption keys, so it cannot orphan retained encrypted
# data (the destructive-rotation risk called out in BUNYIP-273).
#
# SAFETY MODEL
#   - Dry-run by DEFAULT. You only ever delete with an explicit --commit.
#   - --pattern is REQUIRED and has no default, so a bare invocation can never
#     match "everything".
#   - role = 'admin' rows are always excluded.
#   - --commit additionally requires you to type the confirmation phrase, and
#     refuses to run against a database whose URL does not opt in via
#     --i-know-this-is-not-prod (guard against pointing it at prod by mistake).
#
# USAGE
#   # 1. Preview what a pattern matches (safe, read-only):
#   scripts/purge-staging-test-accounts.sh \
#       --database-url "$STAGING_DATABASE_URL" \
#       --pattern '%+test%'
#
#   # 2. When the preview looks right, commit the hard delete:
#   scripts/purge-staging-test-accounts.sh \
#       --database-url "$STAGING_DATABASE_URL" \
#       --pattern '%+test%' \
#       --i-know-this-is-not-prod \
#       --commit
#
# The --pattern value is a raw SQL LIKE pattern matched against users.email
# (e.g. '%+test%' for plus-addressed test mail, '%@example.com' for a test
# domain). Run the preview first and confirm the count matches the ~400 stale
# accounts and that no intentional QA-seed accounts (PMS-331 / PMS-239) are in
# the list before committing.
set -euo pipefail

DATABASE_URL="${DATABASE_URL:-}"
PATTERN=""
COMMIT=0
NOT_PROD_ACK=0
CONFIRM_PHRASE="purge test accounts"

usage() { sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database-url) DATABASE_URL="$2"; shift 2 ;;
    --pattern) PATTERN="$2"; shift 2 ;;
    --commit) COMMIT=1; shift ;;
    --i-know-this-is-not-prod) NOT_PROD_ACK=1; shift ;;
    --help | -h) usage 0 ;;
    *) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
  esac
done

[[ -n "$DATABASE_URL" ]] || { echo "error: set DATABASE_URL or pass --database-url" >&2; exit 2; }
[[ -n "$PATTERN" ]] || { echo "error: --pattern is required (a SQL LIKE pattern, e.g. '%+test%')" >&2; exit 2; }

# Show which host we are about to touch (never print credentials).
DB_HOST="$(printf '%s' "$DATABASE_URL" | sed -E 's#^[^@]*@##; s#[/?].*$##')"
echo "target database host : $DB_HOST"
echo "email LIKE pattern    : $PATTERN"
echo

PREVIEW_SQL="SELECT id, email, role, created_at
FROM users
WHERE email LIKE :'pattern'
  AND role <> 'admin'
ORDER BY created_at;"

COUNT_SQL="SELECT count(*)
FROM users
WHERE email LIKE :'pattern'
  AND role <> 'admin';"

echo "== accounts matched (role='admin' excluded) =="
psql "$DATABASE_URL" -v pattern="$PATTERN" -P pager=off -c "$PREVIEW_SQL"
MATCHED="$(psql "$DATABASE_URL" -v pattern="$PATTERN" -tA -c "$COUNT_SQL")"
echo "matched rows: $MATCHED"
echo

if [[ "$COMMIT" -eq 0 ]]; then
  echo "DRY RUN: no rows deleted. Re-run with --i-know-this-is-not-prod --commit to hard-delete the rows above."
  exit 0
fi

if [[ "$NOT_PROD_ACK" -ne 1 ]]; then
  echo "refusing to --commit without --i-know-this-is-not-prod (this is a hard delete)." >&2
  exit 3
fi

if [[ "$MATCHED" -eq 0 ]]; then
  echo "nothing to delete; exiting."
  exit 0
fi

read -r -p "Type '${CONFIRM_PHRASE}' to hard-delete ${MATCHED} account(s): " REPLY_PHRASE
if [[ "$REPLY_PHRASE" != "$CONFIRM_PHRASE" ]]; then
  echo "confirmation phrase did not match; aborting. No rows deleted." >&2
  exit 3
fi

# Hard delete in a single transaction. The id set is resolved once into a temp
# table so the DELETEs below all see the same rows, mirroring the Rust path's
# "resolve ids once, then clear deps, then delete users" ordering.
psql "$DATABASE_URL" -v pattern="$PATTERN" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;

CREATE TEMP TABLE _purge_ids ON COMMIT DROP AS
SELECT id FROM users
WHERE email LIKE :'pattern'
  AND role <> 'admin';

-- Non-cascade dependents, in the same order as
-- UserRepository::clear_deps_and_delete_users (BUNYIP-246).
DELETE FROM audit_logs WHERE actor_id IN (SELECT id FROM _purge_ids);
DELETE FROM admin_notifications WHERE user_id IN (SELECT id FROM _purge_ids);
UPDATE admin_notifications SET read_by = NULL WHERE read_by IN (SELECT id FROM _purge_ids);

-- Everything else is removed by ON DELETE CASCADE off users.id.
DELETE FROM users WHERE id IN (SELECT id FROM _purge_ids);

COMMIT;
SQL

echo "done: hard-deleted ${MATCHED} test account(s) matching '${PATTERN}'."
