#!/usr/bin/env nu

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
#   scripts/purge-staging-test-accounts.nu \
#       --database-url $env.STAGING_DATABASE_URL \
#       --pattern '%+test%'
#
#   # 2. When the preview looks right, commit the hard delete:
#   scripts/purge-staging-test-accounts.nu \
#       --database-url $env.STAGING_DATABASE_URL \
#       --pattern '%+test%' \
#       --i-know-this-is-not-prod \
#       --commit
#
# The --pattern value is a raw SQL LIKE pattern matched against users.email
# (e.g. '%+test%' for plus-addressed test mail, '%@example.com' for a test
# domain). Run the preview first and confirm the count matches the ~400 stale
# accounts and that no intentional QA-seed accounts (PMS-331 / PMS-239) are in
# the list before committing.
def main [
    --database-url: string = ""          # target DB (defaults to $env.DATABASE_URL)
    --pattern: string = ""               # SQL LIKE pattern matched against users.email
    --commit                             # actually delete; without it this is a dry run
    --i-know-this-is-not-prod            # required acknowledgement for --commit
] {
    let confirm_phrase = "purge test accounts"

    let target = (if ($database_url | is-not-empty) {
        $database_url
    } else {
        $env.DATABASE_URL? | default ""
    })

    if ($target | is-empty) {
        print --stderr "error: set DATABASE_URL or pass --database-url"
        exit 2
    }
    if ($pattern | is-empty) {
        print --stderr "error: --pattern is required (a SQL LIKE pattern, e.g. '%+test%')"
        exit 2
    }

    # Show which host we are about to touch (never print credentials).
    let db_host = ($target | str replace --regex '^[^@]*@' "" | str replace --regex '[/?].*$' "")
    print $"target database host : ($db_host)"
    print $"email LIKE pattern    : ($pattern)"
    print ""

    let preview_sql = "SELECT id, email, role, created_at
FROM users
WHERE email LIKE :'pattern'
  AND role <> 'admin'
ORDER BY created_at;"

    let count_sql = "SELECT count(*)
FROM users
WHERE email LIKE :'pattern'
  AND role <> 'admin';"

    # Fed on stdin, never `-c`: psql does not expand :'pattern' in a -c string,
    # so the query would reach the server with a literal `:` and fail to parse.
    print "== accounts matched (role='admin' excluded) =="
    $preview_sql | ^psql $target -v $"pattern=($pattern)" -P pager=off
    let matched = ($count_sql | ^psql $target -v $"pattern=($pattern)" -tA | str trim | into int)
    print $"matched rows: ($matched)"
    print ""

    if not $commit {
        print "DRY RUN: no rows deleted. Re-run with --i-know-this-is-not-prod --commit to hard-delete the rows above."
        exit 0
    }

    if not $i_know_this_is_not_prod {
        print --stderr "refusing to --commit without --i-know-this-is-not-prod (this is a hard delete)."
        exit 3
    }

    if $matched == 0 {
        print "nothing to delete; exiting."
        exit 0
    }

    # `input` reads the terminal, so a piped phrase cannot stand in for a human
    # typing it. That is the point of the confirmation, but it fails as an I/O
    # error rather than a refusal, so say what is wrong.
    let typed = (try {
        input $"Type '($confirm_phrase)' to hard-delete ($matched) account\(s): "
    } catch {
        print --stderr "error: --commit needs an interactive terminal to read the confirmation phrase; no rows deleted."
        exit 3
    })
    if $typed != $confirm_phrase {
        print --stderr "confirmation phrase did not match; aborting. No rows deleted."
        exit 3
    }

    # Hard delete in a single transaction. The id set is resolved once into a
    # temp table so the DELETEs below all see the same rows, mirroring the Rust
    # path's "resolve ids once, then clear deps, then delete users" ordering.
    let delete_sql = "BEGIN;

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
"
    $delete_sql | ^psql $target -v $"pattern=($pattern)" -v ON_ERROR_STOP=1

    print $"done: hard-deleted ($matched) test account\(s) matching '($pattern)'."
}
