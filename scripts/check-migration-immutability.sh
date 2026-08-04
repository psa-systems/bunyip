#!/usr/bin/env bash
# Migration immutability gate (BUNYIP-293).
#
# sqlx records a SHA-384 checksum of each migration in `_sqlx_migrations` when
# it applies it and re-verifies that checksum on every startup. Modifying,
# renaming, or deleting a migration that has already been applied to any
# database makes that database refuse to boot:
#
#   migration <version> was previously applied but has been modified
#
# Committed migrations are therefore immutable: the only safe change is a NEW
# migration file. This gate fails any PR (and push to main) that modifies (M),
# renames (R), or deletes (D) a migration (*.sql) file relative to the merge-base
# with the base ref, before it can merge. Adding new migration files passes.
# Only *.sql is guarded: sqlx never checksums docs such as README.md that live in
# the migrations dir, so editing them is safe and exempt (BUNYIP-458).
#
# This exact break took down the mokosh-server v0.4.0 production deploy on nc-01
# (DEV-395), and has bitten this repo before (BUNYIP-79 edited 11 applied
# migrations in place; see scripts/reconcile-sqlx-checksums.md). Review
# discipline alone has already failed, hence this mechanical gate.
#
# It fails loud (exit 2) if the diff itself cannot run, so a missing base ref or
# shallow clone never silently reads as "nothing changed". In CI the checkout
# must use `fetch-depth: 0` so the merge-base with `origin/main` is available.
#
# Usage: scripts/check-migration-immutability.sh [base_ref] [migrations_dir]
set -euo pipefail

BASE_REF="${1:-origin/main}"
MIGRATIONS_DIR="${2:-bunyip-api/migrations}"

# --diff-filter=MRD: only Modified, Renamed, Deleted paths (added files are
# fine). The three-dot form diffs HEAD against the merge-base of BASE_REF and
# HEAD, so unrelated commits already on the base do not register as changes.
if ! changed="$(git diff --diff-filter=MRD --name-only "${BASE_REF}...HEAD" -- "$MIGRATIONS_DIR" 2>&1)"; then
    echo "error: cannot diff '$MIGRATIONS_DIR' against '${BASE_REF}...HEAD':" >&2
    echo "  $changed" >&2
    echo "       The base ref must be fetched with full history (CI: fetch-depth: 0)." >&2
    exit 2
fi

# sqlx only checksums *.sql; docs like README.md live in the migrations dir but
# are not migrations, so a change to them must not trip the gate (BUNYIP-458). A
# modified/renamed/deleted *.sql still ends in .sql, so real coverage is kept.
changed="$(grep -E '\.sql$' <<<"$changed" || true)"

if [[ -n "$changed" ]]; then
    echo "error: the following already-committed migration file(s) were modified, renamed, or deleted:" >&2
    while IFS= read -r f; do
        echo "  - $f" >&2
    done <<< "$changed"
    echo >&2
    echo "Committed migrations are IMMUTABLE. sqlx checksums every applied migration and a" >&2
    echo "deployed database refuses to boot once the on-disk content disagrees with the" >&2
    echo "recorded checksum. Revert the change and add a NEW migration file instead of" >&2
    echo "editing, renaming, or deleting an existing one." >&2
    exit 1
fi

echo "migration immutability OK: no committed migration modified, renamed, or deleted"
