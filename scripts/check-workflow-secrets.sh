#!/usr/bin/env bash
# PR-triggered CI secret-scope gate (BUNYIP-425).
#
# A `pull_request` run executes the workflow file, the npm lifecycle scripts and
# the test code from the PR HEAD, so every secret it can read is readable by
# anyone who can push a branch. The E2E suite therefore lives in a workflow that
# does not trigger on `pull_request` (`e2e.yml`: push to main + dispatch only),
# and the PR gate (`e2e-pr.yml`) holds only the two staging base URLs, which
# authenticate nothing.
#
# Three properties, mechanically enforced so the split cannot silently regress:
#   1. e2e.yml has no `pull_request` trigger.
#   2. e2e-pr.yml references no secret outside the base-URL allowlist.
#   3. every `npm ci` under .forgejo/workflows/ passes --ignore-scripts.
#
# Usage: scripts/check-workflow-secrets.sh [workflows_dir]
set -euo pipefail

WORKFLOWS_DIR="${1:-.forgejo/workflows}"

# Secrets the credential-free PR gate may name: deployment base URLs only.
# Adding to this list means handing that secret to unreviewed PR code.
PR_SECRET_ALLOWLIST='E2E_STAGING_BASE_URL|OIDC_ISSUER_STAGING'

SUITE_WORKFLOW="$WORKFLOWS_DIR/e2e.yml"
PR_WORKFLOW="$WORKFLOWS_DIR/e2e-pr.yml"

if [[ ! -d "$WORKFLOWS_DIR" ]]; then
    echo "error: workflows dir not found: $WORKFLOWS_DIR" >&2
    exit 2
fi

for required in "$SUITE_WORKFLOW" "$PR_WORKFLOW"; do
    if [[ ! -f "$required" ]]; then
        echo "error: expected workflow not found: $required" >&2
        exit 2
    fi
done

status=0

# 1. The full suite must not run on PR-authored content. Match the trigger key
# only (a `pull_request` word inside a comment or an expression is fine).
if grep --quiet --extended-regexp '^[[:space:]]{0,4}pull_request:' "$SUITE_WORKFLOW"; then
    echo "error: $SUITE_WORKFLOW declares a pull_request trigger; the full suite resolves account/Stripe/TOTP secrets and must stay on push + workflow_dispatch (BUNYIP-425)" >&2
    status=1
fi

# 2. The PR gate may reference nothing but the allowlisted base URLs.
while IFS= read -r name; do
    if [[ ! "$name" =~ ^($PR_SECRET_ALLOWLIST)$ ]]; then
        echo "error: $PR_WORKFLOW references secrets.$name; a pull_request-triggered job may only hold $PR_SECRET_ALLOWLIST (BUNYIP-425)" >&2
        status=1
    fi
done < <(sed 's/#.*//' "$PR_WORKFLOW" |
    grep --extended-regexp --only-matching 'secrets\.[A-Za-z0-9_]+' | cut -d. -f2 | sort --unique)

# 3. Dependency lifecycle scripts are attacker-authored too: never run them.
while IFS= read -r hit; do
    echo "error: $hit: 'npm ci' without --ignore-scripts (BUNYIP-425)" >&2
    status=1
done < <(grep --extended-regexp --recursive --line-number --no-messages \
    'npm ci( |$)' "$WORKFLOWS_DIR" | grep --invert-match -- '--ignore-scripts')

if [[ "$status" -eq 0 ]]; then
    echo "workflow secret scope OK: no PR-triggered job holds a credential, all 'npm ci' ignore scripts"
fi

exit "$status"
