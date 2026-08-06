#!/usr/bin/env bash
# Stripe-config-is-DB-only gate (BUNYIP-482).
#
# Stripe configuration (secret key, webhook secret, app tag, checkout URLs, $0
# price id) lives ONLY in the `stripe_config` / `tier_config` DB rows, edited on
# the admin Stripe and tier-settings pages. Reintroducing an env read is a
# one-line edit that compiles fine and silently reinstates the "container env
# overrides the admin who cleared the field" behaviour this issue removed, so
# grep-assert that no `STRIPE_*` name outside the allowlist appears anywhere.
#
# Allowed:
#   STRIPE_ENCRYPTION_KEY[_PREV|_FILE], STRIPE_KEY_VERSION
#     At-rest AES-256-GCM key material for the DB row itself (and for the shared
#     email_config secrets). Not Stripe API information, and it cannot live in
#     the database it protects. Renaming/consolidating it is BUNYIP-483.
#   *E2E_*STRIPE_*
#     The Playwright harness talking to the Stripe API directly for fixture
#     setup and teardown, not bunyip application config.
#
# Excluded paths:
#   bunyip-api/migrations/  committed migrations are immutable (sqlx checksums
#                           them; an edit stops a deployed DB from booting), so
#                           historical SQL comments naming removed vars stay.
#   e2e/                    the Playwright harness (see the E2E allowance above).
#   scripts/check-no-stripe-env.sh  this file names the vars it forbids.
#
# Usage: scripts/check-no-stripe-env.sh
set -euo pipefail

allowed='^(STRIPE_ENCRYPTION_KEY(_PREV|_FILE)?|STRIPE_KEY_VERSION)$'

failed=0
while IFS= read -r file; do
    case "$file" in
        bunyip-api/migrations/* | e2e/* | scripts/check-no-stripe-env.sh) continue ;;
    esac
    while IFS=: read -r line name; do
        # E2E_* names (in any position) are the test harness, not app config.
        [[ "$name" == *E2E_* ]] && continue
        [[ "$name" =~ $allowed ]] && continue
        echo "error: $file:$line: '$name' - Stripe config is DB-only (BUNYIP-482)." >&2
        failed=1
    done < <(grep -noE '[A-Z0-9_]*STRIPE_[A-Z0-9_]+' "$file" || true)
done < <(git ls-files)

if [[ $failed -ne 0 ]]; then
    echo >&2
    echo "Stripe configuration must come from the stripe_config / tier_config DB rows" >&2
    echo "(admin Stripe + tier-settings pages), never from the environment. See the" >&2
    echo "allowlist note in scripts/check-no-stripe-env.sh." >&2
    exit 1
fi

echo "check-no-stripe-env: no STRIPE_* env surface outside the encryption-key allowlist"
