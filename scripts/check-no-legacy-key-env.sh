#!/usr/bin/env bash
# One-at-rest-key gate (BUNYIP-483).
#
# The TOTP secrets, the Stripe credentials and the SMTP password are all
# encrypted with the SAME key, provisioned as APP_ENCRYPTION_KEY (plus
# APP_ENCRYPTION_KEY_PREV / APP_KEY_VERSION). The two retired per-consumer key
# families are gone; reintroducing one is a one-line edit that compiles fine and
# silently splits the key material in two again, so grep-assert that no
# `TOTP_ENCRYPTION_KEY*`, `TOTP_KEY_VERSION`, `STRIPE_ENCRYPTION_KEY*` or
# `STRIPE_KEY_VERSION` name appears anywhere in the tree.
#
# Excluded paths:
#   bunyip-api/migrations/  committed migrations are immutable (sqlx checksums
#                           them; an edit stops a deployed DB from booting), so
#                           historical SQL comments naming removed vars stay.
#   scripts/check-no-*-env.sh  the env-name gates themselves, which have to
#                              spell out the variables they forbid.
#
# Usage: scripts/check-no-legacy-key-env.sh
set -euo pipefail

pattern='(TOTP|STRIPE)_(ENCRYPTION_KEY(_PREV|_FILE)?|KEY_VERSION)'

failed=0
while IFS= read -r file; do
    case "$file" in
        bunyip-api/migrations/* | scripts/check-no-*-env.sh) continue ;;
    esac
    while IFS=: read -r line name; do
        echo "error: $file:$line: '$name' - the at-rest key is APP_ENCRYPTION_KEY (BUNYIP-483)." >&2
        failed=1
    done < <(grep -noE "$pattern" "$file" || true)
done < <(git ls-files)

if [[ $failed -ne 0 ]]; then
    echo >&2
    echo "There is ONE at-rest encryption key: APP_ENCRYPTION_KEY (with" >&2
    echo "APP_ENCRYPTION_KEY_PREV for the keys old rows still need, and" >&2
    echo "APP_KEY_VERSION). It protects user_totp, stripe_config and email_config" >&2
    echo "alike. Rewrite existing rows with 'bunyip-api reencrypt-secrets'." >&2
    exit 1
fi

echo "check-no-legacy-key-env: no retired per-consumer at-rest key names"
