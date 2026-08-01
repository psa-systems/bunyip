#!/usr/bin/env bash
# Security-invariant gate (BUNYIP-426).
#
# The 2026-07-30 audit sweep removed four shapes from this repo. Each removal is
# a one-line edit away from coming back, and none of them fails a compile, so
# grep-assert their absence in CI. Every check below names the finding it
# enforces and the file(s) it governs.
#
# The two invariants that ARE expressible in Rust live as unit tests instead:
# F5 (`db::tests::provisioning_error_never_leaks_the_password`) and F9
# (`repositories::token::tests::every_single_use_consume_is_guarded`).
#
# Usage: scripts/check-security-invariants.sh
set -euo pipefail

failed=0

fail() {
    echo "error: $*" >&2
    failed=1
}

# -- F4: the Secure cookie attribute derives from the transport ---------------
# `Config::is_production()` is not the transport. A TLS deployment whose
# ENVIRONMENT is not exactly "production" shipped session cookies without
# `Secure`; `Config::cookies_secure(&req)` is the replacement.
if hits=$(grep -rn 'let secure = config\.is_production()' bunyip-api/src crates 2>/dev/null); then
    fail "F4: set-cookie site derives \`secure\` from ENVIRONMENT, not the transport."
    echo "$hits" >&2
    echo "  use Config::cookies_secure(&req) instead." >&2
fi

# -- F6: the dunite git dependency is pinned by rev --------------------------
# `branch = "main"` lets `cargo update` roll the security kernel forward with no
# reviewable diff outside Cargo.lock.
if hits=$(grep -rn 'dunite.*branch *=' crates/*/Cargo.toml 2>/dev/null); then
    fail "F6: dunite dependency pinned to a branch, not a rev."
    echo "$hits" >&2
fi

# -- F8: POST /v1/billing/setup-intent is not a user-enumeration oracle -------
# A registered/unregistered response difference on an unauthenticated endpoint
# is an oracle; /v1/auth/register is the single place that reports the conflict.
if hits=$(grep -n 'find_by_email' bunyip-api/src/handlers/billing.rs 2>/dev/null |
    grep -v ':[[:space:]]*//'); then
    fail "F8: billing.rs looks an email up, which reintroduces the signup enumeration oracle."
    echo "$hits" >&2
fi

# -- F10: every external base image is pinned by digest ----------------------
# `scratch` is a pseudo-image with no manifest, and a bare stage name (e.g.
# `FROM chef AS builder`) refers to an earlier stage in the same file; neither
# can carry a digest. Everything else must.
for dockerfile in bunyip-api/oci-build/Dockerfile bunyip-web/oci-build/Dockerfile; do
    while read -r ref; do
        case "$ref" in
            scratch) continue ;;
            *@sha256:*) continue ;;
            */* | *:*)
                fail "F10: $dockerfile: base image '$ref' is not pinned by digest."
                continue
                ;;
        esac
        # A bare word with no registry, path, or tag is an internal stage name.
        if ! grep -q "^FROM .* AS $ref\$" "$dockerfile"; then
            fail "F10: $dockerfile: '$ref' is neither a digest-pinned image nor a stage defined in this file."
        fi
    done < <(awk '/^FROM /{print $2}' "$dockerfile")
done

if [[ $failed -ne 0 ]]; then
    echo >&2
    echo "One or more BUNYIP-426 security invariants regressed. See the finding notes in" >&2
    echo "scripts/check-security-invariants.sh for why each shape was removed." >&2
    exit 1
fi

echo "check-security-invariants: all BUNYIP-426 invariants hold"
