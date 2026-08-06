#!/usr/bin/env nu

# Stripe-config-is-DB-only gate (BUNYIP-482).
#
# Stripe configuration (secret key, webhook secret, app tag, checkout URLs, $0
# price id) lives ONLY in the `stripe_config` / `tier_config` DB rows, edited on
# the admin Stripe and tier-settings pages. Reintroducing an env read is a
# one-line edit that compiles fine and silently reinstates the "container env
# overrides the admin who cleared the field" behaviour this issue removed, so
# grep-assert that no `STRIPE_*` name outside the allowlist appears anywhere.
#
# BUNYIP-483 removed the last allowance: the at-rest key material is now the
# single APP_ENCRYPTION_KEY family, so NO Stripe-prefixed name is legitimate.
#
# Allowed:
#   *E2E_*STRIPE_*
#     The Playwright harness talking to the Stripe API directly for fixture
#     setup and teardown, not bunyip application config.
#
# Excluded paths:
#   bunyip-api/migrations/  committed migrations are immutable (sqlx checksums
#                           them; an edit stops a deployed DB from booting), so
#                           historical SQL comments naming removed vars stay.
#   e2e/                    the Playwright harness (see the E2E allowance above).
#   scripts/check-no-*-env.nu  the env-name gates themselves, which have to
#                              spell out the variables they forbid.
#
# Usage: scripts/check-no-stripe-env.nu

# Every match of `pattern` in a tracked file, as { line, text } records,
# mirroring `grep -noE`. A file that is gone or not decodable has no text to
# match, exactly as grep reports nothing for a binary.
def matches-in [path: string, pattern: string]: nothing -> table {
    let content = (try { open --raw $path | decode utf-8 } catch { "" })
    $content
    | lines
    | enumerate
    | where {|r| $r.item =~ $pattern }
    | each {|r|
        $r.item
        | parse --regex ("(?<hit>" + $pattern + ")")
        | get hit
        | each {|m| { line: ($r.index + 1), text: $m } }
    }
    | flatten
}

def main [] {
    let pattern = '[A-Z0-9_]*STRIPE_[A-Z0-9_]+'
    let excluded = '^(bunyip-api/migrations/|e2e/|scripts/check-no-.*-env\.nu$)'

    mut failed = 0
    for file in (^git ls-files | lines) {
        if ($file =~ $excluded) { continue }
        for hit in (matches-in $file $pattern) {
            # E2E_* names (in any position) are the test harness, not app config.
            if ($hit.text | str contains "E2E_") { continue }
            print --stderr $"error: ($file):($hit.line): '($hit.text)' - Stripe config is DB-only \(BUNYIP-482); at-rest key material is APP_ENCRYPTION_KEY \(BUNYIP-483)."
            $failed = 1
        }
    }

    if $failed != 0 {
        print --stderr ""
        print --stderr "Stripe configuration must come from the stripe_config / tier_config DB rows"
        print --stderr "(admin Stripe + tier-settings pages), never from the environment, and the"
        print --stderr "at-rest key is APP_ENCRYPTION_KEY. See the notes in"
        print --stderr "scripts/check-no-stripe-env.nu."
        exit 1
    }

    print "check-no-stripe-env: no STRIPE_* env surface outside the E2E harness"
}
