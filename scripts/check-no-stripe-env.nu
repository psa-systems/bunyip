#!/usr/bin/env nu

# Stripe-config-env gate (BUNYIP-482, amended by BUNYIP-542).
#
# Stripe configuration (app tag, checkout URLs, $0 price id) lives ONLY in the
# `stripe_config` / `tier_config` DB rows, edited on the admin Stripe and
# tier-settings pages. Reintroducing an env read is a one-line edit that
# compiles fine and silently reinstates the "container env overrides the admin
# who cleared the field" behaviour BUNYIP-482 removed, so grep-assert that no
# `STRIPE_*` name outside the allowlist appears anywhere.
#
# BUNYIP-483 removed the at-rest key allowance: the key material is the single
# APP_ENCRYPTION_KEY family.
#
# BUNYIP-542 reintroduces exactly TWO names, and no others. The two Stripe
# SECRETS are governed by `SECRETS_STORAGE`, and `SECRETS_STORAGE=environment`
# needs a name to read them under. They are read file-backed only
# (`GovernedSecret::read_environment` -> `{NAME}_FILE`), never from the plain
# variable: a `STRIPE_SECRET_KEY=sk_live_...` in a compose `environment:` block
# is visible to `docker inspect` and to every child process, which is the
# exposure BUNYIP-38 removed. The non-secret Stripe configuration above stays
# DB-only, so this gate still fails on every other Stripe-shaped name.
#
# Allowed:
#   STRIPE_SECRET_KEY / STRIPE_SECRET_KEY_FILE
#   STRIPE_WEBHOOK_SECRET / STRIPE_WEBHOOK_SECRET_FILE
#     The two governed secrets (BUNYIP-542). The bare spelling is allowed
#     because the code, the docs and this gate must be able to NAME them; the
#     `_FILE` spelling is the only one a value ever arrives through.
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

# The two governed-secret names BUNYIP-542 allows, in both spellings.
const GOVERNED = [
    "STRIPE_SECRET_KEY"
    "STRIPE_SECRET_KEY_FILE"
    "STRIPE_WEBHOOK_SECRET"
    "STRIPE_WEBHOOK_SECRET_FILE"
]

def main [] {
    let pattern = '[A-Z0-9_]*STRIPE_[A-Z0-9_]+'
    let excluded = '^(bunyip-api/migrations/|e2e/|scripts/check-no-.*-env\.nu$)'

    mut failed = 0
    for file in (^git ls-files | lines) {
        if ($file =~ $excluded) { continue }
        for hit in (matches-in $file $pattern) {
            # E2E_* names (in any position) are the test harness, not app config.
            if ($hit.text | str contains "E2E_") { continue }
            # BUNYIP-542: the two governed Stripe secrets, which
            # SECRETS_STORAGE=environment reads through {NAME}_FILE.
            if ($hit.text in $GOVERNED) { continue }
            print --stderr $"error: ($file):($hit.line): '($hit.text)' - Stripe config is DB-only \(BUNYIP-482); at-rest key material is APP_ENCRYPTION_KEY \(BUNYIP-483); only STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET are governed secrets \(BUNYIP-542)."
            $failed = 1
        }
    }

    if $failed != 0 {
        print --stderr ""
        print --stderr "Stripe configuration must come from the stripe_config / tier_config DB rows"
        print --stderr "(admin Stripe + tier-settings pages), never from the environment, and the"
        print --stderr "at-rest key is APP_ENCRYPTION_KEY. The only Stripe env names bunyip reads"
        print --stderr "are STRIPE_SECRET_KEY_FILE and STRIPE_WEBHOOK_SECRET_FILE, and only when"
        print --stderr "SECRETS_STORAGE=environment. See the notes in scripts/check-no-stripe-env.nu."
        exit 1
    }

    print "check-no-stripe-env: no STRIPE_* env surface beyond the two governed secrets and the E2E harness"
}
