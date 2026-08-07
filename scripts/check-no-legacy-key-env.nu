#!/usr/bin/env nu

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
#   scripts/check-no-*-env.nu  the env-name gates themselves, which have to
#                              spell out the variables they forbid.
#
# Usage: scripts/check-no-legacy-key-env.nu

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
    let pattern = '(TOTP|STRIPE)_(ENCRYPTION_KEY(_PREV|_FILE)?|KEY_VERSION)'
    let excluded = '^(bunyip-api/migrations/|scripts/check-no-.*-env\.nu$)'

    mut failed = 0
    for file in (^git ls-files | lines) {
        if ($file =~ $excluded) { continue }
        for hit in (matches-in $file $pattern) {
            print --stderr $"error: ($file):($hit.line): '($hit.text)' - the at-rest key is APP_ENCRYPTION_KEY \(BUNYIP-483)."
            $failed = 1
        }
    }

    if $failed != 0 {
        print --stderr ""
        print --stderr "There is ONE at-rest encryption key: APP_ENCRYPTION_KEY (with"
        print --stderr "APP_ENCRYPTION_KEY_PREV for the keys old rows still need, and"
        print --stderr "APP_KEY_VERSION). It protects user_totp, stripe_config and email_config"
        print --stderr "alike. Rewrite existing rows with 'bunyip-api reencrypt-secrets'."
        exit 1
    }

    print "check-no-legacy-key-env: no retired per-consumer at-rest key names"
}
