#!/usr/bin/env nu

# Retired environment-variable name gate.
#
# Some environment variables are deliberately GONE. Reintroducing one is a
# one-line edit that parses fine, compiles fine and passes every other check,
# while silently restoring the defect that removing it fixed. Each entry in the
# table below grep-asserts that its names appear in no tracked file.
#
#   at-rest keys (BUNYIP-483)   the TOTP secrets, the Stripe credentials and the
#                               SMTP password are encrypted with the SAME key,
#                               provisioned as APP_ENCRYPTION_KEY (plus
#                               APP_ENCRYPTION_KEY_PREV / APP_KEY_VERSION). A
#                               per-consumer key name splits the key material in
#                               two again.
#   dead OIDC vars (BUNYIP-539) bunyip-web is an Axum SSR server that signs in
#                               against bunyip-api's own /v1/auth/* endpoints and
#                               runs no authorization-code flow of its own, so it
#                               reads BUNYIP_OIDC_ISSUER and nothing else from
#                               that family. The other three were consumed by the
#                               deleted SPA's /config.json and survived as
#                               container passthrough no process read, two of
#                               them aborting `compose up` with a `:?` marker.
#   palette vars (BUNYIP-568)   the theme CSS and the two browser-chrome colours
#                               are columns of the admin-managed branding
#                               record. BUNYIP-560 kept the three variables as
#                               bootstrap defaults for one release; removing
#                               them with the plumbing that read them leaves one
#                               source for the palette, because a variable that
#                               silently loses to a database row is a support
#                               call waiting to happen.
#
# Excluded paths:
#   bunyip-api/migrations/  committed migrations are immutable (sqlx checksums
#                           them; an edit stops a deployed DB from booting), so
#                           historical SQL comments naming removed vars stay.
#   scripts/check-no-*-env.nu  the env-name gates themselves, which have to
#                              spell out the variables they forbid.
#
# Usage: scripts/check-no-retired-env.nu

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
    let retired = [
        {
            pattern: '(TOTP|STRIPE)_(ENCRYPTION_KEY(_PREV|_FILE)?|KEY_VERSION)',
            hint: 'the at-rest key is APP_ENCRYPTION_KEY (BUNYIP-483)',
            remedy: [
                "There is ONE at-rest encryption key: APP_ENCRYPTION_KEY (with"
                "APP_ENCRYPTION_KEY_PREV for the keys old rows still need, and"
                "APP_KEY_VERSION). It protects user_totp, stripe_config and email_config"
                "alike. Rewrite existing rows with 'bunyip-api reencrypt-secrets'."
            ]
        }
        {
            pattern: 'BUNYIP_OIDC_(CLIENT_ID|REDIRECT_URI|SCOPES)',
            hint: 'bunyip-web reads only BUNYIP_OIDC_ISSUER (BUNYIP-539)',
            remedy: [
                "bunyip-web is server-rendered and signs in against bunyip-api's own"
                "/v1/auth/* endpoints, so it runs no authorization-code flow and needs no"
                "client id, redirect URI or scope list. BUNYIP_OIDC_ISSUER is the only"
                "variable of that family it reads. If bunyip-web ever becomes a relying"
                "party in its own right, add the variables back WITH the code that reads"
                "them, and drop the entry here."
            ]
        }
        {
            pattern: 'BRAND_THEME_(CSS|COLOR_LIGHT|COLOR_DARK)',
            hint: 'the palette is the branding record, not the environment (BUNYIP-568)',
            remedy: [
                "The theme CSS and the two browser-chrome colours are columns of the"
                "admin-managed branding record, edited on the admin Branding page and"
                "fetched by bunyip-web from GET /v1/branding. BUNYIP-560 kept these three"
                "variables as bootstrap defaults for one release; BUNYIP-568 removed them"
                "with the Config fields and the web-kit shell cells that read them. An"
                "empty column omits its markup, so nothing is compiled in and nothing"
                "falls back to the environment. Set the palette on the admin Branding"
                "page instead."
            ]
        }
    ]
    let excluded = '^(bunyip-api/migrations/|scripts/check-no-.*-env\.nu$)'
    let tracked = (^git ls-files | lines | where {|f| not ($f =~ $excluded) })

    mut failing = []
    for entry in $retired {
        mut hit_any = false
        for file in $tracked {
            for hit in (matches-in $file $entry.pattern) {
                print --stderr $"error: ($file):($hit.line): '($hit.text)' - ($entry.hint)."
                $hit_any = true
            }
        }
        if $hit_any { $failing = ($failing | append $entry) }
    }

    if ($failing | is-not-empty) {
        for entry in $failing {
            print --stderr ""
            for line in $entry.remedy { print --stderr $line }
        }
        exit 1
    }

    print "check-no-retired-env: no retired environment-variable names"
}
