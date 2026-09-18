#!/usr/bin/env nu

# Compose env-parity gate (BUNYIP-749).
#
# `crates/bunyip-domain/src/config.rs` falls back to CORS_ORIGIN's first entry
# when APP_URL / BUNYIP_WEB_ORIGIN are unset - a reasonable default for a
# single-RP dev box with no overlay, but silently wrong for a shipped compose
# file: the OIDC login bounce and every transactional-email link resolve to
# the wrong origin. Every compose file that runs the bunyip-api service must
# set both explicitly to that stage's real web origin (BUNYIP-PAR-2026-09-18
# finding F1, carried from 09-04 F1). This gate fails the build the moment a
# shipped compose file's api service is missing either key.
#
# Usage:
#   scripts/check-compose-env-parity.nu
#   scripts/check-compose-env-parity.nu --self-test

const COMPOSE_FILES = ["compose.yml", "compose.dev.yml", "compose.dev-sso.yml"]
const REQUIRED_KEYS = ["APP_URL", "BUNYIP_WEB_ORIGIN"]

# Every required key that has a line inside the api service's environment
# block, matched loosely (`  KEY:` anywhere in the file) since compose.dev-sso.yml
# is a partial overlay rather than a complete service definition.
def keys-in-file [content: string]: nothing -> list<string> {
    $content
    | lines
    | parse --regex '^\s+(APP_URL|BUNYIP_WEB_ORIGIN):'
    | get capture0
    | uniq
}

def missing-keys [content: string]: nothing -> list<string> {
    let present = (keys-in-file $content)
    $REQUIRED_KEYS | where {|key| $key not-in $present }
}

def self-test []: nothing -> nothing {
    mut ok = true

    for file in $COMPOSE_FILES {
        let content = (open --raw $file | decode utf-8)

        let clean = (missing-keys $content)
        if ($clean | is-not-empty) {
            print --stderr $"self-test FAILED: gate reports a mismatch against the real tree \(($file)\): ($clean | to nuon)"
            $ok = false
        } else {
            print $"self-test ok: gate agrees ($file) sets every required key"
        }

        let injected = ($content | str replace --all "APP_URL" "BUNYIP_749_SELF_TEST_ONLY")
        if $injected == $content {
            print --stderr $"self-test FAILED: injection anchor not found in ($file)"
            $ok = false
        } else {
            let dirty = (missing-keys $injected)
            if ($dirty | is-empty) {
                print --stderr $"self-test FAILED: gate misses an injected missing key in ($file)"
                $ok = false
            } else {
                print $"self-test ok: gate catches an injected missing key in ($file)"
            }
        }
    }

    if not $ok { exit 1 }
}

def main [
    --self-test # prove the gate catches an injected mismatch and agrees the real tree matches, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    mut ok = true
    for file in $COMPOSE_FILES {
        let content = (open --raw $file | decode utf-8)
        let missing = (missing-keys $content)
        if ($missing | is-not-empty) {
            for key in $missing {
                print --stderr $"error: ($file) has no ($key) line - the OIDC login bounce and every transactional-email link fall back to CORS_ORIGIN's first entry instead of the real web origin"
            }
            $ok = false
        } else {
            print $"check-compose-env-parity: ($file) sets ($REQUIRED_KEYS | str join ', ')"
        }
    }

    if not $ok { exit 1 }
}
