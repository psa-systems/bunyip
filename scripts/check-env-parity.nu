#!/usr/bin/env nu

# bunyip-web env-parity gate (BUNYIP-720).
#
# Every environment variable `Config::from_env` reads in
# `bunyip-web/src/config.rs` must have an entry in `.env.example` (active or
# commented-out), or a deployer has no way to discover it exists: the variable
# compiles fine, defaults silently, and the gap surfaces only as a wrong
# runtime value (BUNYIP_API_PUBLIC_ORIGIN's dev-sso mix-up was exactly this
# shape). This gate reads the `var("NAME")` calls out of config.rs and fails
# the build the moment one names a variable `.env.example` does not document.
#
# Usage:
#   scripts/check-env-parity.nu
#   scripts/check-env-parity.nu --self-test

const RUST_FILE = "bunyip-web/src/config.rs"
const ENV_FILE = ".env.example"

# Every uppercase NAME passed to a `var("NAME")` call, sorted and deduplicated.
def config-vars [content: string]: nothing -> list<string> {
    $content
    | parse --regex 'var\("([A-Z0-9_]+)"\)'
    | get capture0
    | uniq
    | sort
}

# Every uppercase NAME assigned at the start of a line in .env.example, active
# or commented out (`NAME=` or `# NAME=`), sorted and deduplicated.
def documented-vars [content: string]: nothing -> list<string> {
    $content
    | lines
    | parse --regex '^#?\s*([A-Z0-9_]+)='
    | get capture0
    | uniq
    | sort
}

def undocumented [rust: list<string>, documented: list<string>]: nothing -> list<string> {
    $rust | where {|k| $k not-in $documented }
}

def self-test []: nothing -> nothing {
    mut ok = true

    let rust_content = (open --raw $RUST_FILE | decode utf-8)
    let env_content = (open --raw $ENV_FILE | decode utf-8)

    let clean = (undocumented (config-vars $rust_content) (documented-vars $env_content))
    if ($clean | is-not-empty) {
        print --stderr $"self-test FAILED: gate reports a mismatch against the real tree: ($clean | to nuon)"
        $ok = false
    } else {
        print "self-test ok: gate agrees the real tree matches"
    }

    let injected = ($rust_content | str replace 'var("BUNYIP_APP_DOMAIN")' 'var("BUNYIP_720_SELF_TEST_ONLY")')
    if $injected == $rust_content {
        print --stderr "self-test FAILED: injection anchor not found in config.rs"
        $ok = false
    } else {
        let dirty = (undocumented (config-vars $injected) (documented-vars $env_content))
        if ($dirty | is-empty) {
            print --stderr "self-test FAILED: gate misses an injected undocumented variable"
            $ok = false
        } else {
            print "self-test ok: gate catches an injected undocumented variable"
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

    let rust_content = (open --raw $RUST_FILE | decode utf-8)
    let env_content = (open --raw $ENV_FILE | decode utf-8)

    let rust = (config-vars $rust_content)
    if ($rust | is-empty) {
        print --stderr $"error: could not find any var\(\"...\"\) reads in ($RUST_FILE)"
        exit 1
    }

    let missing = (undocumented $rust (documented-vars $env_content))
    if ($missing | is-not-empty) {
        for name in $missing {
            print --stderr $"error: ($RUST_FILE) reads '($name)' but ($ENV_FILE) has no entry for it"
        }
        print --stderr ""
        print --stderr $"Add ($ENV_FILE) entries (active or commented) for every variable"
        print --stderr $"($RUST_FILE) reads, so a deployer can discover it exists."
        exit 1
    }

    print $"check-env-parity: ($rust | length) bunyip-web config variables all documented in ($ENV_FILE)"
}
