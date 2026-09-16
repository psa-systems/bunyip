#!/usr/bin/env nu

# System-level key table gate (BUNYIP-734).
#
# `SYSTEM_LEVEL_ENV_KEYS` in `crates/bunyip-domain/src/sys_config.rs` and the
# system-level table in `docs/configuration.md` are two hand-written copies of
# the same set, and nothing compared them: a phantom Infisical variable name
# sat in both for one whole release while the name everything else actually
# read was a different one (BUNYIP-734). This gate reads both as flat sets of
# uppercase identifiers and fails the build the moment they diverge, so a name
# can drift out of only one copy without the build noticing it.
#
# Usage:
#   scripts/check-system-level-keys.nu
#   scripts/check-system-level-keys.nu --self-test

const RUST_FILE = "crates/bunyip-domain/src/sys_config.rs"
const DOC_FILE = "docs/configuration.md"

# The uppercase identifiers quoted inside SYSTEM_LEVEL_ENV_KEYS's array
# literal, as a sorted deduplicated list. Reads the whole array by bracket
# matching rather than a line range, so moving the constant does not break the
# gate.
def rust-keys [content: string]: nothing -> list<string> {
    let anchor = "pub const SYSTEM_LEVEL_ENV_KEYS"
    let start = ($content | str index-of $anchor)
    if $start < 0 {
        return []
    }
    let after = ($content | str substring $start..)
    let open = ($after | str index-of "= &[")
    let close = ($after | str index-of "\n];")
    if $open < 0 or $close < 0 {
        return []
    }
    let body = ($after | str substring ($open + 4)..($close - 1))
    $body | parse --regex '"([A-Z0-9_]+)"' | get capture0 | uniq | sort
}

# The uppercase identifiers backtick-quoted inside the "System-level
# (environment only, never API-writable):" table, as a sorted deduplicated
# list. Stops at the next "**" heading so the application-level prose below it
# (which also carries backtick-quoted names) is never read.
def doc-keys [content: string]: nothing -> list<string> {
    let marker = "System-level (environment only, never API-writable):"
    let start = ($content | str index-of $marker)
    if $start < 0 {
        return []
    }
    let after = ($content | str substring ($start + ($marker | str length))..)
    let lines = ($after | lines)
    let table_lines = ($lines | skip while {|l| not ($l | str starts-with "|") })
    let section = ($table_lines | take while {|l| ($l | str starts-with "|") or ($l | str trim | is-empty) })
    $section
    | str join "\n"
    | parse --regex '`([A-Z0-9_]+)`'
    | get capture0
    | uniq
    | sort
}

def diff-report [rust: list<string>, doc: list<string>]: nothing -> list<string> {
    let only_rust = ($rust | where {|k| $k not-in $doc })
    let only_doc = ($doc | where {|k| $k not-in $rust })
    mut problems = []
    if ($only_rust | is-not-empty) {
        $problems = ($problems | append $"in SYSTEM_LEVEL_ENV_KEYS but not in the docs/configuration.md table: ($only_rust | str join ', ')")
    }
    if ($only_doc | is-not-empty) {
        $problems = ($problems | append $"in the docs/configuration.md table but not in SYSTEM_LEVEL_ENV_KEYS: ($only_doc | str join ', ')")
    }
    $problems
}

def self-test []: nothing -> nothing {
    mut ok = true

    let rust_content = (open --raw $RUST_FILE | decode utf-8)
    let doc_content = (open --raw $DOC_FILE | decode utf-8)

    let clean_problems = (diff-report (rust-keys $rust_content) (doc-keys $doc_content))
    if ($clean_problems | is-not-empty) {
        print --stderr $"self-test FAILED: gate reports a mismatch against the real tree: ($clean_problems | to nuon)"
        $ok = false
    } else {
        print "self-test ok: gate agrees the real tree matches"
    }

    let injected_rust = ($rust_content | str replace '"BUNYIP_WEB_ORIGIN",' '"BUNYIP_WEB_ORIGIN",
    "BUNYIP_734_SELF_TEST_ONLY",')
    if $injected_rust == $rust_content {
        print --stderr "self-test FAILED: injection anchor not found in sys_config.rs"
        $ok = false
    } else {
        let dirty_problems = (diff-report (rust-keys $injected_rust) (doc-keys $doc_content))
        if ($dirty_problems | is-empty) {
            print --stderr "self-test FAILED: gate misses an injected mismatch"
            $ok = false
        } else {
            print "self-test ok: gate catches an injected mismatch"
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
    let doc_content = (open --raw $DOC_FILE | decode utf-8)

    let rust = (rust-keys $rust_content)
    let doc = (doc-keys $doc_content)

    if ($rust | is-empty) {
        print --stderr $"error: could not find SYSTEM_LEVEL_ENV_KEYS in ($RUST_FILE)"
        exit 1
    }
    if ($doc | is-empty) {
        print --stderr $"error: could not find the system-level table in ($DOC_FILE)"
        exit 1
    }

    let problems = (diff-report $rust $doc)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "SYSTEM_LEVEL_ENV_KEYS and the docs/configuration.md system-level table must"
        print --stderr "name the same set of keys. Update whichever side is missing a name."
        exit 1
    }

    print $"check-system-level-keys: ($rust | length) keys agree between SYSTEM_LEVEL_ENV_KEYS and the docs/configuration.md table"
}
