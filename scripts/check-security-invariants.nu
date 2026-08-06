#!/usr/bin/env nu

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
# Usage: scripts/check-security-invariants.nu

# Read a file as UTF-8 lines. A file that is absent or not decodable has no
# lines to match, mirroring how grep treats one.
def read-lines [path: string]: nothing -> list<string> {
    try { open --raw $path | decode utf-8 | lines } catch { [] }
}

# Every line of `files` matching `pattern`, as { file, line, text } records with
# repo-relative paths, mirroring `grep -n`.
def grep-files [files: list<string>, pattern: string]: nothing -> table {
    $files
    | each {|path|
        let rel = (try { $path | path expand | path relative-to $env.PWD } catch { $path })
        read-lines $path
        | enumerate
        | where {|r| $r.item =~ $pattern }
        | each {|r| { file: $rel, line: ($r.index + 1), text: $r.item } }
    }
    | flatten
}

# Same, recursively over directories, mirroring `grep -rn`.
def grep-tree [dirs: list<string>, pattern: string]: nothing -> table {
    grep-files ($dirs | each {|d| glob $"($d)/**/*" --no-dir } | flatten) $pattern
}

def print-hits [hits: table] {
    for hit in $hits { print --stderr $"($hit.file):($hit.line):($hit.text)" }
}

def main [] {
    mut failed = 0

    # -- F4: the Secure cookie attribute derives from the transport -----------
    # `Config::is_production()` is not the transport. A TLS deployment whose
    # ENVIRONMENT is not exactly "production" shipped session cookies without
    # `Secure`; `Config::cookies_secure(&req)` is the replacement.
    let f4 = (grep-tree ["bunyip-api/src" "crates"] 'let secure = config\.is_production\(\)')
    if ($f4 | is-not-empty) {
        print --stderr "error: F4: set-cookie site derives `secure` from ENVIRONMENT, not the transport."
        print-hits $f4
        print --stderr "  use Config::cookies_secure(&req) instead."
        $failed = 1
    }

    # -- F6: the dunite git dependency is pinned by rev ------------------------
    # `branch = "main"` lets `cargo update` roll the security kernel forward with
    # no reviewable diff outside Cargo.lock.
    let f6 = (grep-files (glob "crates/*/Cargo.toml") 'dunite.*branch *=')
    if ($f6 | is-not-empty) {
        print --stderr "error: F6: dunite dependency pinned to a branch, not a rev."
        print-hits $f6
        $failed = 1
    }

    # -- F8: POST /v1/billing/setup-intent is not a user-enumeration oracle ----
    # A registered/unregistered response difference on an unauthenticated
    # endpoint is an oracle; /v1/auth/register is the single place that reports
    # the conflict. A commented mention is prose, not a lookup.
    let f8 = (
        grep-files ["bunyip-api/src/handlers/billing.rs"] 'find_by_email'
        | where {|h| not ($h.text | str trim | str starts-with "//") }
    )
    if ($f8 | is-not-empty) {
        print --stderr "error: F8: billing.rs looks an email up, which reintroduces the signup enumeration oracle."
        print-hits $f8
        $failed = 1
    }

    # -- F10: every external base image is pinned by digest -------------------
    # `scratch` is a pseudo-image with no manifest, and a bare stage name (e.g.
    # `FROM chef AS builder`) refers to an earlier stage in the same file;
    # neither can carry a digest. Everything else must.
    for dockerfile in ["bunyip-api/oci-build/Dockerfile" "bunyip-web/oci-build/Dockerfile"] {
        let lines = (read-lines $dockerfile)
        let refs = ($lines | where {|l| $l =~ '^FROM ' } | each {|l| $l | split row --regex '\s+' | get 1 })
        for ref in $refs {
            if $ref == "scratch" { continue }
            if ($ref | str contains "@sha256:") { continue }
            if ($ref | str contains "/") or ($ref | str contains ":") {
                print --stderr $"error: F10: ($dockerfile): base image '($ref)' is not pinned by digest."
                $failed = 1
                continue
            }
            # A bare word with no registry, path, or tag is an internal stage name.
            if not ($lines | any {|l| $l =~ $"^FROM .* AS ($ref)$" }) {
                print --stderr $"error: F10: ($dockerfile): '($ref)' is neither a digest-pinned image nor a stage defined in this file."
                $failed = 1
            }
        }
    }

    if $failed != 0 {
        print --stderr ""
        print --stderr "One or more BUNYIP-426 security invariants regressed. See the finding notes in"
        print --stderr "scripts/check-security-invariants.nu for why each shape was removed."
        exit 1
    }

    print "check-security-invariants: all BUNYIP-426 invariants hold"
}
