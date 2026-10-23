#!/usr/bin/env nu

# Em-dash ban gate (BUNYIP-694).
#
# CLAUDE.md bans the em-dash character (U+2014) in any output or artifact,
# but nothing enforced it: a repo-wide scan found 50 occurrences across 25
# files with the rule in place the whole time. This gate fails the build when
# a tracked file contains U+2014, so a new one is caught at the PR that
# introduces it instead of accumulating.
#
# The character is built at runtime from its codepoint rather than typed
# literally, so this file cannot trip the gate it defines.
#
# Usage:
#   scripts/check-em-dash.nu
#   scripts/check-em-dash.nu --self-test

const EM_DASH_CODEPOINT = "2014"

# Committed migrations are immutable (sqlx checksums every byte, comments included),
# so these two keep their em-dash. Exact paths: a new migration is still gated.
const IMMUTABLE_EXEMPT = [
    "bunyip-api/migrations/20260417000040_create_oidc_clients.sql"
    "bunyip-api/migrations/20260417000042_create_oidc_tokens.sql"
]

def em-dash []: nothing -> string {
    char --unicode $EM_DASH_CODEPOINT
}

# Inspects one tracked file for the em-dash. A file containing a NUL byte is
# treated as binary and skipped (counted, not inspected). Any other failure to
# open or decode the file as UTF-8 is reported as an error naming the path,
# instead of being silently treated as a clean, zero-line file.
def check-file [path: string, em_dash: string]: nothing -> record<problems: list<string>, skipped: bool, error: string> {
    let raw = (try { open --raw $path | into binary } catch {|err|
        return {problems: [], skipped: false, error: $"($path): could not be inspected: ($err.msg)"}
    })

    if (($raw | bytes index-of 0x[00]) != -1) {
        return {problems: [], skipped: true, error: ""}
    }

    let decoded = ($raw | decode utf-8)
    if (($decoded | encode utf-8) != $raw) {
        return {problems: [], skipped: false, error: $"($path): could not be inspected: not valid UTF-8"}
    }

    let problems = (
        $decoded
        | lines
        | enumerate
        | where {|row| $row.item | str contains $em_dash }
        | each {|row| $"($path):($row.index + 1): contains an em-dash - use a hyphen, colon, parentheses, or a new sentence instead." }
    )
    {problems: $problems, skipped: false, error: ""}
}

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)
    let em_dash = (em-dash)

    let clean_path = $"($dir)/clean.rs"
    'let x = "a hyphen - not a dash";' | save --force $clean_path
    let clean_result = (check-file $clean_path $em_dash)

    let dirty_path = $"($dir)/dirty.rs"
    ('let x = "a sentence' + $em_dash + 'broken in two";') | save --force $dirty_path
    let dirty_result = (check-file $dirty_path $em_dash)

    let undecodable_path = $"($dir)/undecodable.rs"
    0x[61 FF 62] | save --force $undecodable_path
    let undecodable_result = (check-file $undecodable_path $em_dash)

    let binary_path = $"($dir)/binary.rs"
    0x[61 00 62] | save --force $binary_path
    let binary_result = (check-file $binary_path $em_dash)

    rm --recursive $dir

    mut ok = true
    if ($clean_result.problems | is-not-empty) {
        print --stderr $"self-test FAILED: gate flags a file with no em-dash: ($clean_result.problems | to nuon)"
        $ok = false
    } else {
        print "self-test ok: gate leaves a hyphen alone"
    }
    if ($dirty_result.problems | is-empty) {
        print --stderr "self-test FAILED: gate misses an em-dash"
        $ok = false
    } else {
        print "self-test ok: gate catches an em-dash"
    }
    if ($undecodable_result.error | is-empty) or not ($undecodable_result.error | str contains $undecodable_path) {
        print --stderr "self-test FAILED: gate does not fail and name the path of an undecodable file"
        $ok = false
    } else {
        print "self-test ok: gate fails on an undecodable file and names it"
    }
    if (not $binary_result.skipped) or ($binary_result.error | is-not-empty) {
        print --stderr "self-test FAILED: gate does not skip and count a binary file"
        $ok = false
    } else {
        print "self-test ok: gate skips and counts a binary file"
    }
    if not $ok { exit 1 }
}

def main [
    --self-test # prove the gate catches an em-dash and leaves a hyphen alone, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let em_dash = (em-dash)
    let files = (^git ls-files | lines)
    if ($files | is-empty) {
        print --stderr "error: git ls-files returned no tracked files - the gate cannot prove the tree is clean."
        exit 1
    }

    # A submodule gitlink is a tracked path with no blob content of its own, so
    # it is not a file the gate can read or decode and stays out of scope.
    let scanned_files = ($files | where {|f| ($f | path type) == "file" })
    let results = ($scanned_files | where {|f| $f not-in $IMMUTABLE_EXEMPT } | each {|f| check-file $f $em_dash })
    let problems = ($results | each {|r| $r.problems } | flatten)
    let errors = ($results | each {|r| $r.error } | where {|e| $e | is-not-empty })
    let skipped = ($results | where {|r| $r.skipped } | length)

    if ($errors | is-not-empty) {
        for e in $errors { print --stderr $"error: ($e)" }
    }
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        let count = ($problems | length)
        print --stderr ""
        print --stderr $"($count) em-dash occurrence\(s\) found across the tracked tree."
        print --stderr "CLAUDE.md bans the em-dash \(U+2014\) in any output or artifact: use a"
        print --stderr "hyphen, colon, parentheses, or a period and a new sentence instead."
    }
    if ($errors | is-not-empty) or ($problems | is-not-empty) {
        exit 1
    }

    print $"check-em-dash: ($scanned_files | length) tracked files checked, ($skipped) skipped as binary, no em-dash outside the ($IMMUTABLE_EXEMPT | length) exempt immutable migrations"
}
