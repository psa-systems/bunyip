#!/usr/bin/env nu

# Em-dash ban gate (BUNYIP-694).
#
# CLAUDE.md bans the em-dash character (U+2014) in any output or artifact,
# but nothing enforced it: a repo-wide scan found 50 occurrences across 25
# files with the rule in place the whole time. This gate fails the build when
# a tracked file contains U+2014, so a new one is caught at the PR that
# introduces it instead of accumulating. It does not fix the existing
# occurrences; that sweep is tracked separately, as a follow-up issue.
#
# The character is built at runtime from its codepoint rather than typed
# literally, so this file cannot trip the gate it defines.
#
# Usage:
#   scripts/check-em-dash.nu
#   scripts/check-em-dash.nu --self-test

const EM_DASH_CODEPOINT = "2014"

def em-dash []: nothing -> string {
    char --unicode $EM_DASH_CODEPOINT
}

# Occurrences of the em-dash in one tracked file, as human-readable lines.
def check-file [path: string, em_dash: string]: nothing -> list<string> {
    let lines = (try { open --raw $path | decode utf-8 | lines } catch { [] })
    $lines
    | enumerate
    | where {|row| $row.item | str contains $em_dash }
    | each {|row| $"($path):($row.index + 1): contains an em-dash - use a hyphen, colon, parentheses, or a new sentence instead." }
}

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)
    let em_dash = (em-dash)

    let clean_path = $"($dir)/clean.rs"
    'let x = "a hyphen - not a dash";' | save --force $clean_path
    let clean_problems = (check-file $clean_path $em_dash)

    let dirty_path = $"($dir)/dirty.rs"
    ('let x = "a sentence' + $em_dash + 'broken in two";') | save --force $dirty_path
    let dirty_problems = (check-file $dirty_path $em_dash)

    let missing_problems = (check-file $"($dir)/absent.rs" $em_dash)

    rm --recursive $dir

    mut ok = true
    if ($clean_problems | is-not-empty) {
        print --stderr $"self-test FAILED: gate flags a file with no em-dash: ($clean_problems | to nuon)"
        $ok = false
    } else {
        print "self-test ok: gate leaves a hyphen alone"
    }
    if ($dirty_problems | is-empty) {
        print --stderr "self-test FAILED: gate misses an em-dash"
        $ok = false
    } else {
        print "self-test ok: gate catches an em-dash"
    }
    if ($missing_problems | is-not-empty) {
        print --stderr "self-test FAILED: gate reports problems for a file that does not exist"
        $ok = false
    } else {
        print "self-test ok: gate handles an unreadable file"
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

    let problems = ($files | each {|f| check-file $f $em_dash } | flatten)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        let count = ($problems | length)
        print --stderr ""
        print --stderr $"($count) em-dash occurrence\(s\) found across the tracked tree."
        print --stderr "CLAUDE.md bans the em-dash \(U+2014\) in any output or artifact: use a"
        print --stderr "hyphen, colon, parentheses, or a period and a new sentence instead."
        exit 1
    }

    print $"check-em-dash: ($files | length) tracked files carry no em-dash"
}
