#!/usr/bin/env nu

# User-facing copy gate for bunyip-web (BUNYIP-551).
#
# Two shapes that had exactly one holdout each, so the class stays closed once
# the holdout is fixed:
#   - a three-dot ellipsis. BUNYIP-472 standardised the placeholder ellipses on
#     the single-character glyph; `server_status.rs` kept `Reconnecting...`
#     because it is copy rather than a placeholder and fell outside that sweep.
#     It renders on every page, including `/login`, when the API is down.
#   - an ASCII emoticon. The app-docs empty state read
#     `Sorry. No docs for this app yet :(`, the only emoticon in the product and
#     the only empty state that apologised, against 23 terse sibling messages.
#
# Only double-quoted string literals are scanned, so a comment or a Rust path
# (`serde::Deserialize` carries `:D`, `types::PricingResponse` carries `:P`) is
# never a hit. Whole-line comments are dropped first, so prose quoting a
# forbidden shape to explain it does not read as a violation.
#
# Usage:
#   scripts/check-ui-copy.nu
#   scripts/check-ui-copy.nu --self-test

# BUNYIP-502: also scan the shared web-kit crate, which now holds UI toolkit
# code (icons/buttons/badges/boxes) lifted out of bunyip-web/src/views.
const SRC_GLOB = "{bunyip-web/src,crates/web-kit/src}/**/*.rs"

# One double-quoted Rust string literal, escapes included.
const LITERAL = '"(?<lit>(?:[^"\\]|\\.)*)"'

const FORBIDDEN = [
    {
        pattern: '\.\.\.'
        why: "three-dot ellipsis in user-facing copy; use the single-character … glyph"
    }
    {
        pattern: '(^|\s)[:;]-?[()DPp](\s|$|[.,!])'
        why: "ASCII emoticon in user-facing copy; the empty states and banners are terse noun phrases"
    }
]

# Problems in one Rust source file, as human-readable lines.
def check-rs [path: string]: nothing -> list<string> {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): missing or not readable - the gate cannot prove the copy is clean."]
    }

    mut problems = []
    for row in ($content | lines | enumerate) {
        let text = $row.item
        # Whole-line comments are prose about the code, not copy the user reads.
        if ($text | str trim | str starts-with "//") { continue }
        for hit in ($text | parse --regex $LITERAL | get lit) {
            for rule in $FORBIDDEN {
                if ($hit =~ $rule.pattern) {
                    $problems = ($problems | append $"($path):($row.index + 1): \"($hit)\" - ($rule.why).")
                }
            }
        }
    }
    $problems
}

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)

    let cases = [
        {
            name: "clean.rs"
            body: 'span class="font-medium" { "Service unavailable. Reconnecting…" }'
            expect_problems: false
            why: "the single-character ellipsis glyph"
        }
        {
            name: "terse-empty-state.rs"
            body: '(empty_state("file-text", "No documentation for this app yet.", None))'
            expect_problems: false
            why: "a terse empty-state noun phrase"
        }
        {
            name: "rust-paths.rs"
            body: "use serde::Deserialize;\nuse crate::api::types::PricingResponse;"
            expect_problems: false
            why: "`:D` / `:P` inside a Rust path rather than a string literal"
        }
        {
            name: "commented.rs"
            body: '// the old copy read "Reconnecting..." and "yet :(" before BUNYIP-551'
            expect_problems: false
            why: "a comment quoting the forbidden shapes to explain them"
        }
        {
            name: "three-dots.rs"
            body: 'span { "Service unavailable. Reconnecting..." }'
            expect_problems: true
            why: "a three-dot ellipsis in a rendered string"
        }
        {
            name: "three-dots-placeholder.rs"
            body: 'input placeholder="Search by email..." class=(dashboard_input());'
            expect_problems: true
            why: "a three-dot ellipsis in a placeholder attribute"
        }
        {
            name: "emoticon.rs"
            body: '(empty_state("file-text", "Sorry. No docs for this app yet :(", None))'
            expect_problems: true
            why: "an ASCII emoticon in an empty-state message"
        }
        {
            name: "emoticon-mid-string.rs"
            body: 'p { "Nothing here ;) yet" }'
            expect_problems: true
            why: "an ASCII emoticon in the middle of a sentence"
        }
    ]

    let results = ($cases | each {|c|
        let path = $"($dir)/($c.name)"
        $c.body | save --force $path
        let problems = (check-rs $path)
        {why: $c.why, ok: (($problems | is-not-empty) == $c.expect_problems), problems: $problems}
    })
    let missing = (check-rs $"($dir)/absent.rs")
    rm --recursive $dir

    for r in $results {
        if $r.ok {
            print $"self-test ok: gate handles ($r.why)"
        } else {
            print --stderr $"self-test FAILED: gate mis-handles ($r.why): ($r.problems | to nuon)"
        }
    }
    if ($missing | is-empty) {
        print --stderr "self-test FAILED: gate mis-handles an unreadable source file"
    } else {
        print "self-test ok: gate handles an unreadable source file"
    }
    if (($results | any {|r| not $r.ok }) or ($missing | is-empty)) {
        exit 1
    }
}

def main [
    --self-test # prove the gate rejects a three-dot ellipsis and an emoticon, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let files = (glob $SRC_GLOB)
    if ($files | is-empty) {
        print --stderr $"error: ($SRC_GLOB) matched no files - the gate cannot prove the copy is clean."
        exit 1
    }

    let problems = ($files | each {|f| check-rs $f } | flatten)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "User-facing copy uses one ellipsis glyph and one voice (BUNYIP-551):"
        print --stderr "the single-character … rather than three dots, and terse noun phrases with"
        print --stderr "no emoticons. Fix the string literal, or move the text into a comment if it"
        print --stderr "is not copy."
        exit 1
    }

    print $"check-ui-copy: ($files | length) source files carry no three-dot ellipsis and no emoticon"
}
