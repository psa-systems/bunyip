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
#   - an internal issue key. The admin System page shipped
#     `Country allow/deny for sign-in (BUNYIP-581)` as help text, so a tracker id
#     rendered on screen. Issue keys belong in code and in comments, never in
#     text a user reads. Log lines, assertions and attributes are exempt: they
#     are operator and developer output, where the reference is what makes a log
#     searchable.
#
# Scanning stops at `#[cfg(test)]`: a test module's literals are assertion
# messages, not copy. In `.rs` files only double-quoted string literals are
# scanned, so a comment or a Rust path
# (`serde::Deserialize` carries `:D`, `types::PricingResponse`
# carries `:P`) is never a hit. Whole-line comments are dropped first, so prose quoting a
# forbidden shape to explain it does not read as a violation.
#
# BUNYIP-816 (F8): the same rules also scan `bunyip-web/assets/js/**/*.js`,
# where copy lives in single- or double-quoted string literals rather than
# only double-quoted ones, so the gate reaches the same violations there
# (`submitLabel.textContent = 'Sending...'` and a bare close glyph both went
# uncaught because the glob never looked at `.js`). This is a second glob and
# a second literal pattern reusing the one `$FORBIDDEN` rule set and the one
# `check-source` function, not a second gate script.
#
# Usage:
#   scripts/check-ui-copy.nu
#   scripts/check-ui-copy.nu --self-test

# BUNYIP-502: also scan the shared web-kit crate, which now holds UI toolkit
# code (icons/buttons/badges/boxes) lifted out of bunyip-web/src/views.
const RS_GLOB = "{bunyip-web/src,crates/web-kit/src}/**/*.rs"
const JS_GLOB = "bunyip-web/assets/js/**/*.js"

# One double-quoted Rust string literal, escapes included.
const LITERAL_DOUBLE = '"(?<lit>(?:[^"\\]|\\.)*)"'
# One single-quoted JS string literal, escapes included.
const LITERAL_SINGLE = "'(?<lit>(?:[^'\\\\]|\\\\.)*)'"

# Opens a log or assertion macro, whose message is operator or developer output.
const MACRO_OPEN = '(tracing::\w+!\(|^\s*(info|warn|error|debug|trace)!\(|assert[a-z_]*!\(|panic!\()'

const FORBIDDEN = [
    {
        pattern: '\.\.\.'
        why: "three-dot ellipsis in user-facing copy; use the single-character … glyph"
    }
    {
        pattern: '(^|\s)[:;]-?[()DPp](\s|$|[.,!])'
        why: "ASCII emoticon in user-facing copy; the empty states and banners are terse noun phrases"
    }
    {
        pattern: '\b(BUNYIP|PMS|MAPPS|LC|SF|SFT|DEV|GOV|AUDIT|PSA|A8N|ROCI|CLAUDE)-[0-9]+\b'
        why: "internal issue key in user-facing copy; keep the sentence and move the reference into a comment"
        # Operator and developer output. A log line without its issue key is a
        # log nobody can trace back, so the rule stops at what a user reads.
        exempt_lines: '(tracing::|^\s*(info|warn|error|debug|trace)!|assert|panic!|expect\(|unreachable!|#\[)'
    }
]

# Problems in one source file, as human-readable lines. `literals` is the list
# of quoting regexes to extract string literals with (Rust files scan only
# double-quoted; JS files scan single- and double-quoted), and `stop_at_test`
# gates the `#[cfg(test)]` cutoff, which only Rust files have.
def check-source [path: string, literals: list<string>, stop_at_test: bool]: nothing -> list<string> {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): missing or not readable - the gate cannot prove the copy is clean."]
    }

    mut problems = []
    # A log or assertion macro often spans several lines with its message on a
    # line of its own, so the exemption has to survive to the closing paren
    # rather than being decided per line.
    mut in_macro = false
    for row in ($content | lines | enumerate) {
        let text = $row.item
        if $in_macro {
            if ($text =~ '\);') { $in_macro = false }
        } else if (($text =~ $MACRO_OPEN) and not ($text =~ '\);')) {
            $in_macro = true
        }
        # Test modules sit at the end of a file by convention, and their
        # literals are assertion messages rather than copy. Everything from the
        # `#[cfg(test)]` line on is developer output.
        if ($stop_at_test and ($text | str trim | str starts-with "#[cfg(test)]")) { break }
        # Whole-line comments are prose about the code, not copy the user reads.
        if ($text | str trim | str starts-with "//") { continue }
        let hits = ($literals | each {|lit_pattern| $text | parse --regex $lit_pattern | get lit } | flatten)
        for hit in $hits {
            for rule in $FORBIDDEN {
                let exempt = ($rule | get --optional exempt_lines)
                if ($exempt != null and (($text =~ $exempt) or $in_macro)) { continue }
                if ($hit =~ $rule.pattern) {
                    $problems = ($problems | append $"($path):($row.index + 1): \"($hit)\" - ($rule.why).")
                }
            }
        }
    }
    $problems
}

def check-rs [path: string]: nothing -> list<string> {
    check-source $path [$LITERAL_DOUBLE] true
}

def check-js [path: string]: nothing -> list<string> {
    check-source $path [$LITERAL_DOUBLE $LITERAL_SINGLE] false
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
        {
            name: "issue-key-help-text.rs"
            body: 'admin_block("Country access", Some("Country allow/deny for sign-in (BUNYIP-581). Restart required."), html! {})'
            expect_problems: true
            why: "an issue key in admin help text"
        }
        {
            name: "issue-key-message.rs"
            body: 'p { "Login withheld pending email approval (BUNYIP-373)" }'
            expect_problems: true
            why: "an issue key in a message shown to the user"
        }
        {
            name: "issue-key-multiline-log.rs"
            body: "tracing::info!(\n    target: \"consent_post\",\n    \"BUNYIP-234: consent saved, redirecting to authorize\"\n);"
            expect_problems: false
            why: "an issue key in a log message on its own line inside a multi-line macro"
        }
        {
            name: "issue-key-log.rs"
            body: 'tracing::warn!("BUNYIP-79 reconcile: rewrote stale migration checksum");'
            expect_problems: false
            why: "an issue key in a log line, where it is what makes the log traceable"
        }
        {
            name: "issue-key-in-test-module.rs"
            body: "#[cfg(test)]\nmod tests {\n    assert!(off.contains(\"x\"), \"matches what stripe_webhook does (BUNYIP-203)\");\n}"
            expect_problems: false
            why: "an issue key inside a test module"
        }
        {
            name: "issue-key-assert.rs"
            body: 'assert!(offenders.is_empty(), "BUNYIP-487 removed these; they must not come back");'
            expect_problems: false
            why: "an issue key in an assertion message"
        }
        {
            name: "issue-key-clean-copy.rs"
            body: 'admin_block("Country access", Some("Country allow/deny for sign-in. Restart required."), html! {})'
            expect_problems: false
            why: "the same help text with the reference removed"
        }
        {
            name: "encoding-names.rs"
            body: 'p { "Encoded as UTF-8 with SHA-256 digests" }'
            expect_problems: false
            why: "an encoding name that looks like a key but is not one"
        }
    ]

    let js_cases = [
        {
            name: "three-dots.js"
            body: "submitLabel.textContent = 'Sending...';"
            expect_problems: true
            why: "a three-dot ellipsis in a single-quoted JS string"
        }
        {
            name: "clean.js"
            body: "submitLabel.textContent = 'Sending…';"
            expect_problems: false
            why: "the single-character ellipsis glyph in a single-quoted JS string"
        }
        {
            name: "issue-key.js"
            body: 'console.log("BUNYIP-816: retrying");'
            expect_problems: true
            why: "an issue key in a double-quoted JS string"
        }
        {
            name: "commented.js"
            body: "// old copy read 'Sending...' before BUNYIP-816"
            expect_problems: false
            why: "a JS comment quoting the forbidden shape to explain it"
        }
    ]

    let results = (
        ($cases | each {|c|
            let path = $"($dir)/($c.name)"
            $c.body | save --force $path
            let problems = (check-rs $path)
            {why: $c.why, ok: (($problems | is-not-empty) == $c.expect_problems), problems: $problems}
        })
        | append ($js_cases | each {|c|
            let path = $"($dir)/($c.name)"
            $c.body | save --force $path
            let problems = (check-js $path)
            {why: $c.why, ok: (($problems | is-not-empty) == $c.expect_problems), problems: $problems}
        })
    )
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
    --self-test # prove the gate rejects a three-dot ellipsis, an emoticon and an issue key, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let rs_files = (glob $RS_GLOB)
    let js_files = (glob $JS_GLOB)
    if (($rs_files | is-empty) and ($js_files | is-empty)) {
        print --stderr $"error: neither ($RS_GLOB) nor ($JS_GLOB) matched any files - the gate cannot prove the copy is clean."
        exit 1
    }

    let problems = (
        ($rs_files | each {|f| check-rs $f })
        | append ($js_files | each {|f| check-js $f })
        | flatten
    )
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "User-facing copy uses one ellipsis glyph and one voice (BUNYIP-551):"
        print --stderr "the single-character … rather than three dots, terse noun phrases with no"
        print --stderr "emoticons, and no internal issue key on screen. Fix the string literal, or"
        print --stderr "move the text into a comment if it is not copy."
        exit 1
    }

    let files = ($rs_files | append $js_files)
    print $"check-ui-copy: ($files | length) source files carry no three-dot ellipsis, no emoticon and no issue key"
}
