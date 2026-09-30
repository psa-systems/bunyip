#!/usr/bin/env nu

# CLAUDE.md size and link gate (BUNYIP-854).
#
# CLAUDE.md is loaded into every agent session, so it stays an index: each
# convention is one line here and its full text lives in `docs/invariants/`.
# This gate fails the build when:
#
#   - CLAUDE.md exceeds MAX_BYTES;
#   - a line outside a fenced code block exceeds MAX_LINE_CHARS;
#   - a `docs/` link from CLAUDE.md names a path that does not exist, or an
#     anchor that matches no heading in the target file.
#
# Usage:
#   scripts/check-claude-md.nu
#   scripts/check-claude-md.nu --self-test

const MAX_BYTES = 20000
const MAX_LINE_CHARS = 400

# The lines of a markdown text that sit outside fenced code blocks, as
# {index, line} records (index is 1-based).
def unfenced-lines [text: string]: nothing -> list<record<index: int, line: string>> {
    mut fenced = false
    mut out = []
    for row in ($text | lines | enumerate) {
        if ($row.item | str trim | str starts-with "```") {
            $fenced = not $fenced
            continue
        }
        if not $fenced {
            $out = ($out | append {index: ($row.index + 1), line: $row.item})
        }
    }
    $out
}

# The anchor a Forgejo/GitHub renderer gives a heading: lowercase, punctuation
# dropped, spaces to hyphens.
def slug [heading: string]: nothing -> string {
    $heading
    | str downcase
    | str replace --all --regex '[^\w\- ]' ''
    | str replace --all ' ' '-'
}

# Every heading anchor in a markdown file, with the `-1`, `-2` suffixes a
# renderer adds to repeated headings.
def anchors [path: string]: nothing -> list<string> {
    let text = (open --raw $path | into binary | decode utf-8)
    let slugs = (
        unfenced-lines $text
        | get line
        | where {|l| $l =~ '^#{1,6} ' }
        | each {|l| slug ($l | str replace --regex '^#{1,6} +' '' | str trim) }
    )
    mut seen = {}
    mut out = []
    for s in $slugs {
        let n = ($seen | get --optional $s | default 0)
        $out = ($out | append (if $n == 0 { $s } else { $"($s)-($n)" }))
        $seen = ($seen | upsert $s ($n + 1))
    }
    $out
}

# Every problem with `<root>/CLAUDE.md`, as human-readable lines.
def check [root: string]: nothing -> list<string> {
    let path = ($root | path join "CLAUDE.md")
    if not ($path | path exists) {
        return [$"($path): missing"]
    }
    let text = (open --raw $path | into binary | decode utf-8)
    mut problems = []

    let bytes = ($text | encode utf-8 | bytes length)
    if $bytes > $MAX_BYTES {
        $problems = ($problems | append $"CLAUDE.md: ($bytes) bytes exceeds the ($MAX_BYTES)-byte cap; move the detail into docs/invariants/ and keep one index line here")
    }

    for row in (unfenced-lines $text) {
        let n = ($row.line | str length)
        if $n > $MAX_LINE_CHARS {
            $problems = ($problems | append $"CLAUDE.md:($row.index): ($n) characters exceeds the ($MAX_LINE_CHARS)-character line cap")
        }
        let targets = ($row.line | parse --regex '\]\((?<t>[^)\s]+)\)' | get t)
        for t in ($targets | where {|t| $t | str starts-with "docs/" }) {
            let parts = ($t | split row "#")
            let file = ($root | path join ($parts | first))
            if not ($file | path exists) {
                $problems = ($problems | append $"CLAUDE.md:($row.index): link target ($parts | first) does not exist")
                continue
            }
            if ($parts | length) > 1 {
                let anchor = ($parts | skip 1 | str join "#")
                if ($file | path type) != "file" or not ($anchor in (anchors $file)) {
                    $problems = ($problems | append $"CLAUDE.md:($row.index): anchor #($anchor) matches no heading in ($parts | first)")
                }
            }
        }
    }
    $problems
}

def self-test []: nothing -> nothing {
    let base = (mktemp --directory --tmpdir)

    let cases = [
        [name, body, expect_ok];
        ["a resolving link and anchor", "- [Rule one](docs/invariants/t.md#rule-one-bunyip-1) (BUNYIP-1): do it.\n", true]
        ["a missing file", "- [x](docs/invariants/nope.md#a): x.\n", false]
        ["a missing anchor", "- [x](docs/invariants/t.md#rule-two): x.\n", false]
        ["a long line", $"(1..401 | each { 'a' } | str join)\n", false]
        ["a long line inside a fence", $"```\n(1..401 | each { 'a' } | str join)\n```\n", true]
        ["an oversized file", ((1..($MAX_BYTES // 50 + 1)) | each { (1..49 | each { 'b' } | str join) } | str join "\n"), false]
    ]

    mut ok = true
    for c in ($cases | enumerate) {
        let dir = ($base | path join $"case($c.index)")
        mkdir ($dir | path join "docs/invariants")
        "# T\n\n## Rule one (BUNYIP-1)\n\ntext\n" | save ($dir | path join "docs/invariants/t.md")
        $c.item.body | save ($dir | path join "CLAUDE.md")
        let c = $c.item
        let problems = (check $dir)
        let passed = ($problems | is-empty)
        if $passed == $c.expect_ok {
            print $"self-test ok: ($c.name)"
        } else {
            print --stderr $"self-test FAILED: ($c.name): ($problems | to nuon)"
            $ok = false
        }
    }
    rm --recursive $base
    if not $ok { exit 1 }
}

def main [
    --self-test # prove the gate catches each failure shape and passes a clean file, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }
    let problems = (check ".")
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        exit 1
    }
    let bytes = (open --raw CLAUDE.md | into binary | bytes length)
    print $"check-claude-md: CLAUDE.md is ($bytes) bytes \(cap ($MAX_BYTES)\), every line within ($MAX_LINE_CHARS) characters, every docs/ link resolves"
}
