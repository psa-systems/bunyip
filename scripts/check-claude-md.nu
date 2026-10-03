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
#     anchor that matches no heading in the target file;
#   - a non-private `[group: 'release']` recipe in `common/common.just` is
#     named in neither CLAUDE.md nor a doc it links (BUNYIP-869).
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

# The name of every non-private recipe carrying `[group: 'release']` in a
# common.just file, in declaration order. Attributes stack directly above the
# recipe header they apply to, with blank or comment lines allowed between a
# comment and its attributes but not between the last attribute and the
# header.
def release-recipe-names [path: string]: nothing -> list<string> {
    let lines = (open --raw $path | into binary | decode utf-8 | lines)
    mut pending_group = false
    mut pending_private = false
    mut names = []
    for line in $lines {
        let trimmed = ($line | str trim)
        if ($trimmed | str starts-with "[") and ($trimmed | str ends-with "]") {
            if $trimmed == "[private]" {
                $pending_private = true
            }
            if ($trimmed | str contains "group: 'release'") {
                $pending_group = true
            }
            continue
        }
        if ($trimmed | is-empty) or ($trimmed | str starts-with "#") {
            continue
        }
        if ($line | str starts-with " ") or ($line | str starts-with "\t") {
            continue
        }
        let is_header = (
            ($trimmed =~ '^[a-zA-Z_][a-zA-Z0-9_\-]*(\s+[a-zA-Z_][a-zA-Z0-9_\-]*)*:')
            and not ($trimmed | str contains ":=")
        )
        if $is_header {
            let name = ($trimmed | split row ":" | first | split row " " | first)
            if $pending_group and not $pending_private {
                $names = ($names | append $name)
            }
        }
        $pending_group = false
        $pending_private = false
    }
    $names
}

# Every release recipe in `<root>/common/common.just` that is named in
# neither CLAUDE.md nor a `docs/` file CLAUDE.md links, as human-readable
# problem lines. Returns no problems when the common.just path does not exist
# (an uninitialized submodule), since that is a separate, unrelated failure.
def check-release-recipes [root: string]: nothing -> list<string> {
    let just_path = ($root | path join "common/common.just")
    let claude_path = ($root | path join "CLAUDE.md")
    if not ($just_path | path exists) or not ($claude_path | path exists) {
        return []
    }
    let claude_text = (open --raw $claude_path | into binary | decode utf-8)
    mut haystacks = [$claude_text]
    for row in (unfenced-lines $claude_text) {
        let targets = ($row.line | parse --regex '\]\((?<t>[^)\s]+)\)' | get t)
        for t in ($targets | where {|t| $t | str starts-with "docs/" }) {
            let file = ($root | path join ($t | split row "#" | first))
            if ($file | path exists) and ($file | path type) == "file" {
                $haystacks = ($haystacks | append (open --raw $file | into binary | decode utf-8))
            }
        }
    }
    let text = ($haystacks | str join "\n")
    release-recipe-names $just_path
    | where {|n| not ($text | str contains $n) }
    | each {|n| $"common/common.just: release recipe `($n)` is named in no bunyip doc \(CLAUDE.md or a doc it links)" }
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
    $problems = ($problems | append (check-release-recipes $root))
    $problems
}

def self-test-release-recipes []: nothing -> nothing {
    let base = (mktemp --directory --tmpdir)

    let cases = [
        [name, just_body, claude_body, expect_ok];
        ["a release recipe named in CLAUDE.md", "[group: 'release']\npublish-release:\n    true\n", "- `just publish-release` ships it.\n", true]
        ["a release recipe named in no doc", "[group: 'release']\npublish-release:\n    true\n", "- nothing about releases here.\n", false]
        ["a private release recipe is exempt", "[private]\n[group: 'release']\n_create-release manifest:\n    true\n", "- nothing about releases here.\n", true]
    ]

    mut ok = true
    for c in ($cases | enumerate) {
        let dir = ($base | path join $"case($c.index)")
        mkdir ($dir | path join "common")
        let item = $c.item
        $item.just_body | save ($dir | path join "common/common.just")
        $item.claude_body | save ($dir | path join "CLAUDE.md")
        let problems = (check-release-recipes $dir)
        let passed = ($problems | is-empty)
        if $passed == $item.expect_ok {
            print $"self-test ok: ($item.name)"
        } else {
            print --stderr $"self-test FAILED: ($item.name): ($problems | to nuon)"
            $ok = false
        }
    }
    rm --recursive $base
    if not $ok { exit 1 }
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
        self-test-release-recipes
        return
    }
    let problems = (check ".")
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        exit 1
    }
    let bytes = (open --raw CLAUDE.md | into binary | bytes length)
    print $"check-claude-md: CLAUDE.md is ($bytes) bytes \(cap ($MAX_BYTES)\), every line within ($MAX_LINE_CHARS) characters, every docs/ link resolves, every common.just release recipe is named"
}
