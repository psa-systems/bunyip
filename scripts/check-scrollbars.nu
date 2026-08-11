#!/usr/bin/env nu

# Always-visible-scrollbar gate (BUNYIP-509).
#
# `bunyip-web/input.css` shipped a global `::-webkit-scrollbar { display: none }`
# plus `* { scrollbar-width: none }` pair that removed the scrollbar from every
# scroll container in the app: the main pane, the sidebar nav, the admin users
# table, modal bodies and every code block. There was no indicator that a pane
# scrolled and nothing to grab and drag, which is an accessibility defect, not a
# styling preference. The rules were replaced with explicit, theme-driven,
# always-visible scrollbar styling.
#
# Nothing about that survives a paste of vendor CSS or a "hide the ugly bar"
# tweak, so gate both the authored stylesheet and the built Tailwind output:
#   - no hiding rule (`scrollbar-width: none`, `display: none` on any
#     `::-webkit-scrollbar*` pseudo-element) may come back,
#   - no `scrollbar-width: thin`, which is what makes a bar hard to hit,
#   - the visible styling must still be present in BOTH files, so a rebuild that
#     dropped it (or a built asset left stale) fails here instead of shipping.
#
# Usage:
#   scripts/check-scrollbars.nu
#   scripts/check-scrollbars.nu --self-test

const CSS_FILES = ["bunyip-web/input.css", "bunyip-web/assets/styles.css"]

# Rules that must never appear. `[^}]` crosses newlines, so the authored
# multi-line form and the minified one both match.
const FORBIDDEN = [
    {
        pattern: 'scrollbar-width\s*:\s*none'
        why: "hides the Firefox / standards scrollbar"
    }
    {
        pattern: 'scrollbar-width\s*:\s*thin'
        why: "shrinks the bar below a grabbable drag target"
    }
    {
        pattern: '::-webkit-scrollbar[a-z-]*[^{]*\{[^}]*display\s*:\s*none'
        why: "hides the WebKit / Chromium scrollbar"
    }
]

# Rules that must be present, so the visible styling cannot silently regress.
const REQUIRED = [
    {
        pattern: 'scrollbar-width\s*:\s*auto'
        what: "`scrollbar-width: auto` for Firefox / standards engines"
    }
    {
        pattern: 'scrollbar-color\s*:\s*hsl\(var\(--'
        what: "`scrollbar-color` driven by the theme tokens"
    }
    {
        pattern: 'scrollbar-gutter\s*:\s*stable'
        what: "`scrollbar-gutter: stable`, which stops the content shifting"
    }
    {
        pattern: '::-webkit-scrollbar\s*\{[^}]*width\s*:\s*14px'
        what: "a 14px `::-webkit-scrollbar` width (also what opts Chromium and Safari out of the fading overlay bar)"
    }
    {
        pattern: '::-webkit-scrollbar\s*\{[^}]*height\s*:\s*14px'
        what: "a 14px `::-webkit-scrollbar` height, so the horizontal bar is grabbable too"
    }
    {
        pattern: '::-webkit-scrollbar-thumb\s*\{[^}]*background-color\s*:\s*hsl\(var\(--'
        what: "a painted `::-webkit-scrollbar-thumb` in a theme colour"
    }
    {
        pattern: '::-webkit-scrollbar-thumb:hover\s*\{'
        what: "a distinct `::-webkit-scrollbar-thumb:hover` state"
    }
]

# CSS comments are prose, not rules: the block that replaced the hiding rules
# names them so the next reader knows what came out, and that must not read as a
# violation (nor may a required rule count because a comment mentions it).
def strip-comments []: string -> string {
    $in | str replace --all --regex '(?s)/\*.*?\*/' ""
}

# Every match of `pattern` in `scannable`, as { line, text } records. Lines are
# located in the original file text, which is enough to point an author at the
# offending rule.
def matches-in [scannable: string, pattern: string, file_lines: list<string>]: nothing -> table {
    $scannable
    | parse --regex ("(?<hit>" + $pattern + ")")
    | get hit
    | each {|m|
        let head = ($m | lines | first | str trim)
        let found = ($file_lines | enumerate | where {|r| $r.item | str contains $head })
        {
            line: (if ($found | is-empty) { 0 } else { ($found | first | get index) + 1 })
            text: ($m | str replace --all --regex '\s+' " " | str trim)
        }
    }
}

# Problems in one stylesheet, as human-readable lines.
def check-css [path: string]: nothing -> list<string> {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): missing or not readable - the gate cannot prove the scrollbars stay visible."]
    }

    let file_lines = ($content | lines)
    let scannable = ($content | strip-comments)

    mut problems = []
    for rule in $FORBIDDEN {
        for hit in (matches-in $scannable $rule.pattern $file_lines) {
            $problems = ($problems | append $"($path):($hit.line): '($hit.text)' - ($rule.why).")
        }
    }
    for rule in $REQUIRED {
        if not ($scannable =~ $rule.pattern) {
            $problems = ($problems | append $"($path): missing ($rule.what).")
        }
    }
    $problems
}

const COMPLIANT_CSS = '* {
  scrollbar-width: auto;
  scrollbar-color: hsl(var(--muted-foreground)) hsl(var(--muted));
}
html {
  scrollbar-gutter: stable;
}
::-webkit-scrollbar {
  width: 14px;
  height: 14px;
}
::-webkit-scrollbar-thumb {
  background-color: hsl(var(--muted-foreground));
  border-radius: 7px;
}
::-webkit-scrollbar-thumb:hover {
  background-color: hsl(var(--foreground));
}
'

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)

    let compliant = $"($dir)/compliant.css"
    $COMPLIANT_CSS | save --force $compliant

    let minified = $"($dir)/minified.css"
    ($COMPLIANT_CSS | str replace --all --regex '\s*\n\s*' "" | str replace --all ": " ":") | save --force $minified

    let hidden_webkit = $"($dir)/hidden-webkit.css"
    ($COMPLIANT_CSS + "::-webkit-scrollbar {\n  display: none;\n}\n") | save --force $hidden_webkit

    let hidden_thumb = $"($dir)/hidden-thumb.css"
    ($COMPLIANT_CSS + "::-webkit-scrollbar-thumb{display:none}\n") | save --force $hidden_thumb

    let hidden_standards = $"($dir)/hidden-standards.css"
    ($COMPLIANT_CSS + "* {\n  scrollbar-width: none;\n}\n") | save --force $hidden_standards

    let thin = $"($dir)/thin.css"
    ($COMPLIANT_CSS + ".pane {\n  scrollbar-width: thin;\n}\n") | save --force $thin

    let unstyled = $"($dir)/unstyled.css"
    "body {\n  color: red;\n}\n" | save --force $unstyled

    let unrelated_hide = $"($dir)/unrelated-hide.css"
    ($COMPLIANT_CSS + ".hidden {\n  display: none;\n}\n") | save --force $unrelated_hide

    let commented_hide = $"($dir)/commented-hide.css"
    ("/* replaces `* { scrollbar-width: none }` and\n   `::-webkit-scrollbar { display: none }` */\n" + $COMPLIANT_CSS) | save --force $commented_hide

    let commented_styling = $"($dir)/commented-styling.css"
    ("/* " + $COMPLIANT_CSS + " */\nbody {\n  color: red;\n}\n") | save --force $commented_styling

    let cases = [
        {file: $compliant, expect_problems: false, why: "the authored always-visible block"}
        {file: $minified, expect_problems: false, why: "the same block minified"}
        {file: $hidden_webkit, expect_problems: true, why: "a re-added `::-webkit-scrollbar { display: none }`"}
        {file: $hidden_thumb, expect_problems: true, why: "a hidden `::-webkit-scrollbar-thumb`"}
        {file: $hidden_standards, expect_problems: true, why: "a re-added `scrollbar-width: none`"}
        {file: $thin, expect_problems: true, why: "`scrollbar-width: thin`"}
        {file: $unstyled, expect_problems: true, why: "a stylesheet with the visible styling stripped out"}
        {file: $unrelated_hide, expect_problems: false, why: "an unrelated `display: none` rule"}
        {file: $commented_hide, expect_problems: false, why: "a comment naming the removed hiding rules"}
        {file: $commented_styling, expect_problems: true, why: "the visible styling present only inside a comment"}
        {file: $"($dir)/absent.css", expect_problems: true, why: "a missing stylesheet"}
    ]
    let results = ($cases | each {|c|
        let problems = (check-css $c.file)
        {why: $c.why, ok: (($problems | is-not-empty) == $c.expect_problems), problems: $problems}
    })
    rm --recursive $dir

    for r in $results {
        if $r.ok {
            print $"self-test ok: gate handles ($r.why)"
        } else {
            print --stderr $"self-test FAILED: gate mis-handles ($r.why): ($r.problems | to nuon)"
        }
    }
    if ($results | any {|r| not $r.ok }) {
        exit 1
    }
}

def main [
    --self-test # prove the gate rejects a hiding rule and a stripped stylesheet, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let problems = ($CSS_FILES | each {|f| check-css $f } | flatten)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "Every scrollable region in the app shows a scrollbar that is visible at rest,"
        print --stderr "wide enough to grab, and coloured from the theme tokens (BUNYIP-509). No"
        print --stderr "auto-hide, fade, overlay or hover-to-reveal behaviour, and never"
        print --stderr "`scrollbar-width: thin`. Edit bunyip-web/input.css, then rebuild the asset with"
        print --stderr "`bun run build:css` in bunyip-web/ and commit both."
        exit 1
    }

    print $"check-scrollbars: ($CSS_FILES | length) stylesheets keep the scrollbar visible and grabbable"
}
