#!/usr/bin/env nu

# Theme-token gate (BUNYIP-549).
#
# Two surfaces painted outside the theme, both closed here so they cannot come
# back:
#   - the toast pills in `bunyip-web/assets/js/app.js` were stock Tailwind
#     (`bg-emerald-600`, `bg-red-600`, `bg-slate-800`). `input.css` remaps only
#     `indigo` -> reed and `teal` -> water, so any other stock scale is a colour
#     that ignores `.dark` / `.high-contrast` entirely. The client-side files
#     must use the same semantic tokens (`bg-destructive`, `bg-popover`, ...)
#     every server-rendered status surface uses.
#   - `document()` in `bunyip-web/src/views/layout.rs` hardcoded the two
#     `theme-color` metas as hex. BUNYIP-500 made the whole ramp skinnable, so a
#     skin recoloured the page and left the browser chrome bunyip reed-green.
#     BUNYIP-560 moved the palette into the admin-managed branding record and
#     deleted the `#2f4e2e` / `#161a16` defaults that had moved to
#     `bunyip-web/src/config.rs`, so NEITHER file may carry a colour literal
#     now: unset means the meta is omitted, and a re-introduced default would
#     paint every deployment's chrome one product's green again.
#
# `amber` (the warning role) and `violet` are allowed alongside the two remapped
# scales, matching the server-rendered side.
#
# Usage:
#   scripts/check-theme-colors.nu
#   scripts/check-theme-colors.nu --self-test

const JS_GLOB = "bunyip-web/assets/js/*.js"
# The framework shell and its configuration. BUNYIP-560: the palette is the
# branding record's, so both files are colour-free.
const SHELL_SOURCES = [
    "bunyip-web/src/views/layout.rs"
    "bunyip-web/src/config.rs"
]

# Where the shipped shell ends and its tests begin. The tests install sentinel
# hex values on purpose, to prove the metas follow config.
const TEST_MARKER = '#[cfg(test)]'

# Stock Tailwind colour scales `input.css` does NOT remap, in any utility
# position. `teal`, `indigo`, `violet` and `amber` are deliberately absent.
const STOCK_SCALES = 'red|orange|yellow|lime|green|emerald|cyan|sky|blue|purple|fuchsia|pink|rose|slate|gray|zinc|neutral|stone'
const UTILITY_PREFIXES = 'bg|text|border|from|via|to|ring|fill|stroke|divide|placeholder|caret|accent|outline|decoration|shadow'

# A raw colour value, in any CSS notation.
const COLOR_LITERALS = [
    {
        pattern: '#[0-9a-fA-F]{3,8}\b'
        why: "a hex colour"
    }
    {
        pattern: '\b(rgb|rgba|hsl|hsla|oklch|oklab)\s*\('
        why: "a CSS colour function"
    }
]

# Stock-palette utilities in one client-side script.
def check-js [path: string]: nothing -> list<string> {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): missing or not readable - the gate cannot prove the palette is themed."]
    }

    # Built by concatenation: `(` opens a subexpression inside an interpolated
    # string, so a regex cannot be interpolated.
    let pattern = ('(?<util>\b(?:' + $UTILITY_PREFIXES + ')-(?:' + $STOCK_SCALES + ')-[0-9]+)')
    mut problems = []
    for row in ($content | lines | enumerate) {
        let text = $row.item
        # Whole-line comments are prose about the code, not classes the DOM gets.
        if ($text | str trim | str starts-with "//") { continue }
        for hit in ($text | parse --regex $pattern | get util) {
            $problems = ($problems | append $"($path):($row.index + 1): `($hit)` - a stock Tailwind scale that no theme class reskins; use the semantic token its server-rendered counterpart uses.")
        }
    }
    $problems
}

# Raw colour values in the framework shell, above its test module.
def check-shell [path: string]: nothing -> list<string> {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): missing or not readable - the gate cannot prove the shell is colour-free."]
    }

    mut problems = []
    for row in ($content | lines | enumerate) {
        let text = $row.item
        if ($text | str contains $TEST_MARKER) { break }
        # Comments (including doc comments) describe the code, not what renders.
        if ($text | str trim | str starts-with "//") { continue }
        for rule in $COLOR_LITERALS {
            for hit in ($text | parse --regex ('(?<lit>' + $rule.pattern + ')') | get lit) {
                $problems = ($problems | append $"($path):($row.index + 1): `($hit)` - ($rule.why) in the framework shell; take it from the branding record so a rebrand moves it.")
            }
        }
    }
    $problems
}

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)

    let js_cases = [
        {
            name: "themed.js"
            body: "var p = 'bg-destructive text-destructive-foreground';\nvar q = 'bg-popover text-popover-foreground border border-border';"
            expect_problems: false
            why: "semantic tokens in a client-side palette"
        }
        {
            name: "remapped.js"
            body: "var p = 'bg-teal-500/15 text-teal-600 dark:text-teal-400 border border-teal-500/40';"
            expect_problems: false
            why: "the teal scale input.css remaps to the water ramp"
        }
        {
            name: "commented.js"
            body: "// the palette read 'bg-emerald-600' and 'bg-slate-800' before BUNYIP-549"
            expect_problems: false
            why: "a comment quoting the forbidden utilities to explain them"
        }
        {
            name: "emerald.js"
            body: "var p = 'bg-emerald-600 text-white';"
            expect_problems: true
            why: "a stock emerald utility"
        }
        {
            name: "slate.js"
            body: "var p = 'bg-slate-800 text-white';"
            expect_problems: true
            why: "a stock slate utility"
        }
        {
            name: "red.js"
            body: "var p = 'bg-red-600 text-white';"
            expect_problems: true
            why: "a stock red utility"
        }
    ]

    let shell_cases = [
        {
            name: "config-driven.rs"
            body: 'meta name="theme-color" content=(theme_color_light());'
            expect_problems: false
            why: "a config-driven theme-color meta"
        }
        {
            name: "fragment-href.rs"
            body: 'a href="#main" { "Skip to content" }'
            expect_problems: false
            why: "a fragment href, which is not a colour"
        }
        {
            name: "in-test.rs"
            body: ("#[cfg(test)]\nmod tests {\n" + '    install_theme_colors("#123456", "#654321");' + "\n}")
            expect_problems: false
            why: "sentinel hex values below the test marker"
        }
        {
            name: "hex.rs"
            body: 'meta name="theme-color" content="#2f4e2e";'
            expect_problems: true
            why: "a hardcoded hex colour in the shell"
        }
        {
            name: "css-function.rs"
            body: 'style { "body{color:hsl(120 22% 16%)}" }'
            expect_problems: true
            why: "a hardcoded CSS colour function in the shell"
        }
    ]

    let js_results = ($js_cases | each {|c|
        let path = $"($dir)/($c.name)"
        $c.body | save --force $path
        let problems = (check-js $path)
        {why: $c.why, ok: (($problems | is-not-empty) == $c.expect_problems), problems: $problems}
    })
    let shell_results = ($shell_cases | each {|c|
        let path = $"($dir)/($c.name)"
        $c.body | save --force $path
        let problems = (check-shell $path)
        {why: $c.why, ok: (($problems | is-not-empty) == $c.expect_problems), problems: $problems}
    })
    let missing_js = (check-js $"($dir)/absent.js")
    let missing_shell = (check-shell $"($dir)/absent.rs")
    rm --recursive $dir

    let results = ($js_results | append $shell_results)
    for r in $results {
        if $r.ok {
            print $"self-test ok: gate handles ($r.why)"
        } else {
            print --stderr $"self-test FAILED: gate mis-handles ($r.why): ($r.problems | to nuon)"
        }
    }
    let missing_ok = (($missing_js | is-not-empty) and ($missing_shell | is-not-empty))
    if $missing_ok {
        print "self-test ok: gate handles an unreadable source file"
    } else {
        print --stderr "self-test FAILED: gate mis-handles an unreadable source file"
    }
    if (($results | any {|r| not $r.ok }) or (not $missing_ok)) {
        exit 1
    }
}

def main [
    --self-test # prove the gate rejects a stock-palette utility and a shell colour literal, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let js_files = (glob $JS_GLOB)
    if ($js_files | is-empty) {
        print --stderr $"error: ($JS_GLOB) matched no files - the gate cannot prove the palette is themed."
        exit 1
    }

    let problems = (($js_files | each {|f| check-js $f } | flatten) | append ($SHELL_SOURCES | each {|f| check-shell $f } | flatten))
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "Every surface is painted from the theme tokens (BUNYIP-549): the client-side"
        print --stderr "palettes use the same semantic tokens as their server-rendered counterparts,"
        print --stderr $"and neither ($SHELL_SOURCES | str join ' nor ') carries a colour literal -"
        print --stderr "the palette is the admin-managed branding record (BUNYIP-560), and unset means"
        print --stderr "the markup is omitted rather than painted a compiled-in colour."
        exit 1
    }

    print $"check-theme-colors: ($js_files | length) client scripts carry no unmapped stock palette, and ($SHELL_SOURCES | length) shell sources carry no colour literal"
}
