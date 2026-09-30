#!/usr/bin/env nu

# Scrollbar contract gate (BUNYIP-848, superseding BUNYIP-509's always-visible rule): thumb-only
# webkit bars in a 14px zone, `scrollbar-*` in the Firefox block only, and the app.js idle hold.
#
# Usage:
#   scripts/check-scrollbars.nu
#   scripts/check-scrollbars.nu --self-test

const CSS_FILES = ["bunyip-web/input.css", "bunyip-web/assets/styles.css"]
const JS_FILE = "bunyip-web/assets/js/app.js"
const IDLE_MS_MIN = 5000
const IDLE_MS_MAX = 7000

# `transparent` as authored, `#0000` once Tailwind minifies it.
const CLEAR = '(?:transparent|#0000|#00000000)'
const ALPHA_COLOR = 'hsl\(\s*var\(--[a-z-]+\)\s*/\s*var\(--sb-alpha\)\s*\)'
# Handles one level of nested rules, which is all the block holds.
const FIREFOX_BLOCK = '@supports\s+not\s+selector\(\s*::-webkit-scrollbar\s*\)\s*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}'
# A scrollbar part that must never be painted: the bar, the track (and its pieces) and the corner.
const BACKDROP_PART = '::-webkit-scrollbar(?:-track(?:-piece)?|-corner)?(?![a-z-])'

# Forbidden everywhere, the Firefox block included.
const FORBIDDEN = [
    {pattern: 'scrollbar-width\s*:\s*none', why: "hides the Firefox bar"}
    {pattern: '::-webkit-scrollbar[a-z-]*[^{]*\{[^}]*display\s*:\s*none', why: "hides the WebKit / Chromium bar"}
]

# CSS comments are prose: a comment naming a removed rule is not that rule.
def strip-comments []: string -> string {
    $in | str replace --all --regex '(?s)/\*.*?\*/' ""
}

# Innermost `selector { declarations }` blocks, the unit every part rule is judged on.
def css-rules [scannable: string]: nothing -> table<sel: string, body: string> {
    $scannable | parse --regex '(?<sel>[^{}]*)\{(?<body>[^{}]*)\}' | each {|r| {sel: ($r.sel | str trim), body: $r.body} }
}

# 1-based line of the first file line holding `snippet`'s first line, else 0.
def line-of [snippet: string, file_lines: list<string>]: nothing -> int {
    let head = ($snippet | lines | where {|l| $l | str trim | is-not-empty } | first 1 | get 0? | default "" | str trim)
    if ($head | is-empty) { return 0 }
    let found = ($file_lines | enumerate | where {|r| $r.item | str contains $head })
    if ($found | is-empty) { 0 } else { ($found | first | get index) + 1 }
}

def flat []: string -> string {
    $in | str replace --all --regex '\s+' " " | str trim
}

# Problems in one stylesheet, as human-readable lines.
def check-css [path: string]: nothing -> list<string> {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): missing or not readable - the gate cannot prove the scrollbar contract."]
    }
    let file_lines = ($content | lines)
    let scannable = ($content | strip-comments)
    let firefox = ($scannable | parse --regex $"\(?<block>($FIREFOX_BLOCK)\)" | get block)
    let outside = ($scannable | str replace --all --regex $FIREFOX_BLOCK "")
    let rules = (css-rules $scannable)

    mut problems = []
    for rule in $FORBIDDEN {
        for hit in ($scannable | parse --regex $"\(?<hit>($rule.pattern)\)" | get hit) {
            $problems = ($problems | append $"($path):(line-of $hit $file_lines): '($hit | flat)' - ($rule.why).")
        }
    }
    # YOTUN-208: Chromium 121+ ignores every ::-webkit-scrollbar rule on an element that has either one.
    for hit in ($outside | parse --regex '(?<hit>scrollbar-(?:width|color)\s*:[^;}]*)' | get hit) {
        $problems = ($problems | append $"($path):(line-of $hit $file_lines): '($hit | flat)' outside the `@supports not selector\(::-webkit-scrollbar\)` block - Chromium then drops the webkit styling \(YOTUN-208\).")
    }
    for r in ($rules | where {|r| $r.sel =~ $BACKDROP_PART }) {
        let paints = ($r.body | parse --regex '(?<decl>background(?:-color|-image)?\s*:\s*(?<value>[^;}]+))' | where {|d| not (($d.value | str trim) =~ $"^\(?:($CLEAR)|none\)$") })
        for d in $paints {
            $problems = ($problems | append $"($path):(line-of $r.sel $file_lines): '($r.sel | flat) { ($d.decl | flat) }' paints a scrollbar background - only the thumb may be painted.")
        }
    }

    let bar = ($rules | where {|r| $r.sel =~ '::-webkit-scrollbar\s*(?:,|$)' })
    let required = [
        {ok: ($bar | any {|r| $r.body =~ '(?:^|;)\s*width\s*:\s*14px\s*(?:;|$)' }), what: "a 14px `::-webkit-scrollbar` width, the grab zone"}
        {ok: ($bar | any {|r| $r.body =~ '(?:^|;)\s*height\s*:\s*14px\s*(?:;|$)' }), what: "a 14px `::-webkit-scrollbar` height, the horizontal grab zone"}
        {ok: ($rules | any {|r| ($r.sel =~ '::-webkit-scrollbar-track\s*(?:,|$)') and ($r.body =~ $"background\(?:-color\)?\\s*:\\s*($CLEAR)\\s*\(?:;|$\)") }), what: "a transparent `::-webkit-scrollbar-track`"}
        {ok: ($rules | any {|r| ($r.sel =~ '::-webkit-scrollbar-thumb\s*(?:,|$)') and ($r.body =~ $"background\(?:-color\)?\\s*:\\s*($ALPHA_COLOR)") }), what: "a `::-webkit-scrollbar-thumb` color from a theme token carrying `var\(--sb-alpha\)`"}
        {ok: ($rules | any {|r| ($r.sel == "@property --sb-alpha") and ($r.body =~ 'syntax\s*:\s*"<number>"') and ($r.body =~ 'inherits\s*:\s*true') and ($r.body =~ 'initial-value\s*:\s*1\s*(?:;|$)') }), what: "`@property --sb-alpha` registered as an inherited <number> with initial-value 1, which is what fails visible"}
        {ok: ($firefox | any {|b| ($b =~ 'scrollbar-width\s*:\s*thin') and ($b =~ $"scrollbar-color\\s*:\\s*($ALPHA_COLOR)\\s+($CLEAR)") }), what: "the Firefox `@supports not selector\(::-webkit-scrollbar\)` block with `scrollbar-width: thin` and a `var\(--sb-alpha\)` thumb over a transparent track"}
        {ok: ($scannable =~ 'scrollbar-gutter\s*:\s*stable'), what: "`scrollbar-gutter: stable`, which stops the content shifting"}
    ]
    for r in ($required | where {|r| not $r.ok }) {
        $problems = ($problems | append $"($path): missing ($r.what).")
    }
    $problems
}

# The idle hold lives in app.js alone; it must be declared once and sit in the agreed 5-7s range.
def check-js [path: string]: nothing -> list<string> {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): missing or not readable - the gate cannot prove the scrollbar idle hold."]
    }
    let decls = ($content | parse --regex '(?m)^\s*(?:var|let|const)\s+SCROLLBAR_IDLE_MS\s*=\s*(?<ms>[0-9_]+)\s*;' | get ms)
    if ($decls | is-empty) {
        return [$"($path): missing the `SCROLLBAR_IDLE_MS` declaration that times the auto-hide."]
    }
    if ($decls | length) > 1 {
        return [$"($path): `SCROLLBAR_IDLE_MS` is declared ($decls | length) times - declare it once."]
    }
    let ms = ($decls | first | str replace --all "_" "" | into int)
    if $ms < $IDLE_MS_MIN or $ms > $IDLE_MS_MAX {
        return [$"($path): `SCROLLBAR_IDLE_MS = ($ms)` is outside the agreed ($IDLE_MS_MIN)-($IDLE_MS_MAX)ms hold \(BUNYIP-848\)."]
    }
    []
}

const PARTS = {
    property: '@property --sb-alpha {
  syntax: "<number>";
  inherits: true;
  initial-value: 1;
}
'
    gutter: 'html {
  scrollbar-gutter: stable;
}
'
    bar: '::-webkit-scrollbar {
  width: 14px;
  height: 14px;
  background-color: transparent;
}
'
    track: '::-webkit-scrollbar-track,
::-webkit-scrollbar-corner {
  background-color: transparent;
}
'
    thumb: '::-webkit-scrollbar-thumb {
  border: 4px solid transparent;
  background-clip: padding-box;
  background-color: hsl(var(--muted-foreground) / var(--sb-alpha));
}
'
    firefox: '@supports not selector(::-webkit-scrollbar) {
  html,
  pre {
    scrollbar-width: thin;
    scrollbar-color: hsl(var(--muted-foreground) / var(--sb-alpha)) transparent;
  }
}
'
}

def css-of [parts: record]: nothing -> string {
    $parts | values | str join "\n"
}

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)
    let compliant = (css-of $PARTS)
    # What Tailwind's minifier makes of it.
    let minified = ($compliant | str replace --all --regex '\s*\n\s*' "" | str replace --all ": " ":" | str replace --all "transparent" "#0000")

    let css_cases = [
        [name css expect_problems why];
        [compliant $compliant false "the authored auto-hiding block"]
        [minified $minified false "the same block minified, `transparent` as `#0000`"]
        [unrelated-hide ($compliant + ".hidden {\n  display: none;\n}\n") false "an unrelated `display: none` rule"]
        [commented-rules ("/* replaces `* { scrollbar-color: hsl(var(--muted-foreground)) hsl(var(--muted)) }`,\n   `::-webkit-scrollbar { display: none }` and a painted track */\n" + $compliant) false "a comment naming the forbidden rules"]
        [hover-thumb ($compliant + "::-webkit-scrollbar-thumb:hover {\n  background-color: hsl(var(--foreground) / var(--sb-alpha));\n}\n") false "a painted thumb hover state"]
        [hidden-webkit ($compliant + "::-webkit-scrollbar {\n  display: none;\n}\n") true "a re-added `::-webkit-scrollbar { display: none }`"]
        [hidden-thumb ($compliant + "::-webkit-scrollbar-thumb{display:none}\n") true "a hidden `::-webkit-scrollbar-thumb`"]
        [hidden-firefox (css-of ($PARTS | update firefox {|p| $p.firefox | str replace "thin" "none" })) true "`scrollbar-width: none` inside the Firefox block"]
        [global-color ($compliant + "* {\n  scrollbar-color: hsl(var(--muted-foreground)) hsl(var(--muted));\n}\n") true "a re-added global `* { scrollbar-color }` \(YOTUN-208\)"]
        [global-width ($compliant + "* {\n  scrollbar-width: auto;\n}\n") true "a `scrollbar-width` outside the Firefox block"]
        [thin-outside ($compliant + ".pane {\n  scrollbar-width: thin;\n}\n") true "`scrollbar-width: thin` outside the Firefox block"]
        [painted-track ($compliant + "::-webkit-scrollbar-track {\n  background-color: hsl(var(--muted));\n}\n") true "a painted `::-webkit-scrollbar-track`"]
        [painted-track-hover ($compliant + "::-webkit-scrollbar-track:hover{background:#eee}\n") true "a painted track hover state"]
        [painted-track-piece ($compliant + "::-webkit-scrollbar-track-piece {\n  background: hsl(var(--muted));\n}\n") true "a painted `::-webkit-scrollbar-track-piece`"]
        [painted-bar (css-of ($PARTS | update bar {|p| $p.bar | str replace "background-color: transparent" "background-color: hsl(var(--muted))" })) true "a painted `::-webkit-scrollbar`"]
        [painted-corner ($compliant + "::-webkit-scrollbar-corner{background:#fff}\n") true "a painted `::-webkit-scrollbar-corner`"]
        [narrow-bar (css-of ($PARTS | update bar {|p| $p.bar | str replace "width: 14px" "width: 5px" })) true "a `::-webkit-scrollbar` narrower than the 14px zone"]
        [short-bar (css-of ($PARTS | update bar {|p| $p.bar | str replace "height: 14px" "height: 5px" })) true "a horizontal bar lower than the 14px zone"]
        [no-track (css-of ($PARTS | reject track)) true "no transparent `::-webkit-scrollbar-track`"]
        [static-thumb (css-of ($PARTS | update thumb {|p| $p.thumb | str replace " / var(--sb-alpha)" "" })) true "a thumb color without `var\(--sb-alpha\)`"]
        [literal-thumb (css-of ($PARTS | update thumb {|p| $p.thumb | str replace "hsl(var(--muted-foreground) / var(--sb-alpha))" "#888" })) true "a literal thumb color"]
        [no-property (css-of ($PARTS | reject property)) true "no `@property --sb-alpha` registration"]
        [uninherited (css-of ($PARTS | update property {|p| $p.property | str replace "inherits: true" "inherits: false" })) true "an uninherited `--sb-alpha`"]
        [hidden-initial (css-of ($PARTS | update property {|p| $p.property | str replace "initial-value: 1" "initial-value: 0" })) true "`--sb-alpha` starting at 0, which would fail hidden"]
        [no-firefox (css-of ($PARTS | reject firefox)) true "no Firefox `@supports` block"]
        [firefox-auto (css-of ($PARTS | update firefox {|p| $p.firefox | str replace "thin" "auto" })) true "a Firefox block without `thin`"]
        [firefox-static (css-of ($PARTS | update firefox {|p| $p.firefox | str replace " / var(--sb-alpha)" "" })) true "a Firefox thumb color without `var\(--sb-alpha\)`"]
        [no-gutter (css-of ($PARTS | reject gutter)) true "no `scrollbar-gutter: stable`"]
        [unstyled "body {\n  color: red;\n}\n" true "a stylesheet with the scrollbar styling stripped out"]
        [commented-styling ("/* " + $compliant + " */\nbody {\n  color: red;\n}\n") true "the styling present only inside a comment"]
    ]
    let js_cases = [
        [name js expect_problems why];
        [idle-6000 "  var SCROLLBAR_IDLE_MS = 6000;\n" false "a 6000ms hold"]
        [idle-5000 "  const SCROLLBAR_IDLE_MS = 5000;\n" false "the 5000ms lower bound"]
        [idle-7000 "  let SCROLLBAR_IDLE_MS = 7_000;\n" false "the 7000ms upper bound"]
        [idle-1000 "  var SCROLLBAR_IDLE_MS = 1000;\n" true "a 1000ms hold, too short to grab"]
        [idle-4999 "  var SCROLLBAR_IDLE_MS = 4999;\n" true "a hold just under 5000ms"]
        [idle-7001 "  var SCROLLBAR_IDLE_MS = 7001;\n" true "a hold just over 7000ms"]
        [idle-missing "  var TOAST_SHORT_MS = 5000;\n" true "no `SCROLLBAR_IDLE_MS`"]
        [idle-commented "  // var SCROLLBAR_IDLE_MS = 6000;\n" true "a commented-out declaration only"]
        [idle-twice "  var SCROLLBAR_IDLE_MS = 6000;\n  var SCROLLBAR_IDLE_MS = 6500;\n" true "two declarations"]
    ]

    let css_results = ($css_cases | each {|c|
        let file = $"($dir)/($c.name).css"
        $c.css | save $file
        let problems = (check-css $file)
        {why: $c.why, ok: (($problems | is-not-empty) == $c.expect_problems), problems: $problems}
    })
    let js_results = ($js_cases | each {|c|
        let file = $"($dir)/($c.name).js"
        $c.js | save $file
        let problems = (check-js $file)
        {why: $c.why, ok: (($problems | is-not-empty) == $c.expect_problems), problems: $problems}
    })
    let missing = [
        {why: "a missing stylesheet", ok: ((check-css $"($dir)/absent.css") | is-not-empty), problems: []}
        {why: "a missing app.js", ok: ((check-js $"($dir)/absent.js") | is-not-empty), problems: []}
    ]
    rm --recursive $dir

    let results = ($css_results | append $js_results | append $missing)
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
    --self-test # prove the gate catches every forbidden rule and every missing requirement, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let problems = ($CSS_FILES | each {|f| check-css $f } | flatten | append (check-js $JS_FILE))
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "Scrollbars are a 5px thumb with no painted track in a 14px grab zone, hidden at rest only"
        print --stderr "once app.js tags <html>, and shown for SCROLLBAR_IDLE_MS (5-7s) after use (BUNYIP-848)."
        print --stderr "`scrollbar-width` / `scrollbar-color` belong in the Firefox @supports block alone. Edit"
        print --stderr "bunyip-web/input.css, rebuild with `bun run build:css` in bunyip-web/, and commit both."
        exit 1
    }

    print $"check-scrollbars: ($CSS_FILES | length) stylesheets and ($JS_FILE) keep the auto-hiding scrollbar contract"
}
