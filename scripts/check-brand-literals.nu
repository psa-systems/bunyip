#!/usr/bin/env nu

# Brand-literal gate for bunyip-web (BUNYIP-561).
#
# The product name is an admin-managed database record, not a literal compiled
# into the binary. A link to the deployed site previewed as
# "Surfaces what matters. · Bunyip" because the internal codename was spread
# across the views, the page handlers and the marketing skin; every one of those
# sites now interpolates the brand name fetched from `/v1/branding`.
#
# This gate fails the build when the standalone word `Bunyip` reappears in the
# trees that render copy: the Rust views, handlers and skin, plus the `/docs`
# help pages (BUNYIP-576). The BUNYIP-561 sweep had excluded those `.md` files,
# and they still leaked the codename to end users, so they are gated now too.
#
# An occurrence that is legitimately NOT copy (a test fixture asserting the
# fallback, a `BUNYIP-nnn` issue reference in prose, an identifier that would
# change wire or session behaviour if renamed) is exempted by an explicit
# `// brand-literal-ok: <reason>` marker on the same line, so an exemption is a
# visible decision rather than a regex accident.
#
# `BUNYIP-nnn` issue references and `BUNYIP_*` / `bunyip_*` / `bunyip-*`
# identifiers are not matched at all: the pattern requires a word boundary that
# is not one of `-`, `_` or a digit-carrying suffix.
#
# Usage:
#   scripts/check-brand-literals.nu
#   scripts/check-brand-literals.nu --self-test

const GUARDED_GLOBS = [
    "bunyip-web/src/views/**/*.rs"
    "bunyip-web/src/handlers/**/*.rs"
    "bunyip-web/src/skin/**/*.rs"
    # BUNYIP-576: the /docs help pages leaked the codename (they were excluded
    # from the BUNYIP-561 sweep). Gate them too so it cannot come back.
    "bunyip-web/src/skin/docs/**/*.md"
    # BUNYIP-502: the shared web-kit crate holds the UI toolkit lifted out of
    # bunyip-web/src/views. Gate it so a brand literal cannot enter the layer
    # a second front-end also consumes.
    "crates/web-kit/src/**/*.rs"
]

# The standalone codename. `(?-i)` keeps it case-sensitive, so the crate,
# binary, cookie and element-id identifiers (all lowercase `bunyip`, and the
# uppercase `BUNYIP_` env prefix) never match. The trailing guard rejects
# `Bunyip-561`-style issue ids and any `Bunyip_`/`Bunyip-` identifier.
const BRAND_PATTERN = '(?-i)\bBunyip\b(?![-_0-9])'

# The one way to keep an occurrence: say why, on the line.
const EXEMPTION = 'brand-literal-ok:'

# Problems in one Rust source file, as human-readable lines.
def check-rs [path: string]: nothing -> list<string> {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): missing or not readable - the gate cannot prove the brand is not compiled in."]
    }

    mut problems = []
    for row in ($content | lines | enumerate) {
        let text = $row.item
        if ($text | str contains $EXEMPTION) { continue }
        if ($text =~ $BRAND_PATTERN) {
            $problems = ($problems | append $"($path):($row.index + 1): `($text | str trim)` - the product name is the admin-managed branding record, not a literal.")
        }
    }
    $problems
}

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)

    let cases = [
        {
            name: "interpolated.rs"
            body: 'h1 { (format!("Welcome to {brand_name}")) }'
            expect_problems: false
            why: "copy that interpolates the brand name"
        }
        {
            name: "issue-reference.rs"
            body: "// BUNYIP-561: the branding record replaced the compiled-in name."
            expect_problems: false
            why: "a BUNYIP-nnn issue reference in a comment"
        }
        {
            name: "identifiers.rs"
            body: ("let c = \"bunyip_onboard_verify_sent\";\n" + 'let id = "bunyip-toast-root";' + "\nlet e = \"BUNYIP_API_URL\";")
            expect_problems: false
            why: "cookie, element-id and env identifiers, which are not copy"
        }
        {
            name: "exempted.rs"
            body: 'let fixture = "Bunyip"; // brand-literal-ok: fixture asserting the fallback'
            expect_problems: false
            why: "an occurrence carrying an explicit exemption reason"
        }
        {
            name: "heading.rs"
            body: 'h1 class="text-3xl font-bold" { "Welcome to Bunyip" }'
            expect_problems: true
            why: "the product name compiled into a heading"
        }
        {
            name: "marketing.rs"
            body: 'p { "Bunyip is the front door to the products your team already runs." }'
            expect_problems: true
            why: "the product name compiled into marketing copy"
        }
        {
            name: "fallback.rs"
            body: '    APP_NAME.get().map(String::as_str).unwrap_or("Bunyip")'
            expect_problems: true
            why: "a compiled-in fallback literal"
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
    --self-test # prove the gate rejects a compiled-in product name, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let files = ($GUARDED_GLOBS | each {|g| glob $g } | flatten)
    if ($files | is-empty) {
        print --stderr $"error: ($GUARDED_GLOBS | str join ', ') matched no files - the gate cannot prove the brand is not compiled in."
        exit 1
    }

    let problems = ($files | each {|f| check-rs $f } | flatten)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "The product name is admin-managed (BUNYIP-561): read it from"
        print --stderr "crate::views::layout::brand_name\(), which resolves the branding record"
        print --stderr "fetched from /v1/branding, and omit the name when it is empty rather than"
        print --stderr "substituting one. If the occurrence is genuinely not copy, add a"
        print --stderr $"`// ($EXEMPTION) <reason>` marker on the line."
        exit 1
    }

    print $"check-brand-literals: ($files | length) source files carry no compiled-in product name"
}
