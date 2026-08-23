#!/usr/bin/env nu

# Committed-Tailwind-output freshness gate (BUNYIP-598).
#
# `bunyip-web/assets/styles.css` is committed and served directly, so a fresh
# clone and a host run need no JS toolchain. Nothing verified that the committed
# file is what the current sources and the pinned Tailwind actually produce, and
# two defects hid behind that gap: the web-kit extraction moved four markup files
# out of `bunyip-web/src`, where Tailwind's automatic source detection is rooted,
# so 34 utilities the shared components need survived only inside the stale
# output; and the committed file had been built by a Tailwind newer than the one
# `bun.lock` pins. Neither is visible in any single diff.
#
# This gate checks both halves:
#   - every directory under `crates/*/src` that emits markup (`class="`) is
#     named by an `@source` line in `bunyip-web/input.css`, so the next crate
#     that renders markup cannot silently fall outside the scan, and
#   - a fresh `bun run build:css` is byte-for-byte the committed file, so a
#     missed rebuild (or a Tailwind version drift) fails here instead of
#     shipping a thinner stylesheet.
#
# The build goes to a temporary path and the committed file's digest is checked
# either side of it: the gate proves the tree is current, it never fixes it.
#
# Usage:
#   scripts/check-css-current.nu
#   scripts/check-css-current.nu --self-test

const WEB_DIR = "bunyip-web"
const INPUT_CSS = "bunyip-web/input.css"
const BUILT_CSS = "bunyip-web/assets/styles.css"

# Same image `just check-container` uses; it carries bun + tailwind. Only
# reached when the host has no bun of its own.
const BUILDER_IMAGE = "ghcr.io/niceguyit/rust-builder-glibc:v1.0.1-rust1.94-trixie"

# -- @source coverage -------------------------------------------------------

# Collapse `.` and `..` without touching the filesystem, so an `@source` path
# that does not exist yet still normalises instead of erroring.
def normalise-path []: string -> string {
    mut parts = []
    for seg in ($in | split row "/") {
        if $seg == "" or $seg == "." {
            continue
        } else if $seg == ".." and ($parts | is-not-empty) and ($parts | last) != ".." {
            $parts = ($parts | drop 1)
        } else {
            $parts = ($parts | append $seg)
        }
    }
    $parts | str join "/"
}

# The `@source` paths declared in input.css, as repo-relative directories.
# Tailwind resolves them against the stylesheet's own directory.
def declared-sources [css: string]: nothing -> list<string> {
    let content = (try { open --raw $css | decode utf-8 } catch { null })
    if $content == null {
        # Returning "nothing is declared" would report every markup crate as
        # uncovered under a remedy that does not apply. Say what actually broke.
        print --stderr $"error: ($css): missing or not readable, so no @source declaration can be read."
        exit 1
    }
    $content
    | lines
    | parse --regex '^\s*@source\s+"(?<path>[^"]+)"'
    | get path
    | each {|p| $"($WEB_DIR)/($p)" | normalise-path }
}

# Repo-relative `crates/<name>/src` directories whose Rust sources emit markup.
def markup-source-dirs [root: string]: nothing -> list<string> {
    let base = ($root | path expand)
    glob $"($base)/crates/*/src/**/*.rs"
    | where {|f|
        # An unreadable source is not "no markup": it is a file whose coverage
        # this gate cannot judge, so it fails rather than passing vacuously.
        let text = (try { open --raw $f | decode utf-8 } catch {|e|
            print --stderr $"error: ($f): not readable as UTF-8, so its @source coverage cannot be proven: ($e.msg)"
            exit 1
        })
        $text | str contains 'class="'
    }
    | each {|f| $f | path relative-to $base | split row (char path_sep) | first 3 | str join "/" }
    | uniq
    | sort
}

# A directory is covered when an `@source` names it or an ancestor of it.
def covered [dir: string, sources: list<string>]: nothing -> bool {
    $sources | any {|s| $dir == $s or ($dir | str starts-with $"($s)/") }
}

def uncovered-source-dirs [root: string]: nothing -> list<string> {
    let sources = (declared-sources $"($root)/($INPUT_CSS)")
    markup-source-dirs $root | where {|d| not (covered $d $sources) }
}

# -- freshness --------------------------------------------------------------

# Byte-for-byte comparison, reported in a form an author can act on.
def css-diff [fresh: string, committed: string]: nothing -> list<string> {
    let a = (try { open --raw $fresh | into binary } catch { null })
    if $a == null {
        return [$"($fresh): the fresh Tailwind build produced no output, so freshness cannot be proven."]
    }
    let b = (try { open --raw $committed | into binary } catch { null })
    if $b == null {
        return [$"($committed): missing or not readable - the committed stylesheet is what the server serves."]
    }
    if $a == $b {
        return []
    }

    [
        $"($committed) is not what the current sources and the pinned Tailwind produce."
        $"  fresh build: ($a | bytes length) bytes, sha256 ($a | hash sha256)"
        $"  committed:   ($b | bytes length) bytes, sha256 ($b | hash sha256)"
    ]
}

# Run one external command, reporting its own output on failure rather than
# collapsing it into a bare exit code.
def run-or-fail [what: string, cmd: closure]: nothing -> nothing {
    let r = (do $cmd | complete)
    if $r.exit_code != 0 {
        print --stderr $"error: ($what) failed (exit ($r.exit_code)):"
        print --stderr ($r.stdout | default "")
        print --stderr ($r.stderr | default "")
        exit 1
    }
}

# Build the stylesheet to `out`. Uses the host's bun when it has one, else the
# builder image (the only other place bun is known to live); never installs bun.
def build-css [out: string]: nothing -> nothing {
    if (which bun | is-not-empty) {
        run-or-fail "bun install --frozen-lockfile" {|| cd $WEB_DIR; ^bun install --frozen-lockfile }
        run-or-fail "bun run build:css" {|| cd $WEB_DIR; ^bun run build:css --output $out }
        return
    }

    if (which docker | is-empty) {
        print --stderr "error: neither bun nor docker is on PATH, so the committed stylesheet cannot be rebuilt."
        print --stderr $"Install bun, or make docker available so the guard can build inside ($BUILDER_IMAGE)."
        exit 1
    }

    # The repo is bind-mounted read-write because `bun install` writes
    # node_modules/ (gitignored). The build output goes to the separate /out
    # mount, never over the committed file.
    let out_dir = ($out | path dirname)
    let out_name = ($out | path basename)
    let docker_args = [
        "run" "--rm"
        "--user" $"(^id -u | str trim):(^id -g | str trim)"
        "--volume" $"($env.PWD | path expand):/work"
        "--volume" $"($out_dir):/out"
        "--env" "HOME=/tmp"
        "--env" "BUN_INSTALL_CACHE_DIR=/tmp/bun-cache"
        "--workdir" "/work/bunyip-web"
        $BUILDER_IMAGE
        "bash" "-c" $"bun install --frozen-lockfile && bun run build:css --output /out/($out_name)"
    ]
    run-or-fail $"the containerised Tailwind build in ($BUILDER_IMAGE)" {|| ^docker ...$docker_args }
}

# -- entry point ------------------------------------------------------------

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)

    # A tree whose only markup-emitting crate is declared.
    let ok_root = $"($dir)/ok"
    mkdir $"($ok_root)/bunyip-web" $"($ok_root)/crates/web-kit/src" $"($ok_root)/crates/plain/src"
    "@import \"tailwindcss\";\n@source \"../crates/web-kit/src\";\n" | save --force $"($ok_root)/($INPUT_CSS)"
    "html! { div class=\"flex\" {} }\n" | save --force $"($ok_root)/crates/web-kit/src/ui.rs"
    "pub fn plain() -> u8 { 1 }\n" | save --force $"($ok_root)/crates/plain/src/lib.rs"

    # The same tree with the declaration removed - the BUNYIP-566 regression.
    let undeclared_root = $"($dir)/undeclared"
    ^cp --recursive $ok_root $undeclared_root
    "@import \"tailwindcss\";\n" | save --force $"($undeclared_root)/($INPUT_CSS)"

    # A new markup-emitting crate that nobody declared.
    let new_crate_root = $"($dir)/new-crate"
    ^cp --recursive $ok_root $new_crate_root
    mkdir $"($new_crate_root)/crates/mail-kit/src"
    "html! { span class=\"text-sm\" {} }\n" | save --force $"($new_crate_root)/crates/mail-kit/src/lib.rs"

    # An ancestor declaration covers the crate below it.
    let ancestor_root = $"($dir)/ancestor"
    ^cp --recursive $ok_root $ancestor_root
    "@import \"tailwindcss\";\n@source \"../crates\";\n" | save --force $"($ancestor_root)/($INPUT_CSS)"

    let coverage_cases = [
        {root: $ok_root, expect: [], why: "a declared markup crate"}
        {root: $undeclared_root, expect: ["crates/web-kit/src"], why: "a markup crate with no @source line"}
        {root: $new_crate_root, expect: ["crates/mail-kit/src"], why: "a newly added markup crate"}
        {root: $ancestor_root, expect: [], why: "an @source naming an ancestor directory"}
    ]

    let same_a = $"($dir)/same-a.css"
    let same_b = $"($dir)/same-b.css"
    "a{color:red}" | save --force $same_a
    "a{color:red}" | save --force $same_b
    let shorter = $"($dir)/shorter.css"
    "a{color:re" | save --force $shorter
    let other = $"($dir)/other.css"
    "a{color:blu}" | save --force $other

    let diff_cases = [
        {fresh: $same_a, committed: $same_b, expect_problems: false, why: "a committed file equal to the fresh build"}
        {fresh: $same_a, committed: $other, expect_problems: true, why: "a committed file built from different sources"}
        {fresh: $same_a, committed: $shorter, expect_problems: true, why: "a truncated committed file"}
        {fresh: $same_a, committed: $"($dir)/absent.css", expect_problems: true, why: "a missing committed file"}
        {fresh: $"($dir)/absent.css", committed: $same_a, expect_problems: true, why: "a build that produced nothing"}
    ]

    let results = (
        ($coverage_cases | each {|c|
            let got = (uncovered-source-dirs $c.root)
            {why: $c.why, ok: ($got == $c.expect), detail: ($got | to nuon)}
        })
        | append ($diff_cases | each {|c|
            let problems = (css-diff $c.fresh $c.committed)
            {why: $c.why, ok: (($problems | is-not-empty) == $c.expect_problems), detail: ($problems | to nuon)}
        })
    )
    rm --recursive $dir

    for r in $results {
        if $r.ok {
            print $"self-test ok: gate handles ($r.why)"
        } else {
            print --stderr $"self-test FAILED: gate mis-handles ($r.why): ($r.detail)"
        }
    }
    if ($results | any {|r| not $r.ok }) {
        exit 1
    }
}

def main [
    --self-test # prove the gate rejects an undeclared markup crate and a stale stylesheet, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let uncovered = (uncovered-source-dirs ".")
    if ($uncovered | is-not-empty) {
        for d in $uncovered {
            print --stderr $"error: ($d) emits markup but no @source line in ($INPUT_CSS) names it."
        }
        print --stderr ""
        print --stderr "Tailwind's automatic source detection is rooted at bunyip-web/, so a crate"
        print --stderr "outside it is never scanned and the classes it uses are dropped from the built"
        print --stderr "stylesheet (BUNYIP-598). Add `@source \"../crates/<name>/src\";` to"
        print --stderr $"($INPUT_CSS), then rebuild the asset with `bun run build:css` in"
        print --stderr "bunyip-web/ and commit the result."
        exit 1
    }

    # Digest either side of the build: the gate proves the committed file is
    # current, so it must never be the thing that made it current.
    let before = (open --raw $BUILT_CSS | hash sha256)

    let out_dir = (mktemp --directory --tmpdir)
    let fresh = $"($out_dir)/styles.css"
    build-css $fresh
    let problems = (css-diff $fresh $BUILT_CSS)
    let after = (open --raw $BUILT_CSS | hash sha256)
    rm --recursive $out_dir

    if $before != $after {
        print --stderr $"error: the guard itself rewrote ($BUILT_CSS); it must only ever read it."
        exit 1
    }

    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "The committed Tailwind output is served as-is, so a missed rebuild ships a"
        print --stderr "stylesheet that is thinner than the markup needs and nothing reports it"
        print --stderr "(BUNYIP-598). Run `bun run build:css` in bunyip-web/ and commit the result."
        exit 1
    }

    print $"check-css-current: ($BUILT_CSS) matches a fresh build, and every markup crate is declared in ($INPUT_CSS)"
}
