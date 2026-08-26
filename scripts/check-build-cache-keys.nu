#!/usr/bin/env nu

# Build-cache key ordering gate (BUNYIP-519).
#
# A RUN's buildkit cache key includes its exec environment; a COPY's does not.
# So an `ENV` whose value changes every build leaves every RUN below it in the
# stage uncacheable while the COPY above it still hits. That is exactly what the
# API build did: the recipe COPY was CACHED and the cargo-chef cook directly
# below it recompiled every dependency anyway, 461s median, on 20 of 20 runs.
#
# Nothing fails at build time when the ordering is wrong, so a build just pays
# full price forever. Hence a gate rather than a comment.
#
# Usage:
#   scripts/check-build-cache-keys.nu
#   scripts/check-build-cache-keys.nu --self-test

# Env vars whose value differs per build or per commit. An `ENV` setting one of
# these poisons the cache key of every RUN below it in the same stage.
const VOLATILE = ["BUILD_DATE" "GIT_COMMIT" "GIT_TAG" "SOURCE_DATE_EPOCH" "VCS_REF" "BUILD_ID"]

# RUN commands whose whole purpose is to be reused across builds. A volatile ENV
# above one of these is the defect. Extend this list when a new expensive
# dependency-warming step is added.
const EXPENSIVE = ["cargo chef cook" "bun install" "cargo install cargo-chef"]

# Dockerfile instructions, with backslash continuations joined onto the line the
# instruction starts on, so a multi-line `ENV a=1 \` + `b=2` is seen whole and
# reported at the line the author has to edit.
def logical-lines [content: string]: nothing -> list<record<line: int, text: string>> {
    mut out = []
    mut buf = ""
    mut start = 1
    for entry in ($content | lines | enumerate) {
        let trimmed = ($entry.item | str trim)
        if ($buf | is-empty) { $start = $entry.index + 1 }
        let continues = ($trimmed | str ends-with "\\")
        let piece = if $continues { $trimmed | str replace --regex '\\$' '' } else { $trimmed }
        $buf = ([$buf $piece] | str join " " | str trim)
        if not $continues {
            if ($buf | is-not-empty) { $out = ($out | append { line: $start, text: $buf }) }
            $buf = ""
        }
    }
    if ($buf | is-not-empty) { $out = ($out | append { line: $start, text: $buf }) }
    $out
}

# Problems in one Dockerfile, as human-readable lines.
def check-dockerfile [path: string]: nothing -> list<string> {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): missing or not readable - the gate cannot prove the cache keys are clean."]
    }

    mut problems = []
    mut stage = "<global>"
    mut volatile_seen = []
    for l in (logical-lines $content) {
        # A `#` comment can name an ENV while explaining it; that is prose.
        if ($l.text | str starts-with "#") { continue }

        if ($l.text =~ '(?i)^FROM\s') {
            # A new stage restarts the env: `ENV`s do not cross a FROM.
            let parts = ($l.text | split row --regex '\s+')
            $stage = (if (($parts | length) >= 4) and (($parts | get 2 | str downcase) == "as") {
                $parts | get 3
            } else {
                $parts | get 1
            })
            $volatile_seen = []
            continue
        }

        if ($l.text =~ '(?i)^ENV\s') {
            for v in $VOLATILE {
                if ($l.text =~ ('(?i)^ENV\s+(?:.*\s)?' + $v + '\s*=')) {
                    $volatile_seen = ($volatile_seen | append { line: $l.line, name: $v })
                }
            }
            continue
        }

        if ($l.text =~ '(?i)^RUN\s') {
            for e in $EXPENSIVE {
                if not ($l.text | str contains $e) { continue }
                for v in $volatile_seen {
                    $problems = ($problems | append
                        $"($path):($v.line): `ENV ($v.name)` is set in stage `($stage)` above the cacheable `($e)` RUN at line ($l.line). Its value changes every build, and a RUN's cache key includes its env, so that layer can never be reused. Move the volatile ENV below the cook.")
                }
            }
        }
    }
    $problems
}

# Every tracked Dockerfile, whatever the suffix convention.
def dockerfiles []: nothing -> list<string> {
    ^git ls-files | lines | where {|f| ($f | path basename) =~ 'Dockerfile' }
}

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)

    let poisoned = $"($dir)/Dockerfile.poisoned"
    "FROM rust AS builder\nARG BUILD_DATE=unknown\nENV BUILD_DATE=${BUILD_DATE}\nCOPY --from=planner /recipe.json recipe.json\nRUN cargo chef cook --release\nCOPY . .\nRUN cargo build\n" | save --force $poisoned

    let fixed = $"($dir)/Dockerfile.fixed"
    "FROM rust AS builder\nCOPY --from=planner /recipe.json recipe.json\nRUN cargo chef cook --release\nARG BUILD_DATE=unknown\nENV BUILD_DATE=${BUILD_DATE}\nCOPY . .\nRUN cargo build\n" | save --force $fixed

    let multiline = $"($dir)/Dockerfile.multiline"
    "FROM rust AS builder\nENV GIT_COMMIT=${GIT_COMMIT} \\\n    GIT_TAG=${GIT_TAG} \\\n    BUILD_DATE=${BUILD_DATE}\nRUN cargo chef cook --release\n" | save --force $multiline

    let stable_env = $"($dir)/Dockerfile.stable-env"
    "FROM rust AS builder\nENV CARGO_BUILD_JOBS=2\nENV RUSTFLAGS=-Clto\nRUN cargo chef cook --release\n" | save --force $stable_env

    let other_stage = $"($dir)/Dockerfile.other-stage"
    "FROM rust AS builder\nRUN cargo chef cook --release\nFROM alpine AS runtime\nENV BUILD_DATE=${BUILD_DATE}\nRUN apk add curl\n" | save --force $other_stage

    let bun = $"($dir)/Dockerfile.bun"
    "FROM node AS build\nENV GIT_TAG=${GIT_TAG}\nRUN cd web && bun install --frozen-lockfile\n" | save --force $bun

    let commented = $"($dir)/Dockerfile.commented"
    "FROM rust AS builder\n# ENV BUILD_DATE used to sit here, above the cook (BUNYIP-519)\nRUN cargo chef cook --release\nENV BUILD_DATE=${BUILD_DATE}\n" | save --force $commented

    let prefix_name = $"($dir)/Dockerfile.prefix"
    "FROM rust AS builder\nENV MY_BUILD_DATE_SUFFIX=1\nRUN cargo chef cook --release\n" | save --force $prefix_name

    let cases = [
        {file: $poisoned, expect: true, why: "a volatile ENV above the cook"}
        {file: $fixed, expect: false, why: "a volatile ENV below the cook"}
        {file: $multiline, expect: true, why: "a volatile ENV spread over continuation lines"}
        {file: $stable_env, expect: false, why: "stable ENVs above the cook"}
        {file: $other_stage, expect: false, why: "a volatile ENV in a later stage with no cook"}
        {file: $bun, expect: true, why: "a volatile ENV above a bun install"}
        {file: $commented, expect: false, why: "a comment quoting the old poisoned ordering"}
        {file: $prefix_name, expect: false, why: "an unrelated var whose name merely contains a volatile name"}
        {file: $"($dir)/Dockerfile.absent", expect: true, why: "a missing Dockerfile"}
    ]
    let results = ($cases | each {|c|
        let problems = (check-dockerfile $c.file)
        {why: $c.why, ok: (($problems | is-not-empty) == $c.expect), problems: $problems}
    })
    rm --recursive $dir

    for r in $results {
        if $r.ok {
            print $"self-test ok: gate handles ($r.why)"
        } else {
            print --stderr $"self-test FAILED: gate mis-handles ($r.why): ($r.problems | to nuon)"
        }
    }
    if ($results | any {|r| not $r.ok }) { exit 1 }
}

def main [
    --self-test # prove the gate rejects a poisoned ordering and passes a clean one, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let files = (dockerfiles)
    let problems = ($files | each {|f| check-dockerfile $f } | flatten)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "A RUN's BuildKit cache key includes its exec environment (BUNYIP-519), so an"
        print --stderr "`ENV` whose value changes every build makes every RUN below it in the stage"
        print --stderr "uncacheable. Declare build-metadata ENVs after the cargo-chef cook, next to the"
        print --stderr "`COPY . .` + `cargo build` that actually consume them."
        exit 1
    }

    print $"check-build-cache-keys: ($files | length) Dockerfiles keep volatile ENVs below their cacheable layers"
}
