#!/usr/bin/env nu

# Runner-label gate (BUNYIP-444, BUNYIP-446, #CLAUDE-203, #GOV-43).
#
# The principle: the runner image provides the job's runtime dependencies, and a
# job requests the label of an image that has them. Installing them in a workflow
# step re-solves on every run and forks a package list the image already
# maintains; that is the workaround this gate exists to keep out.
#
# The dev image is the one that carries them. It has cc/gcc/ld and the OpenSSL
# headers (verified in ghcr.io/niceguyit/opensuse-dev:v1.7.0-leap-16.0: gcc-15,
# libopenssl-devel-3.5.0), and its dev stage installs the Playwright browser
# system libraries (X / GTK / NSS / glib) plus the pre-baked browser binaries.
# The base image ships cargo/rustc but no C toolchain, so a native cargo build
# there dies with `linker cc not found` on a cold cache, and a Playwright browser
# there dies at launch with `cannot open shared object file`.
#
# Three properties:
#   1. check.yml (native cargo fmt/clippy/build/test) requests the dev label.
#   2. no workflow installs a C toolchain, OpenSSL headers, or the browser system
#      libraries at run time.
#   3. every `runs-on:` carries a comment above it saying why that label is right;
#      an unannotated label is indistinguishable from an unaudited one.
#
# Usage: scripts/check-runner-labels.nu [workflows_dir]

# Read a file as UTF-8 lines. A file that is absent or not decodable has no
# lines to match, mirroring how grep treats one.
def read-lines [path: string]: nothing -> list<string> {
    try { open --raw $path | decode utf-8 | lines } catch { [] }
}

# Every line under `dir` (recursively) matching `pattern`, as
# { file, line, text } records with repo-relative paths, mirroring `grep -rn`.
def grep-tree [dir: string, pattern: string]: nothing -> table {
    glob $"($dir)/**/*" --no-dir
    | each {|path|
        let rel = (try { $path | path relative-to $env.PWD } catch { $path })
        read-lines $path
        | enumerate
        | where {|r| $r.item =~ $pattern }
        | each {|r| { file: $rel, line: ($r.index + 1), text: $r.item } }
    }
    | flatten
}

# A commented-out hit is documentation, not an install step.
def drop-comments []: table -> table {
    $in | where {|h| not ($h.text | str trim | str starts-with "#") }
}

def main [workflows_dir: string = ".forgejo/workflows"] {
    let check_workflow = $"($workflows_dir)/check.yml"

    if ($check_workflow | path type) != "file" {
        print --stderr $"error: expected workflow not found: ($check_workflow)"
        exit 2
    }

    mut status = 0

    # 1. The native Rust job needs the dev image.
    let dev_label = 'runs-on: ${{ vars.RUNS_ON_OPENSUSE_DEV_LATEST }}'
    if not (read-lines $check_workflow | any {|l| $l | str contains $dev_label }) {
        print --stderr $"error: ($check_workflow) must run on RUNS_ON_OPENSUSE_DEV_LATEST; it compiles Rust natively and base has no C toolchain \(BUNYIP-444)"
        $status = 1
    }

    # 2. No run-time toolchain install anywhere: that is the workaround, not the fix.
    let toolchain_hits = (
        grep-tree $workflows_dir '(zypper|apt-get|dnf|yum).*(install).*( gcc| clang| binutils|libopenssl-devel|openssl-devel|build-essential)'
        | drop-comments
    )
    for hit in $toolchain_hits {
        print --stderr $"error: ($hit.file):($hit.line):($hit.text): installs a C toolchain / OpenSSL headers at run time; request RUNS_ON_OPENSUSE_DEV_LATEST instead \(BUNYIP-444)"
        $status = 1
    }

    # 2b. Same rule for the Playwright browser system libraries. Matched by
    # package name rather than by `<pm> install ...`, because a folded YAML
    # command puts the package list on continuation lines the package manager
    # never appears on.
    let browser_hits = (
        grep-tree $workflows_dir '(libgtk-3-0|libgobject-2_0-0|libglib-2_0-0|mozilla-nss|mozilla-nspr|libatk-1_0-0|libasound2|libgbm1|libxkbcommon0)'
        | drop-comments
    )
    for hit in $browser_hits {
        print --stderr $"error: ($hit.file):($hit.line):($hit.text): installs the Playwright browser system libraries at run time; request RUNS_ON_OPENSUSE_DEV_LATEST instead, its image pre-bakes them \(BUNYIP-446)"
        $status = 1
    }

    # 3. Every label is annotated with its reason.
    for hit in (grep-tree $workflows_dir '^\s*runs-on:') {
        let above = (
            read-lines $hit.file
            | first ($hit.line - 1)
            | reverse
            | where {|l| ($l | str trim | is-not-empty) }
        )
        let prev = (if ($above | is-empty) { "" } else { $above | first })
        if not ($prev | str trim | str starts-with "#") {
            print --stderr $"error: ($hit.file):($hit.line): 'runs-on' has no comment above it stating why this runner label is correct \(BUNYIP-444)"
            $status = 1
        }
    }

    if $status == 0 {
        print "runner labels OK: native check on dev, every label annotated, no run-time install of what the image provides"
    }

    exit $status
}
