#!/usr/bin/env nu

# Buildkit cargo cache-mount gate (BUNYIP-534).
#
# A `--mount=type=cache` with no `id=` is keyed by its target path alone, and the
# default `sharing=shared` lets every concurrent build write it at once. Both
# publish workflows land on one buildkit instance, and a release commit fires a
# `main` push and a `v*` tag push together, so four builds unpacked crates into
# the same `/usr/local/cargo/registry` and the v0.14.0 web build died with
# `failed to open .../.cargo-ok: File exists (os error 17)`. Cargo cannot
# serialise them: its `.package-cache` lock lives at `$CARGO_HOME/.package-cache`,
# outside the mounted subdirectories, so each build takes an uncontended lock.
#
# The fix is per-image `id=` (so api and web never contend) plus `sharing=locked`
# (so two runs of the SAME image queue instead of corrupting the cache). Neither
# annotation is load-bearing at build time, so a new mount that omits them builds
# fine and only fails under concurrency, months later, on a release. Gate it.
#
# Usage:
#   scripts/check-cache-mount-sharing.nu
#   scripts/check-cache-mount-sharing.nu --self-test

# One mount option string, e.g. `type=cache,id=x,target=/y,sharing=locked`.
# Mount options carry no whitespace, so a line-oriented scan finds each mount
# whole and reports the line the author has to edit.
const MOUNT_PATTERN = '--mount=type=cache[^\s\\]*'

# Problems in one Dockerfile, as human-readable lines.
def check-dockerfile [path: string]: nothing -> list<string> {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): missing or not readable - the gate cannot prove the cache mounts are annotated."]
    }

    mut problems = []
    for entry in ($content | lines | enumerate) {
        # A `#` comment can name a mount while explaining it; that is prose.
        if ($entry.item | str trim | str starts-with "#") { continue }

        for mount in ($entry.item | parse --regex ("(?<hit>" + $MOUNT_PATTERN + ")") | get hit) {
            let opts = ($mount | str replace "--mount=" "" | split row ",")
            let missing = [
                (if ($opts | any {|o| $o =~ '^id=.+' }) { null } else { "an explicit per-image `id=`" })
                (if ($opts | any {|o| $o == "sharing=locked" }) { null } else { "`sharing=locked`" })
            ] | compact
            if ($missing | is-not-empty) {
                $problems = ($problems | append $"($path):($entry.index + 1): '($mount)' lacks ($missing | str join ' and ').")
            }
        }
    }
    $problems
}

# Every tracked Dockerfile, whatever the suffix convention (`Dockerfile`,
# `Dockerfile.oci-musl`, `api.Dockerfile`).
def dockerfiles []: nothing -> list<string> {
    ^git ls-files | lines | where {|f| ($f | path basename) =~ 'Dockerfile' }
}

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)

    let compliant = $"($dir)/Dockerfile.compliant"
    "FROM scratch AS build\nRUN --mount=type=cache,id=app-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \\\n    --mount=type=cache,id=app-cargo-git,target=/usr/local/cargo/git,sharing=locked \\\n    cargo build\n" | save --force $compliant

    let bare = $"($dir)/Dockerfile.bare"
    "FROM scratch\nRUN --mount=type=cache,target=/usr/local/cargo/registry cargo build\n" | save --force $bare

    let no_id = $"($dir)/Dockerfile.no-id"
    "FROM scratch\nRUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked cargo build\n" | save --force $no_id

    let no_sharing = $"($dir)/Dockerfile.no-sharing"
    "FROM scratch\nRUN --mount=type=cache,id=app-cargo-registry,target=/usr/local/cargo/registry cargo build\n" | save --force $no_sharing

    let wrong_sharing = $"($dir)/Dockerfile.shared"
    "FROM scratch\nRUN --mount=type=cache,id=app-cargo-registry,target=/usr/local/cargo/registry,sharing=shared cargo build\n" | save --force $wrong_sharing

    let empty_id = $"($dir)/Dockerfile.empty-id"
    "FROM scratch\nRUN --mount=type=cache,id=,target=/usr/local/cargo/registry,sharing=locked cargo build\n" | save --force $empty_id

    let other_mounts = $"($dir)/Dockerfile.other-mounts"
    "FROM scratch\nRUN --mount=type=secret,id=token --mount=type=bind,target=/src cargo build\n" | save --force $other_mounts

    let commented = $"($dir)/Dockerfile.commented"
    "FROM scratch\n# was --mount=type=cache,target=/usr/local/cargo/registry before BUNYIP-534\nRUN --mount=type=cache,id=app-cargo-registry,target=/usr/local/cargo/registry,sharing=locked cargo build\n" | save --force $commented

    let cases = [
        {file: $compliant, expect_problems: false, why: "annotated mounts across a line continuation"}
        {file: $bare, expect_problems: true, why: "a bare `type=cache` mount"}
        {file: $no_id, expect_problems: true, why: "a locked mount with no id"}
        {file: $no_sharing, expect_problems: true, why: "an identified mount with no sharing mode"}
        {file: $wrong_sharing, expect_problems: true, why: "an explicit `sharing=shared`"}
        {file: $empty_id, expect_problems: true, why: "an empty `id=`"}
        {file: $other_mounts, expect_problems: false, why: "secret and bind mounts, which this gate does not govern"}
        {file: $commented, expect_problems: false, why: "a comment quoting the old unannotated mount"}
        {file: $"($dir)/Dockerfile.absent", expect_problems: true, why: "a missing Dockerfile"}
    ]
    let results = ($cases | each {|c|
        let problems = (check-dockerfile $c.file)
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
    --self-test # prove the gate rejects an unannotated mount and passes an annotated one, then exit
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
        print --stderr "Every buildkit cargo cache mount carries a per-image `id=` and `sharing=locked`"
        print --stderr "(BUNYIP-534). Without the id, two images share one cache keyed by target path;"
        print --stderr "without the lock, concurrent builds unpack crates into it at the same time and"
        print --stderr "fail with `.cargo-ok: File exists`, because cargo's own `.package-cache` lock"
        print --stderr "sits outside the mount. Use id=bunyip-<image>-cargo-<registry|git>."
        exit 1
    }

    print $"check-cache-mount-sharing: ($files | length) Dockerfiles annotate every cargo cache mount"
}
