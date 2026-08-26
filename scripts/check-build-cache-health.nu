#!/usr/bin/env nu

# Buildkit cache health signal for the publish workflows (BUNYIP-519).
#
# `--cache-to type=gha,...,ignore-error=true` is deliberate: a cache hiccup must
# not fail a publish. The cost is that a dead cache backend and a healthy one
# look identical, because the job exits 0 either way. Measured over 40 image
# builds, `ERROR: blob ...: not found` appeared in 16 and all 16 reported
# success. So split the signal by what each condition actually means.
#
# FATAL (`--preflight`), because it is a deterministic misconfiguration that
# cannot occur on a healthy runner and guarantees a silently cold build forever:
# the gha cache credentials are absent. act_runner only exports them when its
# `cache.enabled` is true, and ignore-error=true would hide their absence.
#
# WARNING (`--log`), because the condition is real cache damage but is
# transient, externally caused and recoverable, and the published image is still
# correct: no manifest imported (also true of a legitimate first build), an
# evicted blob, an error the build swallowed, or a cook that rebuilt despite an
# unchanged recipe. Emitted as `::warning::` so they surface on the run instead
# of being buried in a few thousand lines of buildx progress.
#
# Usage:
#   scripts/check-build-cache-health.nu --preflight
#   scripts/check-build-cache-health.nu --log build.log
#   scripts/check-build-cache-health.nu --self-test

# A step is CACHED, or it is not. Buildkit plain progress emits, per step:
#   #19 [builder 2/4] RUN ... cargo chef cook ...
#   #19 DONE 461.3s      (or)      #19 CACHED
def parse-steps [log: string]: nothing -> table {
    mut steps = {}
    for line in ($log | lines) {
        let m = ($line | parse --regex '^#(?<n>\d+)\s+(?<rest>.*)$')
        if ($m | is-empty) { continue }
        let n = ($m | get 0.n)
        let rest = ($m | get 0.rest | str trim)
        let prior = ($steps | get -o $n | default { name: "", status: "", seconds: 0.0 })
        if $rest == "CACHED" {
            $steps = ($steps | upsert $n ($prior | upsert status "CACHED"))
        } else if ($rest | str starts-with "DONE ") {
            let secs = ($rest | parse --regex '^DONE\s+(?<s>[0-9.]+)s' | get -o 0.s | default "0")
            $steps = ($steps | upsert $n ($prior | upsert status "DONE" | upsert seconds ($secs | into float)))
        } else if ($rest | str starts-with "ERROR") {
            $steps = ($steps | upsert $n ($prior | upsert status "ERROR"))
        } else if ($prior.name | is-empty) and (not ($rest =~ '^[0-9]+\.[0-9]+\s')) {
            # First non-status line for this step is its instruction.
            $steps = ($steps | upsert $n ($prior | upsert name $rest))
        }
    }
    $steps | transpose n step | each {|r| { n: $r.n, name: $r.step.name, status: $r.step.status, seconds: $r.step.seconds } }
}

# Warnings for one build log, as human-readable lines.
def analyse [log: string]: nothing -> list<string> {
    mut warnings = []
    let steps = (parse-steps $log)

    if not ($log | str contains "importing cache manifest") {
        $warnings = ($warnings | append "no cache manifest was imported: this build was fully cold. Expected on the very first build of a new cache scope; on any later build it means --cache-from found nothing.")
    }

    # This runs only after a build that SUCCEEDED, so every `ERROR:` line in it is
    # something ignore-error=true swallowed. Split the known-benign eviction case
    # from everything else rather than reporting one bucket.
    let errors = ($log | lines | where {|l| $l =~ '^#[0-9]+ ERROR' })
    let evicted = ($errors | where {|l| $l =~ 'blob sha256:[0-9a-f]+: not found' })
    let other = ($errors | where {|l| not ($l =~ 'blob sha256:[0-9a-f]+: not found') })
    if ($evicted | is-not-empty) {
        $warnings = ($warnings | append $"the cache server referenced ($evicted | length) blob\(s\) it no longer holds \(`ERROR: blob ...: not found`\). Buildkit rebuilt those layers, so the image is correct, but the reuse they represent was lost.")
    }
    if ($other | is-not-empty) {
        $warnings = ($warnings | append $"the build reported ($other | length) error\(s\) yet still succeeded, so ignore-error=true swallowed them - a failed cache export looks exactly like this and leaves the NEXT build cold: ($other | first 3 | str join ' | ')")
    }

    # The BUNYIP-519 shape: the recipe COPY hit cache, so the dependency graph is
    # provably unchanged, yet the cook below it rebuilt anyway.
    let recipe = ($steps | where {|s| ($s.name | str contains "recipe.json") and ($s.name | str contains "COPY") } | first)
    let cook = ($steps | where {|s| $s.name | str contains "cargo chef cook" } | first)
    if ($recipe != null) and ($cook != null) {
        if $recipe.status == "CACHED" and $cook.status == "DONE" {
            $warnings = ($warnings | append
                $"the dependency recipe was unchanged \(step #($recipe.n) CACHED\) but the cargo-chef cook rebuilt anyway \(step #($cook.n), ($cook.seconds)s\). That is the BUNYIP-519 shape. Three things produce it: a per-build ENV reintroduced above the cook, a CARGO_BUILD_JOBS that differs from the run that primed the cache \(it is a genuine input to the cook, so runners with different core counts key separately\), or the cache server having evicted the cook layer.")
        }
    }
    $warnings
}

def preflight []: nothing -> nothing {
    let token = ($env | get -o ACTIONS_RUNTIME_TOKEN | default "")
    let cache_url = ($env | get -o ACTIONS_CACHE_URL | default "")
    let results_url = ($env | get -o ACTIONS_RESULTS_URL | default "")
    mut missing = []
    if ($token | is-empty) { $missing = ($missing | append "ACTIONS_RUNTIME_TOKEN") }
    if ($cache_url | is-empty) and ($results_url | is-empty) {
        $missing = ($missing | append "ACTIONS_CACHE_URL or ACTIONS_RESULTS_URL")
    }
    if ($missing | is-not-empty) {
        print --stderr $"error: buildx `type=gha` cache is unusable: ($missing | str join ', ') unset."
        print --stderr "error: act_runner only exports these when its `cache.enabled` is true, and the"
        print --stderr "error: build passes `ignore-error=true`, so without this check every build would"
        print --stderr "error: silently recompile every dependency from scratch and still report success."
        exit 1
    }
    print "check-build-cache-health: gha cache credentials present; type=gha can reach the cache server"
}

def self-test []: nothing -> nothing {
    let healthy = "#7 importing cache manifest from gha:123\n#7 DONE 0.5s\n#18 [builder 1/4] COPY --from=planner /build/recipe.json recipe.json\n#18 CACHED\n#19 [builder 2/4] RUN cargo chef cook --release --recipe-path recipe.json\n#19 CACHED\n"
    let poisoned = "#7 importing cache manifest from gha:123\n#7 DONE 0.5s\n#18 [builder 1/4] COPY --from=planner /build/recipe.json recipe.json\n#18 CACHED\n#19 [builder 2/4] RUN cargo chef cook --release --recipe-path recipe.json\n#19 DONE 461.3s\n"
    let cold = "#18 [builder 1/4] COPY --from=planner /build/recipe.json recipe.json\n#18 DONE 0.1s\n#19 [builder 2/4] RUN cargo chef cook --release\n#19 DONE 400.0s\n"
    let evicted = "#7 importing cache manifest from gha:123\n#7 DONE 0.1s\n#11 [chef 3/3] RUN cargo install cargo-chef --locked\n#11 ERROR: blob sha256:fdb8980e723bbe84971d97be9b1b72eddbdc955f84fc67d90f8117077debe813: not found\n#18 [builder 1/4] COPY --from=planner /build/recipe.json recipe.json\n#18 CACHED\n#19 [builder 2/4] RUN cargo chef cook --release\n#19 CACHED\n"
    let first_build = "#18 [builder 1/4] COPY --from=planner /build/recipe.json recipe.json\n#18 DONE 0.1s\n#19 [builder 2/4] RUN cargo chef cook --release\n#19 DONE 400.0s\n"
    let export_failed = "#7 importing cache manifest from gha:123\n#7 DONE 0.1s\n#18 [builder 1/4] COPY --from=planner /build/recipe.json recipe.json\n#18 CACHED\n#19 [builder 2/4] RUN cargo chef cook --release\n#19 CACHED\n#29 exporting to GitHub Actions Cache\n#29 ERROR: failed to push cache blob: 500 Internal Server Error\n"

    let cases = [
        {log: $healthy, expect: 0, why: "a healthy warm build with a CACHED cook"}
        {log: $poisoned, expect: 1, why: "an unchanged recipe with a rebuilt cook"}
        {log: $cold, expect: 1, why: "a build that imported no cache manifest"}
        {log: $evicted, expect: 1, why: "an evicted cache blob on an otherwise warm build"}
        {log: $first_build, expect: 1, why: "a legitimately cold first build (warns, never fails)"}
        {log: $export_failed, expect: 1, why: "a cache export that failed and was swallowed by ignore-error"}
    ]
    let results = ($cases | each {|c|
        let w = (analyse $c.log)
        {why: $c.why, ok: (($w | length) == $c.expect), got: $w}
    })
    for r in $results {
        if $r.ok {
            print $"self-test ok: signal handles ($r.why)"
        } else {
            print --stderr $"self-test FAILED: signal mis-handles ($r.why): ($r.got | to nuon)"
        }
    }
    if ($results | any {|r| not $r.ok }) { exit 1 }
}

def main [
    --preflight   # assert the gha cache backend is usable at all; FATAL when it is not
    --log: string # analyse a captured buildx log and warn on cache damage
    --self-test   # prove the signal fires on damage and stays quiet on a healthy build
]: nothing -> nothing {
    if $self_test { self-test; return }
    if $preflight { preflight; return }
    if ($log | is-empty) {
        print --stderr "error: pass one of --preflight, --log <path>, --self-test"
        exit 2
    }

    let content = (try { open --raw $log | decode utf-8 } catch { null })
    if $content == null {
        # The log is the evidence; losing it is itself worth saying, but the image
        # is already built and correct, so it does not fail the publish.
        print $"::warning::build log ($log) is missing or unreadable; cache health could not be assessed."
        return
    }

    let warnings = (analyse $content)
    if ($warnings | is-empty) {
        print "check-build-cache-health: cache manifest imported, no evicted blobs, dependency layer reused"
        return
    }
    for w in $warnings { print $"::warning::cache health: ($w)" }
    print ""
    print "cache health warnings (BUNYIP-519). The published image is correct; the"
    print "build paid more than it should have. These do not fail the publish:"
    for w in $warnings { print $"  - ($w)" }
}
