#!/usr/bin/env nu

# Workflow-shell gate (BUNYIP-489).
#
# Every `run:` step in `.forgejo/workflows/` executes under Nushell. The shell is
# declared once per job (`defaults.run.shell: nu {0}`) rather than per step, so a
# step added later cannot silently inherit the runner's default shell (Bash) and
# a reader never has to check the preceding line to know which shell a step runs
# under.
#
# Two properties, both required:
#   1. every job sets `defaults.run.shell: nu {0}`;
#   2. no step opts back out with a non-Nushell `shell:`.
#
# The `./scripts/check-*.sh` guards invoked from check.yml are external programs
# with their own shebang, so the calling shell does not change their behaviour;
# rewriting them in Nushell is tracked in BUNYIP-490.
#
# Usage: scripts/check-workflow-shell.nu [workflows_dir]
#        scripts/check-workflow-shell.nu --self-test

const NU_SHELL = "nu {0}"

# Problems found in one workflow file; an empty list means the file is compliant.
def check-workflow [path: string]: nothing -> list<string> {
    let doc = (do --ignore-errors { open --raw $path | from yaml })
    if $doc == null {
        return [$"($path): could not be parsed as YAML"]
    }
    let jobs = ($doc | get --optional jobs | default {})
    if ($jobs | is-empty) {
        # A file with no jobs would pass every check below vacuously.
        return [$"($path): declares no jobs"]
    }

    $jobs | transpose name job | each {|entry|
        let declared = ($entry.job | get --optional defaults.run.shell)
        let job_problems = if $declared == $NU_SHELL { [] } else {
            [$"($path): job `($entry.name)` must set `defaults.run.shell: ($NU_SHELL)`, found ($declared | to nuon)"]
        }
        let step_problems = (
            $entry.job
            | get --optional steps
            | default []
            | enumerate
            | each {|it|
                let shell = ($it.item | get --optional shell)
                let name = ($it.item | get --optional name | default $"step ($it.index)")
                if $shell != null and not ($shell | str starts-with "nu") {
                    [$"($path): job `($entry.name)` step `($name)` declares `shell: ($shell)`; every step runs under Nushell"]
                } else { [] }
            }
            | flatten
        )
        $job_problems | append $step_problems
    } | flatten
}

# Prove the gate rejects what it claims to reject. Runs in CI next to the real
# check, so a gate that silently stopped detecting anything fails the build.
def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)

    let missing_default = $"($dir)/missing-default.yml"
    "jobs:\n  build:\n    steps:\n      - name: Do a thing\n        run: echo hi\n" | save --force $missing_default

    let bash_step = $"($dir)/bash-step.yml"
    "jobs:\n  build:\n    defaults:\n      run:\n        shell: nu {0}\n    steps:\n      - name: Do a thing\n        shell: bash\n        run: echo hi\n" | save --force $bash_step

    let compliant = $"($dir)/compliant.yml"
    "jobs:\n  build:\n    defaults:\n      run:\n        shell: nu {0}\n    steps:\n      - name: Do a thing\n        run: print hi\n" | save --force $compliant

    let cases = [
        {file: $missing_default, expect_problems: true, why: "a job with no defaults.run.shell"}
        {file: $bash_step, expect_problems: true, why: "a step that declares shell: bash"}
        {file: $compliant, expect_problems: false, why: "a converted job"}
    ]
    let results = ($cases | each {|c|
        let problems = (check-workflow $c.file)
        {why: $c.why, ok: ((($problems | is-not-empty)) == $c.expect_problems), problems: $problems}
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
    workflows_dir: string = ".forgejo/workflows" # directory holding the Forgejo workflow files
    --self-test # prove the gate rejects a Bash step and accepts a converted one, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    if not ($workflows_dir | path exists) {
        print --stderr $"error: workflows directory not found: ($workflows_dir)"
        exit 2
    }
    let files = (glob $"($workflows_dir)/*.{yml,yaml}" | sort)
    if ($files | is-empty) {
        print --stderr $"error: no workflow files under ($workflows_dir)"
        exit 2
    }

    let problems = ($files | each {|f| check-workflow $f } | flatten)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr "error: every workflow job must declare `defaults: {run: {shell: nu {0}}}` and no step may opt out (BUNYIP-489)"
        exit 1
    }

    print $"check-workflow-shell: ($files | length) workflows run every step under Nushell"
}
