#!/usr/bin/env nu

# Publish-trigger parity gate (BUNYIP-519).
#
# bunyip-api:latest and bunyip-web:latest are read as a matched pair, and they
# are only a pair if both build workflows fire on exactly the same pushes. When
# the two `paths:` lists were maintained separately they disagreed on 88 of the
# 139 merges that built anything, 63%, and `crates/**` was in the API list but
# not the web one even though bunyip-web depends on crates/web-kit.
#
# One shared filter fixes it: either both images build for a merge or neither
# does. Nothing fails at build time when the lists drift, so gate them.
#
# Usage:
#   scripts/check-publish-triggers.nu
#   scripts/check-publish-triggers.nu --self-test

const WORKFLOWS = [".forgejo/workflows/build-api.yml" ".forgejo/workflows/build-web.yml"]

# The `on.push` keys that decide WHETHER an image publishes. Every one of them
# must agree across the publish workflows.
const TRIGGER_KEYS = ["branches" "tags" "paths"]

# The e2e deploy gate resolves "which commit should staging be serving" by
# replaying the build trigger over `git log`, so it keeps its own copy of the
# path list. A copy that drifts either polls for a SHA the API never serves
# (hangs until the 10 minute timeout) or accepts a stale API, so gate it against
# the workflows rather than trusting the "keep in lock-step" comment.
const DEPLOY_GATE = "e2e/scripts/wait-for-deploy.mjs"

# `on.push` for one workflow, or null when the file is unreadable or has no push
# trigger at all.
def push-trigger [path: string]: nothing -> any {
    let doc = (try { open $path } catch { null })
    if $doc == null { return null }
    $doc | get -o "on" | get -o push
}

# The path list the e2e deploy gate replays, or null when it cannot be read.
# Comments are stripped first so an apostrophe in prose cannot look like a quote.
def deploy-gate-paths [path: string]: nothing -> any {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null { return null }
    let block = ($content | parse --regex '(?s)const BUILD_TRIGGER_PATHS = \[(?<body>.*?)\]' | get -o 0.body)
    if $block == null { return null }
    $block | lines | each {|l| $l | str replace --regex '//.*$' '' } | str join "\n"
          | parse --regex "'(?<p>[^']+)'" | get p
}

# A workflow path glob as a git pathspec: `crates/**` and `crates` select the
# same commits, and the deploy gate passes its entries straight to `git log`.
def as-pathspec []: list<string> -> list<string> {
    $in | each {|p| $p | str replace --regex '/\*\*$' '' } | sort
}

# Problems across the publish workflows and the deploy gate, as readable lines.
def check-parity [workflows: list<string>, deploy_gate: string]: nothing -> list<string> {
    mut problems = []
    let triggers = ($workflows | each {|w| { file: $w, push: (push-trigger $w) } })

    for t in $triggers {
        if $t.push == null {
            $problems = ($problems | append $"($t.file): missing, unreadable, or has no `on.push` trigger - the gate cannot prove the publish triggers match.")
        }
    }
    if ($problems | is-not-empty) { return $problems }

    let reference = ($triggers | first)
    for t in ($triggers | skip 1) {
        for key in $TRIGGER_KEYS {
            # Compare as sets: a reordered list is the same trigger. A missing
            # key is not the same as an empty one, so normalise to a list first.
            let a = ($reference.push | get -o $key | default [] | sort)
            let b = ($t.push | get -o $key | default [] | sort)
            if $a != $b {
                let only_a = ($a | where {|x| $x not-in $b })
                let only_b = ($b | where {|x| $x not-in $a })
                $problems = ($problems | append
                    $"on.push.($key) differs: ($reference.file) has ($only_a | to nuon) that ($t.file) lacks; ($t.file) has ($only_b | to nuon) that ($reference.file) lacks.")
            }
        }
    }
    if ($problems | is-not-empty) { return $problems }

    # The deploy gate must replay exactly the shared filter.
    let gate_paths = (deploy-gate-paths $deploy_gate)
    if $gate_paths == null {
        return [$"($deploy_gate): missing, unreadable, or has no BUILD_TRIGGER_PATHS array - the gate cannot prove the deploy gate replays the publish filter."]
    }
    let want = ($reference.push | get -o paths | default [] | as-pathspec)
    let got = ($gate_paths | as-pathspec)
    if $want != $got {
        let missing = ($want | where {|x| $x not-in $got })
        let extra = ($got | where {|x| $x not-in $want })
        $problems = ($problems | append
            $"($deploy_gate): BUILD_TRIGGER_PATHS does not replay the publish filter: missing ($missing | to nuon), unexpected ($extra | to nuon).")
    }
    $problems
}

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)

    let head = "name: x\non:\n  push:\n"
    let a_match = $"($dir)/a-match.yml"
    $"($head)    branches: [main]\n    tags: ['v*']\n    paths:\n      - 'p/**'\n      - 'q/**'\n" | save --force $a_match
    let b_match = $"($dir)/b-match.yml"
    $"($head)    branches: [main]\n    tags: ['v*']\n    paths:\n      - 'q/**'\n      - 'p/**'\n" | save --force $b_match

    let b_missing_path = $"($dir)/b-missing.yml"
    $"($head)    branches: [main]\n    tags: ['v*']\n    paths:\n      - 'p/**'\n" | save --force $b_missing_path

    let b_branch = $"($dir)/b-branch.yml"
    $"($head)    branches: [main, dev]\n    tags: ['v*']\n    paths:\n      - 'p/**'\n      - 'q/**'\n" | save --force $b_branch

    let b_tags = $"($dir)/b-tags.yml"
    $"($head)    branches: [main]\n    tags: ['v*', 'r*']\n    paths:\n      - 'p/**'\n      - 'q/**'\n" | save --force $b_tags

    let no_push = $"($dir)/no-push.yml"
    "name: x\non:\n  workflow_dispatch: {}\n" | save --force $no_push

    let gate_ok = $"($dir)/gate-ok.mjs"
    "const BUILD_TRIGGER_PATHS = [\n  'p', // p/**\n  'q', // the build's own trigger\n];\n" | save --force $gate_ok
    let gate_drifted = $"($dir)/gate-drifted.mjs"
    "const BUILD_TRIGGER_PATHS = [\n  'p',\n];\n" | save --force $gate_drifted
    let gate_extra = $"($dir)/gate-extra.mjs"
    "const BUILD_TRIGGER_PATHS = [\n  'p',\n  'q',\n  'r',\n];\n" | save --force $gate_extra

    let cases = [
        {files: [$a_match $b_match], gate: $gate_ok, expect: false, why: "identical filters listed in a different order"}
        {files: [$a_match $b_missing_path], gate: $gate_ok, expect: true, why: "a path present in one workflow and missing from the other"}
        {files: [$a_match $b_branch], gate: $gate_ok, expect: true, why: "differing branches"}
        {files: [$a_match $b_tags], gate: $gate_ok, expect: true, why: "differing tags"}
        {files: [$a_match $no_push], gate: $gate_ok, expect: true, why: "a workflow with no push trigger"}
        {files: [$a_match $"($dir)/absent.yml"], gate: $gate_ok, expect: true, why: "a missing workflow"}
        {files: [$a_match $b_match], gate: $gate_drifted, expect: true, why: "a deploy gate missing one of the filter paths"}
        {files: [$a_match $b_match], gate: $gate_extra, expect: true, why: "a deploy gate listing a path the filter does not"}
        {files: [$a_match $b_match], gate: $"($dir)/absent.mjs", expect: true, why: "a missing deploy gate"}
    ]
    let results = ($cases | each {|c|
        let problems = (check-parity $c.files $c.gate)
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
    --self-test # prove the gate rejects a drifted filter and passes a matching one, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let problems = (check-parity $WORKFLOWS $DEPLOY_GATE)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "The publish workflows must fire on exactly the same pushes (BUNYIP-519), so"
        print --stderr "that bunyip-api:latest and bunyip-web:latest always name the same commit."
        print --stderr "Either both images build for a merge or neither does. Keep one shared filter"
        print --stderr "in both files rather than one list per image."
        exit 1
    }

    print $"check-publish-triggers: ($WORKFLOWS | length) publish workflows declare identical push triggers, and ($DEPLOY_GATE) replays them"
}
