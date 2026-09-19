#!/usr/bin/env nu

# PR-triggered CI secret-scope gate (BUNYIP-425).
#
# A `pull_request` run executes the workflow file, the npm lifecycle scripts and
# the test code from the PR HEAD, so every secret it can read is readable by
# anyone who can push a branch. The E2E suite therefore lives in a workflow that
# does not trigger on `pull_request` (`e2e.yml`: push to main + dispatch only),
# and the PR gate (`e2e-pr.yml`) holds only the two staging base URLs, which
# authenticate nothing.
#
# Three properties, mechanically enforced so the split cannot silently regress:
#   1. e2e.yml has no `pull_request` trigger.
#   2. e2e-pr.yml references no secret outside the base-URL allowlist.
#   3. every `npm ci` under .forgejo/workflows/ passes --ignore-scripts.
#
# A fourth and fifth property scan EVERY .forgejo/workflows/*.yml file, not
# just the two named above (BUNYIP-766, carried from the 2026-09-04 parity
# report F4): a `secrets: inherit` and an unpinned cross-repo reusable-workflow
# `uses:` are both invisible to properties 1-3, which match only the literal
# `secrets.<NAME>` form, and both hand a called workflow this repo's secrets on
# the strength of a ref this repo's history does not pin.
#   4. every `secrets: inherit` carries a justification.
#   5. every cross-repo reusable-workflow reference is pinned to a commit SHA,
#      or carries a justification.
# An exemption is a trailing `# secret-scope-ok: <reason>` marker on the
# finding's own line, so relying on `secrets: inherit` or on a mutable ref is a
# visible, reviewed decision rather than a silent gap.
#
# Usage: scripts/check-workflow-secrets.nu [workflows_dir]

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

# Cross-repo reusable-workflow call: org/repo/.forgejo|.github/workflows/name.yml@ref.
# A local call (`uses: ./...`) and an action reference (a URL, or
# `owner/repo@ref` with no workflows path) are both out of scope: only a call
# into ANOTHER repo's workflow file carries the risk this checks, since the
# target can change what it does, secrets included, without this repo's
# history recording it.
const REUSABLE_WORKFLOW_PATTERN = '^\s*uses:\s*(?<target>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.(forgejo|github)/workflows/[A-Za-z0-9_.-]+\.ya?ml)@(?<ref>\S+)\s*$'

const COMMIT_SHA_PATTERN = '^[0-9a-f]{40}$'

# The one way to keep a `secrets: inherit` or an unpinned ref: say why, in a
# trailing comment on the finding's own line.
const EXEMPTION = 'secret-scope-ok:'

def exempt [lines: list<string>, idx: int]: nothing -> bool {
    $lines | get $idx | str contains $EXEMPTION
}

# Properties 4 and 5, for one workflow file.
def check-workflow-scope [path: string]: nothing -> list<string> {
    let lines = (read-lines $path)
    mut problems = []
    for row in ($lines | enumerate) {
        let text = $row.item
        if ($text =~ '^\s*secrets:\s*inherit\s*$') and not (exempt $lines $row.index) {
            $problems = ($problems | append $"($path):($row.index + 1): `secrets: inherit` hands this job every secret the repo/org holds; justify it with a `# ($EXEMPTION) <reason>` marker naming the secret the called workflow needs.")
        }
        let m = ($text | parse --regex $REUSABLE_WORKFLOW_PATTERN)
        if ($m | is-not-empty) {
            let ref = ($m | get 0 | get ref)
            if (not ($ref =~ $COMMIT_SHA_PATTERN)) and not (exempt $lines $row.index) {
                $problems = ($problems | append $"($path):($row.index + 1): cross-repo reusable-workflow reference pinned to `($ref)`, not a commit SHA; a mutable ref can change what the call does, secrets included, without this repo's history recording it - pin to a SHA or justify with a `# ($EXEMPTION) <reason>` marker.")
            }
        }
    }
    $problems
}

def main [workflows_dir: string = ".forgejo/workflows"] {
    # Secrets the credential-free PR gate may name: deployment base URLs only.
    # Adding to this list means handing that secret to unreviewed PR code.
    let pr_secret_allowlist = ["E2E_STAGING_BASE_URL" "OIDC_ISSUER_STAGING"]

    let suite_workflow = $"($workflows_dir)/e2e.yml"
    let pr_workflow = $"($workflows_dir)/e2e-pr.yml"

    if ($workflows_dir | path type) != "dir" {
        print --stderr $"error: workflows dir not found: ($workflows_dir)"
        exit 2
    }

    for required in [$suite_workflow $pr_workflow] {
        if ($required | path type) != "file" {
            print --stderr $"error: expected workflow not found: ($required)"
            exit 2
        }
    }

    mut status = 0

    # 1. The full suite must not run on PR-authored content. Match the trigger
    # key only (a `pull_request` word inside a comment or an expression is fine).
    if (read-lines $suite_workflow | any {|l| $l =~ '^\s{0,4}pull_request:' }) {
        print --stderr $"error: ($suite_workflow) declares a pull_request trigger; the full suite resolves account/Stripe/TOTP secrets and must stay on push + workflow_dispatch \(BUNYIP-425)"
        $status = 1
    }

    # 2. The PR gate may reference nothing but the allowlisted base URLs.
    let allowlist_text = ($pr_secret_allowlist | str join "|")
    let referenced = (
        read-lines $pr_workflow
        | each {|l| $l | str replace --regex '#.*' '' }
        | str join "\n"
        | parse --regex 'secrets\.(?<name>[A-Za-z0-9_]+)'
        | get name
        | uniq
        | sort
    )
    for name in $referenced {
        if not ($name in $pr_secret_allowlist) {
            print --stderr $"error: ($pr_workflow) references secrets.($name); a pull_request-triggered job may only hold ($allowlist_text) \(BUNYIP-425)"
            $status = 1
        }
    }

    # 3. Dependency lifecycle scripts are attacker-authored too: never run them.
    let npm_hits = (
        grep-tree $workflows_dir 'npm ci( |$)'
        | where {|h| not ($h.text | str contains "--ignore-scripts") }
    )
    for hit in $npm_hits {
        print --stderr $"error: ($hit.file):($hit.line):($hit.text): 'npm ci' without --ignore-scripts \(BUNYIP-425)"
        $status = 1
    }

    # 4 and 5. Every workflow file, not just the two named above.
    let all_workflow_files = (glob $"($workflows_dir)/*.yml")
    let scope_problems = ($all_workflow_files | each {|f| check-workflow-scope $f } | flatten)
    for p in $scope_problems {
        print --stderr $"error: ($p) \(BUNYIP-766)"
        $status = 1
    }

    if $status == 0 {
        print $"workflow secret scope OK: no PR-triggered job holds a credential, all 'npm ci' ignore scripts, every 'secrets: inherit' and unpinned reusable-workflow ref across ($all_workflow_files | length) files is justified"
    }

    exit $status
}
