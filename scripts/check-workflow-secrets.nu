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

    if $status == 0 {
        print "workflow secret scope OK: no PR-triggered job holds a credential, all 'npm ci' ignore scripts"
    }

    exit $status
}
