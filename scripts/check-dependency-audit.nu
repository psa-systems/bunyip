#!/usr/bin/env nu

# Audit Cargo.lock against the RustSec advisory database and fail on a
# vulnerability that no dated exception covers.
#
# Why this exists: BUNYIP-205 (security audit roll-up) flagged "No
# dependency-audit gate (cargo-audit / cargo-deny / npm audit) in CI" as still
# open. This guard is that gate (BUNYIP-905). Ported from rusty-links'
# scripts/check-dependency-audit.nu, which solved the identical problem there;
# only the exception-issue prefix (BUNYIP- instead of LINKS-) differs.
#
# Failure policy:
# - A vulnerability (the RustSec `vulnerabilities` list) fails the run, naming
#   the advisory id, the crate, the version and the patched range. These are the
#   findings that are normally one `cargo update --package <crate>` away, so
#   blocking is a fix instruction rather than a toll.
# - A warning (`unmaintained`, `unsound`, `yanked`, `notice`) is printed in full
#   and does not fail. Failing on them would block every unrelated PR until
#   someone wrote an exception for a crate this repo does not control.
#   `cargo audit --deny warnings` gives the stricter view on demand.
# - EXCEPTIONS suppress one advisory id each, until a stated date. Past that date
#   the exception stops holding and the run fails naming its issue, so an
#   acceptance cannot become permanent by neglect. An exception matching nothing
#   also fails, so the table cannot accumulate dead rows.
#
# The push/PR run (.forgejo/workflows/check.yml) and the weekly
# .forgejo/workflows/audit.yml run share this one policy. The schedule is not a
# stricter gate; it is the only thing that catches an advisory published against
# an unchanged Cargo.lock, which a push-triggered job never sees.
#
# Usage:
#   nu scripts/check-dependency-audit.nu --self-test
#   nu scripts/check-dependency-audit.nu
#   nu scripts/check-dependency-audit.nu --runner "docker compose --file compose.dev.yml run --rm --no-deps --env RUST_LOG=warn app"
#
# Exit codes:
# - 0: no vulnerability, or every one of them is covered by an exception still in date.
# - 1: a vulnerability with no exception, an expired or stale exception, a
#      malformed exception row, or a report that could not be read at all.
#
# A failure that is not a real advisory has to be diagnosable from the log. A
# guard that only printed "cargo audit printed something that is not JSON" and
# threw the stdout away would make a failed cargo-audit bootstrap, an empty
# stdout and a genuinely malformed report all read identically, with the only
# fix being a re-run by hand. The three are told apart below, and the stdout is
# printed, bounded to STDOUT_EXCERPT_LIMIT characters.

# Version requirement for the tool itself, not for the advisory database, which
# is fetched fresh on every run. Patch releases are taken; a major is not.
const AUDIT_VERSION_REQ = "^0.22"

# A failed bootstrap exits with this code and prints this marker, so it is reported as
# itself rather than as the unreadable report it would otherwise produce. Either signal
# is enough: a runner that rewrites the exit code still passes stderr through.
const BOOTSTRAP_EXIT = 90
const BOOTSTRAP_MARKER = "cargo-audit-bootstrap-failed"

# How much of an unreadable stdout to print. A full `cargo audit --json` report against
# this lockfile is hundreds of kilobytes and would bury the failure it is meant to expose.
const STDOUT_EXCERPT_LIMIT = 2000

# Advisories accepted for now, one row per advisory id. `issue` is the BUNYIP
# issue that tracks removing the row, `review_by` the date the acceptance stops
# holding. Both are checked, so neither can be left off.
const EXCEPTIONS = [
    {
        id: "RUSTSEC-2023-0071"
        package: "rsa"
        issue: "BUNYIP-905"
        review_by: "2027-10-09"
        reason: "No fixed version exists upstream. rsa is in Cargo.lock only through sqlx-mysql, and every sqlx consumer here (bunyip-api, bunyip-domain, bunyip-oci, bunyip-oidc) takes sqlx without the mysql feature, so nothing compiles it: `cargo tree --offline --workspace` matches no rsa or sqlx-mysql package."
    }
]

# `docker compose run --rm` gives every invocation its own container, so an
# install issued as a separate command is thrown away before the audit runs: when
# a runner fronts cargo, the two have to share one invocation. Binstall output
# goes to stderr to keep stdout pure JSON.
def audit-argv [prefix: list<string>]: nothing -> list<string> {
    if ($prefix | is-empty) { return ["cargo" "audit" "--json"] }
    let install = $"cargo binstall --no-confirm --locked cargo-audit@($AUDIT_VERSION_REQ)"
    let bootstrap = $"command -v cargo-audit >/dev/null || { ($install) >&2 || { echo ($BOOTSTRAP_MARKER) >&2; exit ($BOOTSTRAP_EXIT); }; }"
    $prefix | append ["sh" "-c" $"($bootstrap); cargo audit --json"]
}

# What arrived on stdout, bounded, saying so when it was cut. An empty stdout reads as
# `(empty)` rather than as a blank line, because "nothing arrived" and "something
# unreadable arrived" are different failures that would otherwise read identically.
def excerpt [raw: string]: nothing -> string {
    if ($raw | str trim | is-empty) { return "(empty)" }
    let len = ($raw | str length)
    if $len <= $STDOUT_EXCERPT_LIMIT { return $raw }
    $"($raw | str substring 0..<$STDOUT_EXCERPT_LIMIT)\n[... truncated: ($len) characters arrived on stdout, showing the first ($STDOUT_EXCERPT_LIMIT)]"
}

# Tell the three unreadable-report failures apart. `audit-argv` folds the bootstrap and
# the audit into one `sh -c` when a runner fronts cargo, so a failed `cargo binstall`
# would otherwise surface as a parse failure with no hint that nothing was ever
# installed. The bootstrap test runs first on purpose: a real bootstrap failure also
# leaves stdout empty, so the empty-stdout rule would otherwise swallow it.
def classify-failure [result: record, parsed: record]: nothing -> record {
    if ($result.exit_code == $BOOTSTRAP_EXIT) or ($result.stderr | str contains $BOOTSTRAP_MARKER) {
        return {
            kind: "bootstrap"
            reason: $"cargo-audit is not installed and `cargo binstall --no-confirm --locked cargo-audit@($AUDIT_VERSION_REQ)` failed, so the audit never started"
        }
    }
    if ($result.stdout | str trim | is-empty) {
        return {kind: "empty", reason: "cargo audit printed nothing at all on stdout"}
    }
    {kind: "parse", reason: $parsed.reason}
}

# Run a command through the runner prefix and collect both streams.
def run-through [argv: list<string>]: nothing -> record {
    let exe = ($argv | first)
    let args = ($argv | skip 1)
    do { run-external $exe ...$args } | complete
}

# cargo-audit ships on neither the dev image nor the CI runner image. With no
# runner in front, an install persists, so do it here: binstall when the image
# carries it (seconds), source build otherwise. CI caches the result with the
# rest of CARGO_HOME.
def ensure-audit [prefix: list<string>] {
    if ($prefix | is-not-empty) { return }
    if (run-through ["cargo" "audit" "--version"]).exit_code == 0 { return }

    print $"[check-dependency-audit] cargo-audit ($AUDIT_VERSION_REQ) is not installed; installing it"
    let has_binstall = (run-through ["cargo" "binstall" "--version"]).exit_code == 0
    let install = if $has_binstall {
        ["cargo" "binstall" "--no-confirm" "--locked" $"cargo-audit@($AUDIT_VERSION_REQ)"]
    } else {
        ["cargo" "install" "--locked" "--version" $AUDIT_VERSION_REQ "cargo-audit"]
    }
    print $"[check-dependency-audit] ($install | str join ' ')"
    let result = (run-through $install)
    if $result.exit_code != 0 {
        print --stderr "[check-dependency-audit] FAILED: could not install cargo-audit:"
        print --stderr $result.stdout
        print --stderr $result.stderr
        exit 1
    }
}

# cargo audit writes its progress to stderr and its report to stdout, but a
# runner prefix can print its own lines first, so start at the first brace.
def parse-report [raw: string]: nothing -> record {
    let start = ($raw | str index-of "{")
    if $start < 0 {
        return {ok: false, reason: "cargo audit printed no JSON object at all"}
    }
    let doc = (try { $raw | str substring $start.. | from json } catch { null })
    if $doc == null {
        return {ok: false, reason: "cargo audit printed something that is not JSON"}
    }
    if ($doc | get --optional vulnerabilities) == null {
        return {ok: false, reason: "the report has no `vulnerabilities` key, so its shape changed"}
    }
    {ok: true, doc: $doc}
}

# Flatten the report into one row per finding. `yanked` entries carry no
# advisory, so they are keyed by crate instead of by id.
def findings [doc: record]: nothing -> record {
    let vulns = (
        $doc.vulnerabilities
        | get --optional list
        | default []
        | each {|v|
            let fixed = ($v.versions | get --optional patched | default [])
            {
                id: $v.advisory.id
                package: $v.package.name
                version: $v.package.version
                title: $v.advisory.title
                patched: (if ($fixed | is-empty) { "none published" } else { $fixed | str join " OR " })
            }
        }
    )
    let warns = (
        $doc
        | get --optional warnings
        | default {}
        | items {|kind, rows|
            $rows | default [] | each {|w| {
                kind: $kind
                id: (if ($w.advisory | is-empty) { "no advisory id" } else { $w.advisory.id })
                package: $w.package.name
                version: $w.package.version
                title: (if ($w.advisory | is-empty) { $"($kind) release" } else { $w.advisory.title })
            }}
        }
        | flatten
    )
    {vulnerabilities: $vulns, warnings: $warns}
}

# An exception row that cannot be checked is as bad as no exception at all.
def malformed [row: record]: nothing -> list<string> {
    mut found = []
    if not ($row.id =~ '^RUSTSEC-\d{4}-\d{4}$') {
        $found = ($found | append $"exception `($row.id)` is not a RUSTSEC-YYYY-NNNN advisory id")
    }
    if not ($row.issue =~ '^BUNYIP-\d+$') {
        $found = ($found | append $"exception ($row.id) names `($row.issue)`, which is not a BUNYIP issue id, so nothing tracks removing it")
    }
    if ((try { $row.review_by | into datetime } catch { null }) == null) {
        $found = ($found | append $"exception ($row.id) has an unreadable review_by `($row.review_by)`")
    }
    $found
}

# Every way the audit is a failure: an uncovered vulnerability, an exception past
# its date, an exception covering nothing, an unreadable exception row.
def violations [report: record, exceptions: list<any>, today: datetime]: nothing -> list<string> {
    mut found = ($exceptions | each {|row| malformed $row} | flatten)
    if ($found | is-not-empty) { return $found }

    let ids = (if ($report.vulnerabilities | is-empty) { [] } else { $report.vulnerabilities | get id })

    for row in $exceptions {
        if $row.id not-in $ids {
            $found = ($found | append $"exception ($row.id) covers no reported advisory, so it is stale: delete the row \(($row.issue))")
            continue
        }
        if ($row.review_by | into datetime) < $today {
            $found = ($found | append $"exception ($row.id) for `($row.package)` expired on ($row.review_by): re-decide it in ($row.issue) and move the date, or fix the advisory")
        }
    }

    let live = (
        $exceptions
        | where {|row| ($row.review_by | into datetime) >= $today}
        | each {|row| $row.id}
    )
    for v in $report.vulnerabilities {
        if $v.id not-in $live {
            $found = ($found | append $"($v.id): `($v.package) ($v.version)` is vulnerable \(($v.title)). Patched: ($v.patched)")
        }
    }

    $found
}

def sample-report []: nothing -> record {
    {
        vulnerabilities: {
            found: true
            count: 2
            list: [
                {
                    advisory: {id: "RUSTSEC-2023-0071", package: "rsa", title: "Marvin Attack"}
                    versions: {patched: [], unaffected: []}
                    package: {name: "rsa", version: "0.9.10"}
                }
                {
                    advisory: {id: "RUSTSEC-2026-0258", package: "h2", title: "h2 unbounded empty DATA frames"}
                    versions: {patched: [">=0.4.16"], unaffected: []}
                    package: {name: "h2", version: "0.4.13"}
                }
            ]
        }
        warnings: {
            unsound: [
                {
                    kind: "unsound"
                    package: {name: "anyhow", version: "1.0.102"}
                    advisory: {id: "RUSTSEC-2026-0190", package: "anyhow", title: "Unsoundness in Error::downcast_mut()"}
                }
            ]
            yanked: [
                {kind: "yanked", package: {name: "spin", version: "0.9.8"}, advisory: null}
            ]
        }
    }
}

def expect-rejected [label: string, report: record, exceptions: list<any>, today: datetime] {
    if (violations $report $exceptions $today | is-empty) {
        print --stderr $"[check-dependency-audit] SELF-TEST FAILED: ($label) was accepted."
        exit 1
    }
}

# Prove the classifier still fails on each shape it exists to fail on. Without
# it a drifted parser reports "no vulnerabilities" for every run, which is the
# same blindness one level up that this guard exists to remove.
def run-self-test [] {
    let today = ("2026-08-24" | into datetime)
    let parsed = (parse-report ("Creating container\n" + (sample-report | to json)))
    if not $parsed.ok {
        print --stderr $"[check-dependency-audit] SELF-TEST FAILED: a well-formed report was rejected: ($parsed.reason)"
        exit 1
    }
    let report = (findings $parsed.doc)
    if ($report.vulnerabilities | length) != 2 or ($report.warnings | length) != 2 {
        print --stderr $"[check-dependency-audit] SELF-TEST FAILED: the parser no longer reads the report shape; it found ($report.vulnerabilities | length) vulnerabilities and ($report.warnings | length) warnings, expected 2 and 2."
        exit 1
    }
    if ($report.vulnerabilities | where id == "RUSTSEC-2023-0071" | get patched.0) != "none published" {
        print --stderr "[check-dependency-audit] SELF-TEST FAILED: an empty patched list no longer reads as `none published`."
        exit 1
    }

    let both = [
        {id: "RUSTSEC-2023-0071", package: "rsa", issue: "BUNYIP-56", review_by: "2027-02-24", reason: "x"}
        {id: "RUSTSEC-2026-0258", package: "h2", issue: "BUNYIP-56", review_by: "2027-02-24", reason: "x"}
    ]
    let accepted = (violations $report $both $today)
    if ($accepted | is-not-empty) {
        print --stderr $"[check-dependency-audit] SELF-TEST FAILED: fully excepted findings were rejected: ($accepted | str join '; ')"
        exit 1
    }

    expect-rejected "an uncovered vulnerability" $report ($both | first 1) $today
    expect-rejected "an expired exception" $report ($both | each {|r| $r | update review_by "2026-08-23"}) $today
    expect-rejected "an exception covering nothing" $report ($both | append {id: "RUSTSEC-2020-0001", package: "ghost", issue: "BUNYIP-56", review_by: "2027-02-24", reason: "x"}) $today
    expect-rejected "an exception naming no issue" $report ($both | each {|r| $r | update issue "later"}) $today
    expect-rejected "an exception with an unreadable date" $report ($both | each {|r| $r | update review_by "whenever"}) $today
    expect-rejected "an exception with a made-up advisory id" $report ($both | each {|r| $r | update id "RUSTSEC-BAD"}) $today

    # Warnings are reported, never fatal: a report holding only warnings passes.
    let warn_only = (findings {vulnerabilities: {found: false, count: 0, list: []}, warnings: ($parsed.doc | get warnings)})
    if (violations $warn_only [] $today | is-not-empty) {
        print --stderr "[check-dependency-audit] SELF-TEST FAILED: warnings alone failed the run."
        exit 1
    }

    # An unreadable report must fail rather than read as an empty one.
    for bad in ["" "no json here" "{\"database\": {}}"] {
        if (parse-report $bad).ok {
            print --stderr $"[check-dependency-audit] SELF-TEST FAILED: `($bad)` was accepted as a report."
            exit 1
        }
    }

    # A runner gets one container per invocation, so the bootstrap and the audit
    # must stay in the same one or the install is discarded before it is used.
    let fronted = (audit-argv ["docker" "run" "app"] | last)
    if not (($fronted | str contains "binstall") and ($fronted | str contains "cargo audit --json")) {
        print --stderr $"[check-dependency-audit] SELF-TEST FAILED: a fronted run no longer bootstraps and audits in one invocation: ($fronted)"
        exit 1
    }
    if not (($fronted | str contains $BOOTSTRAP_MARKER) and ($fronted | str contains $"exit ($BOOTSTRAP_EXIT)")) {
        print --stderr $"[check-dependency-audit] SELF-TEST FAILED: a fronted run no longer marks a failed bootstrap, so a failed install would surface as an unreadable report instead of as itself: ($fronted)"
        exit 1
    }

    # The cases above prove an unreadable report is rejected. These prove the
    # rejection is legible: it says which of the three failures it was and prints
    # what actually arrived, which is otherwise the evidence a guard would discard.
    let garbled = '{"database":{"advisory-count":800},"lockfile"'
    let garbled_failure = (classify-failure {exit_code: 1, stdout: $garbled, stderr: ""} (parse-report $garbled))
    if $garbled_failure.kind != "parse" {
        print --stderr $"[check-dependency-audit] SELF-TEST FAILED: a malformed report was classified `($garbled_failure.kind)`, not `parse`."
        exit 1
    }
    if not ((excerpt $garbled) | str contains $garbled) {
        print --stderr $"[check-dependency-audit] SELF-TEST FAILED: an unparsed stdout is not reported with its content: (excerpt $garbled)"
        exit 1
    }

    # An empty stdout is its own failure, and reads as `(empty)` rather than as a blank
    # line. The fixture carries a non-bootstrap exit code so it reaches this rule.
    let empty_failure = (classify-failure {exit_code: 101, stdout: "", stderr: "error: no such command: `audit`"} (parse-report ""))
    if $empty_failure.kind != "empty" {
        print --stderr $"[check-dependency-audit] SELF-TEST FAILED: an empty stdout was classified `($empty_failure.kind)`, not `empty`."
        exit 1
    }
    for blank in ["" "   " "\n\n"] {
        if (excerpt $blank) != "(empty)" {
            print --stderr $"[check-dependency-audit] SELF-TEST FAILED: an empty stdout is not reported as `\(empty)`: (excerpt $blank)"
            exit 1
        }
    }

    # A failed bootstrap is reported as itself, by exit code and by marker separately so
    # neither signal is carried by the other. Both fixtures leave stdout empty, which is
    # what a real bootstrap failure leaves, so this also proves the bootstrap rule wins
    # over the empty-stdout rule rather than being shadowed by it.
    for fixture in [
        {exit_code: $BOOTSTRAP_EXIT, stdout: "", stderr: "error: could not download cargo-audit"}
        {exit_code: 1, stdout: "", stderr: $"error: could not download cargo-audit\n($BOOTSTRAP_MARKER)"}
    ] {
        let boot = (classify-failure $fixture (parse-report ""))
        if $boot.kind != "bootstrap" {
            print --stderr $"[check-dependency-audit] SELF-TEST FAILED: a bootstrap failure signalled by exit ($fixture.exit_code) was classified `($boot.kind)`, not `bootstrap`."
            exit 1
        }
        if not ($boot.reason | str contains "cargo binstall") {
            print --stderr $"[check-dependency-audit] SELF-TEST FAILED: a bootstrap failure does not name the install command: ($boot.reason)"
            exit 1
        }
    }

    # A huge report is cut, and says it was cut.
    let huge = (1..($STDOUT_EXCERPT_LIMIT * 2) | each {|| "x"} | str join)
    let cut = (excerpt $huge)
    if not ($cut | str contains "truncated") {
        print --stderr "[check-dependency-audit] SELF-TEST FAILED: an oversized stdout was not reported as truncated."
        exit 1
    }
    if ($cut | str length) >= ($huge | str length) {
        print --stderr $"[check-dependency-audit] SELF-TEST FAILED: an oversized stdout was not bounded; ($huge | str length) characters in, ($cut | str length) out."
        exit 1
    }

    print "[check-dependency-audit] SELF-TEST OK: an uncovered vulnerability, an expired, stale, untracked, undated or malformed exception and an unreadable report are all rejected; a covered finding and a warning-only report are not; and an unreadable report is reported legibly, with its stdout bounded and truncation stated, an empty stdout named as empty, and a failed cargo-audit bootstrap named as a bootstrap failure rather than a parse failure."
}

export def main [
    --runner: string = "" # command that fronts `cargo`, e.g. a `docker compose run` wrapper
    --self-test # check the guard still detects an uncovered advisory, then exit
] {
    if $self_test {
        run-self-test
        return
    }

    if not ("Cargo.lock" | path exists) {
        print --stderr "[check-dependency-audit] FAILED: run this from the repository root."
        exit 1
    }

    let prefix = ($runner | split row --regex '\s+' | where {|part| $part != ""})
    ensure-audit $prefix

    let argv = (audit-argv $prefix)
    print $"[check-dependency-audit] ($argv | str join ' ')"
    let result = (run-through $argv)
    if ($result.stderr | str trim | is-not-empty) {
        print --stderr $result.stderr
    }

    let parsed = (parse-report $result.stdout)
    if not $parsed.ok {
        let failure = (classify-failure $result $parsed)
        print --stderr $"[check-dependency-audit] FAILED: ($failure.reason), and it exited ($result.exit_code). Nothing was audited."
        print --stderr "[check-dependency-audit] stdout, which is what it had to read the report from:"
        print --stderr (excerpt $result.stdout)
        if $failure.kind == "bootstrap" {
            print --stderr "[check-dependency-audit] The audit itself never started, so this is not an advisory. A fresh cargo volume that has not installed cargo-audit yet, or an unreachable binstall, produces this. Re-run once the cache is seeded."
        }
        exit 1
    }

    let report = (findings $parsed.doc)
    let crates = ($parsed.doc | get --optional lockfile.dependency-count | default "an unknown number of")
    print $"[check-dependency-audit] scanned ($crates) crates in Cargo.lock against ($parsed.doc | get --optional database.advisory-count | default 0) advisories"

    if ($report.warnings | is-not-empty) {
        print $"[check-dependency-audit] ($report.warnings | length) warnings, none of which fail this run:"
        print ($report.warnings | select kind id package version title)
    }
    if ($report.vulnerabilities | is-not-empty) {
        print $"[check-dependency-audit] ($report.vulnerabilities | length) vulnerabilities:"
        print ($report.vulnerabilities | select id package version patched title)
    }

    let found = (violations $report $EXCEPTIONS (date now))
    if ($found | is-not-empty) {
        print --stderr "[check-dependency-audit] FAILED:"
        for problem in $found {
            print --stderr $"  - ($problem)"
        }
        print --stderr ""
        print --stderr "Fix it by taking the patched version (`cargo update --package <crate>`). If there is no fix, file a BUNYIP issue for the acceptance and add a row to EXCEPTIONS in this script naming that issue and the date the acceptance stops holding. Do not widen the policy."
        exit 1
    }

    let excepted = ($EXCEPTIONS | length)
    print $"[check-dependency-audit] OK: no unaccepted vulnerability. ($excepted) accepted by a dated exception, ($report.warnings | length) warnings reported."
}
