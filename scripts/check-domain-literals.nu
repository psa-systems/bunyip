#!/usr/bin/env nu

# Hard-coded-hostname gate for migrations (BUNYIP-861).
#
# BUNYIP-858 shipped a staging host inside
# `bunyip-api/migrations/20260926000040_mokosh_apps_backchannel_logout.sql`
# unnoticed. The migration files are immutable by BUNYIP-293 (sqlx checksums
# the file bytes; editing one breaks every deployed database), so the fix is
# not to rewrite history on the committed ones but to stop any new migration
# from carrying a hard-coded hostname: configuration-driven seeding is the
# intended pattern (BUNYIP-862 extends the startup upsert path to cover the
# fields the already-committed migrations seeded).
#
# What this gate does:
#   - Scans every `*.sql` file under `bunyip-api/migrations`.
#   - Fails on a line carrying a quoted hostname literal of the form
#     `'...https?://<host>...'` or a bare `<host>.<tld>` inside a quoted
#     string, UNLESS the host is a reserved placeholder (`example.com`,
#     `example.net`, `example.org`, `example.test`, `*.example`, `*.test`,
#     `*.localhost`) OR the line carries a `-- domain-literal-ok: <reason>`
#     marker (SQL comment on the same line) with a non-empty reason.
#   - Allowlists by filename the migrations that already carry hostnames on
#     `main` at the time this gate was added. Each allowlisted file is
#     listed explicitly with the issue that seeded it, so a reader can trace
#     the exception.
#
# What this gate deliberately does NOT do (yet):
#   - Scan Rust source under `bunyip-api/src`, `bunyip-web/src`, `crates/`.
#     That scope is still in BUNYIP-861 but needs `#[cfg(test)]` block
#     detection and inline markers for ~130 test-file occurrences; shipped
#     as a follow-up pass. The migration half ships first because it closes
#     the exact hole BUNYIP-858 fell into.
#
# Usage:
#   scripts/check-domain-literals.nu
#   scripts/check-domain-literals.nu --self-test

const MIGRATION_DIR = "bunyip-api/migrations"

# The six migrations already on `main` at 8451f1c7 that seed per-environment
# hostnames. BUNYIP-862 reseeds these fields from configuration at startup;
# the migration bytes themselves must stay unchanged by BUNYIP-293.
const RESIDUAL_ALLOWLIST = [
    "20260603000010_register_mokosh_apps_and_drillmark_oidc_clients.sql"
    "20260603000020_seed_mokosh_hosted_application.sql"
    "20260604000010_seed_drillmark_hosted_application.sql"
    "20260618032217_register_lets_chat_oidc_client.sql"
    "20260713000020_add_application_release_notes_url.sql"
    "20260926000040_mokosh_apps_backchannel_logout.sql"
]

# A hostname literal inside a single-quoted SQL string. Catches either a
# full URL (`'https://...'`) or a bare FQDN ending in `.<tld>` with at
# least two letters. Reserved placeholders are filtered out after the
# match, so a line carrying only `example.com` passes.
const HOSTNAME_PATTERN = "'[^']*(https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}|\\b[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\\.[a-zA-Z]{2,})[^']*'"

# Reserved host suffixes that always pass. A matching host is a documentation
# placeholder, not a configured endpoint.
const RESERVED_SUFFIXES = [
    "example.com"
    "example.net"
    "example.org"
    "example.test"
    ".example"
    ".test"
    ".localhost"
]

const EXEMPTION = "domain-literal-ok:"

def is-reserved [host: string]: nothing -> bool {
    mut hit = false
    for s in $RESERVED_SUFFIXES {
        if ($host == $s) or ($host | str ends-with $s) {
            $hit = true
        }
    }
    $hit
}

def strip-scheme [h: string]: nothing -> string {
    if ($h | str starts-with "https://") {
        $h | str replace "https://" ""
    } else if ($h | str starts-with "http://") {
        $h | str replace "http://" ""
    } else {
        $h
    }
}

def extract-hosts [text: string]: nothing -> list<string> {
    # One row per host match; drops reserved placeholders.
    let candidates = ($text | parse --regex $HOSTNAME_PATTERN)
    if ($candidates | is-empty) { return [] }
    $candidates
    | get capture0
    | each {|h| strip-scheme $h }
    | each {|h| $h | split row "/" | first }
    | where {|h| not (is-reserved $h) }
}

def exemption-reason [text: string]: nothing -> string {
    # Returns the trimmed reason after `domain-literal-ok:` or "" when absent
    # or when the reason is empty (empty reasons are a failure).
    let parts = ($text | split row $EXEMPTION)
    if ($parts | length) < 2 { return "" }
    $parts | skip 1 | first | str trim
}

def check-migration [path: string]: nothing -> list<string> {
    let name = ($path | path basename)
    if ($name in $RESIDUAL_ALLOWLIST) { return [] }

    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): not readable; the gate cannot prove no hostname is seeded."]
    }

    mut problems = []
    for row in ($content | lines | enumerate) {
        let text = $row.item
        let hosts = (extract-hosts $text)
        if ($hosts | is-empty) { continue }
        let reason = (exemption-reason $text)
        if ($reason | is-empty) {
            let joined = ($hosts | str join ", ")
            $problems = ($problems | append $"($path):($row.index + 1): seeds hostname literal \(($joined)\) - move to configuration \(BUNYIP-862\) or justify with a `-- domain-literal-ok: <reason>` marker on this line.")
        }
    }
    $problems
}

def scan-tree []: nothing -> list<string> {
    let migrations = (try { ls $"($MIGRATION_DIR)/*.sql" | get name } catch { [] })
    mut all_problems = []
    for m in $migrations {
        let probs = (check-migration $m)
        $all_problems = ($all_problems | append $probs)
    }
    $all_problems
}

def write-fixture [dir: string, name: string, body: string]: nothing -> string {
    let path = $"($dir)/($name)"
    $body | save --force $path
    $path
}

def self-test []: nothing -> nothing {
    mut ok = true

    let dir = (mktemp --directory --tmpdir)

    # Case 1: allowlisted migration carrying a hostname passes.
    let allowlisted = (write-fixture $dir "20260618032217_register_lets_chat_oidc_client.sql" "INSERT INTO foo VALUES ('https://chat.a8n.systems');\n")
    let r1 = (check-migration $allowlisted)
    if ($r1 | is-empty) {
        print "self-test ok: allowlisted migration carrying a hostname passes"
    } else {
        print --stderr $"self-test FAILED: allowlisted migration flagged: ($r1 | to nuon)"
        $ok = false
    }

    # Case 2: non-allowlisted migration with a hostname fails.
    let hostname_mig = (write-fixture $dir "20260101000010_hostname_seed.sql" "INSERT INTO foo VALUES ('https://api.a8n.run/callback');\n")
    let r2 = (check-migration $hostname_mig)
    if ($r2 | is-empty) {
        print --stderr "self-test FAILED: non-allowlisted hostname seed slipped past the gate"
        $ok = false
    } else {
        print "self-test ok: a non-allowlisted hostname seed fails the gate"
    }

    # Case 3: reserved placeholder passes.
    let placeholder = (write-fixture $dir "20260101000020_placeholder.sql" "INSERT INTO foo VALUES ('https://host.example.com/callback');\n")
    let r3 = (check-migration $placeholder)
    if ($r3 | is-empty) {
        print "self-test ok: reserved placeholder host passes"
    } else {
        print --stderr $"self-test FAILED: reserved placeholder flagged: ($r3 | to nuon)"
        $ok = false
    }

    # Case 4: inline exemption marker passes when it carries a reason.
    let exempted = (write-fixture $dir "20260101000030_exempted.sql" "INSERT INTO foo VALUES ('https://api.a8n.run/x'); -- domain-literal-ok: integration test fixture host\n")
    let r4 = (check-migration $exempted)
    if ($r4 | is-empty) {
        print "self-test ok: a hostname with an inline reasoned marker passes"
    } else {
        print --stderr $"self-test FAILED: inline exemption flagged: ($r4 | to nuon)"
        $ok = false
    }

    # Case 5: inline exemption marker with a blank reason still fails.
    let blank_reason = (write-fixture $dir "20260101000040_blank_reason.sql" "INSERT INTO foo VALUES ('https://api.a8n.run/x'); -- domain-literal-ok:\n")
    let r5 = (check-migration $blank_reason)
    if ($r5 | is-empty) {
        print --stderr "self-test FAILED: blank exemption reason slipped past the gate"
        $ok = false
    } else {
        print "self-test ok: a blank exemption reason fails the gate"
    }

    # Case 6: tree scan agrees that the real tree passes (every seed is on
    # the allowlist or placeholder-valued).
    let tree = (scan-tree)
    if ($tree | is-empty) {
        print "self-test ok: the real migrations tree is clean"
    } else {
        print --stderr $"self-test FAILED: the real tree flagged: ($tree | str join ($'\n ' + ''))"
        $ok = false
    }

    rm --recursive $dir
    if not $ok { exit 1 }
}

def main [
    --self-test # prove the gate catches each failure shape and agrees the real tree passes
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let problems = (scan-tree)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $p }
        print --stderr ""
        print --stderr "Hostnames belong in configuration, not migrations. See BUNYIP-862 for the"
        print --stderr "startup-upsert pattern, or `-- domain-literal-ok: <reason>` for a justified"
        print --stderr "one-off on the same line as the literal."
        exit 1
    }

    let n = ($RESIDUAL_ALLOWLIST | length)
    print $"check-domain-literals: scanned ($MIGRATION_DIR); ($n) immutable migrations allowlisted, no new hostname literal found."
}
