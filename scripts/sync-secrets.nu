#!/usr/bin/env nu

# sync-secrets.nu - render bunyip's file-based secrets from Infisical (BUNYIP-504).
#
# Purpose:
#   compose.yml mounts every application secret from a file under ./secrets/ and
#   the api reads it through the {NAME}_FILE convention (BUNYIP-38). This script
#   SYNCS those files from Infisical rather than fetching at runtime, so a
#   bunyip-api restart never depends on Infisical being reachable and no secret
#   ever re-enters the process environment.
#
# Usage:
#   ./scripts/sync-secrets.nu [--environment prod|staging] [--dry-run]  (repo root)
#   ./scripts/sync-secrets.nu --self-test        (prove the write rules, no CLI needed)
#
#   Nushell reserves `env` as a builtin variable name, so the flag here is
#   `--environment` (short `-e`). `just sync-secrets` accepts the shorter
#   `--env` spelling and translates it.
#
# Authentication:
#   An already-exported INFISICAL_TOKEN short-circuits the login. Otherwise the
#   script logs in with a machine identity via Universal Auth, reading
#   INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET from the environment. Neither
#   present is a hard error naming the missing variable.
#
# CLI calls (no direct REST, per the tooling-gap rule):
#   infisical login --method=universal-auth --client-id=... --client-secret=... --plain --silent
#   infisical secrets get <KEY> --path=/bunyip/app --env=<env> --plain --silent
#   One `secrets get` per mapped key: it is the form already documented in
#   docs/e2e.md, and a per-key call is what makes "key MISSING_KEY is absent"
#   an exact error rather than a diff against a bulk dump. Keys in the folder
#   that the table below does not map are never read and never written.
#
# Mapping rule: the Infisical key is the env var name the api reads, i.e. the
#   {NAME} of the {NAME}_FILE entry in compose.yml. --self-test re-derives the
#   whole table from compose.yml, so a new compose secret fails CI until it is
#   mapped here.
#
# Never printed: a secret value, in any mode. The plan table carries key, file
#   and action columns only.
#
# Out of scope: ./secrets/oidc/*.pem. Signing keys are generated out of band.
#
# Requires: nu, chmod, mv, and the `infisical` CLI (except under --self-test).

# Infisical folder holding the core application secrets, one per environment.
const FOLDER = "/bunyip/app"

# Environment slugs the Infisical project defines.
const ENVIRONMENTS = ["staging" "prod"]

# Infisical key -> ./secrets/<file>. `allow_empty` marks the secrets whose empty
# file means "feature not configured" per the compose.yml header; the rest must
# carry a value or the run aborts.
const SECRET_MAP = [
    {key: "POSTGRES_PASSWORD", file: "postgres_password", allow_empty: false}
    {key: "DATABASE_URL", file: "database_url", allow_empty: false}
    {key: "JWT_SECRET", file: "jwt_secret", allow_empty: false}
    {key: "APP_ENCRYPTION_KEY", file: "app_encryption_key", allow_empty: false}
    # BUNYIP-360: empty pair = RLS inactive. Empty is honoured but reported.
    {key: "BUNYIP_APP_PASSWORD", file: "bunyip_app_password", allow_empty: true}
    {key: "APP_DATABASE_URL", file: "app_database_url", allow_empty: true}
    {key: "SETUP_DEFAULT_ADMIN", file: "setup_default_admin", allow_empty: true}
    {key: "FORGEJO_API_TOKEN", file: "forgejo_api_token", allow_empty: true}
    {key: "BUNYIP_UPDATE_CHECK_TOKEN", file: "update_check_token", allow_empty: true}
]

# ---------------------------------------------------------------------------
# Planning and writing (Infisical-free, so --self-test can exercise all of it)
# ---------------------------------------------------------------------------

# What each mapped secret needs. Carries no secret value, so the caller can
# print the result verbatim.
def plan [secrets_dir: string, values: record]: nothing -> table {
    $SECRET_MAP | each {|m|
        let path = $"($secrets_dir)/($m.file)"
        let wanted = ($values | get $m.key)
        let current = (if ($path | path type) == "file" {
            open --raw $path | decode utf-8
        } else { null })
        let action = if $current == null {
            "create"
        } else if $current == $wanted {
            "unchanged"
        } else {
            "update"
        }
        {key: $m.key, file: $m.file, path: $path, action: $action, empty: ($wanted | is-empty)}
    }
}

# Every reason the fetched values cannot be written, as human-readable lines.
# An empty list means the run may proceed.
def validate [values: record]: nothing -> list<string> {
    $SECRET_MAP | each {|m|
        if $m.key not-in $values {
            [$"key ($m.key) is absent from Infisical ($FOLDER); ./secrets/($m.file) needs it"]
        } else if (($values | get $m.key) | is-empty) and (not $m.allow_empty) {
            [$"key ($m.key) is empty in Infisical ($FOLDER); ./secrets/($m.file) must be non-empty"]
        } else {
            []
        }
    } | flatten
}

# Write one secret atomically at mode 0400. The temp file lives in the target
# directory so the rename stays on one filesystem; the destination is made
# writable first so `mv` never stops to ask, and the renamed file keeps the temp
# file's 0400 mode. An unchanged value is not rewritten, so mtimes stay put.
def write-secret [row: record, value: string] {
    if $row.action == "unchanged" { return }
    let tmp = $"($row.path).tmp"
    if ($tmp | path type) == "file" { rm $tmp }
    $value | save --raw $tmp
    ^chmod 0400 $tmp
    if ($row.path | path type) == "file" { ^chmod 0600 $row.path }
    ^mv $tmp $row.path
}

# What the run says to the operator. Built from the plan alone, so it cannot
# carry a secret value; --self-test asserts exactly that.
def report-lines [rows: table, dry_run: bool]: nothing -> list<string> {
    let changing = ($rows | where action != "unchanged" | length)
    let notes = (
        $rows | where empty | each {|r|
            $"note: ($r.file) is empty in Infisical - the feature it configures stays off"
        }
    )
    let summary = if $dry_run {
        $"dry run: ($changing) of ($rows | length) files would change, nothing was written"
    } else {
        $"synced ($rows | length) secrets, ($changing) changed"
    }
    [($rows | select key file action | table | into string)] | append $notes | append ["" $summary]
}

# Apply a plan to disk (or describe it under --dry-run) and report.
def apply-plan [rows: table, values: record, dry_run: bool] {
    if not $dry_run {
        for row in $rows {
            write-secret $row ($values | get $row.key)
        }
    }
    for line in (report-lines $rows $dry_run) { print $line }
}

# ---------------------------------------------------------------------------
# Infisical
# ---------------------------------------------------------------------------

# An exported INFISICAL_TOKEN wins; otherwise log in with the machine identity.
def infisical-token []: nothing -> string {
    let existing = ($env | get --optional INFISICAL_TOKEN | default "")
    if ($existing | is-not-empty) { return $existing }

    for var in ["INFISICAL_CLIENT_ID" "INFISICAL_CLIENT_SECRET"] {
        if (($env | get --optional $var | default "") | is-empty) {
            print --stderr $"error: ($var) is not set. Export INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET for the bunyip machine identity, or export an INFISICAL_TOKEN obtained out of band. See docs/secrets-infisical.md."
            exit 2
        }
    }

    let result = (
        ^infisical login --method=universal-auth --client-id=($env.INFISICAL_CLIENT_ID) --client-secret=($env.INFISICAL_CLIENT_SECRET) --plain --silent
        | complete
    )
    if $result.exit_code != 0 {
        print --stderr $"error: infisical login failed \(exit ($result.exit_code)): ($result.stderr | str trim)"
        exit 1
    }
    let token = ($result.stdout | str trim)
    if ($token | is-empty) {
        print --stderr "error: infisical login returned an empty token"
        exit 1
    }
    $token
}

# Fetch every mapped key. A key the CLI cannot resolve is omitted from the
# result so `validate` can name it; nothing is written before that check runs.
def fetch-secrets [env_slug: string, token: string]: nothing -> record {
    mut values = {}
    for m in $SECRET_MAP {
        let result = (
            with-env {INFISICAL_TOKEN: $token} {
                ^infisical secrets get $m.key --path=($FOLDER) --env=($env_slug) --plain --silent | complete
            }
        )
        if $result.exit_code != 0 { continue }
        # --plain terminates the value with a newline; strip exactly that one.
        $values = ($values | insert $m.key ($result.stdout | str replace --regex '\n$' ""))
    }
    $values
}

# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def assert [ok: bool, why: string]: nothing -> bool {
    if $ok {
        print $"self-test ok: ($why)"
    } else {
        print --stderr $"self-test FAILED: ($why)"
    }
    $ok
}

# The octal mode of a file, e.g. "0400".
def mode-of [path: string]: nothing -> string {
    ^stat --format=%04a $path | str trim
}

# Prove the write rules hold, without an Infisical round trip: the table matches
# compose.yml, files land at 0400, a no-op re-run touches no mtime, a missing or
# empty-but-required key aborts, and no mode ever prints a secret value.
def self-test []: nothing -> nothing {
    mut ok = []

    # 1. The mapping table is exactly the compose.yml `secrets:` block, and each
    #    Infisical key is the {NAME} of that secret's {NAME}_FILE env entry.
    let compose = (open --raw compose.yml | from yaml)
    let compose_files = ($compose.secrets | transpose name spec | get name | sort)
    let mapped_files = ($SECRET_MAP | get file | sort)
    $ok = ($ok | append (assert ($compose_files == $mapped_files) $"mapping table covers the compose.yml secrets block \(($mapped_files | length) files)"))

    let file_vars = (
        $compose.services
        | transpose name spec
        | each {|s| $s.spec | get --optional environment | default {} | transpose var value }
        | flatten
        | where {|e| ($e.var | str ends-with "_FILE") and (($e.value | describe) == "string") and ($e.value | str starts-with "/run/secrets/") }
        | each {|e| {file: ($e.value | path basename), key: ($e.var | str replace --regex '_FILE$' "")} }
    )
    let key_mismatches = ($SECRET_MAP | each {|m|
        let wired = ($file_vars | where file == $m.file | get key)
        if ($m.key in $wired) { [] } else { [$"($m.file): mapped to ($m.key) but compose wires ($wired | str join ', ')"] }
    } | flatten)
    $ok = ($ok | append (assert ($key_mismatches | is-empty) $"every Infisical key matches its compose {NAME}_FILE env var ($key_mismatches | str join '; ')"))

    # 2-5. Write rules, in a throwaway directory with sentinel values.
    let dir = (mktemp --directory --tmpdir)
    let values = ($SECRET_MAP | reduce --fold {} {|m, acc|
        $acc | insert $m.key (if $m.allow_empty and $m.key == "FORGEJO_API_TOKEN" { "" } else { $"sentinel-value-for-($m.key)" })
    })

    let first = (plan $dir $values)
    $ok = ($ok | append (assert (($first | all {|r| $r.action == "create" })) "an empty directory plans every secret as create"))
    for row in $first { write-secret $row ($values | get $row.key) }
    $ok = ($ok | append (assert (($SECRET_MAP | all {|m| (mode-of $"($dir)/($m.file)") == "0400" })) "written files are mode 0400"))
    $ok = ($ok | append (assert (($SECRET_MAP | all {|m| (open --raw $"($dir)/($m.file)" | decode utf-8) == ($values | get $m.key) })) "written files hold the fetched value byte for byte"))
    $ok = ($ok | append (assert (((ls $dir | where name =~ '\.tmp$') | is-empty)) "no temp file is left behind"))

    let before = (ls $dir | select name modified | sort-by name)
    let second = (plan $dir $values)
    $ok = ($ok | append (assert (($second | all {|r| $r.action == "unchanged" })) "a re-run with unchanged values plans nothing"))
    for row in $second { write-secret $row ($values | get $row.key) }
    let after = (ls $dir | select name modified | sort-by name)
    $ok = ($ok | append (assert ($before == $after) "a re-run with unchanged values touches no mtime"))

    let rotated = ($values | update JWT_SECRET "sentinel-value-rotated")
    let third = (plan $dir $rotated)
    $ok = ($ok | append (assert (($third | where action == "update" | get file) == ["jwt_secret"]) "a rotated value plans exactly that one file as update"))
    for row in $third { write-secret $row ($rotated | get $row.key) }
    $ok = ($ok | append (assert ((mode-of $"($dir)/jwt_secret") == "0400") "an overwritten file is still mode 0400"))
    $ok = ($ok | append (assert ((open --raw $"($dir)/jwt_secret" | decode utf-8) == "sentinel-value-rotated") "an overwritten file holds the new value"))

    # 6. Neither the plan table nor the dry-run summary leaks a value, and a
    #    dry run over a changed value writes nothing.
    let pending = (plan $dir $values)
    let printed = ([(report-lines $pending false) (report-lines $pending true)] | flatten | str join "\n")
    $ok = ($ok | append (assert (not ($printed | str contains "sentinel-value")) "no mode prints a secret value"))
    let untouched = (ls $dir | select name modified | sort-by name)
    apply-plan $pending $values true | ignore
    $ok = ($ok | append (assert ($untouched == (ls $dir | select name modified | sort-by name)) "--dry-run writes nothing"))

    # 7. Missing and empty-but-required keys abort before anything is written.
    let missing = (validate ($values | reject JWT_SECRET))
    $ok = ($ok | append (assert (($missing | length) == 1 and ($missing | first | str contains "JWT_SECRET")) "a missing mapped key is reported by name"))
    let blank = (validate ($values | update APP_ENCRYPTION_KEY ""))
    $ok = ($ok | append (assert (($blank | length) == 1 and ($blank | first | str contains "APP_ENCRYPTION_KEY")) "an empty required key is reported by name"))
    $ok = ($ok | append (assert ((validate ($values | update FORGEJO_API_TOKEN "")) | is-empty) "an empty optional key is allowed"))

    rm --recursive $dir
    if ($ok | any {|r| not $r }) { exit 1 }
    print $"self-test: ($ok | length) checks passed"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main [
    --environment (-e): string = "prod" # Infisical environment slug to read (staging or prod)
    --dry-run # print the plan and the would-change set without writing anything
    --self-test # prove the write rules without contacting Infisical, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    if $environment not-in $ENVIRONMENTS {
        print --stderr $"error: unknown environment '($environment)'; expected one of ($ENVIRONMENTS | str join ', ')"
        exit 2
    }

    let secrets_dir = "./secrets"
    if ($secrets_dir | path type) != "dir" {
        mkdir $secrets_dir
        ^chmod 700 $secrets_dir
    }

    print $"Reading ($FOLDER) from the ($environment) environment."
    let values = (fetch-secrets $environment (infisical-token))

    let problems = (validate $values)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr "error: nothing was written. Add the missing values in Infisical and re-run; see docs/secrets-infisical.md."
        exit 1
    }

    apply-plan (plan $secrets_dir $values) $values $dry_run
}
