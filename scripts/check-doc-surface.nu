#!/usr/bin/env nu

# Doc-surface drift gate (BUNYIP-783).
#
# `docs/configuration.md` used to assert its tables were machine-generated and
# therefore could not drift, with nothing behind the sentence: five
# consecutive doc-drift audits found it unchanged while the gaps widened. This
# gate reads the three source-of-truth constants as flat sets of uppercase
# variable names and diffs each against its corresponding table or list in
# `docs/configuration.md`, failing the build the moment either side names
# something the other does not:
#
#   - `ENV_INVENTORY` (crates/bunyip-domain/src/config.rs) against the
#     Required, Feature-gating and Defaulted tables plus the bunyip-web
#     variable list.
#   - `SYSTEM_LEVEL_ENV_KEYS` (crates/bunyip-domain/src/sys_config.rs) against
#     the system-level table (absorbs BUNYIP-734's check-system-level-keys.nu,
#     folded in here rather than left as a second script).
#   - `GovernedSecret::ALL` (crates/bunyip-domain/src/config.rs) against the
#     governed-secrets table.
#
# A name with no underscore is excluded from the doc-side extraction (it is
# indistinguishable from a backtick-quoted prose word like `WARN` or `BYTEA`),
# with one named exception: `ENVIRONMENT`, the one real variable name that has
# none.
#
# Usage:
#   scripts/check-doc-surface.nu
#   scripts/check-doc-surface.nu --self-test

const CONFIG_RS = "crates/bunyip-domain/src/config.rs"
const SYS_CONFIG_RS = "crates/bunyip-domain/src/sys_config.rs"
const DOC_FILE = "docs/configuration.md"

# The text between the first occurrence of `start` and the next occurrence of
# `end` after it, or the rest of the string when `end` never recurs.
def between [content: string, start: string, end: string]: nothing -> string {
    let s = ($content | str index-of $start)
    if $s < 0 {
        return ""
    }
    let after = ($content | str substring ($s + ($start | str length))..)
    let e = ($after | str index-of $end)
    if $e < 0 {
        $after
    } else {
        $after | str substring 0..<$e
    }
}

# Every backtick-quoted uppercase identifier in a string, sorted and
# deduplicated. Requires an underscore (or the literal name `ENVIRONMENT`) so
# a prose word like `WARN`, `INFO` or `BYTEA` inside backticks is not mistaken
# for a variable name.
def backtick-names [text: string]: nothing -> list<string> {
    $text
    | parse --regex '`([A-Z][A-Z0-9_]*)`'
    | get capture0
    | where {|n| ($n | str contains "_") or $n == "ENVIRONMENT" }
    | uniq
    | sort
}

# The first-column cell of every `|`-prefixed line in a markdown table,
# backtick-name-extracted. Cells with more than one name ("`A` / `B`") yield
# every name they carry.
def table-first-column-names [section: string]: nothing -> list<string> {
    $section
    | lines
    | where {|l| $l | str starts-with "|" }
    | each {|l| $l | split row "|" | get 1 }
    | each {|cell| backtick-names $cell }
    | flatten
    | uniq
    | sort
}

# `ENV_INVENTORY`'s flat slice of string literals: the quoted names inside
# `WRITTEN_ENV_INVENTORY`'s array literal (the generated `RATE_LIMIT_*` family
# appended at runtime carries no source literal, so it is out of scope here).
def env-inventory-names [content: string]: nothing -> list<string> {
    let body = (between $content "static WRITTEN_ENV_INVENTORY" "\n];")
    $body | parse --regex '"([A-Z][A-Z0-9_]*)"' | get capture0 | uniq | sort
}

# `SYSTEM_LEVEL_ENV_KEYS`'s array literal.
def system-level-names [content: string]: nothing -> list<string> {
    let body = (between $content "pub const SYSTEM_LEVEL_ENV_KEYS" "\n];")
    $body | parse --regex '"([A-Z][A-Z0-9_]*)"' | get capture0 | uniq | sort
}

# `GovernedSecret::ALL`'s names, read off the `name()` match arms rather than
# the `ALL` array itself (which names enum variants, not strings).
def governed-secret-names [content: string]: nothing -> list<string> {
    let body = (between $content "pub fn name(self) -> &'static str {" "\n    }")
    $body | parse --regex '"([A-Z][A-Z0-9_]*)"' | get capture0 | uniq | sort
}

# The union of every doc surface that documents an ENV_INVENTORY variable:
# the Required table, the Feature-gating table, the Defaulted bullet list, and
# the bunyip-web variable list (its own binary, sharing the one inventory
# per BUNYIP-751).
def doc-env-inventory-names [doc: string]: nothing -> list<string> {
    let required = (table-first-column-names (between $doc "\n## Required\n" "\n## "))
    let gating = (table-first-column-names (between $doc "\n## Feature-gating" "\n## "))
    let defaulted = (backtick-names (between $doc "\n## Defaulted" "\n## "))
    let web = (backtick-names (between $doc "\n## bunyip-web\n\n" "\n\n"))
    $required | append $gating | append $defaulted | append $web | uniq | sort
}

def doc-system-level-names [doc: string]: nothing -> list<string> {
    table-first-column-names (between $doc "\n## The configuration boundary" "\n## ")
}

def doc-governed-secret-names [doc: string]: nothing -> list<string> {
    table-first-column-names (between $doc "\n## `SECRETS_STORAGE`" "\n## ")
}

def diff-report [label: string, source: list<string>, doc: list<string>]: nothing -> list<string> {
    let only_source = ($source | where {|n| $n not-in $doc })
    let only_doc = ($doc | where {|n| $n not-in $source })
    mut problems = []
    if ($only_source | is-not-empty) {
        $problems = ($problems | append $"($label) names ($only_source | str join ', ') but docs/configuration.md does not")
    }
    if ($only_doc | is-not-empty) {
        $problems = ($problems | append $"docs/configuration.md names ($only_doc | str join ', ') but ($label) does not")
    }
    $problems
}

def all-problems [config_content: string, sys_content: string, doc_content: string]: nothing -> list<string> {
    let env_problems = (diff-report "ENV_INVENTORY" (env-inventory-names $config_content) (doc-env-inventory-names $doc_content))
    let sys_problems = (diff-report "SYSTEM_LEVEL_ENV_KEYS" (system-level-names $sys_content) (doc-system-level-names $doc_content))
    let secret_problems = (diff-report "GovernedSecret::ALL" (governed-secret-names $config_content) (doc-governed-secret-names $doc_content))
    $env_problems | append $sys_problems | append $secret_problems
}

def self-test []: nothing -> nothing {
    mut ok = true

    let config_content = (open --raw $CONFIG_RS | decode utf-8)
    let sys_content = (open --raw $SYS_CONFIG_RS | decode utf-8)
    let doc_content = (open --raw $DOC_FILE | decode utf-8)

    let clean = (all-problems $config_content $sys_content $doc_content)
    if ($clean | is-not-empty) {
        print --stderr $"self-test FAILED: gate reports a mismatch against the real tree: ($clean | to nuon)"
        $ok = false
    } else {
        print "self-test ok: gate agrees the real tree matches"
    }

    let injected_config = ($config_content | str replace '"DATABASE_URL",' '"DATABASE_URL",
    "BUNYIP_783_SELF_TEST_ONLY",')
    if $injected_config == $config_content {
        print --stderr "self-test FAILED: ENV_INVENTORY injection anchor not found in config.rs"
        $ok = false
    } else {
        let dirty = (all-problems $injected_config $sys_content $doc_content)
        if ($dirty | is-empty) {
            print --stderr "self-test FAILED: gate misses an injected ENV_INVENTORY mismatch"
            $ok = false
        } else {
            print "self-test ok: gate catches an injected ENV_INVENTORY mismatch"
        }
    }

    let injected_sys = ($sys_content | str replace '"BUNYIP_WEB_ORIGIN",' '"BUNYIP_WEB_ORIGIN",
    "BUNYIP_783_SELF_TEST_ONLY",')
    if $injected_sys == $sys_content {
        print --stderr "self-test FAILED: SYSTEM_LEVEL_ENV_KEYS injection anchor not found in sys_config.rs"
        $ok = false
    } else {
        let dirty = (all-problems $config_content $injected_sys $doc_content)
        if ($dirty | is-empty) {
            print --stderr "self-test FAILED: gate misses an injected SYSTEM_LEVEL_ENV_KEYS mismatch"
            $ok = false
        } else {
            print "self-test ok: gate catches an injected SYSTEM_LEVEL_ENV_KEYS mismatch"
        }
    }

    let injected_doc = ($doc_content | str replace "| `SMTP_PASSWORD`         |" "| `BUNYIP_783_SELF_TEST_ONLY` |")
    if $injected_doc == $doc_content {
        print --stderr "self-test FAILED: GovernedSecret table injection anchor not found in docs/configuration.md"
        $ok = false
    } else {
        let dirty = (all-problems $config_content $sys_content $injected_doc)
        if ($dirty | is-empty) {
            print --stderr "self-test FAILED: gate misses an injected GovernedSecret::ALL mismatch"
            $ok = false
        } else {
            print "self-test ok: gate catches an injected GovernedSecret::ALL mismatch"
        }
    }

    if not $ok { exit 1 }
}

def main [
    --self-test # prove the gate catches an injected mismatch in each of the three sources, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let config_content = (open --raw $CONFIG_RS | decode utf-8)
    let sys_content = (open --raw $SYS_CONFIG_RS | decode utf-8)
    let doc_content = (open --raw $DOC_FILE | decode utf-8)

    let env_names = (env-inventory-names $config_content)
    let sys_names = (system-level-names $sys_content)
    let secret_names = (governed-secret-names $config_content)

    if ($env_names | is-empty) {
        print --stderr $"error: could not find WRITTEN_ENV_INVENTORY in ($CONFIG_RS)"
        exit 1
    }
    if ($sys_names | is-empty) {
        print --stderr $"error: could not find SYSTEM_LEVEL_ENV_KEYS in ($SYS_CONFIG_RS)"
        exit 1
    }
    if ($secret_names | is-empty) {
        print --stderr $"error: could not find GovernedSecret::name\(\) in ($CONFIG_RS)"
        exit 1
    }

    let problems = (all-problems $config_content $sys_content $doc_content)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "ENV_INVENTORY, SYSTEM_LEVEL_ENV_KEYS and GovernedSecret::ALL must each name exactly"
        print --stderr $"the same set of variables as their table in ($DOC_FILE). Update whichever"
        print --stderr "side is missing a name."
        exit 1
    }

    print $"check-doc-surface: ($env_names | length) ENV_INVENTORY, ($sys_names | length) SYSTEM_LEVEL_ENV_KEYS and ($secret_names | length) GovernedSecret::ALL names agree with docs/configuration.md"
}
