#!/usr/bin/env nu

# Doc-surface drift gate.
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
# `docs/public/configuration.md` is a second, hand-written prose description
# of the same `ENV_INVENTORY` surface, published externally and outside the
# table-shaped diff above. Its format (sentences, not a table) makes exact
# per-row parsing impractical, so it gets a weaker check instead: every
# backtick-quoted name in the file must either be a real
# `ENV_INVENTORY` entry, the `{NAME}_FILE` secret-file form of one, or the
# `ENV_INVENTORY` identifier itself (used in prose to name the source of
# truth, not as a variable). Anything else fails the build, with the closest
# real entry (by edit distance) printed alongside it.
#
# Usage:
#   scripts/check-doc-surface.nu
#   scripts/check-doc-surface.nu --self-test

const CONFIG_RS = "crates/bunyip-domain/src/config.rs"
const SYS_CONFIG_RS = "crates/bunyip-domain/src/sys_config.rs"
const DOC_FILE = "docs/configuration.md"
const PUBLIC_DOC_FILE = "docs/public/configuration.md"
# Names that legitimately appear backtick-quoted in docs/public/configuration.md
# without being themselves an ENV_INVENTORY variable.
const PUBLIC_DOC_META_NAMES = ["ENV_INVENTORY"]

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
# SPEC-3.22.4
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
# SPEC-3.22.1
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
# SPEC-3.22.2
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

# Levenshtein edit distance between two strings, used only to pick the
# closest real name to print alongside an unmatched one.
def edit-distance [a: string, b: string]: nothing -> int {
    let ac = ($a | split chars)
    let bc = ($b | split chars)
    let la = ($ac | length)
    let lb = ($bc | length)
    mut prev = (0..$lb | each {|i| $i })
    for i in 1..$la {
        mut cur = [$i]
        for j in 1..$lb {
            let cost = if ($ac | get ($i - 1)) == ($bc | get ($j - 1)) { 0 } else { 1 }
            let del = ($prev | get $j) + 1
            let ins = ($cur | get ($j - 1)) + 1
            let sub = ($prev | get ($j - 1)) + $cost
            $cur = ($cur | append ([$del $ins $sub] | math min))
        }
        $prev = $cur
    }
    $prev | last
}

def closest-name [name: string, candidates: list<string>]: nothing -> string {
    $candidates | each {|c| { name: $c, dist: (edit-distance $name $c) } } | sort-by dist | get name.0
}

# Every backtick-quoted candidate name in docs/public/configuration.md that
# cannot be matched to an `ENV_INVENTORY` entry: not the entry itself, not
# its `{NAME}_FILE` secret-file form, and not a known meta name. Each failure
# carries the closest real entry by edit distance.
# SPEC-3.22.6
def public-doc-problems [doc: string, env_names: list<string>]: nothing -> list<string> {
    let candidates = (backtick-names $doc | where {|n| $n not-in $PUBLIC_DOC_META_NAMES })
    mut problems = []
    for n in $candidates {
        if $n in $env_names { continue }
        if ($n | str ends-with "_FILE") {
            let base = ($n | str substring 0..<(($n | str length) - ("_FILE" | str length)))
            if $base in $env_names { continue }
        }
        let near = (closest-name $n $env_names)
        $problems = ($problems | append $"($PUBLIC_DOC_FILE) names `($n)`, which is not an ENV_INVENTORY variable \(closest: `($near)`\)")
    }
    $problems
}

# SPEC-3.22.3
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

# SPEC-3.22.5
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

    let env_names = (env-inventory-names $config_content)

    let real_name = ($env_names | first)
    if (public-doc-problems $"- `($real_name)` is fine." $env_names) != [] {
        print --stderr $"self-test FAILED: public-doc-problems flags a real ENV_INVENTORY name \(`($real_name)`)"
        $ok = false
    } else {
        print "self-test ok: public-doc-problems accepts a real ENV_INVENTORY name"
    }

    if (public-doc-problems "- `ENV_INVENTORY` describes the source of truth." $env_names) != [] {
        print --stderr "self-test FAILED: public-doc-problems flags the ENV_INVENTORY meta name"
        $ok = false
    } else {
        print "self-test ok: public-doc-problems accepts the ENV_INVENTORY meta name"
    }

    if (public-doc-problems $"- File-based through `($real_name)_FILE`." $env_names) != [] {
        print --stderr $"self-test FAILED: public-doc-problems flags the real {NAME}_FILE secret form \(`($real_name)_FILE`)"
        $ok = false
    } else {
        print "self-test ok: public-doc-problems accepts the {NAME}_FILE secret form of a real name"
    }

    let fake_bad = (public-doc-problems "- `BUNYIP_1095_SELF_TEST_ONLY` is fake." $env_names)
    if ($fake_bad | is-empty) {
        print --stderr "self-test FAILED: public-doc-problems misses an invented name"
        $ok = false
    } else {
        print "self-test ok: public-doc-problems catches an invented name"
    }

    let fake_file_bad = (public-doc-problems "- `BUNYIP_1095_SELF_TEST_ONLY_FILE` is fake." $env_names)
    if ($fake_file_bad | is-empty) {
        print --stderr "self-test FAILED: public-doc-problems misses an invented {NAME}_FILE name whose base is not real"
        $ok = false
    } else {
        print "self-test ok: public-doc-problems catches an invented {NAME}_FILE name whose base is not real"
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

    let public_doc_content = (open --raw $PUBLIC_DOC_FILE | decode utf-8)
    let public_problems = (public-doc-problems $public_doc_content $env_names)
    if ($public_problems | is-not-empty) {
        for p in $public_problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr $"Every env var name in ($PUBLIC_DOC_FILE) must be a real ENV_INVENTORY entry \(or its"
        print --stderr "{NAME}_FILE secret-file form). Fix the name, or add it to ENV_INVENTORY if it is"
        print --stderr "missing there."
        exit 1
    }

    print $"check-doc-surface: ($env_names | length) ENV_INVENTORY, ($sys_names | length) SYSTEM_LEVEL_ENV_KEYS and ($secret_names | length) GovernedSecret::ALL names agree with docs/configuration.md, and ($PUBLIC_DOC_FILE) names no invented variables"
}
