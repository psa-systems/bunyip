#!/usr/bin/env nu

# BUNYIP-890: render / check the Recently added section of docs/configuration.md
# from ENV_INVENTORY in `crates/bunyip-domain/src/config.rs` and the release
# facts in `config/changes.toml`.
#
# Subcommands:
#   generate     overwrite the Recently added section in docs/configuration.md
#   check        exit 1 if the current section disagrees with what generate would write
#   since <v>    print every variable added in release v, newline-separated
#   self-test    parser + round-trip tests over fixture inputs
#
# Shape: the generator writes a single Recently added block delimited by
# matching BEGIN/END HTML comments at the top of `docs/configuration.md`.
# `check` reads the file, splits on the markers and compares the enclosed
# body to the regenerated one byte-for-byte, so a hand-edit between the
# markers fails just like a stale `since`.

const CONFIG_FILE = "crates/bunyip-domain/src/config.rs"
const CHANGES_FILE = "config/changes.toml"
const DOC_FILE = "docs/configuration.md"
const BEGIN = "<!-- BEGIN GENERATED: recently-added (just config-docs) -->"
const END = "<!-- END GENERATED: recently-added -->"
const WINDOW = 5  # releases included in the Recently added section
const BASELINE = "v0.18.0"  # the pre-BUNYIP-890 backfill marker

# --- Version parsing -----------------------------------------------------------

def vnum [v: string] {
    let p = ($v | parse --regex '^v(?<a>\d+)\.(?<b>\d+)\.(?<c>\d+)$')
    if ($p | is-empty) { error make { msg: $"($v) is not a vX.Y.Z release tag" } }
    (($p.a.0 | into int) * 1000000) + (($p.b.0 | into int) * 1000) + ($p.c.0 | into int)
}

# --- Inventory parsing ---------------------------------------------------------

# Parse an EnvVarSpec block: `EnvVarSpec::<ctor>(` ... `"NAME"` [ ... `.since("vX.Y.Z")` ].
# Returns [{name, class, since}, ...] in source order. Trailing `.since(...)` is
# the only chainable the generator reads; the AC asks for Added-in only and the
# rest of the row (feature / remedy / gate) comes from the hand-written tables
# the surface guard already covers.
def parse-inventory [text: string] {
    mut entries = []
    let specs = ($text
        | parse --regex '(?s)EnvVarSpec::(?<ctor>required|required_in_production|gating|defaulted)\(\s*"(?<name>[A-Z][A-Z0-9_]*)",(?<body>.*?)\)(?<tail>(?:\s*\.(?:gated_by|since)\(\s*"[^"]*"\s*\))*)\s*,'
    )
    for row in $specs {
        let class = (match $row.ctor {
            "required" => "Required"
            "required_in_production" => "Required in production"
            "gating" => "Feature-gating"
            "defaulted" => "Defaulted"
            _ => $row.ctor
        })
        let since_m = ($row.tail | parse --regex '\.since\(\s*"(?<v>v\d+\.\d+\.\d+)"\s*\)')
        let since = (if ($since_m | is-empty) { $BASELINE } else { $since_m.v.0 })
        $entries = ($entries | append { name: $row.name, class: $class, since: $since })
    }
    $entries
}

# --- Changes parsing -----------------------------------------------------------

def read-changes [path: string] {
    if not ($path | path exists) {
        return { removed: [], change: [] }
    }
    let raw = (open $path)
    let removed = (if ("removed" in ($raw | columns)) { $raw.removed } else { [] })
    let change = (if ("change" in ($raw | columns)) { $raw.change } else { [] })
    { removed: $removed, change: $change }
}

# --- Section rendering ---------------------------------------------------------

def render-section [inventory: list, changes: record, releases_included: list<string>] {
    mut sections = []
    for release in $releases_included {
        let added = ($inventory | where since == $release | sort-by name)
        let removed = ($changes.removed | where release == $release | sort-by name)
        let changed = ($changes.change | where release == $release | sort-by name)
        if (($added | length) + ($removed | length) + ($changed | length)) == 0 {
            continue
        }
        mut lines = [$"### ($release)"]
        if ($added | length) > 0 {
            $lines = ($lines | append "")
            # The baseline release lumps every pre-BUNYIP-890 entry together,
            # which would be hundreds of lines. Summarise the count instead;
            # per-variable since values after the baseline enumerate in full.
            if $release == $BASELINE {
                let count = ($added | length)
                $lines = ($lines | append $"**Added:** ($count) variables \(the pre-BUNYIP-890 baseline inventory; exact release per entry is backfilled as new work touches it\).")
            } else {
                $lines = ($lines | append "**Added:**")
                for e in $added {
                    $lines = ($lines | append $"- `($e.name)` \(($e.class)\)")
                }
            }
        }
        if ($changed | length) > 0 {
            $lines = ($lines | append "")
            $lines = ($lines | append "**Changed:**")
            for c in $changed {
                let level_prefix = (if ($c.level? | default "") == "Breaking" { "**Breaking** " } else { "" })
                $lines = ($lines | append $"- `($c.name)` \(($c.issue)\): ($level_prefix)($c.action)")
            }
        }
        if ($removed | length) > 0 {
            $lines = ($lines | append "")
            $lines = ($lines | append "**Removed:**")
            for r in $removed {
                $lines = ($lines | append $"- `($r.name)` \(($r.issue)\): ($r.action)")
            }
        }
        $lines = ($lines | append "")
        $sections = ($sections | append ($lines | str join (char newline)))
    }
    if ($sections | is-empty) {
        $"($BEGIN)\n\n## Recently added\n\n_No configuration changes in the last ($WINDOW) releases._\n\n($END)"
    } else {
        let body = ($sections | str join (char newline))
        $"($BEGIN)\n\n## Recently added\n\n_The last ($WINDOW) releases that touched the config surface, newest first. The full inventory is below._\n\n($body)\n($END)"
    }
}

# Pick the WINDOW most recent releases that appear in the data (inventory +
# changes), ordered newest first. Fewer than WINDOW is fine; render whatever
# exists.
def releases-with-changes [inventory: list, changes: record] {
    let from_inventory = ($inventory | get since)
    let from_removed = ($changes.removed | get release)
    let from_changed = ($changes.change | get release)
    let all = ([$from_inventory $from_removed $from_changed] | flatten | uniq)
    $all
    | each {|v| { v: $v, n: (vnum $v) } }
    | sort-by n --reverse
    | first $WINDOW
    | get v
}

# --- Doc file I/O --------------------------------------------------------------

def splice-section [doc_text: string, section: string] {
    let before_begin = ($doc_text | split row $BEGIN | first)
    let after_end = ($doc_text | split row $END | last)
    $"($before_begin)($section)($after_end)"
}

def extract-section [doc_text: string] {
    if not ($doc_text | str contains $BEGIN) or not ($doc_text | str contains $END) {
        return ""
    }
    let begin_idx = ($doc_text | str index-of $BEGIN)
    let end_idx = ($doc_text | str index-of $END)
    # Nu `str substring a..b` is inclusive on both ends, so subtract 1 from the
    # end-marker's past-the-end to land on the final `>` of the END marker.
    $doc_text | str substring $begin_idx..($end_idx + ($END | str length) - 1)
}

# --- Subcommands ---------------------------------------------------------------

def "main generate" [] {
    let config_text = (open --raw $CONFIG_FILE)
    let inventory = (parse-inventory $config_text)
    let changes = (read-changes $CHANGES_FILE)
    let releases = (releases-with-changes $inventory $changes)
    let section = (render-section $inventory $changes $releases)
    let doc_text = (open --raw $DOC_FILE)
    if not ($doc_text | str contains $BEGIN) {
        error make { msg: $"($DOC_FILE) has no `($BEGIN)` marker; add the pair where the Recently added section should go." }
    }
    let updated = (splice-section $doc_text $section)
    $updated | save --force $DOC_FILE
    print $"generated: ($inventory | length) variables, ($releases | length) release\(s\) in the Recently added section"
}

def "main check" [] {
    let config_text = (open --raw $CONFIG_FILE)
    let inventory = (parse-inventory $config_text)
    let changes = (read-changes $CHANGES_FILE)
    let releases = (releases-with-changes $inventory $changes)
    let expected = (render-section $inventory $changes $releases)
    let doc_text = (open --raw $DOC_FILE)
    let actual = (extract-section $doc_text)
    if $actual != $expected {
        print --stderr $"($DOC_FILE) disagrees with ($CONFIG_FILE) + ($CHANGES_FILE); run `just config-docs` to regenerate."
        exit 1
    }
    print $"config docs OK: ($inventory | length) variables, ($releases | length) release\(s\) in the Recently added section"
}

def "main since" [version: string] {
    let config_text = (open --raw $CONFIG_FILE)
    let inventory = (parse-inventory $config_text)
    $inventory | where since == $version | get name | str join (char newline)
}

def "main self-test" [] {
    # Parser round-trip: a canned EnvVarSpec snippet exercises each ctor + the
    # `.since(...)` chainable + the no-since baseline.
    let fixture = '
    EnvVarSpec::required(
        "REQ_VAR",
        "always required",
        "set it.",
    ),
    EnvVarSpec::required_in_production(
        "PROD_VAR",
        "required in production",
        "set it in production.",
    )
    .since("v0.19.0"),
    EnvVarSpec::gating(
        "GATED_VAR",
        "gates a feature",
        "set it.",
    )
    .gated_by("REQ_VAR")
    .since("v0.18.2"),
    EnvVarSpec::defaulted("DEFAULTED_VAR", "has a default"),
    '
    let parsed = (parse-inventory $fixture)
    assert (($parsed | length) == 4) "parser read every entry"
    assert ((($parsed | where name == "REQ_VAR" | get since.0)) == $BASELINE) "no since -> baseline"
    assert ((($parsed | where name == "PROD_VAR" | get since.0)) == "v0.19.0") ".since reads"
    assert ((($parsed | where name == "GATED_VAR" | get since.0)) == "v0.18.2") ".since reads after .gated_by"
    assert ((($parsed | where name == "GATED_VAR" | get class.0)) == "Feature-gating") "ctor -> class"
    print "config-docs self-test: clean"
}

# Default: list the subcommands when no arg is given, matching how `--list`
# surfaces this script's `just` recipe.
def main [] {
    print "subcommands: generate | check | since <version> | self-test"
}

# --- Nu assert helper (nu has no built-in `assert`) ----------------------------

def assert [cond: bool, msg: string] {
    if not $cond { error make { msg: $"assertion failed: ($msg)" } }
}
