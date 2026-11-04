#!/usr/bin/env nu

# Render and check docs/configuration.md's per-variable release facts and the
# Recently-added changelog.
#
# Subcommands:
#   generate                        rewrite the generated sections of docs/configuration.md
#   check                           fail when docs/configuration.md disagrees with the facts
#   since <version>                 report the changes an operator running <version> faces today
#   release-notes <version>         emit the configuration-changes block for the <version> release
#   self-test                       run the built-in regression cases
#
# Source of truth:
#   WRITTEN_ENV_INVENTORY in crates/bunyip-domain/src/config.rs declares every
#   variable the api reads; `crates/bunyip-domain/config/variables.toml` carries
#   the per-variable facts the Rust struct cannot (`since`, `required`,
#   `deprecated`, `removed`) and the authored changelog wording ([[change]]).

const INVENTORY_FILE = "crates/bunyip-domain/src/config.rs"
const VARIABLES_FILE = "crates/bunyip-domain/config/variables.toml"
const DOC_FILE = "docs/configuration.md"
const REPO_URL = "https://dev.a8n.run/psa-systems/bunyip"
const WINDOW = 5
const BEGIN_RECENT = "<!-- BEGIN GENERATED: recently-added (just config-docs) -->"
const END_RECENT = "<!-- END GENERATED: recently-added -->"
const BEGIN_LIST = "<!-- BEGIN GENERATED: all-variables (just config-docs) -->"
const END_LIST = "<!-- END GENERATED: all-variables -->"
const GROUPS = ["Added" "Changed" "Deprecated" "Removed"]
# Earliest bunyip tag; a variable with no `-S` hit against a release tag is
# dated here, which is also what nothing upgrades into.
const BASELINE = "v0.1.0"
const LEVELS = { "wont-start": "Breaking: won't start", "feature-off": "Breaking: feature off" }

# -- Versions -------------------------------------------------------------------

def vnum [v: string] {
    let p = ($v | parse --regex '^v(?<a>\d+)\.(?<b>\d+)\.(?<c>\d+)$')
    if ($p | is-empty) { error make { msg: $"($v) is not a vX.Y.Z release" } }
    (($p.a.0 | into int) * 1000000) + (($p.b.0 | into int) * 1000) + ($p.c.0 | into int)
}

def is-version [v: any] {
    ($v | describe) == "string" and ($v =~ '^v\d+\.\d+\.\d+$')
}

def release-tags [] {
    ^git tag --list "v*" | lines | where {|t| is-version $t }
}

def slug [name: string] {
    $"var-($name | str downcase | str replace --all '_' '-')"
}

def release-anchor [v: string] {
    $"release-($v | str replace --all '.' '-')"
}

# -- Inputs ---------------------------------------------------------------------

# Every name declared in WRITTEN_ENV_INVENTORY, in source order.
def parse-inventory [text: string] {
    let body_pos = ($text | str index-of "static WRITTEN_ENV_INVENTORY")
    if $body_pos < 0 {
        error make { msg: $"($INVENTORY_FILE): no WRITTEN_ENV_INVENTORY definition" }
    }
    let after = ($text | str substring ($body_pos)..)
    let end_pos = ($after | str index-of "\n];")
    if $end_pos < 0 {
        error make { msg: $"($INVENTORY_FILE): WRITTEN_ENV_INVENTORY has no terminator" }
    }
    let body = ($after | str substring 0..<$end_pos)
    let rows = ($body | parse --regex 'EnvVarSpec::(?<fn>required|required_in_production|gating|defaulted)\s*\(\s*"(?<name>[A-Z][A-Z0-9_]+)"')
    if ($rows | length) == 0 {
        error make { msg: $"($INVENTORY_FILE): parsed 0 EnvVarSpec declarations; the inventory shape changed" }
    }
    $rows | each {|r|
        let cls = match $r.fn {
            "required" => "required",
            "required_in_production" => "required_in_production",
            "gating" => "gating",
            "defaulted" => "defaulted",
            _ => "defaulted",
        }
        { name: $r.name, class: $cls }
    }
}

# Catalog rows merge inventory names with [[variable]] facts (and [[removed]]
# tombstones for variables the server no longer reads).
def build-catalog [inventory: list, meta: record] {
    let by_name = ($meta.variable? | default [] | each {|v|
        {
            name: $v.name
            since: $v.since
            required: ($v.required? | default false)
            deprecated: ($v.deprecated? | default null)
            source: "variables.toml"
            removed: null
            class: null
        }
    })
    let inv_names = ($inventory | get name)
    let rows = ($by_name | each {|r|
        let hit = ($inventory | where name == $r.name)
        let cls = if ($hit | is-empty) { null } else { $hit.0.class }
        $r | upsert class $cls
    })
    let removed = ($meta.removed? | default [] | each {|v|
        {
            name: $v.name
            since: $v.since
            required: false
            deprecated: null
            source: "removed"
            removed: { release: $v.removed, issue: ($v.issue? | default ""), action: ($v.action? | default ""), level: ($v.breaking? | default "") }
            class: null
        }
    })
    $rows | append $removed
}

def catalog-errors [inventory: list, catalog: list] {
    mut errors = []
    let inv_names = ($inventory | get name)
    let listed = ($catalog | where source == "variables.toml" | get name)
    for n in $inv_names {
        if not ($n in $listed) {
            $errors = ($errors | append $"($n) is in WRITTEN_ENV_INVENTORY but has no [[variable]] row in ($VARIABLES_FILE); add it with its since and required")
        }
    }
    let removed_names = ($catalog | where source == "removed" | get name)
    for v in ($catalog | where source == "variables.toml") {
        if not ($v.name in $inv_names) {
            $errors = ($errors | append $"($v.name) is listed in ($VARIABLES_FILE) but no longer in WRITTEN_ENV_INVENTORY; move it to [[removed]] or restore it to the inventory")
        }
    }
    for v in $catalog {
        for field in [$v.since ($v.deprecated?.release?) ($v.removed?.release?)] {
            if $field != null and not (is-version $field) {
                $errors = ($errors | append $"($v.name): '($field)' is not a vX.Y.Z release")
            }
        }
    }
    let dupes = ($catalog | group-by name | items {|k, v| { name: $k, n: ($v | length) } } | where n > 1)
    for d in $dupes {
        $errors = ($errors | append $"($d.name) appears ($d.n) times across ($VARIABLES_FILE)")
    }
    $errors
}

# -- Changelog entries -----------------------------------------------------------

def default-action [e: record] {
    if $e.group != "Added" { return "" }
    if $e.required { "Required: set it before the server starts." } else { "Optional. Leave it unset to keep the default." }
}

def build-entries [catalog: list, meta: record] {
    mut auto = []
    for v in $catalog {
        let level = if $v.required and $v.since != $BASELINE { "wont-start" } else { "" }
        $auto = ($auto | append { release: $v.since, group: "Added", var: $v.name, required: $v.required, level: $level, feature: "", issue: "", action: "" })
        if $v.deprecated != null {
            let d = $v.deprecated
            $auto = ($auto | append { release: $d.release, group: "Deprecated", var: $v.name, required: false, level: "", feature: "", issue: ($d.issue? | default ""), action: $"Renamed to `($d.replacement)`. The old name still works and logs a warning; rename it at your next compose edit." })
        }
        if $v.removed != null {
            let r = $v.removed
            $auto = ($auto | append { release: $r.release, group: "Removed", var: $v.name, required: false, level: $r.level, feature: "", issue: $r.issue, action: $r.action })
        }
    }

    mut errors = []
    mut explicit = []
    let names = ($catalog | get name)
    for c in ($meta.change? | default []) {
        if not ($c.group in $GROUPS) {
            $errors = ($errors | append $"change record for ($c.release): group '($c.group)' is not one of ($GROUPS | str join ', ')")
            continue
        }
        let level = ($c.breaking? | default "")
        if not ($level in ["" "wont-start" "feature-off"]) {
            $errors = ($errors | append $"change record ($c.release) ($c.group): breaking '($level)' is not wont-start or feature-off")
            continue
        }
        for var in ($c.variables? | default []) {
            if not ($var in $names) {
                $errors = ($errors | append $"change record ($c.release) ($c.group) names ($var), which has no [[variable]] or [[removed]] row")
                continue
            }
            let hit = ($auto | enumerate | where {|e| $e.item.release == $c.release and $e.item.group == $c.group and $e.item.var == $var })
            if ($hit | is-empty) {
                if $c.group != "Changed" {
                    $errors = ($errors | append $"change record ($c.release) ($c.group) ($var) does not match the facts: check its since / deprecated / removed release")
                    continue
                }
                let v = ($catalog | where name == $var | first)
                $explicit = ($explicit | append { release: $c.release, group: "Changed", var: $var, required: $v.required, level: $level, feature: ($c.feature? | default ""), issue: ($c.issue? | default ""), action: ($c.action? | default "") })
            } else {
                let i = $hit.0.index
                let e = $hit.0.item
                $auto = ($auto | update $i ($e | merge {
                    issue: ($c.issue? | default $e.issue)
                    action: ($c.action? | default $e.action)
                    level: (if ($level | is-empty) { $e.level } else { $level })
                    feature: ($c.feature? | default $e.feature)
                }))
            }
        }
    }

    let all = ($auto | append $explicit | each {|e|
        if ($e.action | is-empty) { $e | update action (default-action $e) } else { $e }
    })
    { entries: $all, errors: $errors }
}

# Validate Breaking entries carry an action and an issue id, scoped to the
# releases the Recently-added window covers. A pre-window Breaking (a required
# variable backfilled from history) is listed in All variables but is not
# forced to carry authored wording, because the ticket that introduced it
# predates this gate.
def validate-breaking [entries: list, tags: list] {
    let w = (window $entries $tags)
    let covered = ($w.unreleased | append $w.released)
    mut errors = []
    for e in ($entries | where {|e| $e.release in $covered }) {
        if ($e.level | is-not-empty) and (($e.action | is-empty) or not ($e.issue =~ '^[A-Z]+-\d+$')) {
            $errors = ($errors | append $"($LEVELS | get $e.level) ($e.group) ($e.var) in ($e.release) needs a [[change]] record in ($VARIABLES_FILE) with the operator action and the issue that introduced it")
        }
        if $e.level == "feature-off" and ($e.feature | str trim | is-empty) {
            $errors = ($errors | append $"Breaking: feature off ($e.group) ($e.var) in ($e.release) needs `feature` naming what stops working")
        }
        if ($e.issue | is-not-empty) and not ($e.issue =~ '^[A-Z]+-\d+$') {
            $errors = ($errors | append $"($e.var) in ($e.release): issue '($e.issue)' is not an issue id")
        }
    }
    $errors
}

def window [entries: list, tags: list] {
    let sorted = ($tags | sort-by {|t| vnum $t } --reverse)
    let latest = if ($sorted | is-empty) { 0 } else { vnum $sorted.0 }
    let unreleased = ($entries | get release | uniq | where {|r| (vnum $r) > $latest } | sort-by {|r| vnum $r } --reverse)
    { unreleased: $unreleased, released: ($sorted | first ([$WINDOW ($sorted | length)] | math min)) }
}

def level-rank [level: string] {
    match $level { "wont-start" => 0, "feature-off" => 1, _ => 2 }
}

def entry-sort [rows: list] {
    $rows | sort-by {|e| $"(level-rank $e.level)(if $e.required { 0 } else { 1 })($e.var)" }
}

def render-entry [e: record] {
    let mark = if ($e.level | is-empty) { "" } else { $"**($LEVELS | get $e.level):** " }
    let req = if $e.required { "yes" } else { "no" }
    let feature = if $e.level == "feature-off" { $"Feature: ($e.feature). " } else { "" }
    let issue = if ($e.issue | is-empty) { "" } else { $" \(($e.issue))" }
    $"- ($mark)[`($e.var)`]\(#(slug $e.var)) \(Required: ($req)) - ($feature)($e.action)($issue)"
}

def render-recent [entries: list, tags: list] {
    let w = (window $entries $tags)
    mut out = [
        $BEGIN_RECENT
        ""
        $"Configuration changes in the last ($WINDOW) releases, newest first, rendered by `just config-docs` from `($INVENTORY_FILE)` and `($VARIABLES_FILE)` \(edit those, not this section). **Breaking: won't start** marks a change after which the restart fails until the operator acts; apply it before restarting. **Breaking: feature off** marks a change after which the server runs but the named feature stops working or changes until the operator acts; review it before restarting. Both name the operator action and the issue that introduced them. An unmarked entry needs no action unless you relied on the old behavior. Upgrading across more releases than this? Run `just config-since <running version>`."
    ]
    let versions = ($w.unreleased | each {|v| { v: $v, label: $"Unreleased \(($v))" } } | append ($w.released | each {|v| { v: $v, label: $v } }))
    for r in $versions {
        $out = ($out | append ["" $"<a id=\"(release-anchor $r.v)\"></a>" "" $"### ($r.label)"])
        let rows = ($entries | where release == $r.v)
        if ($rows | is-empty) {
            $out = ($out | append ["" "No configuration changes."])
            continue
        }
        for g in $GROUPS {
            let group_rows = (entry-sort ($rows | where group == $g))
            if ($group_rows | is-empty) { continue }
            $out = ($out | append ["" $"#### ($g)" ""] | append ($group_rows | each {|e| render-entry $e }))
        }
    }
    $out | append ["" $END_RECENT] | str join "\n"
}

# -- The "All variables" generated list -----------------------------------------

def expected-required [v: record] {
    if $v.required { "yes" } else { "no" }
}

def expected-added [v: record] {
    mut cell = $v.since
    if $v.deprecated != null { $cell = $"($cell); deprecated in ($v.deprecated.release), use `($v.deprecated.replacement)`" }
    if $v.removed != null { $cell = $"($cell); removed in ($v.removed.release)" }
    $cell
}

def class-label [v: record] {
    match ($v.class? | default "") {
        "required" => "Required",
        "required_in_production" => "Required in production",
        "gating" => "Feature-gating",
        "defaulted" => "Defaulted",
        _ => (if $v.source == "removed" { "Removed" } else { "" }),
    }
}

def render-list [catalog: list] {
    let sorted = ($catalog | sort-by name)
    mut out = [
        $BEGIN_LIST
        ""
        $"Every variable, with the release it first shipped in, rendered by `just config-docs` from `($INVENTORY_FILE)` and `($VARIABLES_FILE)` \(edit those, not this section). The reason the api reads it, and how its absence is reported, is in [The reporting contract](#the-reporting-contract-bunyip-537) and the classification tables above."
        ""
        "| Variable | Required | Added in | Classification |"
        "| --- | --- | --- | --- |"
    ]
    for v in $sorted {
        $out = ($out | append $"| <a id=\"(slug $v.name)\"></a>`($v.name)` | (expected-required $v) | (expected-added $v) | (class-label $v) |")
    }
    $out | append ["" $END_LIST] | str join "\n"
}

# -- Bounds and generation --------------------------------------------------------

def section-bounds [lines: list, begin: string, end: string] {
    let b = ($lines | enumerate | where item == $begin | get index)
    let e = ($lines | enumerate | where item == $end | get index)
    if ($b | length) != 1 or ($e | length) != 1 or $b.0 > $e.0 { return null }
    { start: $b.0, stop: $e.0 }
}

def generate-doc [doc: string, catalog: list, entries: list, tags: list] {
    mut lines = ($doc | lines)
    let rb = (section-bounds $lines $BEGIN_RECENT $END_RECENT)
    if $rb == null {
        error make { msg: $"($DOC_FILE): add the two marker lines under the Recently-added section first:\n($BEGIN_RECENT)\n($END_RECENT)" }
    }
    let recent = (render-recent $entries $tags | lines)
    $lines = ($lines | first $rb.start | append $recent | append ($lines | skip ($rb.stop + 1)))

    let lb = (section-bounds $lines $BEGIN_LIST $END_LIST)
    if $lb == null {
        error make { msg: $"($DOC_FILE): add the two marker lines under the All-variables section first:\n($BEGIN_LIST)\n($END_LIST)" }
    }
    let listing = (render-list $catalog | lines)
    $lines = ($lines | first $lb.start | append $listing | append ($lines | skip ($lb.stop + 1)))
    $"($lines | str join "\n")\n"
}

# -- Check ----------------------------------------------------------------------

const ENTRY_RE = r#'^- (?:\*\*Breaking: (?<b>won't start|feature off):\*\* )?\[`(?<var>[A-Z][A-Z0-9_]*)`\]\(#(?<anchor>[a-z0-9-]+)\) \(Required: (?<req>yes|no)\) - (?<text>.+)$'#
const ROW_RE = '^\| <a id="(?<anchor>[^"]*)"></a>`(?<var>[A-Z][A-Z0-9_]*)` \| (?<req>yes|no) \| (?<added>[^|]*?) \| (?<cls>[^|]*?) \|$'

def check-list [lines: list, catalog: list] {
    let bounds = (section-bounds $lines $BEGIN_LIST $END_LIST)
    if $bounds == null { return [$"($DOC_FILE): the All-variables markers are missing or out of order; run `just config-docs`"] }
    mut errors = []
    mut seen = []
    for line in ($lines | skip ($bounds.start + 1) | first ($bounds.stop - $bounds.start - 1)) {
        if not ($line starts-with "| <a id=") { continue }
        let row = ($line | parse --regex $ROW_RE)
        if ($row | is-empty) {
            $errors = ($errors | append $"($DOC_FILE): a row in All variables is malformed: ($line | str substring 0..80)")
            continue
        }
        let r = $row.0
        $seen = ($seen | append $r.var)
        let found = ($catalog | where name == $r.var)
        if ($found | is-empty) {
            $errors = ($errors | append $"($DOC_FILE): All variables row ($r.var) is neither in WRITTEN_ENV_INVENTORY nor listed as [[removed]]")
            continue
        }
        let v = $found.0
        if $r.anchor != (slug $r.var) {
            $errors = ($errors | append $"($DOC_FILE): All variables row ($r.var) has anchor '($r.anchor)', expected '(slug $r.var)'")
        }
        if $r.req != (expected-required $v) {
            $errors = ($errors | append $"($DOC_FILE): All variables row ($r.var) says Required '($r.req)', the facts say '(expected-required $v)'")
        }
        let want = (expected-added $v | str trim)
        let got = ($r.added | str trim)
        if $got != $want {
            $errors = ($errors | append $"($DOC_FILE): All variables row ($r.var) says Added in '($got)', the facts say '($want)'")
        }
        let cls_want = (class-label $v | str trim)
        let cls_got = ($r.cls | str trim)
        if $cls_got != $cls_want {
            $errors = ($errors | append $"($DOC_FILE): All variables row ($r.var) says Classification '($cls_got)', the facts say '($cls_want)'")
        }
    }
    for v in $catalog {
        let n = ($seen | where {|s| $s == $v.name } | length)
        if $n == 0 { $errors = ($errors | append $"($DOC_FILE): ($v.name) has no row in All variables; run `just config-docs`") }
        if $n > 1 { $errors = ($errors | append $"($DOC_FILE): ($v.name) has ($n) rows in All variables") }
    }
    $errors
}

def check-recent [lines: list, entries: list, tags: list] {
    let bounds = (section-bounds $lines $BEGIN_RECENT $END_RECENT)
    if $bounds == null { return [$"($DOC_FILE): the Recently-added markers are missing or out of order; run `just config-docs`"] }
    let anchors = ($lines | str join "\n" | parse --regex '<a id="(?<id>[^"]+)"></a>' | get id)
    mut errors = []
    mut found = []
    mut release: any = null
    mut group: any = null
    for line in ($lines | skip ($bounds.start + 1) | first ($bounds.stop - $bounds.start - 1)) {
        if ($line starts-with "### ") {
            $release = ($line | parse --regex '(?<v>v\d+\.\d+\.\d+)' | get 0?.v)
            $group = null
            continue
        }
        if ($line starts-with "#### ") {
            $group = ($line | str replace "#### " "" | str trim)
            continue
        }
        if not ($line starts-with "- ") { continue }
        let p = ($line | parse --regex $ENTRY_RE)
        if ($p | is-empty) or $release == null or not ($group in $GROUPS) {
            $errors = ($errors | append $"($DOC_FILE): malformed Recently-added entry: ($line | str substring 0..80)")
            continue
        }
        let d = $p.0
        let exp = ($entries | where {|e| $e.release == $release and $e.group == $group and $e.var == $d.var })
        if ($exp | is-empty) {
            $errors = ($errors | append $"($DOC_FILE): ($release) ($group) ($d.var) is not a change the inventory or ($VARIABLES_FILE) records")
            continue
        }
        let e = $exp.0
        $found = ($found | append $"($release)|($group)|($d.var)")
        let req = if $e.required { "yes" } else { "no" }
        if $d.req != $req {
            $errors = ($errors | append $"($DOC_FILE): ($release) ($group) ($d.var) says Required: ($d.req), the facts say ($req)")
        }
        let want = if ($e.level | is-empty) { "" } else { $LEVELS | get $e.level | str replace "Breaking: " "" }
        if ($d.b | default "") != $want {
            $errors = ($errors | append $"($DOC_FILE): ($release) ($group) ($d.var) mark is '($d.b | default "none")', the facts say '(if ($want | is-empty) { "none" } else { $want })'")
        }
        if ($e.level | is-not-empty) and not ($d.text | str contains $e.issue) {
            $errors = ($errors | append $"($DOC_FILE): ($release) Breaking ($d.var) does not name its issue ($e.issue)")
        }
        if $e.level == "feature-off" and not ($d.text | str starts-with $"Feature: ($e.feature). ") {
            $errors = ($errors | append $"($DOC_FILE): ($release) feature-off ($d.var) does not name its feature '($e.feature)'")
        }
        if $d.anchor != (slug $d.var) or not ($d.anchor in $anchors) {
            $errors = ($errors | append $"($DOC_FILE): ($release) ($d.var) links to #($d.anchor), which is not that variable's row anchor")
        }
    }
    let w = (window $entries $tags)
    let covered = ($w.unreleased | append $w.released)
    for e in ($entries | where {|e| $e.release in $covered }) {
        if not ($"($e.release)|($e.group)|($e.var)" in $found) {
            let what = if ($e.level | is-empty) { "" } else { $"($LEVELS | get $e.level) " }
            $errors = ($errors | append $"($DOC_FILE): ($what)($e.group) ($e.var) in ($e.release) is missing from Recently added; run `just config-docs`")
        }
    }
    $errors
}

# -- Repo plumbing ----------------------------------------------------------------

def load-repo [] {
    let inventory = (parse-inventory (open --raw $INVENTORY_FILE | decode utf-8))
    let meta = (open --raw $VARIABLES_FILE | decode utf-8 | from toml)
    let catalog = (build-catalog $inventory $meta)
    let built = (build-entries $catalog $meta)
    let tags = (release-tags)
    let errors = ((catalog-errors $inventory $catalog) | append $built.errors | append (validate-breaking $built.entries $tags))
    { inventory: $inventory, catalog: $catalog, entries: $built.entries, errors: $errors, tags: $tags }
}

def fail-on [errors: list, what: string] {
    if ($errors | is-empty) { return }
    print --stderr $"ERROR: ($what)"
    for e in $errors { print --stderr $"  ($e)" }
    exit 1
}

def main [] {
    print "usage: nu scripts/config-docs.nu <generate|check|since <version>|release-notes <version>|self-test>"
}

def "main generate" [] {
    let repo = (load-repo)
    fail-on $repo.errors "the configuration facts are inconsistent"
    let doc = (open --raw $DOC_FILE | decode utf-8)
    let next = (generate-doc $doc $repo.catalog $repo.entries $repo.tags)
    if $next == $doc { print $"($DOC_FILE) is current"; return }
    $next | save --force $DOC_FILE
    print $"rewrote the generated parts of ($DOC_FILE)"
}

def "main check" [] {
    let repo = (load-repo)
    let lines = (open --raw $DOC_FILE | decode utf-8 | lines)
    let errors = (
        $repo.errors
        | append (check-list $lines $repo.catalog)
        | append (check-recent $lines $repo.entries $repo.tags)
    )
    fail-on $errors "docs/configuration.md disagrees with the configuration facts"
    print $"config docs OK: ($repo.catalog | length) variables, ($repo.entries | length) changelog entries"
}

def "main since" [
    version: string
    --json
] {
    let repo = (load-repo)
    let after = ($repo.entries | where {|e| (vnum $e.release) > (vnum $version) })
    let sorted = ($after | sort-by {|e| $"((vnum $e.release) + 1000000000)(level-rank $e.level)($e.var)" })
    if $json {
        print ($sorted | each {|e| { release: $e.release, group: $e.group, variable: $e.var, required: $e.required, level: (if ($e.level | is-empty) { "none" } else { $e.level }), feature: $e.feature, issue: $e.issue, action: $e.action } } | to json)
        return
    }
    if ($after | is-empty) { print $"No configuration changes after ($version)."; return }
    let rows = ($sorted | each {|e|
        {
            release: $e.release
            change: $e.group
            variable: $e.var
            required: (if $e.required { "REQUIRED" } else { "no" })
            level: (match $e.level { "wont-start" => "WON'T START", "feature-off" => $"FEATURE OFF: ($e.feature)", _ => "" })
            issue: $e.issue
            action: $e.action
        }
    })
    print ($rows | table --expand --width 200)
    let wont = ($after | where level == "wont-start" | length)
    let off = ($after | where level == "feature-off" | length)
    print $"($rows | length) changes after ($version): ($wont) WON'T START \(apply before restarting), ($off) FEATURE OFF \(review and acknowledge before restarting)."
}

def "main release-notes" [
    version: string
    --ref: string
] {
    let repo = (load-repo)
    let ref = ($ref | default $version)
    let rows = ($repo.entries | where release == $version)
    let link = $"($REPO_URL)/src/tag/($ref)/($DOC_FILE)#(release-anchor $version)"
    let link = if $ref == $version { $link } else { $"($REPO_URL)/src/branch/($ref)/($DOC_FILE)#(release-anchor $version)" }
    print "## Configuration changes"
    print ""
    if ($rows | is-empty) {
        print $"No configuration changes in ($version). Full list: [docs/configuration.md]\(($link))."
        return
    }
    let breaking = ($rows | where {|e| $e.level | is-not-empty } | sort-by {|e| $"(level-rank $e.level)($e.var)" })
    let wont = ($breaking | where level == "wont-start" | length)
    print $"[Configuration changes in ($version)]\(($link)): ($rows | length) entries, ($wont) won't start, (($breaking | length) - $wont) feature off."
    if ($breaking | is-not-empty) {
        print ""
        for e in $breaking {
            let feature = if $e.level == "feature-off" { $"Feature: ($e.feature). " } else { "" }
            print $"- **($LEVELS | get $e.level):** `($e.var)` - ($feature)($e.action) \(($e.issue))"
        }
    }
}

# -- Self-test --------------------------------------------------------------------

def fixture [] {
    let inventory_text = '
static WRITTEN_ENV_INVENTORY: &[EnvVarSpec] = &[
    EnvVarSpec::required("OLD_KEY", "a", "b"),
    EnvVarSpec::defaulted("OPT_KEY", "a"),
    EnvVarSpec::required("LATE_REQ", "a", "b"),
    EnvVarSpec::defaulted("BOOT_KEY", "a"),
];
'
    let meta = {
        variable: [
            { name: "OLD_KEY", since: "v0.1.0", required: true }
            { name: "OPT_KEY", since: "v9.1.0", required: false }
            { name: "LATE_REQ", since: "v9.1.0", required: true }
            { name: "BOOT_KEY", since: "v9.1.0", required: false }
        ]
        removed: [{ name: "GONE_KEY", since: "v9.0.0", removed: "v9.1.0", issue: "BUNYIP-2", action: "Delete it." }]
        change: [
            { release: "v9.1.0", group: "Added", variables: ["LATE_REQ"], issue: "BUNYIP-1", action: "Set it." }
            { release: "v9.1.0", group: "Changed", variables: ["OLD_KEY"], issue: "BUNYIP-4", breaking: "feature-off", feature: "Widget export", action: "Move it." }
        ]
    }
    { inventory_text: $inventory_text, meta: $meta, tags: ["v0.1.0" "v9.0.0" "v9.1.0"] }
}

def fixture-doc [] {
    [
        "# Configuration"
        ""
        "## Recently added"
        ""
        $BEGIN_RECENT
        $END_RECENT
        ""
        "## All variables"
        ""
        $BEGIN_LIST
        $END_LIST
        ""
    ] | str join "\n"
}

def all-errors [inventory_text: string, meta: record, tags: list, doc: string] {
    let inventory = (parse-inventory $inventory_text)
    let catalog = (build-catalog $inventory $meta)
    let built = (build-entries $catalog $meta)
    let lines = ($doc | lines)
    (catalog-errors $inventory $catalog) | append $built.errors | append (validate-breaking $built.entries $tags) | append (check-list $lines $catalog) | append (check-recent $lines $built.entries $tags)
}

def generated [f: record] {
    let inventory = (parse-inventory $f.inventory_text)
    let catalog = (build-catalog $inventory $f.meta)
    let built = (build-entries $catalog $f.meta)
    generate-doc (fixture-doc) $catalog $built.entries $f.tags
}

def "main self-test" [] {
    let f = (fixture)
    let good = (generated $f)
    let cases = [
        [name, errors, expect];
        ["a generated doc passes", (all-errors $f.inventory_text $f.meta $f.tags $good), 0]
        ["generating twice changes nothing", (do {
            let inv = (parse-inventory $f.inventory_text)
            let cat = (build-catalog $inv $f.meta)
            let again = (generate-doc $good $cat (build-entries $cat $f.meta).entries $f.tags)
            if $again == $good { [] } else { ["the second run rewrote the doc"] }
        }), 0]
        ["a missing row fails", (all-errors $f.inventory_text $f.meta $f.tags ($good | lines | where {|l| not ($l | str contains '`OPT_KEY` |') } | str join "\n")), 1]
        ["a wrong since fails", (all-errors $f.inventory_text $f.meta $f.tags ($good | str replace '`OPT_KEY` | no | v9.1.0' '`OPT_KEY` | no | v9.0.0')), 1]
        ["a Breaking change without its mark fails", (all-errors $f.inventory_text $f.meta $f.tags ($good | str replace "- **Breaking: won't start:** [`LATE_REQ`]" '- [`LATE_REQ`]')), 1]
    ]
    mut failed = 0
    for c in $cases {
        let n = ($c.errors | length)
        if ($c.expect == 0 and $n == 0) or ($c.expect > 0 and $n > 0) {
            print $"self-test: ($c.name)"
        } else {
            let want = if $c.expect == 0 { "no errors" } else { "an error" }
            print --stderr $"self-test: FAIL \(($c.name): expected ($want), got ($n))"
            for e in $c.errors { print --stderr $"    ($e)" }
            $failed += 1
        }
    }
    if $failed > 0 { exit 1 }
    print "config-docs self-test: clean"
}
