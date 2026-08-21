#!/usr/bin/env nu

# Price / deadline literal gate for bunyip-web (BUNYIP-590).
#
# Two numbers were compiled into user-facing copy that nothing in the system
# backed:
#   - `$3/month`, in the signup card and three membership panels. The real
#     price is the tier's Stripe amount in `/v1/pricing`; `$3` was a leaked
#     bootstrap figure that survived every price change.
#   - `within 30 days`, in the past-due dunning banner. The real deadline is the
#     per-user, Stripe-driven `grace_period_end`, so a fixed count told the
#     member a date the system does not enforce.
#
# Both shapes are now rendered from configuration (`util::entry_price` /
# `util::tier_price` for a price, `grace_period_end` for the deadline), with a
# non-numeric line when the value is absent. This gate keeps them out: a price
# per period, or a deadline stated as a fixed number of days or months, in a
# string literal under the guarded trees.
#
# Only double-quoted string literals are scanned, and every literal on a line is
# joined first, so copy split across maud fragments (`"$3" "/month"`) is caught
# too. Whole-line comments are dropped, so prose explaining the rule (including
# the paragraph above) is never a hit.
#
# An occurrence that is legitimately NOT copy (a test asserting that a
# configured price renders) is exempted by an explicit `// price-literal-ok:
# <reason>` marker on the same line, so an exemption is a visible decision
# rather than a regex accident.
#
# Usage:
#   scripts/check-price-literals.nu
#   scripts/check-price-literals.nu --self-test

# BUNYIP-502: the shared web-kit crate holds UI toolkit code lifted out of
# bunyip-web/src/views, so it renders copy too.
const SRC_GLOB = "{bunyip-web/src,crates/web-kit/src}/**/*.rs"

# One double-quoted Rust string literal, escapes included.
const LITERAL = '"(?<lit>(?:[^"\\]|\\.)*)"'

const FORBIDDEN = [
    {
        pattern: '[$€£][0-9][0-9.,]*\s*(/\s*|per\s+|a\s+)(month|mo\b|year|yr\b)'
        why: "a price per period compiled into copy; render the configured amount (util::entry_price / util::tier_price) and omit the number when nothing is published"
    }
    {
        pattern: '\bwithin\s+[0-9]+\s+(day|days|month|months)\b'
        why: "a deadline stated as a fixed count; render the real deadline (grace_period_end) and name the period without a number when it is absent"
    }
]

# The one way to keep an occurrence: say why, on the line.
const EXEMPTION = 'price-literal-ok:'

# Problems in one Rust source file, as human-readable lines.
def check-rs [path: string]: nothing -> list<string> {
    let content = (try { open --raw $path | decode utf-8 } catch { null })
    if $content == null {
        return [$"($path): missing or not readable - the gate cannot prove no price is compiled in."]
    }

    mut problems = []
    for row in ($content | lines | enumerate) {
        let text = $row.item
        # Whole-line comments are prose about the code, not copy the user reads.
        if ($text | str trim | str starts-with "//") { continue }
        if ($text | str contains $EXEMPTION) { continue }
        let joined = ($text | parse --regex $LITERAL | get lit | str join "")
        if ($joined | is-empty) { continue }
        for rule in $FORBIDDEN {
            if ($joined =~ $rule.pattern) {
                $problems = ($problems | append $"($path):($row.index + 1): \"($joined)\" - ($rule.why).")
            }
        }
    }
    $problems
}

def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)

    let cases = [
        {
            name: "rendered-price.rs"
            body: '{ @if let Some(p) = &price { (p) "/month" } @else { "See pricing" } }'
            expect_problems: false
            why: "a price interpolated from the pricing payload"
        }
        {
            name: "session-length.rs"
            body: '{ "Remember me for 30 days" }'
            expect_problems: false
            why: "a session length the system actually enforces"
        }
        {
            name: "prose.rs"
            body: '// The subtitle used to hardcode $3/month within 30 days of signup.'
            expect_problems: false
            why: "a comment explaining the rule"
        }
        {
            name: "exempted.rs"
            body: 'assert!(html.contains("$5.00/month")); // price-literal-ok: asserts the configured price renders'
            expect_problems: false
            why: "an occurrence carrying an explicit exemption reason"
        }
        {
            name: "hardcoded-price.rs"
            body: '{ "Subscribe to get access to all applications for just $3/month." }'
            expect_problems: true
            why: "a price per period compiled into copy"
        }
        {
            name: "split-price.rs"
            body: '{ "$3" "/month" }'
            expect_problems: true
            why: "a price split across two maud fragments"
        }
        {
            name: "euro-price.rs"
            body: '{ "€9.00 per month" }'
            expect_problems: true
            why: "a non-dollar price per period"
        }
        {
            name: "fixed-deadline.rs"
            body: '{ "Update your payment method within 30 days to avoid losing access." }'
            expect_problems: true
            why: "a dunning deadline stated as a fixed count"
        }
    ]

    let results = ($cases | each {|c|
        let path = $"($dir)/($c.name)"
        $c.body | save --force $path
        let problems = (check-rs $path)
        {why: $c.why, ok: (($problems | is-not-empty) == $c.expect_problems), problems: $problems}
    })
    let missing = (check-rs $"($dir)/absent.rs")
    rm --recursive $dir

    for r in $results {
        if $r.ok {
            print $"self-test ok: gate handles ($r.why)"
        } else {
            print --stderr $"self-test FAILED: gate mis-handles ($r.why): ($r.problems | to nuon)"
        }
    }
    if ($missing | is-empty) {
        print --stderr "self-test FAILED: gate mis-handles an unreadable source file"
    } else {
        print "self-test ok: gate handles an unreadable source file"
    }
    if (($results | any {|r| not $r.ok }) or ($missing | is-empty)) {
        exit 1
    }
}

def main [
    --self-test # prove the gate rejects a compiled-in price and deadline, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let files = (glob $SRC_GLOB)
    if ($files | is-empty) {
        print --stderr $"error: ($SRC_GLOB) matched no files - the gate cannot prove no price is compiled in."
        exit 1
    }

    let problems = ($files | each {|f| check-rs $f } | flatten)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr ""
        print --stderr "Prices and deadlines are configuration, not copy (BUNYIP-590): the price"
        print --stderr "comes from /v1/pricing via util::entry_price / util::tier_price, and the"
        print --stderr "dunning deadline from the member's grace_period_end. When the value is"
        print --stderr "absent, render the non-numeric line rather than a number nothing backs."
        print --stderr $"If the occurrence is genuinely not copy, add a `// ($EXEMPTION) <reason>`"
        print --stderr "marker on the line."
        exit 1
    }

    print $"check-price-literals: ($files | length) source files carry no compiled-in price or deadline"
}
