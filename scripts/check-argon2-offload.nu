#!/usr/bin/env nu

# Argon2-off-the-worker gate (BUNYIP-553).
#
# actix-web pins a connection to one worker arbiter and never moves its futures
# elsewhere, so a ~100 ms Argon2 hash on a request future stalls every other
# request on that arbiter, `/v1/health` included. Every request-path hash and
# verify therefore goes through `bunyip_domain::services::argon2_offload`, which
# runs it on the blocking pool. Reintroducing a direct call compiles fine and
# fails no test, so grep-assert the shapes here.
#
# Rules:
#   1. `self.password.hash(` / `self.password.verify(` - forbidden outright.
#      `AuthService::password` exists only for the strength / email-containment
#      checks now; its Argon2 work moved to `argon2_offload`.
#   2. `PasswordService::new` - only in the files listed in ALLOW_CONSTRUCT.
#   3. `password_service.hash(` / `hasher.verify(` and friends - only in the
#      files listed in ALLOW_DIRECT_CALL, where the call already sits inside an
#      `argon2_offload::offload` closure or runs at startup.
#   4. The TOTP recovery-code helpers - only in totp.rs, and only as many call
#      sites as there are blocking tasks wrapping them (one for the up-to-8
#      verifies, one for the 8 hashes). An extra site means either a per-code
#      spawn or an unwrapped call.
#   5. A raw `Argon2::new` / `Argon2::default` - only in the files listed in
#      ALLOW_RAW_ARGON2, which build their own parameter presets inside offload
#      closures. Everything else goes through PasswordService.
#
# Usage: scripts/check-argon2-offload.nu [--self-test]

# Files allowed to construct a PasswordService, each with why it is exempt.
const ALLOW_CONSTRUCT = [
    "crates/bunyip-domain/src/services/argon2_offload.rs" # the offload wrapper itself
    "crates/bunyip-domain/src/services/auth.rs"           # strength checks only, no Argon2
    "crates/bunyip-oci/src/handlers/oci_auth.rs"          # both uses sit inside offload closures
    "bunyip-api/src/seed.rs"                              # hashes inside one offload closure
    "bunyip-api/src/main.rs"                              # startup bootstrap admin, before the server binds
    "bunyip-api/tests/login_approval.rs"                  # test fixture, no actix worker involved
]

# Files allowed to call hash/verify on a PasswordService binding directly.
const ALLOW_DIRECT_CALL = [
    "bunyip-api/src/seed.rs" # inside the "seed password hash" offload closure
    "bunyip-api/src/main.rs" # startup bootstrap admin, before the server binds
]

# Files allowed to build an Argon2 directly rather than via PasswordService,
# because they need a non-password parameter preset.
const ALLOW_RAW_ARGON2 = [
    "crates/bunyip-domain/src/services/totp.rs"     # the 19 MiB recovery-code preset
    "crates/bunyip-oidc/src/handlers/oidc.rs"       # the OIDC client-secret verify
    "crates/bunyip-oidc/src/machine_client.rs"      # client-secret hash, inside an offload closure
]

# The one file allowed to call the TOTP recovery-code Argon2 helpers, and the
# number of call sites it may have (one per blocking task).
const TOTP_FILE = "crates/bunyip-domain/src/services/totp.rs"
const TOTP_CALL_SITES = 2

const FIELD_CALL = 'self\.password\s*\.\s*(?:hash|verify)\s*\('
const CONSTRUCT = 'PasswordService::new'
const DIRECT_CALL = '\b(?:password_service|password_svc|hasher)\s*\.\s*(?:hash|verify)\s*\('
const TOTP_CALL = 'Self::(?:hash_code_argon2|verify_code_against_hash)\s*\('
const RAW_ARGON2 = 'Argon2::(?:new|default)\s*\('

# Every line of `content` matching `pattern`, as { line, text } records,
# mirroring `grep -n`.
def grep-content [content: string, pattern: string]: nothing -> table {
    $content
    | lines
    | enumerate
    | where {|r| $r.item =~ $pattern }
    | each {|r| { line: ($r.index + 1), text: ($r.item | str trim) } }
}

# Read a tracked file as UTF-8. One that is absent or not decodable has no text
# to match, mirroring how grep treats a binary.
def read-text [path: string]: nothing -> string {
    try { open --raw $path | decode utf-8 } catch { "" }
}

def print-hits [file: string, hits: table] {
    for hit in $hits { print --stderr $"error: ($file):($hit.line): ($hit.text)" }
}

# Run every rule over one file's content. Returns the failure messages, so the
# self-test can drive the same logic over synthetic sources.
def check-source [file: string, content: string]: nothing -> list<string> {
    mut problems = []

    let field = (grep-content $content $FIELD_CALL)
    if ($field | is-not-empty) {
        print-hits $file $field
        $problems = ($problems | append "AuthService hashes on the request future")
    }

    if $file not-in $ALLOW_CONSTRUCT {
        let built = (grep-content $content $CONSTRUCT)
        if ($built | is-not-empty) {
            print-hits $file $built
            $problems = ($problems | append "PasswordService built outside the allowlist")
        }
    }

    if $file not-in $ALLOW_DIRECT_CALL {
        let direct = (grep-content $content $DIRECT_CALL)
        if ($direct | is-not-empty) {
            print-hits $file $direct
            $problems = ($problems | append "Argon2 called outside a blocking task")
        }
    }

    if $file not-in $ALLOW_RAW_ARGON2 {
        let raw = (grep-content $content $RAW_ARGON2)
        if ($raw | is-not-empty) {
            print-hits $file $raw
            $problems = ($problems | append "raw Argon2 built outside the allowlist")
        }
    }

    let totp = (grep-content $content $TOTP_CALL)
    if $file != $TOTP_FILE {
        if ($totp | is-not-empty) {
            print-hits $file $totp
            $problems = ($problems | append "TOTP recovery-code Argon2 helper called outside totp.rs")
        }
    } else if ($totp | length) != $TOTP_CALL_SITES {
        print-hits $file $totp
        $problems = ($problems | append $"totp.rs has ($totp | length) recovery-code Argon2 call sites, expected ($TOTP_CALL_SITES)")
    }

    $problems
}

def self-test [] {
    let cases = [
        [name, file, content];
        ["field call", "crates/bunyip-domain/src/services/auth.rs", "let h = self.password.hash(&password)?;"]
        ["construction", "bunyip-api/src/handlers/user.rs", "let svc = PasswordService::new();"]
        ["direct call", "bunyip-api/src/handlers/totp.rs", "if !password_service.verify(&p, h)? { }"]
        ["totp helper elsewhere", "bunyip-api/src/handlers/totp.rs", "Self::verify_code_against_hash(&c, &h)?"]
        ["totp call-site count", $TOTP_FILE, "Self::hash_code_argon2(&c)?"]
        ["raw Argon2", "crates/bunyip-oci/src/handlers/oci_auth.rs", "Argon2::default().verify_password(s, &p)"]
    ]

    mut failed = 0
    for case in $cases {
        if (check-source $case.file $case.content | is-empty) {
            print --stderr $"self-test: the gate no longer detects ($case.name)"
            $failed = 1
        }
    }

    let clean = (check-source "bunyip-api/src/handlers/user.rs" "argon2_offload::verify_password(p, h).await?")
    if ($clean | is-not-empty) {
        print --stderr $"self-test: the gate rejects a compliant call site: ($clean)"
        $failed = 1
    }

    if $failed != 0 { exit 1 }
    print "check-argon2-offload: self-test passed"
}

def main [--self-test] {
    if $self_test {
        self-test
        return
    }

    mut problems = []
    for file in (^git ls-files "*.rs" | lines) {
        $problems = ($problems | append (check-source $file (read-text $file)))
    }

    # A totp.rs that vanished or was renamed must not pass silently.
    if ($TOTP_FILE | path exists) == false {
        print --stderr $"error: ($TOTP_FILE) is missing; update this gate."
        $problems = ($problems | append "totp.rs missing")
    }

    if ($problems | is-not-empty) {
        print --stderr ""
        print --stderr "Argon2 must not run on an actix worker (BUNYIP-553). Route the call"
        print --stderr "through bunyip_domain::services::argon2_offload (hash_password /"
        print --stderr "verify_password, or offload() for a multi-hash loop), and keep the"
        print --stderr "whole loop in ONE blocking task rather than one task per iteration."
        exit 1
    }

    print "check-argon2-offload: every Argon2 call runs off the request future"
}
