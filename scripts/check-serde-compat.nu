#!/usr/bin/env nu

# Wire-compatibility gate for the bunyip-api response models (BUNYIP-506).
#
# serde requires a field to be PRESENT unless it carries `#[serde(default)]`.
# `Option<T>` is not enough: it permits an explicit `null`, not an absent key.
# So every field of a `Deserialize` struct in `bunyip-web/src/api/types.rs` that
# lacks a default is a version-skew break waiting for the next rename or field
# addition - that is exactly how a membership-tier rename blocked login and 2FA
# in v0.13.0.
#
# The rule: every field defaults, EXCEPT the ones listed in ESSENTIAL_FIELDS
# below. Those are identifiers, tokens and URLs the calling flow cannot proceed
# without, where a default would be a lie and the decode must keep failing
# loudly. The table is the declared essential set: auditable here rather than
# implied by whichever field a reviewer remembered to annotate.
#
# The rule is asymmetric by direction: it covers RESPONSE structs (bunyip-api ->
# bunyip-web) only. Request structs under `bunyip-api/src/handlers/` keep their
# required inputs required, so a malformed request still fails with a 400.
#
# Usage: scripts/check-serde-compat.nu [types_file]
#        scripts/check-serde-compat.nu --self-test

const TYPES_FILE = "bunyip-web/src/api/types.rs"

# Fields allowed to stay required, each with the reason a default would be wrong.
const ESSENTIAL_FIELDS = [
    {field: "SessionInfo.id", reason: "revoke target for one session"}
    {field: "TrustedDeviceInfo.id", reason: "revoke target for one device"}
    {field: "User.id", reason: "identity: the subject of the session"}
    {field: "User.email", reason: "identity: shown as who is signed in"}
    {field: "User.role", reason: "security: authorization surface, never guessed"}
    {field: "User.email_verified", reason: "security: gates the verify-email flow"}
    {field: "User.two_factor_enabled", reason: "security: gates the 2FA surface"}
    {field: "AuthResponse.user", reason: "the whole payload of a sign-in"}
    {field: "Application.id", reason: "identifier the app links are built from"}
    {field: "Application.slug", reason: "identifier the app links are built from"}
    {field: "CheckoutSessionResponse.checkout_url", reason: "the URL the browser is sent to"}
    {field: "StripePaymentResponse.id", reason: "payment identifier"}
    {field: "StripeInvoice.id", reason: "invoice identifier"}
    {field: "TwoFactorSetupResponse.otpauth_uri", reason: "the QR payload being enrolled"}
    {field: "TwoFactorSetupResponse.secret", reason: "the manual-entry key being enrolled"}
    {field: "RecoveryCodesResponse.codes", reason: "an empty list would look like zero codes issued"}
    {field: "DownloadAsset.download_url", reason: "the URL the download button points at"}
    {field: "OciImage.reference", reason: "the pull reference shown to copy"}
    {field: "AppDownloadGroup.app_slug", reason: "identifier the catalog card links on"}
    {field: "SystemHealthResponse.health", reason: "the envelope's only payload"}
    {field: "AdminUser.id", reason: "target of every admin action on the row"}
    {field: "AdminAuditLog.id", reason: "audit entry identifier"}
    {field: "SeedTemplateInfo.name", reason: "the template the import posts back"}
    {field: "AdminIpBan.ip", reason: "the unban target"}
    {field: "AdminRateLimit.action", reason: "identifies the throttle to the reset endpoint"}
    {field: "AdminRateLimit.key", reason: "identifies the throttle to the reset endpoint"}
    {field: "AdminRateLimitConfig.action", reason: "identifies the config row being edited"}
    {field: "AdminApplication.id", reason: "target of every admin action on the row"}
    {field: "UserEntitlement.application_id", reason: "the revoke target"}
    {field: "ApplicationGroup.id", reason: "target of every admin action on the row"}
    {field: "AdminFeedbackSummary.id", reason: "the row's detail / status target"}
    {field: "AdminFeedbackDetail.id", reason: "the respond / archive target"}
    {field: "FeedbackAttachmentMeta.id", reason: "the attachment proxy URL is built from it"}
    {field: "ArchivedFeedback.id", reason: "the row's detail target"}
    {field: "StripeProduct.id", reason: "product identifier posted back on edit"}
    {field: "StripePrice.id", reason: "price identifier posted back on edit"}
    {field: "StripePrice.product_id", reason: "groups the price under its product; a default would misgroup it"}
    {field: "StripeWebhookEndpoint.id", reason: "the delete target"}
    {field: "AppRestoreOutcome.status", reason: "a defaulted restore outcome would report a fake result"}
    {field: "PricingTier.amount", reason: "a defaulted 0 would advertise a price nobody is charged"}
    {field: "AppDoc.slug", reason: "the doc page's URL key"}
    {field: "AppDocSummary.slug", reason: "the doc page's URL key"}
    {field: "DocumentedApp.slug", reason: "the app docs link is built from it"}
]

# Every `Struct.field` of a `Deserialize` struct in `path` that carries no
# `#[serde(default...)]`. The `mod tests` block is out of scope.
def undefaulted-fields [path: string]: nothing -> list<string> {
    mut found = []
    mut current = null
    mut deserializable = false
    mut has_default = false

    for line in (open --raw $path | lines) {
        let t = ($line | str trim)
        if ($t | str starts-with "mod tests") { break }

        if ($t | str starts-with "#[derive") {
            $deserializable = ($t | str contains "Deserialize")
            continue
        }
        if ($t | str starts-with "pub struct ") {
            let name = ($t | parse --regex 'pub struct (?<name>\w+)' | get --optional 0.name)
            $current = (if $deserializable { $name } else { null })
            $has_default = false
            continue
        }
        if $current == null { continue }
        if $t == "}" {
            $current = null
            continue
        }
        if ($t | str starts-with "#[serde(") {
            if ($t | str contains "default") { $has_default = true }
            continue
        }
        let field = ($t | parse --regex '^pub (?<name>\w+):' | get --optional 0.name)
        if $field != null {
            if not $has_default {
                $found = ($found | append $"($current).($field)")
            }
            $has_default = false
        }
    }
    $found
}

# Problems found in `path`; an empty list means the file is compliant.
def check-types [path: string, essential: list<string>]: nothing -> list<string> {
    if not ($path | path exists) {
        return [$"($path): file not found"]
    }
    let found = (undefaulted-fields $path)
    let missing_default = ($found | where {|f| $f not-in $essential }
        | each {|f| $"($path): `($f)` has no `#[serde\(default)]` and is not in ESSENTIAL_FIELDS" })
    # A stale entry (renamed field, or one that has since gained a default) makes
    # the table lie about what is load-bearing, so it fails too.
    let stale = ($essential | where {|f| $f not-in $found }
        | each {|f| $"($path): ESSENTIAL_FIELDS lists `($f)`, which is not an undefaulted field of a Deserialize struct" })
    $missing_default | append $stale
}

# Prove the gate rejects what it claims to reject. Runs in CI next to the real
# check, so a gate that silently stopped detecting anything fails the build.
def self-test []: nothing -> nothing {
    let dir = (mktemp --directory --tmpdir)

    let undefaulted = $"($dir)/undefaulted.rs"
    "#[derive(Debug, Deserialize)]\npub struct Thing {\n    pub id: String,\n    pub tier: Tier,\n}\n" | save --force $undefaulted

    let defaulted = $"($dir)/defaulted.rs"
    "#[derive(Debug, Deserialize)]\npub struct Thing {\n    pub id: String,\n    #[serde(default)]\n    pub tier: Tier,\n    #[serde(default = \"default_true\")]\n    pub on: bool,\n}\n" | save --force $defaulted

    let not_deserialize = $"($dir)/not-deserialize.rs"
    "#[derive(Debug, Serialize)]\npub struct Outbound {\n    pub tier: Tier,\n}\n" | save --force $not_deserialize

    let cases = [
        {file: $undefaulted, essential: ["Thing.id"], expect_problems: true, why: "an undefaulted field missing from ESSENTIAL_FIELDS"}
        {file: $undefaulted, essential: ["Thing.id", "Thing.tier"], expect_problems: false, why: "an undefaulted field declared essential"}
        {file: $defaulted, essential: ["Thing.id"], expect_problems: false, why: "both spellings of #[serde(default)]"}
        {file: $defaulted, essential: ["Thing.id", "Thing.tier"], expect_problems: true, why: "a stale ESSENTIAL_FIELDS entry"}
        {file: $not_deserialize, essential: [], expect_problems: false, why: "a struct that is not deserialized"}
        {file: $"($dir)/absent.rs", essential: [], expect_problems: true, why: "a missing types file"}
    ]
    let results = ($cases | each {|c|
        let problems = (check-types $c.file $c.essential)
        {why: $c.why, ok: (($problems | is-not-empty) == $c.expect_problems), problems: $problems}
    })
    rm --recursive $dir

    for r in $results {
        if $r.ok {
            print $"self-test ok: gate handles ($r.why)"
        } else {
            print --stderr $"self-test FAILED: gate mis-handles ($r.why): ($r.problems | to nuon)"
        }
    }
    if ($results | any {|r| not $r.ok }) {
        exit 1
    }
}

def main [
    types_file: string = $TYPES_FILE # the response-model file to gate
    --self-test # prove the gate rejects an undefaulted field and a stale entry, then exit
]: nothing -> nothing {
    if $self_test {
        self-test
        return
    }

    let essential = ($ESSENTIAL_FIELDS | get field)
    let problems = (check-types $types_file $essential)
    if ($problems | is-not-empty) {
        for p in $problems { print --stderr $"error: ($p)" }
        print --stderr "error: every field of a Deserialize response struct needs `#[serde(default)]` or an ESSENTIAL_FIELDS entry (BUNYIP-506)"
        exit 1
    }

    print $"check-serde-compat: ($types_file) defaults every response field outside the ($essential | length) declared essential ones"
}
