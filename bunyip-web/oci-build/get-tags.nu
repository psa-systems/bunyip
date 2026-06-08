#!/usr/bin/env nu

# Get image tags for the release pipeline.
#
# Version tags are IMMUTABLE: a `vX.Y.Z` image tag is published ONLY when the
# build is a tag event - in CI when $GITHUB_REF is `refs/tags/vX.Y.Z`, and
# locally when HEAD sits exactly on a `v*` tag. Branch builds (main, feature-*,
# workflow_dispatch) publish ONLY `latest`, so a routine push can never
# overwrite an already-released version tag (BUNYIP-59). Version-tagged images
# therefore come exclusively from the `v*` tag push that create-release makes.
#
# When used as a module (`use get-tags.nu`), returns list<string>.
# When run as a script, use --joined to get comma-separated output suitable for
# capturing in a subprocess.
export def main [
    --joined(-j)  # Output as comma-separated string instead of a list
] {
    use std log

    # The CI ref is authoritative for the event type; fall back to an
    # exact-tag check for local / manual runs where GITHUB_REF is unset.
    let ci_ref = ($env.GITHUB_REF? | default "")
    let tag = if ($ci_ref | str starts-with "refs/tags/") {
        # CI tag event: this is the release build.
        $ci_ref | str replace "refs/tags/" ""
    } else if ($ci_ref | is-empty) {
        # Local / manual run with no CI ref: emit a version tag only when HEAD
        # is exactly on a tag.
        let exact = (do { ^git describe --tags --exact-match HEAD } | complete)
        if $exact.exit_code == 0 { $exact.stdout | str trim } else { "" }
    } else {
        # CI branch build (refs/heads/...): never a version tag, even if the
        # commit happens to coincide with a tag - keeps release tags immutable.
        ""
    }

    let tags = if ($tag | str starts-with "v") {
        log info $"[get-tags] Tag build. Resolved tags: [($tag), latest]"
        [$tag, "latest"]
    } else {
        log info "[get-tags] Non-tag build. Resolved tags: [latest]"
        ["latest"]
    }

    if $joined { $tags | str join "," } else { $tags }
}
