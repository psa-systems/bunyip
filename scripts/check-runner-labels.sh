#!/usr/bin/env bash
# Runner-label gate (BUNYIP-444, BUNYIP-446, #CLAUDE-203, #GOV-43).
#
# The principle: the runner image provides the job's runtime dependencies, and a
# job requests the label of an image that has them. Installing them in a workflow
# step re-solves on every run and forks a package list the image already
# maintains; that is the workaround this gate exists to keep out.
#
# The dev image is the one that carries them. It has cc/gcc/ld and the OpenSSL
# headers (verified in ghcr.io/niceguyit/opensuse-dev:v1.7.0-leap-16.0: gcc-15,
# libopenssl-devel-3.5.0), and its dev stage installs the Playwright browser
# system libraries (X / GTK / NSS / glib) plus the pre-baked browser binaries.
# The base image ships cargo/rustc but no C toolchain, so a native cargo build
# there dies with `linker cc not found` on a cold cache, and a Playwright browser
# there dies at launch with `cannot open shared object file`.
#
# Three properties:
#   1. check.yml (native cargo fmt/clippy/build/test) requests the dev label.
#   2. no workflow installs a C toolchain, OpenSSL headers, or the browser system
#      libraries at run time.
#   3. every `runs-on:` carries a comment above it saying why that label is right;
#      an unannotated label is indistinguishable from an unaudited one.
#
# Usage: scripts/check-runner-labels.sh [workflows_dir]
set -euo pipefail

WORKFLOWS_DIR="${1:-.forgejo/workflows}"
CHECK_WORKFLOW="$WORKFLOWS_DIR/check.yml"

if [[ ! -f "$CHECK_WORKFLOW" ]]; then
    echo "error: expected workflow not found: $CHECK_WORKFLOW" >&2
    exit 2
fi

status=0

# 1. The native Rust job needs the dev image.
if ! grep --quiet --fixed-strings 'runs-on: ${{ vars.RUNS_ON_OPENSUSE_DEV_LATEST }}' "$CHECK_WORKFLOW"; then
    echo "error: $CHECK_WORKFLOW must run on RUNS_ON_OPENSUSE_DEV_LATEST; it compiles Rust natively and base has no C toolchain (BUNYIP-444)" >&2
    status=1
fi

# 2. No run-time toolchain install anywhere: that is the workaround, not the fix.
while IFS= read -r hit; do
    echo "error: $hit: installs a C toolchain / OpenSSL headers at run time; request RUNS_ON_OPENSUSE_DEV_LATEST instead (BUNYIP-444)" >&2
    status=1
done < <(grep --extended-regexp --recursive --line-number --no-messages \
    '(zypper|apt-get|dnf|yum).*(install).*( gcc| clang| binutils|libopenssl-devel|openssl-devel|build-essential)' \
    "$WORKFLOWS_DIR" | grep --invert-match --extended-regexp '^[^:]+:[0-9]+:[[:space:]]*#')

# 2b. Same rule for the Playwright browser system libraries. Matched by package
# name rather than by `<pm> install ...`, because a folded YAML command puts the
# package list on continuation lines the package manager never appears on.
while IFS= read -r hit; do
    echo "error: $hit: installs the Playwright browser system libraries at run time; request RUNS_ON_OPENSUSE_DEV_LATEST instead, its image pre-bakes them (BUNYIP-446)" >&2
    status=1
done < <(grep --extended-regexp --recursive --line-number --no-messages \
    '(libgtk-3-0|libgobject-2_0-0|libglib-2_0-0|mozilla-nss|mozilla-nspr|libatk-1_0-0|libasound2|libgbm1|libxkbcommon0)' \
    "$WORKFLOWS_DIR" | grep --invert-match --extended-regexp '^[^:]+:[0-9]+:[[:space:]]*#')

# 3. Every label is annotated with its reason.
while IFS= read -r hit; do
    file="${hit%%:*}"
    line="${hit#*:}"
    line="${line%%:*}"
    prev=""
    for ((n = line - 1; n > 0; n--)); do
        candidate="$(sed --quiet "${n}p" "$file")"
        [[ -z "${candidate//[[:space:]]/}" ]] && continue
        prev="$candidate"
        break
    done
    if [[ ! "$prev" =~ ^[[:space:]]*# ]]; then
        echo "error: $file:$line: 'runs-on' has no comment above it stating why this runner label is correct (BUNYIP-444)" >&2
        status=1
    fi
done < <(grep --extended-regexp --recursive --line-number --no-messages \
    '^[[:space:]]*runs-on:' "$WORKFLOWS_DIR")

if [[ "$status" -eq 0 ]]; then
    echo "runner labels OK: native check on dev, every label annotated, no run-time install of what the image provides"
fi

exit "$status"
