#!/usr/bin/env bash
# Migration version-number gate (BUNYIP-79).
#
# sqlx orders and identifies migrations by the leading numeric version of the
# filename (the digits before the first underscore), NOT by the 3-digit "index"
# suffix humans read. Parallel feature branches reused those suffixes
# (010/020/040/041/042) across different dates, which is harmless to sqlx but
# misleads anyone reading migration order. This gate enforces the only property
# that actually matters and that prevents a real collision: every migration's
# numeric version is well-formed, UNIQUE, and STRICTLY INCREASING in filename
# order. A duplicate version (two files sqlx would treat as the same migration)
# or an out-of-order version fails CI before it can merge.
#
# Gaps are allowed: a deleted seed (e.g. the position-8 gap from the removed
# 20241230000008_seed_applications.sql) leaves a hole in the sequence but breaks
# nothing, so this gate does not require contiguity.
#
# Usage: scripts/check-migration-versions.sh [migrations_dir]
set -euo pipefail

MIGRATIONS_DIR="${1:-bunyip-api/migrations}"

if [[ ! -d "$MIGRATIONS_DIR" ]]; then
    echo "error: migrations dir not found: $MIGRATIONS_DIR" >&2
    exit 2
fi

status=0
prev_version=""
prev_file=""

# Iterate in lexical filename order, which (for fixed-width 14-digit versions)
# equals numeric version order.
while IFS= read -r path; do
    file="$(basename "$path")"
    version="${file%%_*}"

    if ! [[ "$version" =~ ^[0-9]{14}$ ]]; then
        echo "error: $file: version prefix '$version' is not a 14-digit YYYYMMDDHHMMSS stamp" >&2
        status=1
        continue
    fi

    if [[ -n "$prev_version" ]]; then
        if [[ "$version" == "$prev_version" ]]; then
            echo "error: duplicate migration version $version: '$prev_file' and '$file' collide (sqlx would treat them as one migration)" >&2
            status=1
        elif [[ "$version" < "$prev_version" ]]; then
            echo "error: migration versions out of order: '$file' ($version) sorts after '$prev_file' ($prev_version) by name but is numerically smaller" >&2
            status=1
        fi
    fi

    prev_version="$version"
    prev_file="$file"
done < <(find "$MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' | sort)

if [[ "$status" -eq 0 ]]; then
    echo "migration versions OK: unique and strictly increasing"
fi

exit "$status"
