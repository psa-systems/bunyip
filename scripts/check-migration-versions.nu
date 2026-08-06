#!/usr/bin/env nu

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
# Usage: scripts/check-migration-versions.nu [migrations_dir]
def main [migrations_dir: string = "bunyip-api/migrations"] {
    if ($migrations_dir | path type) != "dir" {
        print --stderr $"error: migrations dir not found: ($migrations_dir)"
        exit 2
    }

    mut status = 0
    mut prev_version = ""
    mut prev_file = ""

    # Iterate in lexical filename order, which (for fixed-width 14-digit
    # versions) equals numeric version order.
    for file in (glob $"($migrations_dir)/*.sql" | path basename | sort) {
        let version = ($file | split row "_" | first)

        if not ($version =~ '^[0-9]{14}$') {
            print --stderr $"error: ($file): version prefix '($version)' is not a 14-digit YYYYMMDDHHMMSS stamp"
            $status = 1
            continue
        }

        if ($prev_version | is-not-empty) {
            if $version == $prev_version {
                print --stderr $"error: duplicate migration version ($version): '($prev_file)' and '($file)' collide \(sqlx would treat them as one migration)"
                $status = 1
            } else if $version < $prev_version {
                print --stderr $"error: migration versions out of order: '($file)' \(($version)) sorts after '($prev_file)' \(($prev_version)) by name but is numerically smaller"
                $status = 1
            }
        }

        $prev_version = $version
        $prev_file = $file
    }

    if $status == 0 {
        print "migration versions OK: unique and strictly increasing"
    }

    exit $status
}
