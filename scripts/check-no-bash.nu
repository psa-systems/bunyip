#!/usr/bin/env nu

# Bash-free tooling gate (BUNYIP-490).
#
# Every script under scripts/ was rewritten in Nushell, which the repo already
# requires (docs/getting-started.md) and the runners already carry. Nothing
# enforces that mechanically, so a contributor reaching for `#!/usr/bin/env
# bash` out of habit would quietly reintroduce the shell this issue removed.
# This gate fails on any tracked shell script under scripts/, matched two ways:
# the .sh extension, and a POSIX-shell shebang under any filename.
#
# Usage: scripts/check-no-bash.nu [scripts_dir]
def main [scripts_dir: string = "scripts"] {
    mut failed = 0

    for file in (^git ls-files $scripts_dir | lines) {
        if ($file | path parse | get extension) == "sh" {
            print --stderr $"error: ($file): scripts/ is Nushell-only \(BUNYIP-490); write a .nu script with a '#!/usr/bin/env nu' shebang."
            $failed = 1
            continue
        }

        let lines = (try { open --raw $file | decode utf-8 | lines } catch { [] })
        let shebang = (if ($lines | is-empty) { "" } else { $lines | first })
        if ($shebang =~ '^#!.*\b(sh|bash|dash|zsh|ksh)\b') {
            print --stderr $"error: ($file):1: '($shebang)' - scripts/ is Nushell-only \(BUNYIP-490); use '#!/usr/bin/env nu'."
            $failed = 1
        }
    }

    if $failed != 0 {
        print --stderr ""
        print --stderr "The CI guards and operator scripts are Nushell (BUNYIP-490). Nushell 0.112.2"
        print --stderr "is a documented prerequisite (docs/getting-started.md) and is present on the"
        print --stderr "runners, so a shell script here is a fork of the toolchain, not a shortcut."
        exit 1
    }

    print "check-no-bash: no shell scripts under scripts/"
}
