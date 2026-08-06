#!/usr/bin/env nu

# Refresh the offline IP2Location / IP2Proxy LITE .BIN datasets (BUNYIP-474).
#
# bunyip reads these files at the paths IP2LOCATION_DB_PATH (login-country geoip)
# and IP2PROXY_DB_PATH (ASN / VPN enrichment). The library never fetches them;
# this script keeps them fresh. IP2Location LITE rebuilds monthly, so run this on
# a monthly schedule (cron / scheduled job). The admin dashboard "Datasets" card
# shows each file's age, so a missed run is visible.
#
# Requirements: nu, curl, unzip, and a free IP2Location download token.
#
# Environment:
#   IP2LOCATION_TOKEN  (required)          the IP2Location download token
#   DATASET_DIR        (default /data)     directory to install the .BIN files in
#   DATASETS           (default "PX11 DB11") which LITE datasets to refresh:
#                                          PX11 -> IP2PROXY-LITE-PX11.BIN
#                                          DB11 -> IP2LOCATION-LITE-DB11.BIN
#
# Point IP2PROXY_DB_PATH at $DATASET_DIR/IP2PROXY-LITE-PX11.BIN and
# IP2LOCATION_DB_PATH at $DATASET_DIR/IP2LOCATION-LITE-DB11.BIN.
#
# Exits non-zero if any requested dataset fails, so a scheduler surfaces it. Each
# file is installed atomically (download to a temp dir, then a same-directory
# rename), so a partial download never replaces a good file and readers never see
# a half-written .BIN.

# Map a short dataset id to its download-file code and installed filename.
def resolve [id: string]: nothing -> record {
    match $id {
        "PX11" => { code: "PX11LITEBIN", name: "IP2PROXY-LITE-PX11.BIN" }
        "DB11" => { code: "DB11LITEBIN", name: "IP2LOCATION-LITE-DB11.BIN" }
        _ => { code: "", name: "" }
    }
}

# Fetch and install one dataset. Returns true on success.
def refresh-one [id: string, token: string, dataset_dir: string, tmp: string]: nothing -> bool {
    let spec = (resolve $id)
    if ($spec.code | is-empty) {
        print --stderr $"refresh: unknown dataset id '($id)' \(known: PX11 DB11)"
        return false
    }
    print $"refresh: fetching ($id) -> ($spec.name)"

    let zip = $"($tmp)/($id).zip"
    # --fail turns an HTTP error into a non-zero exit (it is a fail-fast flag,
    # not a destructive one); the download endpoint answers 200 with an error
    # page on a bad token, so the zip integrity check below is the real gate.
    let url = $"https://www.ip2location.com/download/?token=($token)&file=($spec.code)"
    let download = (^curl --fail --silent --show-error --location $url --output $zip | complete)
    if $download.exit_code != 0 {
        print --stderr $"refresh:   download failed for ($id)"
        return false
    }
    if (^unzip -tq $zip | complete).exit_code != 0 {
        print --stderr $"refresh:   downloaded file is not a valid zip for ($id) \(bad token or quota exhausted?)"
        return false
    }

    let listing = (^unzip -Z1 $zip | complete)
    let bins = (
        if $listing.exit_code == 0 { $listing.stdout | lines } else { [] }
        | where {|entry| $entry =~ '(?i)\.BIN$' }
    )
    if ($bins | is-empty) {
        print --stderr $"refresh:   no .BIN inside the ($id) archive"
        return false
    }
    let bin = ($bins | first)

    # Extract into a fresh per-id subdir (no existing files, so no overwrite),
    # then stage in the destination directory and rename into place atomically.
    let outdir = $"($tmp)/($id)"
    mkdir $outdir
    ^unzip -j $zip $bin -d $outdir | ignore
    let staged = $"($dataset_dir)/.($spec.name).staged.($nu.pid)"
    mv $"($outdir)/($bin | path basename)" $staged
    mv $staged $"($dataset_dir)/($spec.name)"
    print $"refresh:   installed ($dataset_dir)/($spec.name)"
    true
}

def main [] {
    let token = ($env.IP2LOCATION_TOKEN? | default "")
    if ($token | is-empty) {
        print --stderr "IP2LOCATION_TOKEN is required (free IP2Location account token)"
        exit 1
    }
    let dataset_dir = ($env.DATASET_DIR? | default "/data")
    let datasets = ($env.DATASETS? | default "PX11 DB11" | split row --regex '\s+' | where {|d| $d | is-not-empty })

    for required in ["curl" "unzip"] {
        if (which $required | is-empty) {
            print --stderr $"refresh: ($required) not found"
            exit 1
        }
    }
    mkdir $dataset_dir

    let tmp = (mktemp --directory)
    # Recursive (not forced) cleanup of our own temp dir; tolerate an
    # already-gone dir. `try` stands in for the shell's EXIT trap: it runs
    # whether the loop succeeded, failed, or raised.
    let results = (try {
        $datasets | each {|id| refresh-one $id $token $dataset_dir $tmp }
    } catch {|err|
        print --stderr $"refresh: ($err.msg)"
        [false]
    })
    try { rm --recursive $tmp }

    if ($results | any {|ok| not $ok }) {
        print --stderr "refresh: one or more datasets failed"
        exit 1
    }
}
