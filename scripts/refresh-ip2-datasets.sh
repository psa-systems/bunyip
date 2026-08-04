#!/bin/sh
# Refresh the offline IP2Location / IP2Proxy LITE .BIN datasets (BUNYIP-474).
#
# bunyip reads these files at the paths IP2LOCATION_DB_PATH (login-country geoip)
# and IP2PROXY_DB_PATH (ASN / VPN enrichment). The library never fetches them;
# this script keeps them fresh. IP2Location LITE rebuilds monthly, so run this on
# a monthly schedule (cron / scheduled job). The admin dashboard "Datasets" card
# shows each file's age, so a missed run is visible.
#
# Requirements: curl, unzip, and a free IP2Location download token.
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
set -eu

: "${IP2LOCATION_TOKEN:?IP2LOCATION_TOKEN is required (free IP2Location account token)}"
DATASET_DIR="${DATASET_DIR:-/data}"
DATASETS="${DATASETS:-PX11 DB11}"

# Map a short dataset id to "<download-file-code> <installed-filename>".
resolve() {
  case "$1" in
    PX11) echo "PX11LITEBIN IP2PROXY-LITE-PX11.BIN" ;;
    DB11) echo "DB11LITEBIN IP2LOCATION-LITE-DB11.BIN" ;;
    *) echo "" ;;
  esac
}

command -v curl >/dev/null 2>&1 || { echo "refresh: curl not found" >&2; exit 1; }
command -v unzip >/dev/null 2>&1 || { echo "refresh: unzip not found" >&2; exit 1; }
mkdir -p "$DATASET_DIR"

tmp="$(mktemp -d)"
# Recursive (not forced) cleanup of our own temp dir; tolerate an already-gone dir.
trap 'rm -r "$tmp" 2>/dev/null || true' EXIT

status=0
for id in $DATASETS; do
  spec="$(resolve "$id")"
  if [ -z "$spec" ]; then
    echo "refresh: unknown dataset id '$id' (known: PX11 DB11)" >&2
    status=1
    continue
  fi
  code="${spec%% *}"
  name="${spec##* }"
  echo "refresh: fetching $id -> $name"

  zip="$tmp/$id.zip"
  # curl --fail turns an HTTP error into a non-zero exit (it is a fail-fast flag,
  # not a destructive one); the download endpoint answers 200 with an error page
  # on a bad token, so the zip integrity check below is the real gate.
  if ! curl -fsSL "https://www.ip2location.com/download/?token=${IP2LOCATION_TOKEN}&file=${code}" -o "$zip"; then
    echo "refresh:   download failed for $id" >&2
    status=1
    continue
  fi
  if ! unzip -tq "$zip" >/dev/null 2>&1; then
    echo "refresh:   downloaded file is not a valid zip for $id (bad token or quota exhausted?)" >&2
    status=1
    continue
  fi

  bin="$(unzip -Z1 "$zip" | grep -i '\.BIN$' | head -n1 || true)"
  if [ -z "$bin" ]; then
    echo "refresh:   no .BIN inside the $id archive" >&2
    status=1
    continue
  fi

  # Extract into a fresh per-id subdir (no existing files, so no overwrite), then
  # stage in the destination directory and rename into place atomically.
  outdir="$tmp/$id"
  mkdir -p "$outdir"
  unzip -j "$zip" "$bin" -d "$outdir" >/dev/null
  staged="$DATASET_DIR/.$name.staged.$$"
  mv "$outdir/$(basename "$bin")" "$staged"
  mv "$staged" "$DATASET_DIR/$name"
  echo "refresh:   installed $DATASET_DIR/$name"
done

if [ "$status" -ne 0 ]; then
  echo "refresh: one or more datasets failed" >&2
fi
exit "$status"
