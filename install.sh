#!/usr/bin/env bash
#
# Install one or more extensions from this repository.
#
#   sudo ./install.sh --list                 show the available extensions
#   sudo ./install.sh samba-adc              install one (any option below is passed through)
#   sudo ./install.sh --all                  install every extension
#        ./install.sh samba-adc --user       install for the current user only
#        ./install.sh samba-adc --check      pre-flight checks only
#   sudo ./install.sh samba-adc --uninstall
#
# Each extension also has its own install.sh and can be used standalone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

extensions() {
  local d
  for d in "$ROOT"/*/; do
    d="${d%/}"
    if [ -f "$d/manifest.json" ] && [ -f "$d/install.sh" ]; then basename "$d"; fi
  done
}

usage() {
  cat <<USAGE
Usage: $0 [--list | --all | <extension>...] [options passed to the extension's installer]

Extensions in this repository:
$(extensions | sed 's/^/  - /')

Common options: --user  --prefix DIR  --dev  --with-deps  --check  --uninstall  --purge  -y
Run '$0 <extension> --help' for the full list.
USAGE
}

if [ $# -eq 0 ]; then usage; exit 0; fi

selected=(); passthrough=(); all=0
while [ $# -gt 0 ]; do
  a="$1"; shift
  case "$a" in
    --list) extensions; exit 0 ;;
    --all) all=1 ;;
    -h|--help) if [ ${#selected[@]} -eq 0 ] && [ "$all" = 0 ]; then usage; exit 0; else passthrough+=("$a"); fi ;;
    --prefix) passthrough+=("$a" "${1:?--prefix needs a directory}"); shift ;;   # takes a value: do not mistake it for an extension
    -*) passthrough+=("$a") ;;
    *) selected+=("$a") ;;
  esac
done

if [ "$all" = 1 ]; then mapfile -t selected < <(extensions); fi
if [ ${#selected[@]} -eq 0 ]; then echo "No extension named. Use --list to see the options." >&2; exit 2; fi

for e in "${selected[@]}"; do
  if [ ! -x "$ROOT/$e/install.sh" ]; then echo "Unknown extension: $e (see --list)" >&2; exit 2; fi
done
for e in "${selected[@]}"; do
  echo "=== $e ==="
  "$ROOT/$e/install.sh" "${passthrough[@]}"
done
