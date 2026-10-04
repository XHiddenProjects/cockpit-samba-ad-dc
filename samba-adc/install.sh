#!/usr/bin/env bash
#
# Installer for the "Samba AD DC" Cockpit module.
#
#   sudo ./install.sh                 install system-wide (/usr/share/cockpit/samba-adc)
#        ./install.sh --user          install for the current user only (~/.local/share/cockpit)
#   sudo ./install.sh --with-deps     also apt-install the helper packages the module uses
#        ./install.sh --check         only run the pre-flight checks, change nothing
#        ./install.sh --dev           symlink to this checkout instead of copying (development)
#   sudo ./install.sh --uninstall     remove it again (same as ./uninstall.sh)
#
# Run ./install.sh --help for all options.
set -euo pipefail

EXT="samba-adc"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_VERSION="$(tr -d '[:space:]' < "$SRC/VERSION" 2>/dev/null || echo unknown)"

# Only these files are needed at runtime. Tests, tools and docs stay in the repo.
RUNTIME_FILES=(
  manifest.json index.html style.css
  samba-adc.js gpo-core.js gpo-builtin.js gpo-catalogs.js gpo-ui.js sharing-ui.js
  gpo_backend.py sharing_diag.py
  vendor/xlsx.core.min.js vendor/XLSX-LICENSE.txt
)

MODE="install"; SCOPE="system"; PREFIX=""; DEV=0; DEPS=0; ASSUME_YES=0; PURGE=0

usage() {
  cat <<USAGE
Samba AD DC Cockpit module $MODULE_VERSION - installer

Usage: $0 [options]

  --user            Install for the current user (~/.local/share/cockpit). No root needed;
                    privileged actions inside the page still use Cockpit's normal sudo prompt.
  --prefix DIR      Install into DIR/$EXT instead of /usr/share/cockpit/$EXT.
  --dev             Symlink DIR/$EXT to this checkout instead of copying (for development).
  --with-deps       apt-get install the helper packages (cockpit, python3, smbclient,
                    ldb-tools, acl, attr). Does NOT install or configure Samba itself.
  --check           Run the pre-flight checks only; change nothing.
  --uninstall       Remove the module (see also ./uninstall.sh).
  --purge           With --uninstall: also remove the systemd drop-in the module may have
                    created for wsdd2. Never touches GPOs, SYSVOL or smb.conf.
  -y, --yes         Do not ask for confirmation.
  -h, --help        Show this help.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --user) SCOPE="user" ;;
    --prefix) shift; PREFIX="${1:?--prefix needs a directory}" ;;
    --prefix=*) PREFIX="${1#*=}" ;;
    --dev) DEV=1 ;;
    --with-deps) DEPS=1 ;;
    --check) MODE="check" ;;
    --uninstall) MODE="uninstall" ;;
    --purge) PURGE=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ -n "$PREFIX" ]; then BASE="$PREFIX"
elif [ "$SCOPE" = "user" ]; then BASE="${XDG_DATA_HOME:-$HOME/.local/share}/cockpit"
else BASE="/usr/share/cockpit"; fi
DEST="$BASE/$EXT"

# A system-wide install/uninstall writes to /usr/share, so say so up front rather than half-way through.
if [ "$MODE" != "check" ] && [ -z "$PREFIX" ] && [ "$SCOPE" = "system" ] && [ "$(id -u)" -ne 0 ]; then
  echo "This writes to $BASE and needs root. Re-run with sudo, or use --user to install for your own account." >&2
  exit 1
fi

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'; else G=""; Y=""; R=""; B=""; N=""; fi
ok()   { echo "  ${G}ok${N}    $*"; }
warn() { echo "  ${Y}warn${N}  $*"; WARNINGS=$((WARNINGS+1)); }
bad()  { echo "  ${R}FAIL${N}  $*"; FAILURES=$((FAILURES+1)); }
WARNINGS=0; FAILURES=0

confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || return 0
  read -r -p "$1 [Y/n] " a; case "${a:-Y}" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

need_root() {
  if [ -n "$PREFIX" ] || [ "$SCOPE" = "user" ]; then return 0; fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "${R}This needs root to write to $BASE.${N} Re-run with sudo, or use --user." >&2
    exit 1
  fi
}

# ------------------------------------------------------------------ uninstall
if [ "$MODE" = "uninstall" ]; then
  need_root
  echo "${B}Removing $EXT from $BASE${N}"
  if [ -L "$DEST" ]; then
    rm -f "$DEST"; ok "removed symlink $DEST"
  elif [ -d "$DEST" ]; then
    # Refuse to delete a directory that is not ours.
    if grep -q "\"name\": *\"$EXT\"" "$DEST/manifest.json" 2>/dev/null; then
      rm -rf "$DEST"; ok "removed $DEST"
    else
      echo "${R}$DEST does not look like this module (manifest.json name mismatch). Not removing it.${N}" >&2; exit 1
    fi
  else
    ok "nothing to remove at $DEST"
  fi
  if [ "$PURGE" = 1 ]; then
    DROP=/etc/systemd/system/wsdd2.service.d/samba-ad-dc.conf
    if [ -f "$DROP" ] && [ "$(id -u)" -eq 0 ]; then
      rm -f "$DROP"; rmdir /etc/systemd/system/wsdd2.service.d 2>/dev/null || true
      if command -v systemctl >/dev/null; then systemctl daemon-reload || true; fi
      ok "removed $DROP"
    fi
  fi
  cat <<NOTE

Left in place on purpose (these belong to your domain, not to the module):
  - GPOs and everything in SYSVOL, including any ADMX templates in the Central Store
  - /etc/samba/smb.conf and any shares or ACLs you created
  - /etc/systemd/system/wsdd2.service.d/samba-ad-dc.conf (use --purge to remove)
NOTE
  exit 0
fi

# ------------------------------------------------------------------ pre-flight
echo "${B}Samba AD DC Cockpit module $MODULE_VERSION${N}  ->  $DEST"
echo "Pre-flight checks:"

# the files we are about to install must all exist in this checkout
for f in "${RUNTIME_FILES[@]}"; do
  [ -f "$SRC/$f" ] || bad "missing file in this checkout: $f"
done
if [ "$FAILURES" -eq 0 ]; then ok "all ${#RUNTIME_FILES[@]} module files present"; fi

if [ -r /etc/os-release ]; then
  # read in a subshell so os-release variables (VERSION, ID, ...) cannot clobber ours
  OS_ID="$( . /etc/os-release; echo "${ID:-}${ID_LIKE:-}" )"
  OS_NAME="$( . /etc/os-release; echo "${PRETTY_NAME:-unknown}" )"
  case "$OS_ID" in
    *debian*|*ubuntu*) ok "OS: $OS_NAME" ;;
    *) warn "OS is $OS_NAME; the module targets Debian 13 (Ubuntu works, others untested)" ;;
  esac
fi

if [ "$DEPS" = 1 ] && [ "$MODE" = "install" ]; then
  need_root
  if command -v apt-get >/dev/null; then
    echo "Installing helper packages with apt-get ..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y cockpit python3 smbclient ldb-tools acl attr
  else
    warn "--with-deps is only supported on apt-based systems"
  fi
fi

COCKPIT_SHARE="${COCKPIT_SHARE:-/usr/share/cockpit}"   # where Cockpit's own files live (override for testing)
if command -v cockpit-bridge >/dev/null || [ -f "$COCKPIT_SHARE/base1/cockpit.js" ]; then
  CV="$(cockpit-bridge --version 2>/dev/null | sed -n 's/.*[Vv]ersion[: ]*\([0-9]\+\).*/\1/p' | head -n1 || true)"
  if [ -z "$CV" ] && command -v dpkg-query >/dev/null; then CV="$(dpkg-query -W -f='${Version}' cockpit-bridge 2>/dev/null | sed 's/[^0-9].*//' || true)"; fi
  if [ -z "$CV" ]; then ok "Cockpit found (version not detected)"
  elif [ "$CV" -ge 250 ]; then ok "Cockpit $CV (needs >= 250)"
  else bad "Cockpit $CV is older than the required 250"; fi
elif [ -n "$PREFIX" ]; then
  warn "Cockpit is not installed on this machine (fine when installing into a custom --prefix, e.g. for packaging)"
else
  bad "Cockpit is not installed. Install it (apt install cockpit) or run with --with-deps."
fi

if command -v python3 >/dev/null; then ok "python3 present"; else bad "python3 is required for the Group Policy and diagnostics helpers"; fi
if command -v samba-tool >/dev/null; then
  ok "samba-tool present"
  if python3 -c 'import samba, ldb' 2>/dev/null; then ok "Samba Python modules importable (needed by gpo_backend.py)"
  else warn "python3 cannot import samba/ldb; the Group Policy editor needs python3-samba (installed with samba-ad-dc)"; fi
else
  warn "samba-tool not found. Fine if this is a staging machine, but the module needs a Samba AD DC to do anything."
fi
if command -v smbclient >/dev/null; then ok "smbclient present"; else warn "smbclient missing: the 'Test access' / sign-in test will not work (apt install smbclient)"; fi
if command -v ldbsearch >/dev/null; then ok "ldbsearch present"; else warn "ldbsearch missing (apt install ldb-tools); user lists fall back to a slower method"; fi
if command -v msiextract >/dev/null; then ok "msitools present"; else echo "  info  msitools not installed; it is installed on demand when you download Microsoft's ADMX templates"; fi

echo
if [ "$FAILURES" -gt 0 ]; then echo "${R}$FAILURES blocking problem(s).${N} Fix them and re-run."; exit 1; fi
if [ "$WARNINGS" -gt 0 ]; then echo "${Y}$WARNINGS warning(s)${N} (non-blocking)."; fi
if [ "$MODE" = "check" ]; then echo "Pre-flight OK. Nothing was changed."; exit 0; fi

# ------------------------------------------------------------------ install
need_root
confirm "Install to $DEST?" || { echo "Aborted."; exit 1; }
mkdir -p "$BASE"

if [ "$DEV" = 1 ]; then
  rm -rf "$DEST"
  ln -s "$SRC" "$DEST"
  ok "symlinked $DEST -> $SRC (edits are live; reload the browser tab)"
else
  STAGE="$(mktemp -d "$BASE/.${EXT}.new.XXXXXX")"
  trap 'rm -rf "$STAGE"' EXIT
  for f in "${RUNTIME_FILES[@]}"; do
    mkdir -p "$STAGE/$(dirname "$f")"
    cp "$SRC/$f" "$STAGE/$f"
  done
  find "$STAGE" -type d -exec chmod 755 {} +
  find "$STAGE" -type f -exec chmod 644 {} +
  if [ "$(id -u)" -eq 0 ]; then chown -R root:root "$STAGE"; fi
  # swap in atomically so a half-copied module is never visible to Cockpit
  if [ -e "$DEST" ] || [ -L "$DEST" ]; then
    OLD="$BASE/.${EXT}.old.$$"; mv "$DEST" "$OLD"; mv "$STAGE" "$DEST"; rm -rf "$OLD"
  else
    mv "$STAGE" "$DEST"
  fi
  trap - EXIT
  ok "installed $MODULE_VERSION to $DEST"
fi

cat <<DONE

${G}Done.${N} Open Cockpit (https://<this-host>:9090) and look for "Samba AD DC" in the menu.
If it is not there yet, hard-refresh the browser (Ctrl+Shift+R). No Cockpit restart is needed.

First things to try:
  Group Policy  ->  "Health check", then "Templates..." to install the Windows 11 policy set
  Configuration ->  "File sharing & network discovery" -> "Run diagnostics"
DONE
