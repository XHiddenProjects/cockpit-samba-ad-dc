#!/usr/bin/env bash
# Removes the Samba AD DC Cockpit module. Accepts the same options as install.sh
# (--user, --prefix DIR, --purge, --yes).
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh" --uninstall "$@"
