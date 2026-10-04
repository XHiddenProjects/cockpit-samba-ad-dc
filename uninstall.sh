#!/usr/bin/env bash
# Uninstall extensions: ./uninstall.sh samba-adc   (or --all). Same options as install.sh.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh" "$@" --uninstall
