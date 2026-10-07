#!/usr/bin/env bash

set -euo pipefail

# If executed via sudo or as root, drop privileges back to the actual user
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    exec sudo -u "$SUDO_USER" "$0" "$@"
elif [ "$(id -u)" -eq 0 ]; then
    echo "Error: Do not run this script directly as root." >&2
    exit 1
fi

# Target directory paths
SFM_DATA_DIR="$HOME/.local/share/sfm"
SFM_STATE_DIR="$HOME/.local/state/sfm"
SFM_CONFIG_DIR="$HOME/.config/sfm"

# Permanently delete all sfm directories and contents
rm -rf "$SFM_DATA_DIR"
rm -rf "$SFM_STATE_DIR"
rm -rf "$SFM_CONFIG_DIR"

echo "Reset complete for user: $(whoami)"
echo "Permanently removed:"
echo "  - $SFM_DATA_DIR"
echo "  - $SFM_STATE_DIR"
echo "  - $SFM_CONFIG_DIR"