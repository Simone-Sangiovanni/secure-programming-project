#!/usr/bin/env bash
set -euo pipefail
rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/sfm" \
       "${XDG_DATA_HOME:-$HOME/.local/share}/sfm" \
       "${XDG_STATE_HOME:-$HOME/.local/state}/sfm"
echo "Cleared sfm config, vault, and log directories."
