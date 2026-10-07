#!/usr/bin/env bash

set -euo pipefail

# If executed via sudo or as root, drop privileges back to the actual user
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    exec sudo -u "$SUDO_USER" "$0" "$@"
elif [ "$(id -u)" -eq 0 ]; then
    echo "Error: Do not run this script directly as root." >&2
    exit 1
fi

# Target paths (now guaranteed to run in the target user context)
VAULT_DIR="$HOME/.local/share/sfm/vault"
LOG_DIR="$HOME/.local/state/sfm"
LOG_FILE="$LOG_DIR/sfm.log"
CONFIG_DIR="$HOME/.config/sfm"
CONFIG_FILE="$CONFIG_DIR/sfm.config"

# Create directories with user permissions
mkdir -p "$VAULT_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$CONFIG_DIR"

# Ensure log file exists
touch "$LOG_FILE"

# Create sfm.config JSON blueprint
cat <<EOF > "$CONFIG_FILE"
{
  "kdf": "argon2id",
  "salt": "",
  "verifier": "",
  "vault": "$VAULT_DIR/",
  "log": "$LOG_FILE",
  "config": "$CONFIG_FILE"
}
EOF

echo "Initialization complete for user: $(whoami)"
echo "  Vault directory: $VAULT_DIR"
echo "  Log file:        $LOG_FILE"
echo "  Config file:     $CONFIG_FILE"