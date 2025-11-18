#!/bin/bash

set -e

# ---------------------------
# Check for root
# ---------------------------
if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo ./cleanup.sh"
    exit 1
fi

echo "=== vpnet TAP Cleanup ==="
echo

# ---------------------------
# Check if tap0 exists
# ---------------------------
if ! ip link show tap0 &> /dev/null; then
    echo "tap0 does not exist — nothing to clean."
    exit 0
fi

echo "[*] Found tap0 → Removing..."

# Bring tap0 down
ip link set tap0 down || true

# Delete TAP
ip tuntap del dev tap0 mode tap || true

echo "[*] tap0 deleted successfully."
echo
echo "=== DONE ==="