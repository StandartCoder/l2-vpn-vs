#!/bin/bash

set -e

# ---------------------------
# Check for root
# ---------------------------
if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo ./setup.sh"
    exit 1
fi

echo "=== vpnet TAP Setup ==="
echo
echo "This will create: tap0 (10.10.0.X/24)"
echo

# ---------------------------
# Ask for last octet
# ---------------------------
read -p "Enter desired host IP (1-255): " HOST

# Validate numeric
if ! [[ "$HOST" =~ ^[0-9]+$ ]]; then
    echo "Error: Not a number"
    exit 1
fi

# Validate range
if (( HOST < 1 || HOST > 255 )); then
    echo "Error: IP must be 1–255"
    exit 1
fi

IP="10.10.0.$HOST"

echo
echo "Using TAP = tap0"
echo "Using IP  = $IP/24"
echo

# ---------------------------
# Clean old tap0 if exists
# ---------------------------
if ip link show tap0 &> /dev/null; then
    echo "[*] tap0 already exists — deleting old one"
    ip link set tap0 down || true
    ip tuntap del dev tap0 mode tap || true
fi

# ---------------------------
# Create TAP
# ---------------------------
echo "[*] Creating tap0"
ip tuntap add dev tap0 mode tap

echo "[*] Bringing tap0 up"
ip link set tap0 up

echo "[*] Setting MTU to 1400 on tap0"
ip link set dev tap0 mtu 1400

echo "[*] Assigning IP $IP/24"
ip addr add "$IP/24" dev tap0

echo
echo "=== DONE ==="
ip addr show tap0
echo
echo "You can now run vportd with: sudo ./vportd <server_ip> <server_port> tap0"
