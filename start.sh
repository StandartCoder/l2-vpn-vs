#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS_NAME="$(uname -s)"

echo "=== vpnet Starter ==="
echo
echo "1) Client  (vportd, Linux/macOS)"
echo "2) Server  (switchd, Linux only)"
echo
read -p "Select mode [1/2]: " MODE

if [[ "$MODE" != "1" && "$MODE" != "2" ]]; then
    echo "Invalid selection."
    exit 1
fi

if [[ "$MODE" == "2" ]]; then
    # -------------------------------
    # SERVER MODE (switchd, Linux only)
    # -------------------------------
    if [[ "$OS_NAME" != "Linux" ]]; then
        echo "Server mode is currently supported on Linux only."
        exit 1
    fi

    SWITCHD_BIN="$SCRIPT_DIR/build/src/switchd"
    if [[ ! -x "$SWITCHD_BIN" ]]; then
        # Try local binary in repo root as fallback
        if [[ -x "$SCRIPT_DIR/switchd" ]]; then
            SWITCHD_BIN="$SCRIPT_DIR/switchd"
        else
            echo "Error: switchd binary not found or not executable."
            echo "Looked for:"
            echo "  $SCRIPT_DIR/build/src/switchd"
            echo "  $SCRIPT_DIR/switchd"
            echo "Run ./build.sh first to build the binaries."
            exit 1
        fi
    fi

    echo
    echo "=== switchd Setup (Linux) ==="

    if command -v openssl >/dev/null 2>&1; then
        PSK="$(openssl rand -hex 32)"
        echo "Generated VP_PSK (share with clients):"
        echo "  $PSK"
    else
        echo "openssl not found. Please enter a strong hex VP_PSK:"
        read -p "VP_PSK: " PSK
        if [[ -z "$PSK" ]]; then
            echo "VP_PSK is required."
            exit 1
        fi
    fi
    export VP_PSK="$PSK"

    read -p "Enter VP_DEBUG level (0-4, default 2): " DBG
    if [[ -z "$DBG" ]]; then
        DBG=2
    fi
    export VP_DEBUG="$DBG"

    read -p "Enter UDP listen port (default 9999): " PORT
    if [[ -z "$PORT" ]]; then
        PORT=9999
    fi

    echo
    echo "Starting switchd with:"
    echo "  Listen port : $PORT"
    echo "  VP_PSK      : (generated / provided above)"
    echo "  VP_DEBUG    : $VP_DEBUG"
    echo

    exec "$SWITCHD_BIN" "$PORT"
fi

# -------------------------------
# CLIENT MODE (vportd, Linux/macOS)
# -------------------------------

if [[ "$OS_NAME" != "Linux" && "$OS_NAME" != "Darwin" ]]; then
    echo "Unsupported OS: $OS_NAME"
    echo "Client mode currently supports Linux and macOS only."
    exit 1
fi

# Root / sudo check (needed for TAP + IP config)
if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo ./start.sh"
    exit 1
fi

echo
echo "TAP interface: tap0"
echo "Default subnet: 10.10.0.0/24"
echo

read -p "Enter host IP last octet (1-254, e.g. 1 => 10.10.0.1): " HOST

if ! [[ "$HOST" =~ ^[0-9]+$ ]]; then
    echo "Error: Not a number"
    exit 1
fi

if (( HOST < 1 || HOST > 254 )); then
    echo "Error: IP last octet must be between 1 and 254"
    exit 1
fi

IP="10.10.0.$HOST"

echo
echo "Using TAP  = tap0"
echo "Using IP   = $IP/24"
echo "OS         = $OS_NAME"
echo

if [[ "$OS_NAME" == "Linux" ]]; then
    echo "[*] Configuring TAP on Linux"

    if ip link show tap0 &> /dev/null; then
        echo "    - tap0 exists → deleting old one"
        ip link set tap0 down || true
        ip tuntap del dev tap0 mode tap || true
    fi

    echo "    - Creating tap0"
    ip tuntap add dev tap0 mode tap

    echo "    - Bringing tap0 up"
    ip link set tap0 up

    # Random locally administered unicast MAC (02:xx:xx:xx:xx:xx)
    mac=$(printf "02:%02x:%02x:%02x:%02x:%02x" \
        $((RANDOM&0xFF)) \
        $((RANDOM&0xFF)) \
        $((RANDOM&0xFF)) \
        $((RANDOM&0xFF)) \
        $((RANDOM&0xFF)) )

    echo "    - Assigning random MAC = $mac"
    ip link set dev tap0 address "$mac" || true

    echo "    - Assigning IP $IP/24"
    ip addr flush dev tap0 || true
    ip addr add "$IP/24" dev tap0

else
    echo "[*] Configuring TAP on macOS"

    # Require /dev/tap0 to exist (e.g. from a tun/tap driver).
    if [[ ! -e /dev/tap0 ]]; then
        echo "Error: /dev/tap0 not found."
        echo "Install and load a TAP driver (find help at https://github.com/ntop/n2n/issues/773) before running this script."
        exit 1
    fi

    if ifconfig tap0 >/dev/null 2>&1; then
        echo "    - tap0 exists → resetting configuration"
        ifconfig tap0 down || true
    fi

    echo "    - Assigning IP $IP/24 and bringing tap0 up"
    # On macOS, set the interface IP with itself as the peer.
    ifconfig tap0 inet "$IP" "$IP" netmask 255.255.255.0 up
fi

echo
echo "=== Environment / Crypto (Client) ==="

read -p "Enter VP_PSK (hex, must match server): " PSK
if [[ -z "$PSK" ]]; then
    echo "VP_PSK is required for the client."
    exit 1
fi
export VP_PSK="$PSK"

read -p "Enter VP_DEBUG level (0-4, default 2): " DBG
if [[ -z "$DBG" ]]; then
    DBG=2
fi
export VP_DEBUG="$DBG"

echo
echo "=== Switch / Server ==="
read -p "Enter switch IP or hostname: " SERVER_IP
read -p "Enter switch UDP port: " SERVER_PORT

if [[ -z "$SERVER_IP" || -z "$SERVER_PORT" ]]; then
    echo "Error: server IP and port are required."
    exit 1
fi

VPORTD_BIN="$SCRIPT_DIR/build/src/vportd"

if [[ ! -x "$VPORTD_BIN" ]]; then
    # Try local binary in repo root as fallback
    if [[ -x "$SCRIPT_DIR/vportd" ]]; then
        VPORTD_BIN="$SCRIPT_DIR/vportd"
    else
        echo "Error: vportd binary not found or not executable."
        echo "Looked for:"
        echo "  $SCRIPT_DIR/build/src/vportd"
        echo "  $SCRIPT_DIR/vportd"
        echo "Run ./build.sh first to build the binaries."
        exit 1
    fi
fi

echo
echo "Starting vportd with:"
echo "  TAP     : tap0 ($IP/24)"
echo "  Server  : $SERVER_IP:$SERVER_PORT"
echo "  VP_PSK  : (must match server)"
echo "  VP_DEBUG: $VP_DEBUG"
echo

exec "$VPORTD_BIN" "$SERVER_IP" "$SERVER_PORT" tap0
