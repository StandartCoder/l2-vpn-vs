#!/bin/bash

set -e

BUILD_DIR="build"

echo "=== vpnet Builder ==="

# -------------------------------------
# 1) Clean old build folder
# -------------------------------------
if [ -d "$BUILD_DIR" ]; then
    echo "[*] Removing old build directory..."
    rm -rf "$BUILD_DIR"
fi

# -------------------------------------
# 2) Create fresh build folder
# -------------------------------------
echo "[*] Creating new build directory..."
mkdir "$BUILD_DIR"
cd "$BUILD_DIR"

# -------------------------------------
# 3) Run CMake
# -------------------------------------
echo "[*] Running CMake..."
cmake ..

# -------------------------------------
# 4) Build with all CPU cores
# -------------------------------------
echo "[*] Building project..."
make -j"$(nproc)"

echo
echo "=== Build Complete ==="
echo "Binaries are located in:"
echo "   $BUILD_DIR/src/switchd"
echo "   $BUILD_DIR/src/vportd"
echo
echo "Run them like:"
echo "   $BUILD_DIR/src/switchd <port>"
echo "   sudo $BUILD_DIR/src/vportd <server_ip> <port> tap0"
echo