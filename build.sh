#!/usr/bin/env bash

set -e

BUILD_DIR="build"

echo "=== vpnet Builder ==="

# -------------------------------------
# 0) Pull latest changes (optional but handy)
# -------------------------------------
if command -v git >/dev/null 2>&1; then
    echo "[*] Updating repository (git pull --ff-only)..."
    git pull --ff-only || echo "    (git pull failed, continuing with local tree)"
fi

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

if command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc)"
elif [[ "$(uname -s)" == "Darwin" ]]; then
    JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 1)"
else
    JOBS=1
fi

make -j"$JOBS"

echo
echo "=== Build Complete ==="
echo "Binaries are located in:"
echo "   $BUILD_DIR/src/switchd  (Linux/UNIX)"
echo "   $BUILD_DIR/src/vportd   (Linux/macOS/Windows)"
echo
