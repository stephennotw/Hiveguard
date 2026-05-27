#!/usr/bin/env bash
# HiveGuard Bootstrap — macOS / Linux
# Downloads portable Node.js if not found, then runs the scanner.
# Usage: ./run.sh [hiveguard flags]
# Example: ./run.sh --offline --output /tmp/results --verbose

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NODE_DIR="$SCRIPT_DIR/.node"
HIVEGUARD_JS="$SCRIPT_DIR/bin/hiveguard.js"
REQUIRED_MAJOR=18
NODE_VERSION="v22.15.0"
NODE_DIST_BASE="https://nodejs.org/dist/$NODE_VERSION"

get_node_major() {
    local ver
    ver=$("$1" --version 2>/dev/null || echo "v0")
    echo "$ver" | sed 's/^v\([0-9]*\).*/\1/'
}

find_system_node() {
    if command -v node >/dev/null 2>&1; then
        local major
        major=$(get_node_major "$(command -v node)")
        if [ "$major" -ge "$REQUIRED_MAJOR" ]; then
            echo "[bootstrap] Using system Node.js ($(command -v node), v$major)" >&2
            command -v node
            return 0
        fi
        echo "[bootstrap] System Node.js too old (v$major, need >=$REQUIRED_MAJOR)" >&2
    fi
    return 1
}

install_portable_node() {
    local node_exe="$NODE_DIR/node"

    if [ -f "$node_exe" ]; then
        local major
        major=$(get_node_major "$node_exe")
        if [ "$major" -ge "$REQUIRED_MAJOR" ]; then
            echo "[bootstrap] Using portable Node.js (.node/node, v$major)" >&2
            echo "$node_exe"
            return 0
        fi
        echo "[bootstrap] Portable Node.js too old (v$major), re-downloading..." >&2
    fi

    # Detect OS and arch
    local os_name arch_name
    os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch_name="$(uname -m)"

    case "$os_name" in
        darwin) os_name="darwin" ;;
        linux)  os_name="linux" ;;
        *)
            echo "[bootstrap] ERROR: Unsupported OS: $os_name" >&2
            echo "            Install Node.js 18+ manually: https://nodejs.org" >&2
            exit 3
            ;;
    esac

    case "$arch_name" in
        x86_64|amd64)  arch_name="x64" ;;
        aarch64|arm64) arch_name="arm64" ;;
        armv7l)        arch_name="armv7l" ;;
        *)
            echo "[bootstrap] ERROR: Unsupported arch: $arch_name" >&2
            exit 3
            ;;
    esac

    local tarball="node-${NODE_VERSION}-${os_name}-${arch_name}.tar.gz"
    local url="${NODE_DIST_BASE}/${tarball}"
    local tmp_tar="/tmp/${tarball}"
    local extract_dir="/tmp/node-${NODE_VERSION}-${os_name}-${arch_name}"

    echo "[bootstrap] Downloading Node.js $NODE_VERSION ($os_name-$arch_name)..." >&2
    echo "            $url" >&2

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$tmp_tar" || {
            echo "[bootstrap] ERROR: Failed to download Node.js" >&2
            echo "            Install Node.js 18+ manually: https://nodejs.org" >&2
            exit 3
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$tmp_tar" || {
            echo "[bootstrap] ERROR: Failed to download Node.js" >&2
            exit 3
        }
    else
        echo "[bootstrap] ERROR: Neither curl nor wget found" >&2
        exit 3
    fi

    echo "[bootstrap] Extracting..." >&2
    rm -rf "$extract_dir"
    mkdir -p "$NODE_DIR"
    tar -xzf "$tmp_tar" -C /tmp

    cp "$extract_dir/bin/node" "$node_exe"
    chmod +x "$node_exe"

    # Cleanup
    rm -f "$tmp_tar"
    rm -rf "$extract_dir"

    local major
    major=$(get_node_major "$node_exe")
    echo "[bootstrap] Node.js $NODE_VERSION installed to .node/node" >&2
    echo "$node_exe"
}

# --- Main ---
echo "" >&2
echo "  HiveGuard Bootstrap ($(uname -s))" >&2
echo "  =============================" >&2
echo "" >&2

# 1. Try system node
NODE_EXE=""
NODE_EXE=$(find_system_node) || true

# 2. Fall back to portable node
if [ -z "$NODE_EXE" ]; then
    NODE_EXE=$(install_portable_node)
fi

# 3. Run HiveGuard
echo "[bootstrap] Starting HiveGuard scan..." >&2
echo "" >&2

exec "$NODE_EXE" "$HIVEGUARD_JS" "$@"
