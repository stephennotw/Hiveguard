#!/usr/bin/env bash
# HiveGuard Bootstrap — macOS / Linux
# Downloads portable Node.js if not found, then runs the scanner.
# Usage: ./run.sh [hiveguard flags]
# Example: ./run.sh --offline --output /tmp/results --verbose

set -euo pipefail

# Pre-create output directory if --output is specified
PREV_ARG=""
for arg in "$@"; do
    if [ "$PREV_ARG" = "--output" ]; then
        if [ ! -d "$arg" ]; then
            mkdir -p "$arg"
            echo "[bootstrap] Created output directory: $arg" >&2
        fi
        break
    fi
    PREV_ARG="$arg"
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Self-extraction: if bin/hiveguard.js is missing, try to unzip ---
if [ ! -f "$SCRIPT_DIR/bin/hiveguard.js" ]; then
    echo "[bootstrap] bin/hiveguard.js not found — looking for ZIP archive..." >&2

    # Look for the ZIP in SCRIPT_DIR, parent dir, and current working dir
    ZIP_FILE=""
    for candidate in \
        "$SCRIPT_DIR/Hiveguard.zip" "$SCRIPT_DIR/hiveguard.zip" \
        "$SCRIPT_DIR/../Hiveguard.zip" "$SCRIPT_DIR/../hiveguard.zip" \
        "./Hiveguard.zip" "./hiveguard.zip"; do
        if [ -f "$candidate" ]; then
            ZIP_FILE="$candidate"
            break
        fi
    done

    # Also check for .tar.gz
    TAR_FILE=""
    if [ -z "$ZIP_FILE" ]; then
        for candidate in \
            "$SCRIPT_DIR/Hiveguard.tar.gz" "$SCRIPT_DIR/hiveguard.tar.gz" \
            "$SCRIPT_DIR/../Hiveguard.tar.gz" "$SCRIPT_DIR/../hiveguard.tar.gz" \
            "./Hiveguard.tar.gz" "./hiveguard.tar.gz"; do
            if [ -f "$candidate" ]; then
                TAR_FILE="$candidate"
                break
            fi
        done
    fi

    if [ -n "$ZIP_FILE" ]; then
        echo "[bootstrap] Found archive: $ZIP_FILE" >&2
        EXTRACT_TARGET="$SCRIPT_DIR"

        if command -v unzip >/dev/null 2>&1; then
            echo "[bootstrap] Extracting with unzip..." >&2
            unzip -qo "$ZIP_FILE" -d "$EXTRACT_TARGET"
        elif command -v python3 >/dev/null 2>&1; then
            echo "[bootstrap] unzip not found, extracting with python3..." >&2
            python3 -c "
import zipfile, sys
with zipfile.ZipFile('$ZIP_FILE', 'r') as z:
    z.extractall('$EXTRACT_TARGET')
"
        elif command -v jar >/dev/null 2>&1; then
            echo "[bootstrap] Extracting with jar..." >&2
            (cd "$EXTRACT_TARGET" && jar xf "$ZIP_FILE")
        else
            echo "[bootstrap] ERROR: Cannot extract ZIP — no unzip, python3, or jar found" >&2
            echo "            Please extract manually: unzip $ZIP_FILE -d $EXTRACT_TARGET" >&2
            exit 3
        fi

        # Handle nested folder: if extraction created Hiveguard/bin/ inside SCRIPT_DIR
        if [ ! -f "$SCRIPT_DIR/bin/hiveguard.js" ]; then
            for nested in "$SCRIPT_DIR/Hiveguard" "$SCRIPT_DIR/hiveguard" "$SCRIPT_DIR/Hiveguard-main"; do
                if [ -f "$nested/bin/hiveguard.js" ]; then
                    echo "[bootstrap] Moving files from nested folder: $nested" >&2
                    cp -r "$nested"/* "$SCRIPT_DIR/"
                    rm -rf "$nested"
                    break
                fi
            done
        fi
    elif [ -n "$TAR_FILE" ]; then
        echo "[bootstrap] Found archive: $TAR_FILE" >&2
        echo "[bootstrap] Extracting with tar..." >&2
        tar -xzf "$TAR_FILE" -C "$SCRIPT_DIR"

        # Handle nested folder
        if [ ! -f "$SCRIPT_DIR/bin/hiveguard.js" ]; then
            for nested in "$SCRIPT_DIR/Hiveguard" "$SCRIPT_DIR/hiveguard" "$SCRIPT_DIR/Hiveguard-main"; do
                if [ -f "$nested/bin/hiveguard.js" ]; then
                    echo "[bootstrap] Moving files from nested folder: $nested" >&2
                    cp -r "$nested"/* "$SCRIPT_DIR/"
                    rm -rf "$nested"
                    break
                fi
            done
        fi
    fi

    # Final check
    if [ ! -f "$SCRIPT_DIR/bin/hiveguard.js" ]; then
        echo "[bootstrap] ERROR: bin/hiveguard.js still not found after extraction." >&2
        echo "            Ensure the ZIP contains: bin/hiveguard.js, src/, catalogs/" >&2
        ls -la "$SCRIPT_DIR" >&2 || true
        exit 3
    fi

    echo "[bootstrap] Extraction successful." >&2
fi

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
