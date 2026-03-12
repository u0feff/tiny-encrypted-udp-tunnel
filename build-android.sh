#!/bin/bash
# build-android.sh - Cross-compile tiny-tunnel for Android using the NDK
#
# Usage: ./build-android.sh [ABI] [API_LEVEL]
#   ABI:       arm64-v8a (default), armeabi-v7a, x86, x86_64
#   API_LEVEL: Android API level, minimum 24 (default: 24)
#
# Environment:
#   ANDROID_NDK_HOME or ANDROID_NDK: Path to Android NDK (required)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ABI="${1:-arm64-v8a}"
API_LEVEL="${2:-24}"
BUILD_DIR="${SCRIPT_DIR}/build-android/${ABI}"
DEPS_DIR="${BUILD_DIR}/deps"
OPENSSL_VERSION="3.4.1"
CLI11_VERSION="2.4.2"

# --- Locate Android NDK ---
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK:-}}"
if [ -z "$NDK" ]; then
    echo "Error: Set ANDROID_NDK_HOME or ANDROID_NDK to the NDK path"
    exit 1
fi
if [ ! -d "$NDK" ]; then
    echo "Error: NDK directory not found: $NDK"
    exit 1
fi

# --- Map ABI to target triple ---
case "$ABI" in
    arm64-v8a)
        TARGET="aarch64-linux-android"
        OPENSSL_TARGET="android-arm64"
        ;;
    armeabi-v7a)
        TARGET="armv7a-linux-androideabi"
        OPENSSL_TARGET="android-arm"
        ;;
    x86)
        TARGET="i686-linux-android"
        OPENSSL_TARGET="android-x86"
        ;;
    x86_64)
        TARGET="x86_64-linux-android"
        OPENSSL_TARGET="android-x86_64"
        ;;
    *)
        echo "Error: Unsupported ABI: $ABI"
        echo "Supported: arm64-v8a, armeabi-v7a, x86, x86_64"
        exit 1
        ;;
esac

# --- Detect host platform ---
HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$HOST_OS" in
    linux)  HOST_TAG="linux-x86_64" ;;
    darwin) HOST_TAG="darwin-x86_64" ;;
    *)      echo "Error: Unsupported host OS: $HOST_OS"; exit 1 ;;
esac

TOOLCHAIN="${NDK}/toolchains/llvm/prebuilt/${HOST_TAG}"
if [ ! -d "$TOOLCHAIN" ]; then
    echo "Error: NDK toolchain not found at ${TOOLCHAIN}"
    exit 1
fi

export CC="${TOOLCHAIN}/bin/${TARGET}${API_LEVEL}-clang"
export CXX="${TOOLCHAIN}/bin/${TARGET}${API_LEVEL}-clang++"
export AR="${TOOLCHAIN}/bin/llvm-ar"
export RANLIB="${TOOLCHAIN}/bin/llvm-ranlib"
export STRIP="${TOOLCHAIN}/bin/llvm-strip"
export PATH="${TOOLCHAIN}/bin:${PATH}"
export ANDROID_NDK_ROOT="$NDK"

echo "=== Building tiny-tunnel for Android ==="
echo "ABI:       $ABI"
echo "API Level: $API_LEVEL"
echo "NDK:       $NDK"
echo "CXX:       $CXX"
echo ""

mkdir -p "$BUILD_DIR" "$DEPS_DIR"

# --- Build OpenSSL ---
OPENSSL_INSTALL="${DEPS_DIR}/openssl"
if [ ! -f "${OPENSSL_INSTALL}/lib/libssl.a" ]; then
    echo "=== Building OpenSSL ${OPENSSL_VERSION} for ${ABI} ==="
    OPENSSL_SRC="${DEPS_DIR}/openssl-${OPENSSL_VERSION}"
    OPENSSL_TAR="${DEPS_DIR}/openssl-${OPENSSL_VERSION}.tar.gz"

    if [ ! -f "$OPENSSL_TAR" ]; then
        echo "Downloading OpenSSL..."
        curl -fSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
            -o "$OPENSSL_TAR"
    fi

    rm -rf "$OPENSSL_SRC"
    tar xzf "$OPENSSL_TAR" -C "$DEPS_DIR"

    pushd "$OPENSSL_SRC" > /dev/null
    ./Configure "$OPENSSL_TARGET" \
        -D__ANDROID_API__="$API_LEVEL" \
        --prefix="$OPENSSL_INSTALL" \
        no-shared no-tests
    make -j"$(nproc)" > /dev/null 2>&1
    make install_sw > /dev/null 2>&1
    popd > /dev/null

    rm -rf "$OPENSSL_SRC"
    echo "OpenSSL built successfully"
else
    echo "=== OpenSSL already built for ${ABI}, skipping ==="
fi

# --- Download CLI11 ---
CLI11_DIR="${DEPS_DIR}/cli11"
CLI11_HEADER="${CLI11_DIR}/CLI/CLI.hpp"
if [ ! -f "$CLI11_HEADER" ]; then
    echo "=== Downloading CLI11 ${CLI11_VERSION} ==="
    mkdir -p "${CLI11_DIR}/CLI"
    curl -fSL "https://github.com/CLIUtils/CLI11/releases/download/v${CLI11_VERSION}/CLI11.hpp" \
        -o "$CLI11_HEADER"
    echo "CLI11 downloaded successfully"
else
    echo "=== CLI11 already downloaded, skipping ==="
fi

# --- Build tiny-tunnel ---
echo "=== Compiling tiny-tunnel for ${ABI} ==="
OUTPUT_DIR="${BUILD_DIR}/bin"
mkdir -p "$OUTPUT_DIR"

CXXFLAGS="-std=c++17 -O3 -Wall -Wextra -pthread"
CXXFLAGS="${CXXFLAGS} -I${SCRIPT_DIR}"
CXXFLAGS="${CXXFLAGS} -I${OPENSSL_INSTALL}/include"
CXXFLAGS="${CXXFLAGS} -I${CLI11_DIR}"

LDFLAGS="-L${OPENSSL_INSTALL}/lib"
LDFLAGS="${LDFLAGS} -lssl -lcrypto -pthread"
# Android needs explicit linking of log and dl
LDFLAGS="${LDFLAGS} -ldl"
LDFLAGS="${LDFLAGS} -static-libstdc++"

SOURCES=(
    main.cpp
    crypto/aes_crypto.cpp
    crypto/xor_crypto.cpp
    connection.cpp
    connection_pool.cpp
    session_store.cpp
    tunnels/client_tcp_tunnel.cpp
    tunnels/server_tcp_tunnel.cpp
    tunnels/client_udp_tunnel.cpp
    tunnels/server_udp_tunnel.cpp
)

OBJECTS=()
for src in "${SOURCES[@]}"; do
    obj="${BUILD_DIR}/$(echo "$src" | sed 's/\.cpp$/.o/')"
    mkdir -p "$(dirname "$obj")"
    echo "  CC  $src"
    $CXX $CXXFLAGS -c "${SCRIPT_DIR}/${src}" -o "$obj"
    OBJECTS+=("$obj")
done

echo "  LD  tiny-tunnel"
$CXX "${OBJECTS[@]}" -o "${OUTPUT_DIR}/tiny-tunnel" $LDFLAGS
$STRIP "${OUTPUT_DIR}/tiny-tunnel"

echo ""
echo "=== Build complete ==="
echo "Binary: ${OUTPUT_DIR}/tiny-tunnel"
file "${OUTPUT_DIR}/tiny-tunnel" 2>/dev/null || true
