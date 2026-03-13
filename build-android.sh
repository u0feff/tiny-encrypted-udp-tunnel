#!/bin/bash
# Usage: ./build-android.sh [ABI] [API_LEVEL]
#   ABI:       arm64-v8a (default), armeabi-v7a, x86, x86_64
#   API_LEVEL: Android API level, minimum 24 (default: 24)
#
# Environment:
#   ANDROID_NDK_HOME or ANDROID_NDK: Path to Android NDK (required)

set -e

ABI="${1:-arm64-v8a}"
API_LEVEL="${2:-24}"

OPENSSL_VERSION="3.4.1"
CLI11_VERSION="2.4.2"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin/android/${ABI}"
DEPS_DIR="${SCRIPT_DIR}/deps/android"

NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK:-}}"
if [ -z "$NDK" ]; then
    echo "Error: Set ANDROID_NDK_HOME or ANDROID_NDK to the NDK path"
    exit 1
fi

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
        exit 1
        ;;
esac

HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
HOST_ARCH="$(uname -m)"
case "$HOST_OS" in
    linux)
        HOST_TAG="linux-x86_64"
        ;;
    darwin)
        if [ "$HOST_ARCH" = "arm64" ] && [ -d "${NDK}/toolchains/llvm/prebuilt/darwin-arm64" ]; then
            HOST_TAG="darwin-arm64"
        else
            HOST_TAG="darwin-x86_64"
        fi
        ;;
    *)
        echo "Error: Unsupported host OS: $HOST_OS"
        exit 1
        ;;
esac

TOOLCHAIN="${NDK}/toolchains/llvm/prebuilt/${HOST_TAG}"

CXX="${TOOLCHAIN}/bin/${TARGET}${API_LEVEL}-clang++"
STRIP="${TOOLCHAIN}/bin/llvm-strip"

export ANDROID_NDK_ROOT="$NDK"
export PATH="${TOOLCHAIN}/bin:${PATH}"

mkdir -p "${DEPS_DIR}"

OPENSSL_DIR="${DEPS_DIR}/openssl"
OPENSSL_API="${OPENSSL_DIR}/api/${API_LEVEL}"
OPENSSL_SRC="${OPENSSL_DIR}/src/${OPENSSL_VERSION}"
OPENSSL_TAR="${OPENSSL_DIR}/src/${OPENSSL_VERSION}.tar.gz"
if [ ! -f "${OPENSSL_API}/lib/libssl.a" ]; then
    mkdir -p "${OPENSSL_DIR}"

    if [ ! -f "$OPENSSL_TAR" ]; then
        mkdir -p "$(dirname "${OPENSSL_TAR}")"
        curl -fSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
            -o "$OPENSSL_TAR"
    fi

    rm -rf "$OPENSSL_SRC"
    mkdir -p "$OPENSSL_SRC"
    tar xzf "$OPENSSL_TAR" --strip-components=1 -C "$OPENSSL_SRC"

    pushd "$OPENSSL_SRC" > /dev/null
    ./Configure "$OPENSSL_TARGET" \
        -D__ANDROID_API__="$API_LEVEL" \
        --prefix="$OPENSSL_API" \
        no-shared no-tests
    if ! make -j"$(nproc)"; then
        echo "Error: OpenSSL build failed"
        exit 1
    fi
    if ! make install_sw; then
        echo "Error: OpenSSL install failed"
        exit 1
    fi
    popd > /dev/null
fi

CLI11_DIR="${DEPS_DIR}/cli11"
CLI11_API="${CLI11_DIR}/${CLI11_VERSION}"
CLI11_HEADER="${CLI11_API}/CLI/CLI.hpp"
if [ ! -f "$CLI11_HEADER" ]; then
    mkdir -p "$(dirname "${CLI11_HEADER}")"
    curl -fSL "https://github.com/CLIUtils/CLI11/releases/download/v${CLI11_VERSION}/CLI11.hpp" \
        -o "$CLI11_HEADER"
fi

CXXFLAGS="-I${OPENSSL_API}/include -I${CLI11_API}"
LDFLAGS="-L${OPENSSL_API}/lib -ldl -static-libstdc++"

make clean
make build \
    CXX="$CXX" \
    BIN_DIR="$BIN_DIR" \
    EXTRA_CXXFLAGS="$CXXFLAGS" \
    EXTRA_LDFLAGS="$LDFLAGS"

$STRIP "${BIN_DIR}/tiny-tunnel"

echo ""
echo "=== Build complete ==="
echo "Binary: ${BIN_DIR}/tiny-tunnel"
