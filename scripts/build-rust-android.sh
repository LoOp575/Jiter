#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_DIR="${REPO_ROOT}/engine-rust"
OUT_BASE="${REPO_ROOT}/android/app/src/main/cpp/prebuilt"

# Locate Android NDK automatically if ANDROID_NDK_HOME is not explicitly set
NDK_DIR="${ANDROID_NDK_HOME:-}"
if [[ -z "${NDK_DIR}" ]]; then
    SDK_DIR="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
    if [[ -n "${SDK_DIR}" && -d "${SDK_DIR}/ndk" ]]; then
        NDK_DIR="$(ls -d "${SDK_DIR}/ndk/"* 2>/dev/null | sort -V | tail -n 1)"
    fi
fi

if [[ -z "${NDK_DIR}" || ! -d "${NDK_DIR}" ]]; then
    echo "ERROR: Android NDK not found. Set ANDROID_NDK_HOME or ANDROID_HOME." >&2
    exit 1
fi

HOST_TAG="linux-x86_64"
if [[ "$(uname -s)" == "Darwin" ]]; then
    HOST_TAG="darwin-x86_64"
fi
LLVM_BIN="${NDK_DIR}/toolchains/llvm/prebuilt/${HOST_TAG}/bin"
if [[ ! -d "${LLVM_BIN}" ]]; then
    echo "ERROR: NDK LLVM bin directory not found at ${LLVM_BIN}" >&2
    exit 1
fi

build_target() {
    local rust_target="$1"
    local android_abi="$2"
    local clang_prefix="$3"

    echo "==> Building jiter-math (Rust) for ${android_abi} (${rust_target})..."
    local linker="${LLVM_BIN}/${clang_prefix}29-clang"
    local ar="${LLVM_BIN}/llvm-ar"
    local env_target
    env_target="$(echo "${rust_target}" | tr '[:lower:]-' '[:upper:]_')"

    (
        cd "${RUST_DIR}"
        export "CARGO_TARGET_${env_target}_LINKER=${linker}"
        export "CARGO_TARGET_${env_target}_AR=${ar}"
        cargo build --release --target "${rust_target}"
    )

    mkdir -p "${OUT_BASE}/${android_abi}"
    cp "${RUST_DIR}/target/${rust_target}/release/libjiter_math.a" "${OUT_BASE}/${android_abi}/libjiter_math.a"
    ls -lh "${OUT_BASE}/${android_abi}/libjiter_math.a"
}

ABIS="${1:-arm64-v8a,x86_64}"
IFS=',' read -ra TARGET_LIST <<< "${ABIS}"
for abi in "${TARGET_LIST[@]}"; do
    case "${abi}" in
        arm64-v8a)
            build_target "aarch64-linux-android" "arm64-v8a" "aarch64-linux-android"
            ;;
        x86_64)
            build_target "x86_64-linux-android" "x86_64" "x86_64-linux-android"
            ;;
        *)
            echo "Unsupported ABI: ${abi} (supported: arm64-v8a, x86_64)" >&2
            exit 1
            ;;
    esac
done

echo "Done! Rust staticlibs ready under ${OUT_BASE}"
