#!/bin/bash

set -euo pipefail

readonly RUST_TOOLCHAIN="stable"

have_command() {
    command -v "$1" >/dev/null 2>&1
}

ensure_bindgen_cli() {
    if have_command bindgen; then
        echo "bindgen is already available in PATH. Skipping bindgen-cli install."
        return
    fi

    echo "Installing bindgen-cli..."
    cargo +stable install --locked bindgen-cli
}

kernel_rust_support_status() {
    if [ -r /proc/config.gz ] && zgrep -q '^CONFIG_RUST=y$' /proc/config.gz; then
        return 0
    fi

    if [ -r "/boot/config-$(uname -r)" ] && grep -q '^CONFIG_RUST=y$' "/boot/config-$(uname -r)"; then
        return 0
    fi

    return 1
}

echo "Installing Ubuntu packages required for Rust-for-Linux external module builds..."
sudo apt update
sudo apt install -y build-essential flex bison dwarves libssl-dev libelf-dev clang llvm libclang-dev

if ! have_command rustup; then
    echo "Installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

if [ -n "${HOME:-}" ] && [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1090
    . "$HOME/.cargo/env"
fi

echo "Installing Rust toolchain: ${RUST_TOOLCHAIN}"
rustup toolchain install "${RUST_TOOLCHAIN}"
rustup default "${RUST_TOOLCHAIN}"
rustup component add rust-src --toolchain "${RUST_TOOLCHAIN}"
ensure_bindgen_cli

if kernel_rust_support_status; then
    echo "Detected CONFIG_RUST=y in the current kernel configuration."
else
    cat <<'EOF'
Warning: CONFIG_RUST=y was not detected for the current kernel.
Compiling this module requires a matching Linux kernel build tree with Rust support.
On WSL2, that usually means using a custom Rust-enabled WSL kernel rather than the default stock kernel.
EOF
fi
