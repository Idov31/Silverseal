#!/bin/bash

set -euo pipefail

readonly DEFAULT_RUST_VERSION="1.82"
readonly DEFAULT_GCC_VERSION="13"

usage() {
    cat <<'EOF'
Usage: ./scripts/ubuntu_target_setup.sh [kernel-release]

Prepares a WSL Ubuntu environment to build the Silverseal rootkit against a
Rust-enabled Ubuntu generic kernel such as 6.17.0-20-generic.

This script:
  1. installs the matching Ubuntu header and linux-lib-rust packages
  2. installs the Ubuntu-packaged Rust toolchain used for generic-kernel builds
  3. verifies that /usr/src/linux-headers-<release>/rust resolves correctly
  4. repairs the rust symlink if the header tree points at a missing package path
  5. prints the exact make command to build the module from WSL
EOF
}

log() {
    printf '[ubuntu_target_setup] %s\n' "$*"
}

die() {
    printf '[ubuntu_target_setup] ERROR: %s\n' "$*" >&2
    exit 1
}

have_command() {
    command -v "$1" >/dev/null 2>&1
}

ensure_wsl_or_ubuntu() {
    if [ ! -d /usr/src ]; then
        die "This script must run in a Linux environment with /usr/src available."
    fi
}

install_packages() {
    local kernel_release="$1"

    log "Installing Ubuntu packages for target kernel ${kernel_release}..."
    sudo apt update
    sudo apt install -y \
        "linux-headers-${kernel_release}" \
        "linux-lib-rust-${kernel_release}" \
        build-essential \
        clang \
        llvm \
        libclang-dev \
        libelf-dev \
        libssl-dev \
        flex \
        bison \
        dwarves \
        "gcc-${DEFAULT_GCC_VERSION}" \
        bindgen \
        "cargo-${DEFAULT_RUST_VERSION}" \
        "rustc-${DEFAULT_RUST_VERSION}" \
        "rust-${DEFAULT_RUST_VERSION}-src" \
        "libstd-rust-${DEFAULT_RUST_VERSION}" \
        "libstd-rust-${DEFAULT_RUST_VERSION}-dev"
}

repair_header_rust_symlink() {
    local kernel_release="$1"
    local headers_dir="/usr/src/linux-headers-${kernel_release}"
    local header_rust="${headers_dir}/rust"
    local generic_rust="/usr/src/linux-lib-rust-${kernel_release}/rust"
    local resolved_path=""

    [ -e "${headers_dir}" ] || die "Kernel headers directory ${headers_dir} was not found."
    [ -e "${generic_rust}" ] || die "Installed linux-lib-rust contents were not found at ${generic_rust}."

    if [ -L "${header_rust}" ]; then
        resolved_path="$(readlink -f "${header_rust}" || true)"
        if [ -n "${resolved_path}" ] && [ -d "${resolved_path}" ]; then
            log "Header rust path already resolves to ${resolved_path}"
            return
        fi

        log "Header rust symlink is broken. Repointing ${header_rust} to ${generic_rust}..."
        sudo rm -f "${header_rust}"
        sudo ln -s "${generic_rust}" "${header_rust}"
        return
    fi

    if [ -d "${header_rust}" ]; then
        log "Header rust directory already exists at ${header_rust}"
        return
    fi

    log "Creating missing rust symlink ${header_rust} -> ${generic_rust}"
    sudo ln -s "${generic_rust}" "${header_rust}"
}

verify_kernel_rust_tree() {
    local kernel_release="$1"
    local header_rust="/usr/src/linux-headers-${kernel_release}/rust"
    local resolved_path

    resolved_path="$(readlink -f "${header_rust}")"
    [ -d "${resolved_path}" ] || die "Resolved rust directory ${resolved_path} does not exist."

    for artifact in libcore.rmeta libkernel.rmeta libmacros.so; do
        [ -e "${resolved_path}/${artifact}" ] || die "Expected Rust kernel artifact ${resolved_path}/${artifact} was not found."
    done

    log "Rust kernel artifacts are present under ${resolved_path}"
}

print_build_instructions() {
    local kernel_release="$1"

    cat <<EOF

Ubuntu target kernel setup is complete.

Next build command from WSL:

  cd /path/to/Silverseal/silverseal-rootkit
  make clean
  PATH=/usr/bin:/bin:\$PATH \\
  RUST_LIB_SRC=/usr/src/rustc-${DEFAULT_RUST_VERSION}.0/library \\
  make RUST_MIN_TOOLCHAIN= \\
  KDIR=/usr/src/linux-headers-${kernel_release} \\
  CC=x86_64-linux-gnu-gcc-${DEFAULT_GCC_VERSION} \\
  RUSTC=rustc-${DEFAULT_RUST_VERSION} \\
  RUSTDOC=rustdoc-${DEFAULT_RUST_VERSION}

Validation after build:

  readlink -f /usr/src/linux-headers-${kernel_release}/rust
  modinfo target/silverseal_rootkit.ko | grep vermagic
EOF
}

main() {
    local kernel_release="${1:-}"

    if [ "${kernel_release}" = "--help" ] || [ "${kernel_release}" = "-h" ]; then
        usage
        exit 0
    fi

    if [ -z "${kernel_release}" ]; then
        die "Please pass the target Ubuntu kernel release, for example: 6.17.0-20-generic"
    fi

    ensure_wsl_or_ubuntu
    install_packages "${kernel_release}"
    repair_header_rust_symlink "${kernel_release}"
    verify_kernel_rust_tree "${kernel_release}"
    print_build_instructions "${kernel_release}"
}

main "$@"
