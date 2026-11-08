#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./scripts/ubuntu_target_setup.sh [kernel-release] [rust-version]

Prepares an Ubuntu ARM64 VM to build the Silverseal module against a matching
Rust-enabled Ubuntu generic kernel. The Rust version is derived from the target
kernel config when possible; pass it explicitly (for example 1.93.1) only when
the config is unavailable.

This script:
  1. installs the matching Ubuntu header and linux-lib-rust packages
  2. installs the Ubuntu-packaged Rust series required by the target kernel
  3. verifies that /usr/src/linux-headers-<release>/rust resolves correctly
  4. repairs the rust symlink if the header tree points at a missing package path
  5. prints the exact native ARM64 Kbuild command to use afterward
EOF
}

log() {
    printf '[ubuntu_target_setup] %s\n' "$*"
}

die() {
    printf '[ubuntu_target_setup] ERROR: %s\n' "$*" >&2
    exit 1
}

derive_rust_version() {
    local kernel_release="$1"
    local config_path=""
    local encoded=""

    for candidate in "/boot/config-${kernel_release}" "/lib/modules/${kernel_release}/build/.config"; do
        if [ -r "${candidate}" ]; then
            config_path="${candidate}"
            break
        fi
    done

    [ -n "${config_path}" ] || return 1
    encoded="$(sed -n 's/^CONFIG_RUSTC_VERSION=//p' "${config_path}" | head -n 1)"
    case "${encoded}" in
        ''|*[!0-9]*) return 1 ;;
    esac

    # Linux encodes compiler versions as major * 100000 + minor * 100 + patch.
    printf '%d.%d.%d\n' \
        "$((encoded / 100000))" \
        "$(((encoded / 100) % 1000))" \
        "$((encoded % 100))"
}

package_exists() {
    apt-cache show "$1" >/dev/null 2>&1
}

install_packages() {
    local kernel_release="$1"
    local rust_version="$2"
    local rust_series="${rust_version%.*}"
    local rust_packages=()

    for package in \
        "cargo-${rust_series}" \
        "rustc-${rust_series}" \
        "rust-${rust_series}-src" \
        "libstd-rust-${rust_series}" \
        "libstd-rust-${rust_series}-dev"; do
        if package_exists "${package}"; then
            rust_packages+=("${package}")
        fi
    done

    if [ "${#rust_packages[@]}" -eq 0 ]; then
        die "No Ubuntu Rust ${rust_series} packages are visible. Enable the matching Ubuntu repository or pass the correct kernel Rust version."
    fi

    log "Installing packages for target kernel ${kernel_release} and Rust ${rust_version}..."
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
        bindgen \
        "${rust_packages[@]}"
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

find_rust_source() {
    local rust_version="$1"
    local rust_series="${rust_version%.*}"

    for candidate in \
        "/usr/src/rustc-${rust_version}/library" \
        "/usr/src/rustc-${rust_series}.0/library" \
        "/usr/lib/rustlib/src/rust/library"; do
        if [ -d "${candidate}" ]; then
            printf '%s\n' "${candidate}"
            return
        fi
    done
    return 1
}

print_build_instructions() {
    local kernel_release="$1"
    local rust_version="$2"
    local rust_series="${rust_version%.*}"
    local rust_source

    rust_source="$(find_rust_source "${rust_version}")" || die "Could not locate the Rust ${rust_version} library sources."

    cat <<EOF

Ubuntu ARM64 target kernel setup is complete.

Next build command on the ARM64 VM:

  cd /path/to/Silverseal/silverseal-rootkit
  make clean ARCH=arm64 KDIR=/lib/modules/${kernel_release}/build
  PATH=/usr/bin:/bin:\$PATH \\
  RUST_LIB_SRC=${rust_source} \\
  make RUST_MIN_TOOLCHAIN= \\
  ARCH=arm64 \\
  KDIR=/lib/modules/${kernel_release}/build \\
  RUSTC=rustc-${rust_series} \\
  RUSTDOC=rustdoc-${rust_series}

Validation after build:

  readlink -f /lib/modules/${kernel_release}/build/rust
  file target/arm64/${kernel_release}/silverseal_rootkit.ko
  modinfo target/arm64/${kernel_release}/silverseal_rootkit.ko | grep vermagic
EOF
}

main() {
    local kernel_release="${1:-}"
    local rust_version="${2:-}"

    if [ "${kernel_release}" = "--help" ] || [ "${kernel_release}" = "-h" ]; then
        usage
        exit 0
    fi

    if [ -z "${kernel_release}" ]; then
        die "Please pass the target Ubuntu kernel release, for example: 7.0.0-31-generic"
    fi
    if [ "$(uname -m)" != "aarch64" ]; then
        die "Run this helper natively in the ARM64 target VM (uname -m must be aarch64)."
    fi

    if [ -z "${rust_version}" ]; then
        rust_version="$(derive_rust_version "${kernel_release}")" || die "Could not derive CONFIG_RUSTC_VERSION; pass the exact version as the second argument."
    fi

    log "Target kernel requires Rust ${rust_version}"
    sudo apt update
    install_packages "${kernel_release}" "${rust_version}"
    repair_header_rust_symlink "${kernel_release}"
    verify_kernel_rust_tree "${kernel_release}"
    print_build_instructions "${kernel_release}" "${rust_version}"
}

main "$@"
