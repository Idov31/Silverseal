#!/bin/bash

set -euo pipefail

readonly DEFAULT_REPO_URL="https://github.com/microsoft/WSL2-Linux-Kernel.git"
readonly DEFAULT_WORK_ROOT="${HOME}/.cache/silverseal/wsl-kernel"
readonly DEFAULT_RUST_TOOLCHAIN="stable"

CONFIG_CHANGED=0
KERNEL_RUST_TOOLCHAIN=""
WINDOWS_ARTIFACT_DIR_WIN=""

usage() {
    cat <<'EOF'
Usage: ./scripts/wsl_setup.sh [options]

Sets up a WSL2 Ubuntu environment so it can build Rust-for-Linux modules by:
  1. installing Ubuntu build dependencies
  2. cloning the matching Microsoft WSL2 kernel source
  3. enabling CONFIG_RUST in the kernel config
  4. building a custom WSL2 kernel and modules VHDX
  5. generating a .wslconfig snippet and wiring /lib/modules/<release>/build

Options:
  --work-root PATH        Override the working directory used for kernel sources
  --repo-url URL          Override the WSL2 kernel Git repository
  --kernel-ref REF        Override the kernel git tag/branch/commit to build
  --jobs N                Override the number of parallel make jobs
  --write-wslconfig       Write %UserProfile%\.wslconfig on the Windows side
  --help                  Show this help text

Examples:
  ./scripts/wsl_setup.sh
  ./scripts/wsl_setup.sh --kernel-ref linux-msft-wsl-6.6.87.2 --write-wslconfig
EOF
}

log() {
    printf '[wsl_setup] %s\n' "$*"
}

die() {
    printf '[wsl_setup] ERROR: %s\n' "$*" >&2
    exit 1
}

have_command() {
    command -v "$1" >/dev/null 2>&1
}

kernel_make() {
    local repo_dir="$1"
    shift

    if [ -z "${KERNEL_RUST_TOOLCHAIN}" ]; then
        make -C "${repo_dir}" LLVM=1 "$@"
    else
        env RUSTUP_TOOLCHAIN="${KERNEL_RUST_TOOLCHAIN}" make -C "${repo_dir}" LLVM=1 "$@"
    fi
}

diagnose_rust_config_failure() {
    local repo_dir="$1"

    log "Rust config diagnostics:"

    if [ -f "${repo_dir}/.config" ]; then
        grep -E '^(CONFIG_HAVE_RUST|CONFIG_RUST|CONFIG_RUST_IS_AVAILABLE)=' "${repo_dir}/.config" || true
    fi

    if [ -f "${repo_dir}/include/config/auto.conf" ]; then
        grep -E '^(CONFIG_HAVE_RUST|CONFIG_RUST|CONFIG_RUST_IS_AVAILABLE)=' "${repo_dir}/include/config/auto.conf" || true
    fi

    if [ -x "${repo_dir}/scripts/config" ] && [ -f "${repo_dir}/.config" ]; then
        "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --state RUST || true
    fi

    log "Re-running rustavailable for details..."
    kernel_make "${repo_dir}" rustavailable || true
}

require_wsl2() {
    grep -qiE '(microsoft|wsl)' /proc/version || die "This script must run inside WSL."
    uname -r | grep -q 'WSL2' || die "This script only supports WSL2."
}

derive_kernel_tag() {
    local release="$1"
    release="${release%-microsoft-standard-WSL2}"
    printf 'linux-msft-wsl-%s\n' "$release"
}

derive_kernel_branch() {
    local release="$1"
    local base major minor
    base="${release%%-*}"
    major="$(printf '%s' "$base" | cut -d. -f1)"
    minor="$(printf '%s' "$base" | cut -d. -f2)"
    printf 'linux-msft-wsl-%s.%s.y\n' "$major" "$minor"
}

ensure_apt_packages() {
    log "Installing Ubuntu packages required to build a Rust-enabled WSL2 kernel..."
    sudo apt update
    sudo apt install -y \
        bc \
        bison \
        build-essential \
        ca-certificates \
        clang \
        cpio \
        curl \
        dwarves \
        flex \
        git \
        libclang-dev \
        libelf-dev \
        libncurses-dev \
        libssl-dev \
        lld \
        llvm \
        pahole \
        qemu-utils \
        rsync
}

ensure_rustup_and_toolchain() {
    if ! have_command rustup; then
        log "Installing rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    fi

    if [ -f "${HOME}/.cargo/env" ]; then
        # shellcheck disable=SC1090
        . "${HOME}/.cargo/env"
    fi

    if rustup toolchain list | grep -q "^${DEFAULT_RUST_TOOLCHAIN}"; then
        log "Rust toolchain ${DEFAULT_RUST_TOOLCHAIN} is already installed. Skipping toolchain install."
    else
        log "Installing Rust toolchain ${DEFAULT_RUST_TOOLCHAIN}..."
        rustup toolchain install "${DEFAULT_RUST_TOOLCHAIN}"
    fi

    rustup default "${DEFAULT_RUST_TOOLCHAIN}"

    if rustup component list --toolchain "${DEFAULT_RUST_TOOLCHAIN}" --installed | grep -q '^rust-src$'; then
        log "Rust component rust-src is already installed for ${DEFAULT_RUST_TOOLCHAIN}. Skipping component install."
    else
        log "Installing Rust component rust-src for ${DEFAULT_RUST_TOOLCHAIN}..."
        rustup component add rust-src --toolchain "${DEFAULT_RUST_TOOLCHAIN}"
    fi
}

ensure_bindgen_cli() {
    if have_command bindgen; then
        log "bindgen is already available in PATH. Skipping bindgen-cli install."
        return
    fi

    log "Installing bindgen-cli..."
    cargo +stable install --locked bindgen-cli
}

ensure_kernel_min_bindgen_cli() {
    local repo_dir="$1"
    local required_bindgen installed_bindgen

    if [ ! -x "${repo_dir}/scripts/min-tool-version.sh" ]; then
        log "Kernel min-tool-version helper was not found. Skipping kernel-specific bindgen pin."
        return
    fi

    required_bindgen="$("${repo_dir}/scripts/min-tool-version.sh" bindgen)"
    if [ -z "${required_bindgen}" ]; then
        log "Kernel min-tool-version helper returned an empty bindgen version. Skipping bindgen pin."
        return
    fi

    if have_command bindgen; then
        installed_bindgen="$(bindgen --version | awk '{print $2}')"
        if [ "${installed_bindgen}" = "${required_bindgen}" ]; then
            log "Kernel-required bindgen version ${required_bindgen} is already installed."
            return
        fi
    fi

    log "Installing kernel-required bindgen-cli version ${required_bindgen} with the stable Cargo toolchain..."
    cargo +stable install --locked --force --version "${required_bindgen}" bindgen-cli
}

ensure_kernel_min_rust_toolchain() {
    local repo_dir="$1"
    local required_rustc

    if [ ! -x "${repo_dir}/scripts/min-tool-version.sh" ]; then
        log "Kernel min-tool-version helper was not found. Skipping kernel-specific Rust override."
        return
    fi

    required_rustc="$("${repo_dir}/scripts/min-tool-version.sh" rustc)"
    if [ -z "${required_rustc}" ]; then
        log "Kernel min-tool-version helper returned an empty rustc version. Skipping override."
        return
    fi

    if rustup toolchain list | grep -q "^${required_rustc}"; then
        log "Kernel-required rustc toolchain ${required_rustc} is already installed."
    else
        log "Installing kernel-required rustc toolchain ${required_rustc}..."
        rustup toolchain install "${required_rustc}"
    fi

    rustup override set "${required_rustc}"
    KERNEL_RUST_TOOLCHAIN="${required_rustc}"

    if rustup component list --toolchain "${required_rustc}" --installed | grep -q '^rust-src$'; then
        log "Rust component rust-src is already installed for ${required_rustc}. Skipping component install."
    else
        log "Installing Rust component rust-src for ${required_rustc}..."
        rustup component add rust-src --toolchain "${required_rustc}"
    fi
}

checkout_kernel_source() {
    local repo_dir="$1"
    local repo_url="$2"
    local preferred_ref="$3"
    local fallback_branch="$4"

    mkdir -p "$(dirname "$repo_dir")"

    if [ ! -d "${repo_dir}/.git" ]; then
        log "Cloning ${repo_url} into ${repo_dir}..."
        git clone "$repo_url" "$repo_dir"
    fi

    if git -C "$repo_dir" rev-parse -q --verify "refs/tags/${preferred_ref}" >/dev/null; then
        log "Checking out exact matching WSL kernel tag ${preferred_ref}..."
        git -C "$repo_dir" checkout "tags/${preferred_ref}"
        return
    fi

    git -C "$repo_dir" fetch --tags --prune origin

    if git -C "$repo_dir" rev-parse -q --verify "refs/tags/${preferred_ref}" >/dev/null; then
        log "Checking out exact matching WSL kernel tag ${preferred_ref}..."
        git -C "$repo_dir" checkout "tags/${preferred_ref}"
        return
    fi

    log "Exact tag ${preferred_ref} was not found. Falling back to branch ${fallback_branch}..."
    git -C "$repo_dir" checkout "$fallback_branch"
    git -C "$repo_dir" pull --ff-only origin "$fallback_branch"
}

configure_kernel() {
    local repo_dir="$1"

    if [ -f "${repo_dir}/.config" ] && grep -q '^CONFIG_RUST=y$' "${repo_dir}/.config"; then
        log "Kernel config already has CONFIG_RUST=y. Skipping config regeneration."
        return
    fi

    log "Checking whether the kernel tree currently accepts Rust support..."
    if ! kernel_make "${repo_dir}" rustavailable; then
        die "Rust is not available to this kernel tree. Run 'make -C ${repo_dir} LLVM=1 rustavailable' to inspect the failure details."
    fi

    log "Preparing WSL kernel config with Rust support..."
    cp "${repo_dir}/Microsoft/config-wsl" "${repo_dir}/.config"

    # Some WSL baseline options conflict with CONFIG_RUST in Linux 6.6.
    # Disable the known blockers before enabling Rust support.
    "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --disable MODVERSIONS
    "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --disable DEBUG_INFO_BTF
    "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --disable GCC_PLUGIN_RANDSTRUCT
    "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --disable RANDSTRUCT
    "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --disable CFI
    "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --disable CALL_PADDING
    "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --disable KASAN_SW_TAGS
    "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --enable MODULES
    "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --enable IKCONFIG
    "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --enable IKCONFIG_PROC
    "${repo_dir}/scripts/config" --file "${repo_dir}/.config" --enable RUST

    kernel_make "$repo_dir" olddefconfig

    if ! grep -q '^CONFIG_RUST=y$' "${repo_dir}/.config"; then
        diagnose_rust_config_failure "${repo_dir}"
        die "CONFIG_RUST was not enabled in ${repo_dir}/.config even though the script requested it."
    fi

    CONFIG_CHANGED=1
}

invalidate_build_artifacts_if_needed() {
    local repo_dir="$1"
    local output_dir="$2"

    if [ "${CONFIG_CHANGED}" -ne 1 ]; then
        return
    fi

    log "Kernel config changed. Removing stale build artifacts so the Rust-enabled kernel is rebuilt."
    rm -f "${repo_dir}/arch/x86/boot/bzImage"
    rm -f "${output_dir}/bzImage" "${output_dir}/modules.vhdx"
    rm -rf "${output_dir}/modules"
}

build_kernel() {
    local repo_dir="$1"
    local jobs="$2"

    if [ -f "${repo_dir}/arch/x86/boot/bzImage" ] && [ "${repo_dir}/arch/x86/boot/bzImage" -nt "${repo_dir}/.config" ]; then
        log "Kernel image already exists at ${repo_dir}/arch/x86/boot/bzImage. Skipping kernel build."
        return
    fi

    log "Building custom WSL2 kernel with LLVM..."
    kernel_make "$repo_dir" -j"${jobs}"
}

stage_artifacts() {
    local repo_dir="$1"
    local output_dir="$2"
    local kernel_release="$3"

    local modules_root="${output_dir}/modules"
    local staged_modules_dir="${modules_root}/lib/modules/${kernel_release}"
    mkdir -p "$output_dir" "$modules_root"

    if [ ! -f "${output_dir}/bzImage" ]; then
        log "Copying kernel image to ${output_dir}/bzImage..."
        cp "${repo_dir}/arch/x86/boot/bzImage" "${output_dir}/bzImage"
    else
        log "Kernel image artifact already exists at ${output_dir}/bzImage. Skipping copy."
    fi

    if [ ! -e "${staged_modules_dir}" ]; then
        log "Installing kernel modules into ${modules_root}..."
        kernel_make "$repo_dir" INSTALL_MOD_PATH="${modules_root}" modules_install
    else
        log "Kernel modules already staged under ${modules_root}. Skipping modules_install."
    fi

    if [ ! -d "${staged_modules_dir}" ] || [ -z "$(find "${staged_modules_dir}" -mindepth 1 -print -quit 2>/dev/null)" ]; then
        log "No kernel modules were staged for ${kernel_release}. Skipping modules.vhdx generation."
        rm -f "${output_dir}/modules.vhdx"
    elif [ -f "${output_dir}/modules.vhdx" ]; then
        log "Modules VHDX already exists at ${output_dir}/modules.vhdx. Skipping VHDX generation."
    elif [ -x "${repo_dir}/Microsoft/scripts/gen_modules_vhdx.sh" ]; then
        sudo "${repo_dir}/Microsoft/scripts/gen_modules_vhdx.sh" "${modules_root}" "${kernel_release}" "${output_dir}/modules.vhdx"
    else
        die "Microsoft/scripts/gen_modules_vhdx.sh was not found in the kernel tree."
    fi
}

link_build_tree() {
    local repo_dir="$1"
    local kernel_release="$2"

    log "Linking /lib/modules/${kernel_release}/build to the custom kernel source tree..."
    sudo mkdir -p "/lib/modules/${kernel_release}"

    if [ -L "/lib/modules/${kernel_release}/build" ] && [ "$(readlink -f "/lib/modules/${kernel_release}/build")" = "$(readlink -f "${repo_dir}")" ]; then
        log "/lib/modules/${kernel_release}/build already points to ${repo_dir}. Skipping relink."
        return
    fi

    sudo ln -sfn "${repo_dir}" "/lib/modules/${kernel_release}/build"
}

windows_profile_dir() {
    if have_command cmd.exe; then
        cmd.exe /c "echo %UserProfile%" 2>/dev/null | tr -d '\r'
    fi
}

windows_artifact_dir() {
    local windows_profile="$1"
    local kernel_release="$2"
    printf '%s\\silverseal\\wsl-kernel\\%s\n' "${windows_profile}" "${kernel_release}"
}

copy_file_if_needed() {
    local source_path="$1"
    local dest_path="$2"
    local label="$3"

    if [ ! -f "${dest_path}" ] || ! cmp -s "${source_path}" "${dest_path}"; then
        cp "${source_path}" "${dest_path}"
        log "Copied ${label} to ${dest_path}"
    else
        log "${label} already matches ${dest_path}. Skipping copy."
    fi
}

stage_windows_artifacts() {
    local output_dir="$1"
    local windows_profile="$2"
    local kernel_release="$3"

    [ -n "${windows_profile}" ] || die "Unable to locate the Windows %UserProfile% directory from WSL."

    local default_dir_win default_dir_linux fallback_dir_win fallback_dir_linux
    default_dir_win="$(windows_artifact_dir "${windows_profile}" "${kernel_release}")"
    default_dir_linux="$(wslpath "${default_dir_win}")"
    fallback_dir_win="${default_dir_win}-next"
    fallback_dir_linux="$(wslpath "${fallback_dir_win}")"

    mkdir -p "${default_dir_linux}"

    WINDOWS_ARTIFACT_DIR_WIN="${default_dir_win}"

    if ! copy_file_if_needed "${output_dir}/bzImage" "${default_dir_linux}/bzImage" "kernel image"; then
        log "Primary Windows kernel path appears to be locked. Falling back to ${fallback_dir_win}"
        mkdir -p "${fallback_dir_linux}"
        copy_file_if_needed "${output_dir}/bzImage" "${fallback_dir_linux}/bzImage" "kernel image"
        WINDOWS_ARTIFACT_DIR_WIN="${fallback_dir_win}"
    fi

    local windows_artifact_dir_linux
    windows_artifact_dir_linux="$(wslpath "${WINDOWS_ARTIFACT_DIR_WIN}")"

    if [ ! -f "${output_dir}/modules.vhdx" ]; then
        log "No modules.vhdx artifact was produced. Skipping Windows modules copy."
        rm -f "${windows_artifact_dir_linux}/modules.vhdx"
    else
        copy_file_if_needed "${output_dir}/modules.vhdx" "${windows_artifact_dir_linux}/modules.vhdx" "modules VHDX"
    fi
}

write_generated_wslconfig() {
    local output_dir="$1"
    local windows_profile="$2"
    local kernel_release="$3"

    local windows_artifact_dir_win kernel_win_path modules_win_path escaped_kernel_win_path escaped_modules_win_path
    if [ -n "${WINDOWS_ARTIFACT_DIR_WIN}" ]; then
        windows_artifact_dir_win="${WINDOWS_ARTIFACT_DIR_WIN}"
    else
        windows_artifact_dir_win="$(windows_artifact_dir "${windows_profile}" "${kernel_release}")"
    fi
    kernel_win_path="${windows_artifact_dir_win}\\bzImage"
    modules_win_path="${windows_artifact_dir_win}\\modules.vhdx"
    escaped_kernel_win_path="${kernel_win_path//\\/\\\\}"
    escaped_modules_win_path="${modules_win_path//\\/\\\\}"

    local generated_wslconfig_path="${output_dir}/wslconfig.generated"

    if [ -f "${generated_wslconfig_path}" ]; then
        log "Generated .wslconfig already exists at ${generated_wslconfig_path}. Refreshing it."
    fi

    cat > "${generated_wslconfig_path}" <<EOF
[wsl2]
kernel=${escaped_kernel_win_path}
EOF

    if [ -f "${output_dir}/modules.vhdx" ]; then
        printf 'kernelModules=%s\n' "${escaped_modules_win_path}" >> "${generated_wslconfig_path}"
    fi

    log "Generated .wslconfig snippet at ${generated_wslconfig_path}"
    log "Windows profile detected at ${windows_profile}"
}

write_windows_wslconfig() {
    local output_dir="$1"
    local windows_profile="$2"

    [ -n "${windows_profile}" ] || die "Unable to locate the Windows %UserProfile% directory from WSL."

    local windows_wslconfig_win windows_wslconfig
    windows_wslconfig_win="${windows_profile}\\.wslconfig"
    windows_wslconfig="$(wslpath "${windows_wslconfig_win}")"

    if [ -f "${windows_wslconfig}" ]; then
        cp "${windows_wslconfig}" "${windows_wslconfig}.bak"
        log "Backed up existing ${windows_wslconfig} to ${windows_wslconfig}.bak"
    fi

    cp "${output_dir}/wslconfig.generated" "${windows_wslconfig}"
    log "Wrote ${windows_wslconfig}"
}

main() {
    local work_root="${DEFAULT_WORK_ROOT}"
    local repo_url="${DEFAULT_REPO_URL}"
    local kernel_ref=""
    local jobs
    local write_wslconfig="false"
    local kernel_tag kernel_branch repo_dir output_dir kernel_release windows_profile

    jobs="$(nproc)"

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --work-root)
                [ "$#" -ge 2 ] || die "--work-root requires a value"
                work_root="$2"
                shift 2
                ;;
            --repo-url)
                [ "$#" -ge 2 ] || die "--repo-url requires a value"
                repo_url="$2"
                shift 2
                ;;
            --kernel-ref)
                [ "$#" -ge 2 ] || die "--kernel-ref requires a value"
                kernel_ref="$2"
                shift 2
                ;;
            --jobs)
                [ "$#" -ge 2 ] || die "--jobs requires a value"
                jobs="$2"
                shift 2
                ;;
            --write-wslconfig)
                write_wslconfig="true"
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    require_wsl2

    kernel_release="$(uname -r)"
    kernel_tag="${kernel_ref:-$(derive_kernel_tag "${kernel_release}")}"
    kernel_branch="$(derive_kernel_branch "${kernel_release}")"
    repo_dir="${work_root}/WSL2-Linux-Kernel"
    output_dir="${work_root}/output/${kernel_tag}"

    log "Detected WSL2 kernel release: ${kernel_release}"
    log "Target WSL kernel ref: ${kernel_tag}"
    log "Kernel source work tree: ${repo_dir}"
    log "Build artifacts output: ${output_dir}"

    ensure_apt_packages
    ensure_rustup_and_toolchain
    ensure_bindgen_cli
    checkout_kernel_source "${repo_dir}" "${repo_url}" "${kernel_tag}" "${kernel_branch}"
    ensure_kernel_min_rust_toolchain "${repo_dir}"
    ensure_kernel_min_bindgen_cli "${repo_dir}"
    configure_kernel "${repo_dir}"
    invalidate_build_artifacts_if_needed "${repo_dir}" "${output_dir}"
    build_kernel "${repo_dir}" "${jobs}"

    if [ -z "${KERNEL_RUST_TOOLCHAIN}" ]; then
        kernel_release="$(make -s -C "${repo_dir}" kernelrelease)"
    else
        kernel_release="$(env RUSTUP_TOOLCHAIN="${KERNEL_RUST_TOOLCHAIN}" make -s -C "${repo_dir}" kernelrelease)"
    fi
    output_dir="${work_root}/output/${kernel_release}"

    stage_artifacts "${repo_dir}" "${output_dir}" "${kernel_release}"
    link_build_tree "${repo_dir}" "${kernel_release}"

    windows_profile="$(windows_profile_dir || true)"
    [ -n "${windows_profile}" ] || die "Unable to locate the Windows %UserProfile% directory from WSL."
    stage_windows_artifacts "${output_dir}" "${windows_profile}" "${kernel_release}"
    write_generated_wslconfig "${output_dir}" "${windows_profile}" "${kernel_release}"

    if [ "${write_wslconfig}" = "true" ]; then
        write_windows_wslconfig "${output_dir}" "${windows_profile}"
    fi

    cat <<EOF

Setup is complete.

Artifacts:
  Kernel image: ${output_dir}/bzImage
  Modules VHDX: ${output_dir}/modules.vhdx
  Generated .wslconfig: ${output_dir}/wslconfig.generated
  Kernel source tree: ${repo_dir}
  KDIR for external modules: ${repo_dir}

Next steps:
  1. If you did not use --write-wslconfig, copy ${output_dir}/wslconfig.generated to %UserProfile%\\.wslconfig on Windows.
  2. Run: wsl.exe --shutdown
  3. Start Ubuntu again.
  4. Verify: uname -r
  5. Verify: zgrep '^CONFIG_RUST=y$' /proc/config.gz || grep '^CONFIG_RUST=y$' /boot/config-\$(uname -r)
  6. Build the module from Silverseal with:
       cd /path/to/Silverseal/silverseal-rootkit
       make KDIR=${repo_dir} M=\$PWD LLVM=1

Note:
  The stock WSL2 kernel does not expose Rust support here, so this script builds a custom Rust-enabled WSL2 kernel.
EOF
}

main "$@"
