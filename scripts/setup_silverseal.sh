#!/usr/bin/env bash
set -euo pipefail

arch="${1:-x86_64}"
artifact="${2:-./silverseal-bootkit.efi}"
efi_dir="${EFI_DIR:-/boot/efi/EFI/ubuntu}"

case "$arch" in
  x86_64) grub_name="grubx64.efi" ;;
  arm64|aarch64) grub_name="grubaa64.efi" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

grub_path="$efi_dir/$grub_name"
backup_path="$grub_path.original"
pending_path="$grub_path.silverseal.pending"

test -f "$artifact" || { echo "missing bootkit artifact: $artifact" >&2; exit 1; }
test -f "$grub_path" || { echo "missing GRUB image: $grub_path" >&2; exit 1; }
test ! -e "$backup_path" || { echo "backup already exists: $backup_path" >&2; exit 1; }
test ! -e "$pending_path" || { echo "staged image already exists: $pending_path" >&2; exit 1; }

install -m 0644 -- "$artifact" "$pending_path"
mv -- "$grub_path" "$backup_path"
mv -- "$pending_path" "$grub_path"
