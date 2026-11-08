#!/usr/bin/env bash
set -euo pipefail

arch="${1:-x86_64}"
efi_dir="${EFI_DIR:-/boot/efi/EFI/ubuntu}"

case "$arch" in
  x86_64) grub_name="grubx64.efi" ;;
  arm64|aarch64) grub_name="grubaa64.efi" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

grub_path="$efi_dir/$grub_name"
backup_path="$grub_path.original"
deployed_backup="$grub_path.silverseal"

test -f "$backup_path" || { echo "missing GRUB backup: $backup_path" >&2; exit 1; }
test ! -e "$deployed_backup" || { echo "refusing to overwrite: $deployed_backup" >&2; exit 1; }

if test -e "$grub_path"; then
  mv -- "$grub_path" "$deployed_backup"
fi
mv -- "$backup_path" "$grub_path"
