#! /bin/bash

set -euo pipefail

KVER="$(uname -r)"
OUT="$HOME/silverseal-kernel-$KVER"

mkdir -p "$OUT"

sudo cp "/boot/vmlinuz-$KVER" "$OUT/"
sudo cp "/boot/System.map-$KVER" "$OUT/"
sudo cp "/boot/config-$KVER" "$OUT/"
sudo chown -R "$USER:$USER" "$OUT"

uname -a > "$OUT/uname.txt"
cat /proc/version > "$OUT/proc-version.txt"

EXTRACT="/usr/src/linux-headers-$KVER/scripts/extract-vmlinux"
"$EXTRACT" "$OUT/vmlinuz-$KVER" > "$OUT/vmlinux-$KVER"

# Include the symbol-rich image if debug symbols are installed.
if [ -f "/usr/lib/debug/boot/vmlinux-$KVER" ]; then
    cp "/usr/lib/debug/boot/vmlinux-$KVER" \
       "$OUT/vmlinux-$KVER.debug"
fi

file "$OUT"/* > "$OUT/file-info.txt"
sha256sum "$OUT"/* > "$OUT/SHA256SUMS"

tar -C "$HOME" -caf \
    "$HOME/silverseal-kernel-$KVER.tar.zst" \
    "silverseal-kernel-$KVER"