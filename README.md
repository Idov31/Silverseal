# Silverseal

![Silverseal Logo](./resources/silverseal_logo.png)

Silverseal demonstrates a UEFI bootkit that loads a Rust Linux kernel module. The repository contains the `no_std` UEFI bootkit in `silverseal-bootkit/`, the Kbuild-managed Rust module in `silverseal-rootkit/`, and deployment helpers in `scripts/`.

## ARM64 boot flow

ARM64 mirrors the existing x86 deployment model:

1. `grubaa64.efi` is replaced by `silverseal-bootkit.efi`; the original is retained as `grubaa64.efi.original`.
2. The bootkit chain-loads that original GRUB image and detours its existing Linux boot-image path. It does not add or require a GRUB menu entry.
3. The bootkit finds the stock ARM64 zboot PE inside the staged `vmlinuz` `.linux` section and observes its successful decompression into `vmlinux`.
4. The decompressed kernel is matched against the exact target profile. A late-initcall entry is redirected to a position-independent stager.
5. The stager initializes a kernel `work_struct` and calls the target kernel's `schedule_work.isra.0`. Its worker sleeps for 10 seconds, then invokes `/sbin/insmod /silverseal_rootkit.ko` from the real root filesystem.
6. The original initcall still runs.

This flow does not build, replace, or load the module from initrd/initramfs. It does not use a wrapper EFI binary or a repackaged kernel. The checked-in profile is intentionally pinned to Ubuntu kernel `7.0.0-31-generic`; mismatched images fail closed. Secure Boot must be disabled for the unsigned research binaries.

## Build the ARM64 rootkit in the Ubuntu VM

Use the native ARM64 Ubuntu VM on Apple Silicon. The real module must be built through the target kernel's Kbuild tree, not with Cargo's IDE stub:

```bash
cd Silverseal
./scripts/ubuntu_target_setup.sh 7.0.0-31-generic

cd silverseal-rootkit
make clean ARCH=arm64 LLVM= KDIR=/lib/modules/7.0.0-31-generic/build
PATH=/usr/bin:/bin:$PATH \
RUST_LIB_SRC=/path/printed/by/ubuntu_target_setup.sh \
make RUST_MIN_TOOLCHAIN= \
  ARCH=arm64 \
  LLVM= \
  KDIR=/lib/modules/7.0.0-31-generic/build \
  RUSTC=rustc-1.93 \
  RUSTDOC=rustdoc-1.93
```

Confirm that Kbuild produced the module for the pinned kernel:

```bash
file target/arm64/7.0.0-31-generic/silverseal_rootkit.ko
modinfo target/arm64/7.0.0-31-generic/silverseal_rootkit.ko | grep vermagic
```

Before runtime testing, validate the target kernel's `work_struct` layout from its BTF or DWARF: size 32 bytes, `entry` at offset 8, and `func` at offset 24. A mismatch is a hard stop because those values are encoded by the stager.

## Build the ARM64 bootkit on macOS

Apple Silicon can build the AArch64 UEFI binary directly. Install stable Rust with the `aarch64-unknown-uefi` target and PowerShell (`pwsh`) for fixture verification.

The large pinned artifacts are expected in `tmp/silverseal-kernel-7.0.0-31-generic/`. Generate the v3 profile after verifying their hashes, unique signatures, nested stock-zboot PE, caves, initcall, and linked System.map evidence:

```bash
cd Silverseal
pwsh ./scripts/verify_arm64_fixture.ps1 \
  -ArtifactDirectory ./tmp/silverseal-kernel-7.0.0-31-generic \
  -OutputDirectory ./target/arm64-fixture/7.0.0-31-generic-v3

export SILVERSEAL_ARM64_PROFILE="$PWD/target/arm64-fixture/7.0.0-31-generic-v3/7.0.0-31-generic.ssarm64p"
cargo build-bootkit-arm64 --release
```

The result is:

```text
target/aarch64-unknown-uefi/release/silverseal-bootkit.efi
```

An ARM64 build with no `SILVERSEAL_ARM64_PROFILE` deliberately installs no hook. The profile and small signature fixtures live under `fixtures/arm64/7.0.0-31-generic/`; the large kernel and GRUB artifacts remain ignored.

Host-side contracts can be run with:

```bash
cargo test-arm64
cargo test -p silverseal-bootkit --bin silverseal-arm64-tool --features arm64-tools
```

## Deploy in the ARM64 Ubuntu VM

Copy the bootkit and module into the VM, then put the module on the real root filesystem and replace the existing ARM64 GRUB binary:

```bash
sudo install -m 0644 \
  silverseal-rootkit/target/arm64/7.0.0-31-generic/silverseal_rootkit.ko \
  /silverseal_rootkit.ko

sudo ./scripts/setup_silverseal.sh arm64 \
  target/aarch64-unknown-uefi/release/silverseal-bootkit.efi
sudo reboot
```

Do not create a menu entry and do not rebuild initramfs. The VM should boot its normal existing Ubuntu entry. After boot, inspect the module result with:

```bash
sudo dmesg -w
lsmod | grep silverseal_rootkit
```

To restore the saved original GRUB image:

```bash
sudo ./scripts/restore_silverseal.sh arm64
```

The restore helper keeps the replaced image as `grubaa64.efi.silverseal` for recovery.

## Serial logs with VMware Fusion on macOS

Add a virtual serial port to the powered-off ARM64 VM and configure its output to a file on macOS. The bootkit discovers the firmware's UEFI Serial I/O protocol; it does not assume QEMU's PL011 MMIO address. If Fusion firmware exposes no Serial I/O protocol, logging is silently disabled and boot continues.

On macOS, watch the configured output file while the VM boots:

```bash
touch /path/to/fusion-serial.log
tail -F /path/to/fusion-serial.log
```

This captures bootkit messages before Linux starts. Once Linux is available, `sudo dmesg -w` in the VM is the simpler source for the delayed worker and module logs. QEMU is not required by this workflow.

## x86_64

The existing x86 build remains available and requires `nasm` on `PATH`:

```bash
cargo build-bootkit-x64 --release
cd silverseal-rootkit && make ARCH=x86_64
```

Deploy or restore with `scripts/setup_silverseal.sh x86_64` and `scripts/restore_silverseal.sh x86_64` respectively.

## Safety

EFI replacement can make a machine unbootable. Use a disposable VM, retain the `.original` GRUB image, confirm the exact kernel/header version, and keep Secure Boot disabled for testing. Runtime ARM64 boot and module-load claims require evidence from that VM; host builds and static verification alone do not establish runtime success.

## Resources

- [UEFI crate](https://rust-osdev.github.io/uefi-rs/how_to/protocols.html)
- [Elixir Bootlin](https://elixir.bootlin.com/linux)
- [memN0p's Bootkit](https://github.com/memN0ps/redlotus-rs)
