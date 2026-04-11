# Silverseal

![Silverseal Logo](./resources/silverseal_logo.png)

Silverseal is a Linux framework containing a bootkit and a rootkit.

## Installing Dependencies

### Ubuntu

```bash
./scripts/install_dependencies.sh
```

### WSL

> ![IMPORTANT]
> If you're using WSL, make sure to set up WSL 2 and install Ubuntu. This script is going to replace the default WSL kernel with a custom one that supports Rust.

```bash
./scripts/wsl_setup.sh
```

To build the rootkit against your wanted target kernel, you need to run the following script on your build machine (either WSL or a native Linux machine):

```bash
./scripts/ubuntu_target_setup.sh <uname -r of your target kernel>
```

This flow expects the target Ubuntu kernel to already have `CONFIG_RUST=y`. It also verifies the `linux-lib-rust-<kernel>` package linkage under `/usr/src/linux-headers-<kernel>/rust`, because a broken symlink there can cause external Rust module builds to fail with `can't find crate for core`.

## Build

* Build the rootkit

```bash
cd Silverseal/silverseal-rootkit
make
```

* Build the rootkit for an Ubuntu generic target kernel from WSL

```bash
cd Silverseal/silverseal-rootkit
PATH=/usr/bin:/bin:$PATH \
RUST_LIB_SRC=/usr/src/rustc-1.82.0/library \
make RUST_MIN_TOOLCHAIN= \
KDIR=/usr/src/linux-headers-6.17.0-20-generic \
CC=x86_64-linux-gnu-gcc-13 \
RUSTC=rustc-1.82 \
RUSTDOC=rustdoc-1.82
```

The module Makefile auto-detects `/usr/src/linux-headers-*` targets and passes the Rust compatibility cfg through Kbuild's Rust flag variables so the newer Ubuntu `module!` metadata schema uses `authors` instead of the older `author` key.

After the build, verify the target kernel version was embedded correctly:

```bash
modinfo target/silverseal_rootkit.ko | grep vermagic
```

* Build the bootkit

```bash
cd Silverseal/silverseal-bootkit
cargo build --release
```

## Test

You can use the `setup_silverseal.sh` script to replace the current GRUB with the Silverseal bootkit.

```bash
chmod +x setup_silverseal.sh
sudo ./setup_silverseal.sh
```

## Remove Silverseal

To remove Silverseal, you can use the `restore_silverseal.sh` script to restore the original GRUB configuration.

```bash
chmod +x restore_silverseal.sh
sudo ./restore_silverseal.sh
```

## Serial Logging Setup

### Linux

* **Identify the serial port:**

```bash
ls -la /dev/ttyS*
```

Common ports: `/dev/ttyS0` (COM1), `/dev/ttyS1` (COM2)

* **Monitor serial output with `minicom`:**

```bash
sudo minicom -D /dev/ttyS0 -b 115200

# Or with `screen`:
sudo screen /dev/ttyS0 115200

# Or with `picocom`:
sudo picocom -b 115200 /dev/ttyS0
```

### Windows

* Download and run [PuTTY](https://www.putty.org/)
* Select "Serial" connection type
* Enter the serial line you created in the VM (e.g., `\\.\pipe\com_1`)
* Set speed to 115200
* Under Connection > Serial, set "Flow control" to "None" and "Parity" to "None"
* Click Open

## Resources

* [UEFI Crate](https://rust-osdev.github.io/uefi-rs/how_to/protocols.html)
