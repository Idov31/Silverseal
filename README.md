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

## Build

* Build the rootkit

```bash
cd Silverseal/silverseal-rootkit
make
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
