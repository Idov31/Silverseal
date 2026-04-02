# Silverseal

Silverseal is a Linux framework containing a bootkit, rootkit loader and a rootkit

## Setup

### Repository Setup

* Clone the repository

```bash
git clone https://github.com/idov31/Silverseal.git
```

* Build the project

```bash
cd Silverseal
cargo build --release
```

* Replace the grub

```bash
# Copy Silverseal.efi to the same directory as setup_silverseal.sh and run the script
chmod +x setup_silverseal.sh
sudo ./setup_silverseal.sh
```

### Serial Logging Setup

#### Linux

1. **Identify the serial port:**

```bash
ls -la /dev/ttyS*
```

Common ports: `/dev/ttyS0` (COM1), `/dev/ttyS1` (COM2)

2. **Monitor serial output with `minicom`:**

```bash
sudo minicom -D /dev/ttyS0 -b 115200

# Or with `screen`:
sudo screen /dev/ttyS0 115200

# Or with `picocom`:
sudo picocom -b 115200 /dev/ttyS0
```

#### Windows

* Download and run [PuTTY](https://www.putty.org/)
* Select "Serial" connection type
* Enter the serial line you created in the VM (e.g., `\\.\pipe\com_1`)
* Set speed to 115200
* Under Connection > Serial, set "Flow control" to "None" and "Parity" to "None"
* Click Open

## Resources

* [UEFI Crate](https://rust-osdev.github.io/uefi-rs/how_to/protocols.html)
