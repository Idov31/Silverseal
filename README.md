# Silverseal

Silverseal is a Linux framework containing a bootkit, rootkit loader and a rootkit

## Setup

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

## Resources

* [UEFI Crate](https://rust-osdev.github.io/uefi-rs/how_to/protocols.html)
