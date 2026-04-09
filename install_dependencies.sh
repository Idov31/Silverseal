#! /bin/bash
rust_support=`cat /proc/config.gz | gunzip | grep CONFIG_RUST=y`

if [ -z "$rust_support" ]; then
    echo "Your kernel does not support Rust. Please install a kernel with Rust support."
    exit 1
fi
sudo apt install build-essential flex bison dwarves libssl-dev libelf-dev
rustup component add rust-src
sudo apt install llvm clang libclang-dev
cargo install bindgen-cli