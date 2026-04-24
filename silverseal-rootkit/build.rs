// SPDX-License-Identifier: GPL-2.0

//! Cargo build script for workspace ergonomics only.
//!
//! The real kernel module is built by Kbuild via `make`; Cargo is kept around
//! so the workspace, rust-analyzer, and `cargo check` still have a valid crate.

fn main() {
    println!(
        "cargo:warning=silverseal-rootkit is built with Kbuild, not Cargo. \
         Use: make KDIR=/lib/modules/$(uname -r)/build M=$PWD LLVM=1"
    );

    println!("cargo:rerun-if-changed=silverseal_rootkit.rs");
    println!("cargo:rerun-if-changed=Kbuild");
    println!("cargo:rerun-if-changed=Makefile");
}
