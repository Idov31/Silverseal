// SPDX-License-Identifier: GPL-2.0

//! Cargo build script.
//!
//! On Linux (WSL2) this invokes the Kbuild Makefile to compile the kernel
//! module.  On Windows the build is skipped with a warning — `cargo check`
//! and rust-analyzer still work for IDE support via the `src/lib.rs` stub.

fn main() {
    if std::env::consts::OS != "linux" {
        println!(
            "cargo:warning=Kernel module build skipped on non-Linux host. \
             In WSL2 run: make KDIR=/lib/modules/$(uname -r)/build M=$PWD LLVM=1"
        );
        return;
    }

    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    let status = std::process::Command::new("make")
        .current_dir(&manifest_dir)
        .status()
        .expect("Failed to run make — is build-essential installed?");

    if !status.success() {
        panic!(
            "Kernel module build failed. \
             Verify CONFIG_RUST=y with: cat /proc/config.gz | gunzip | grep CONFIG_RUST"
        );
    }

    // Re-run this script only when the module sources or build files change.
    println!("cargo:rerun-if-changed=silverseal_rootkit.rs");
    println!("cargo:rerun-if-changed=Kbuild");
    println!("cargo:rerun-if-changed=Makefile");
}
