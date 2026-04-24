// SPDX-License-Identifier: GPL-2.0

//! IDE-only stub for rust-analyzer and `cargo check`.
//!
//! The actual kernel module source is `silverseal_rootkit.rs` at the project
//! root, which is compiled by Kbuild and the Linux kernel build system.
//!
//! This file exists so that `cargo check` and rust-analyzer have a valid
//! `#![no_std]` crate to index. It deliberately omits `kernel::*` imports
//! since the `kernel` crate is not available via crates.io.

#![no_std]
