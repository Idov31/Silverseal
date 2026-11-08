#![no_std]

//! Shared code for the Silverseal UEFI binaries.

pub mod arm64_profile;
pub mod arm64_trampoline;

// Compile the firmware detour helpers into the host test crate so their pure
// encoding, relocation, and runtime-address restoration contracts execute in
// the consolidated ARM64 test suite.
#[cfg(test)]
#[allow(dead_code)]
#[path = "helpers/arm64.rs"]
mod arm64_detour_tests;
