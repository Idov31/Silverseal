#![no_std]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(test)]
extern crate std;

/// The module for the logger.
mod logger;

/// The module for the serial port driver.
mod serial;

/// Minimal synchronization used by the global logger configuration.
mod sync;

pub use crate::logger::{builder, init, init_with_filter, Builder};
#[cfg(target_arch = "x86_64")]
pub use crate::serial::Serial;
