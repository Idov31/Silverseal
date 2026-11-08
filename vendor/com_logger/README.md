# com_logger

[![Latest version](https://img.shields.io/crates/v/com_logger.svg)](https://crates.io/crates/com_logger)
[![Documentation](https://docs.rs/com_logger/badge.svg)](https://docs.rs/com_logger)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Actions Status](https://github.com/YushiOMOTE/com_logger/workflows/Main/badge.svg)](https://github.com/YushiOMOTE/com_logger/actions)

Serial port logger through [COM ports](https://en.wikipedia.org/wiki/COM_(hardware_interface)).

* Doesn't require `std` (`no_std`)
* Doesn't require `alloc`

```rust,no_run
use log::*;

fn main() {
    com_logger::init();

    info!("Starting");
}
```

## Configuration

```rust,no_run
use log::*;

fn main() {
    com_logger::builder()
        .base(0x2f8)                  // Use COM2 port
        .filter(LevelFilter::Debug)   // Print debug log
        .setup();

    debug!("Hello");
}
```

## Repository adaptation

This vendored fork is based on upstream `com_logger` 0.1.2, commit
`7b272bb6caeb13cab2f8144e6c2ab65608e869d6`. It preserves the x86 COM API and
adds `Builder::pl011_mmio` for PL011 serial devices such as QEMU `virt`.

```rust,no_run
use log::*;

fn main() {
    com_logger::builder()
        .pl011_mmio(0x0900_0000)
        .filter(LevelFilter::Debug)
        .setup();
}
```

