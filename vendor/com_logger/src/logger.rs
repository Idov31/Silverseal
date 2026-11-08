use crate::serial::{self, Backend};
use crate::sync::Mutex;
use core::format_args;
use log::*;

#[cfg(target_arch = "x86_64")]
const COM1_PORT: u16 = 0x3f8;
#[cfg(not(target_arch = "x86_64"))]
const QEMU_VIRT_PL011: usize = 0x0900_0000;

#[cfg(target_arch = "x86_64")]
const DEFAULT_BACKEND: Backend = Backend::Com(COM1_PORT);

#[cfg(not(target_arch = "x86_64"))]
const DEFAULT_BACKEND: Backend = Backend::Pl011(QEMU_VIRT_PL011);

static LOGGER: Logger = Logger(Mutex::new(DEFAULT_BACKEND));

struct Logger(Mutex<Backend>);

impl log::Log for Logger {
    fn enabled(&self, _m: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let backend = *self.0.lock();

        let _ = serial::write_fmt(
            backend,
            format_args!(
                "{:>8}: {} ({}, {}:{})\n",
                record.level(),
                record.args(),
                record.target(),
                record.file().unwrap_or("<unknown>"),
                record.line().unwrap_or(0),
            ),
        );
    }

    fn flush(&self) {}
}

fn set_logger_backend(backend: Backend) {
    let mut data = LOGGER.0.lock();
    *data = backend;
}

/// The builder for a serial port logger.
///
/// The builder instance can be created also by [`builder`][] function.
pub struct Builder {
    backend: Backend,
    filter: LevelFilter,
}

impl Builder {
    /// Create a builder for fine-tuning logger.
    pub fn new() -> Self {
        Self {
            backend: DEFAULT_BACKEND,
            filter: LevelFilter::Info,
        }
    }

    /// Set the base address of an x86 COM port.
    ///
    /// This remains available on every target for source compatibility, but
    /// [`setup`](Self::setup) rejects COM-port output on non-x86 targets.
    pub fn base(mut self, base: u16) -> Self {
        self.backend = Backend::Com(base);
        self
    }

    /// Select a PL011 device at the supplied MMIO base address.
    ///
    /// The caller must ensure that `base` names mapped, writable PL011 register
    /// memory for the entire time the global logger can be used. The address
    /// must be aligned to a 32-bit register boundary.
    pub fn pl011_mmio(mut self, base: usize) -> Self {
        assert_eq!(base & 0x3, 0, "PL011 MMIO base must be 32-bit aligned");
        self.backend = Backend::Pl011(base);
        self
    }

    /// Set the level filter.
    pub fn filter(mut self, filter: LevelFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Setup a logger based on the configuration.
    pub fn setup(self) {
        serial::init(self.backend);
        set_logger_backend(self.backend);

        set_logger(&LOGGER).unwrap();
        set_max_level(self.filter);
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a builder for fine-tuning logger.
///
/// Call [`Builder::setup`][] to apply the configuration and actually setup the logger.
///
/// ```rust,no_run
/// use log::*;
///
/// fn main() {
///    com_logger::builder()
///        .base(0x2f8)                  // Use COM2 port
///        .filter(LevelFilter::Debug)   // Print debug log
///        .setup();
///
///    debug!("Hello");
/// }
/// ```
pub fn builder() -> Builder {
    Builder::new()
}

/// Setup a logger with the default settings.
///
/// The default is COM1 on x86_64 and the QEMU `virt` PL011 address
/// (`0x0900_0000`) on other architectures.
pub fn init() {
    builder().filter(LevelFilter::Info).setup();
}

/// Setup a logger with a custom level filter.
///
/// This overwrites the level filter of the default settings.
pub fn init_with_filter(filter: LevelFilter) {
    builder().filter(filter).setup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_selects_com_backend() {
        let builder = Builder::new().base(0x2f8);
        assert_eq!(builder.backend, Backend::Com(0x2f8));
    }

    #[test]
    fn builder_selects_pl011_backend() {
        let builder = Builder::new().pl011_mmio(0x0900_0000);
        assert_eq!(builder.backend, Backend::Pl011(0x0900_0000));
    }

    #[test]
    #[should_panic(expected = "PL011 MMIO base must be 32-bit aligned")]
    fn builder_rejects_unaligned_pl011_backend() {
        let _ = Builder::new().pl011_mmio(0x0900_0001);
    }
}
