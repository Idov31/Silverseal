use core::fmt;

#[cfg(target_arch = "x86_64")]
use uart_16550::SerialPort;

const PL011_DATA_REGISTER: usize = 0x00;
const PL011_FLAG_REGISTER: usize = 0x18;
const PL011_TX_FIFO_FULL: u32 = 1 << 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Backend {
    Com(u16),
    Pl011(usize),
}

pub(crate) fn init(backend: Backend) {
    match backend {
        #[cfg(target_arch = "x86_64")]
        Backend::Com(base) => Serial::new(base).init(),
        #[cfg(not(target_arch = "x86_64"))]
        Backend::Com(_) => panic!("COM-port logging is supported only on x86_64"),
        Backend::Pl011(_) => {
            // Firmware is responsible for configuring the PL011. Initializing
            // it here could change baud rate or disrupt an active console.
        }
    }
}

pub(crate) fn write_fmt(backend: Backend, args: fmt::Arguments<'_>) -> fmt::Result {
    match backend {
        #[cfg(target_arch = "x86_64")]
        Backend::Com(base) => fmt::write(&mut Serial::new(base), args),
        #[cfg(not(target_arch = "x86_64"))]
        Backend::Com(_) => Err(fmt::Error),
        Backend::Pl011(base) => {
            // SAFETY: Builder::pl011_mmio documents the requirement that the
            // selected base remain mapped as PL011 MMIO while logging is active.
            let mut serial = unsafe { Pl011::from_mmio(base) };
            fmt::write(&mut serial, args)
        }
    }
}

/// Serial port driver which implements [`core::fmt::Write`][].
///
/// ```rust,no_run
/// use com_logger::Serial;
///
/// fn main() {
///    // Setup COM1 serial port.
///    let mut s = Serial::new(0x3f8);
///    s.init();
///
///    // Write the single byte to the serial port.
///    s.write(b'P');
///
///    // Write the string to the serial port.
///    core::fmt::write(&mut s, format_args!("Hello {}", 0xdead));
/// }
/// ```
#[cfg(target_arch = "x86_64")]
pub struct Serial(SerialPort);

#[cfg(target_arch = "x86_64")]
impl Serial {
    /// Create the driver instance for the specified base address.
    pub fn new(base: u16) -> Self {
        Self(unsafe { SerialPort::new(base) })
    }

    /// Initialize the serial port.
    pub fn init(&mut self) {
        self.0.init();
    }

    /// Write a single byte to the serial port.
    pub fn write(&mut self, d: u8) {
        self.0.send(d);
    }
}

#[cfg(target_arch = "x86_64")]
impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            self.0.send(b);
        }
        Ok(())
    }
}

trait RegisterAccess {
    fn read(&self, address: usize) -> u32;
    fn write(&self, address: usize, value: u32);
}

struct VolatileRegisters;

impl RegisterAccess for VolatileRegisters {
    fn read(&self, address: usize) -> u32 {
        // SAFETY: Pl011::from_mmio requires a mapped PL011 register bank and
        // computes only documented, 32-bit-aligned offsets from that base.
        unsafe { core::ptr::read_volatile(address as *const u32) }
    }

    fn write(&self, address: usize, value: u32) {
        // SAFETY: See read(). The data register is writable and 32-bit aligned.
        unsafe { core::ptr::write_volatile(address as *mut u32, value) }
    }
}

struct Pl011<R> {
    base: usize,
    registers: R,
}

impl Pl011<VolatileRegisters> {
    /// Construct a PL011 writer over a live MMIO register bank.
    ///
    /// # Safety
    ///
    /// `base` must be a mapped, writable PL011 register bank aligned to a
    /// 32-bit boundary and valid for the lifetime of the returned writer.
    unsafe fn from_mmio(base: usize) -> Self {
        debug_assert_eq!(base & 0x3, 0);
        Self {
            base,
            registers: VolatileRegisters,
        }
    }
}

impl<R: RegisterAccess> Pl011<R> {
    #[cfg(test)]
    fn with_registers(base: usize, registers: R) -> Self {
        Self { base, registers }
    }

    fn write_byte(&self, byte: u8) {
        while self.registers.read(self.base + PL011_FLAG_REGISTER) & PL011_TX_FIFO_FULL != 0 {
            core::hint::spin_loop();
        }
        self.registers
            .write(self.base + PL011_DATA_REGISTER, u32::from(byte));
    }
}

impl<R: RegisterAccess> fmt::Write for Pl011<R> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;

    struct MockRegisters {
        flags: RefCell<VecDeque<u32>>,
        reads: RefCell<Vec<usize>>,
        writes: RefCell<Vec<(usize, u32)>>,
    }

    impl MockRegisters {
        fn with_flags(flags: &[u32]) -> Self {
            Self {
                flags: RefCell::new(flags.iter().copied().collect()),
                reads: RefCell::new(Vec::new()),
                writes: RefCell::new(Vec::new()),
            }
        }
    }

    impl RegisterAccess for MockRegisters {
        fn read(&self, address: usize) -> u32 {
            self.reads.borrow_mut().push(address);
            self.flags.borrow_mut().pop_front().unwrap_or(0)
        }

        fn write(&self, address: usize, value: u32) {
            self.writes.borrow_mut().push((address, value));
        }
    }

    #[test]
    fn pl011_waits_for_tx_fifo_space_before_writing() {
        let registers = MockRegisters::with_flags(&[PL011_TX_FIFO_FULL, PL011_TX_FIFO_FULL, 0]);
        let serial = Pl011::with_registers(0x1000, registers);

        serial.write_byte(b'P');

        assert_eq!(
            *serial.registers.reads.borrow(),
            vec![0x1018, 0x1018, 0x1018]
        );
        assert_eq!(
            *serial.registers.writes.borrow(),
            vec![(0x1000, b'P' as u32)]
        );
    }

    #[test]
    fn pl011_fmt_write_emits_each_byte() {
        let registers = MockRegisters::with_flags(&[0, 0]);
        let mut serial = Pl011::with_registers(0x2000, registers);

        fmt::Write::write_str(&mut serial, "OK").unwrap();

        assert_eq!(
            *serial.registers.writes.borrow(),
            vec![(0x2000, b'O' as u32), (0x2000, b'K' as u32)]
        );
    }
}
