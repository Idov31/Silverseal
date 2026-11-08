//! Best-effort logger backed by the firmware's UEFI Serial I/O protocol.

use core::fmt::Write;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use log::{LevelFilter, Log, Metadata, Record};
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::console::serial::Serial;

struct UefiSerialLogger;

static LOGGER: UefiSerialLogger = UefiSerialLogger;
static SERIAL: AtomicPtr<Serial> = AtomicPtr::new(ptr::null_mut());
static WRITING: AtomicBool = AtomicBool::new(false);

impl Log for UefiSerialLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata())
            || WRITING
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let serial = SERIAL.load(Ordering::Acquire);
        if !serial.is_null() {
            // SAFETY: setup stores a live Serial protocol pointer and retains
            // its ScopedProtocol for the lifetime of this UEFI image. WRITING
            // serializes every mutable access.
            let serial = unsafe { &mut *serial };
            let _ = writeln!(serial, "[{}] {}\r", record.level(), record.args());
        }
        WRITING.store(false, Ordering::Release);
    }

    fn flush(&self) {}
}

/// Installs logging on the first firmware Serial I/O protocol, if one exists.
///
/// Absence or rejection of Serial I/O is non-fatal: the boot flow continues
/// without pre-kernel logs.
pub fn setup() {
    let Ok(handles) = boot::find_handles::<Serial>() else {
        return;
    };
    for handle in handles {
        let opened = unsafe {
            boot::open_protocol::<Serial>(
                OpenProtocolParams {
                    handle,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        };
        let Ok(mut serial) = opened else {
            continue;
        };
        let _ = serial.reset();
        SERIAL.store(&mut *serial, Ordering::Release);
        // Keep the GetProtocol relationship and pointer live while GRUB runs.
        core::mem::forget(serial);
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(LevelFilter::Debug);
        }
        return;
    }
}
