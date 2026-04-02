use core::time::Duration;

use uefi::boot;

use crate::helpers::memory_helper::{INLINE_HOOK_SIZE, InlineHook, restore_inline_hook};
use log::{debug, error};

pub static mut GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE: InlineHook = InlineHook {
    target: 0,
    hook: 0,
    original_bytes: [0; INLINE_HOOK_SIZE],
};

/// grub_arch_efi_linux_boot_image_hook is an inline hook for the GRUB function responsible for loading Linux boot images on EFI systems.
/// It restores the original function before executing it to ensure stability, and hooking the Linux kernel.
///
/// # Arguments
/// - `kernel_entry`: The entry point of the Linux kernel.
/// - `kernel_size`: The size of the Linux kernel.
/// - `args`: Additional arguments passed to the original function.
///
/// # Returns
/// - `i32`: The return value from the original function, or -1 if an error occurs.
pub extern "C" fn grub_arch_efi_linux_boot_image_hook(
    kernel_entry: usize,
    kernel_size: usize,
    args: *const u8,
) -> i32 {
    let original_fn_addr: usize;
    let real_kernel_entry: usize;
    unsafe {
        core::arch::asm!(
            "mov {}, rax",
            out(reg) original_fn_addr,
            options(nomem, nostack, preserves_flags)
        );
        core::arch::asm!(
            "mov {}, r12",
            out(reg) real_kernel_entry,
            options(nomem, nostack, preserves_flags)
        );
    }

    debug!(
        "grub_arch_efi_linux_boot_image_hook called with kernel_entry: {:#x}, kernel_size: {:#x}, args: {:#x}",
        real_kernel_entry, kernel_size, args as usize
    );
    boot::stall(Duration::from_secs(5));

    // Snapshot hook state once so restore/jump use the same values.
    let target = unsafe {
        core::ptr::addr_of!(GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE.target).read_volatile()
    };
    let original_bytes = unsafe {
        core::ptr::addr_of!(GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE.original_bytes)
            .read_volatile()
    };

    if target == 0 {
        error!("Hook target was not initialized");
        boot::stall(Duration::from_secs(5));
        return -1;
    }

    if original_fn_addr == 0 {
        error!("Original function address was not preserved");
        boot::stall(Duration::from_secs(5));
        return -1;
    }

    if let Err(e) = restore_inline_hook(target, &original_bytes) {
        error!("Failed to restore original function: {}", e);
        boot::stall(Duration::from_secs(5));
        return -1;
    }

    // TODO: Deploy another hook here to overwrite specific kernel handler.

    // Call the original callee that was held in rax at the patched call site.
    let original_fn: extern "C" fn(usize, usize, *const u8) -> i32 =
        unsafe { core::mem::transmute(original_fn_addr) };
    original_fn(kernel_entry, kernel_size, args)
}
