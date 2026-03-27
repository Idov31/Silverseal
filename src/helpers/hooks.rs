use core::time::Duration;

use log::info;
use uefi::boot;

use crate::helpers::memory_helper::{INLINE_HOOK_SIZE, InlineHook, restore_inline_hook};

pub static mut GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE: InlineHook = InlineHook {
    target: 0,
    hook: 0,
    original_bytes: [0; INLINE_HOOK_SIZE],
};

pub fn grub_arch_efi_linux_boot_image_hook(
    kernel_entry: usize,
    kernel_size: usize,
    args: *const u8,
) -> i32 {
    info!(
        "grub_arch_efi_linux_boot_image_hook called with kernel_entry: {:#x}, kernel_size: {}, args: {:#x}",
        kernel_entry, kernel_size, args as usize
    );
    boot::stall(Duration::from_secs(5));

    // Snapshot hook state once so restore/jump use the same values.
    let target = unsafe {
        core::ptr::addr_of!(GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE.target).read_volatile()
    };
    let original_bytes = unsafe {
        core::ptr::addr_of!(GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE.original_bytes).read_volatile()
    };

    if target == 0 {
        info!("Hook target was not initialized");
        return -1;
    }
    
    if let Err(e) = restore_inline_hook(target, &original_bytes) {
        info!("Failed to restore original function: {}", e);
        return -1;
    }

    // TODO: Deploy another hook here to overwrite specific kernel handler.

    // Jump to the original function.
    let original_fn: extern "C" fn(usize, usize, *const u8) -> i32 = unsafe { core::mem::transmute(target) };
    original_fn(kernel_entry, kernel_size, args)
}
