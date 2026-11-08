//! ARM64 GRUB and stock zboot decompressor hooks.

use core::arch::global_asm;

use log::{debug, error, info};
use silverseal_bootkit::arm64_profile::{ProfileError, embedded_profile};
use uefi::Status;

use crate::helpers::arm64::{
    Aarch64Detour, RuntimeEntryRegister, StagedImageKind, find_unique_pe_section,
    find_unique_signature, install_detour_in_staged_image, restore_detour_at_runtime_entry,
};

global_asm!(include_str!("../../asm/arm/hook_veneers.S"));

unsafe extern "C" {
    fn silverseal_grub_linux_boot_image_hook_veneer(
        kernel_entry: usize,
        kernel_size: usize,
        args: *const u8,
    ) -> i32;
    fn silverseal_zboot_decompress_hook_veneer(
        destination: usize,
        decompressed_size: usize,
    ) -> usize;
}

static mut GRUB_BOOT_DETOUR: Option<Aarch64Detour> = None;
static mut ZBOOT_DETOUR: Option<Aarch64Detour> = None;

/// Finds the profiled GRUB boot-image function and redirects it to the ARM64
/// boot hook.
pub fn install_grub_hook(image_base: usize, image_size: usize) -> Result<bool, Status> {
    let profile = match embedded_profile() {
        Ok(profile) => profile,
        Err(ProfileError::Placeholder) => return Ok(false),
        Err(_) => return Err(Status::COMPROMISED_DATA),
    };
    let target = find_unique_signature(image_base, image_size, profile.grub_signature)
        .ok_or(Status::NOT_FOUND)?;
    let detour = unsafe {
        install_detour_in_staged_image(
            image_base,
            image_size,
            target,
            silverseal_grub_linux_boot_image_hook_veneer as *const () as usize,
            RuntimeEntryRegister::X3,
            StagedImageKind::EmbeddedElfRelocatable,
        )?
    };
    unsafe { GRUB_BOOT_DETOUR = Some(detour) };
    Ok(true)
}

#[unsafe(no_mangle)]
extern "C" fn silverseal_grub_linux_boot_image_hook_rust(
    kernel_entry: usize,
    kernel_size: usize,
    args: *const u8,
    runtime_entry: usize,
) -> i32 {
    let detour = unsafe { core::ptr::addr_of!(GRUB_BOOT_DETOUR).read_volatile() };
    let Some(detour) = detour else {
        error!("ARM64 GRUB hook state was not initialized");
        return -1;
    };
    if unsafe { restore_detour_at_runtime_entry(&detour, runtime_entry) }.is_err() {
        error!("Failed to restore ARM64 GRUB boot-image entry");
        return -1;
    }
    let original: extern "C" fn(usize, usize, *const u8) -> i32 =
        unsafe { core::mem::transmute(runtime_entry) };

    let (nested_base, nested_size) = match find_unique_pe_section(
        kernel_entry,
        kernel_size,
        b".linux\0\0",
    ) {
        Ok(section) => section,
        Err(status) => {
            error!(
                "ARM64 stock kernel .linux section was rejected: {:?}; continuing original GRUB path",
                status
            );
            return original(kernel_entry, kernel_size, args);
        }
    };
    let profile = match embedded_profile() {
        Ok(profile) => profile,
        Err(_) => {
            error!("ARM64 profile became unavailable after installing the GRUB hook");
            return original(kernel_entry, kernel_size, args);
        }
    };
    let Some(zboot_target) =
        find_unique_signature(nested_base, nested_size, profile.zboot_signature)
    else {
        error!(
            "ARM64 stock zboot signature was missing or non-unique; continuing original GRUB path"
        );
        return original(kernel_entry, kernel_size, args);
    };
    match unsafe {
        install_detour_in_staged_image(
            nested_base,
            nested_size,
            zboot_target,
            silverseal_zboot_decompress_hook_veneer as *const () as usize,
            RuntimeEntryRegister::X2,
            StagedImageKind::PeCoff,
        )
    } {
        Ok(zboot_detour) => unsafe { ZBOOT_DETOUR = Some(zboot_detour) },
        Err(status) => error!(
            "ARM64 stock zboot detour was rejected: {:?}; continuing original GRUB path",
            status
        ),
    }
    original(kernel_entry, kernel_size, args)
}

#[unsafe(no_mangle)]
extern "C" fn silverseal_zboot_decompress_hook_rust(
    destination: usize,
    decompressed_size: usize,
    runtime_entry: usize,
) -> usize {
    let detour = unsafe { core::ptr::addr_of!(ZBOOT_DETOUR).read_volatile() };
    let Some(detour) = detour else {
        error!("ARM64 stock zboot hook state was not initialized");
        return Status::LOAD_ERROR.0;
    };
    if unsafe { restore_detour_at_runtime_entry(&detour, runtime_entry) }.is_err() {
        error!("Failed to restore ARM64 stock zboot entry");
        return Status::LOAD_ERROR.0;
    }
    let original: extern "C" fn(usize, usize) -> usize =
        unsafe { core::mem::transmute(runtime_entry) };
    let result = original(destination, decompressed_size);
    if result != Status::SUCCESS.0 {
        debug!("ARM64 stock zboot decompression failed; skipping kernel injection");
        return result;
    }

    let profile = match embedded_profile() {
        Ok(profile) => profile,
        Err(_) => {
            error!("ARM64 profile became unavailable after installing the zboot hook");
            return result;
        }
    };
    match crate::hooks::arm64_injection::install_post_decompression_trampoline(
        destination,
        decompressed_size,
        &profile,
    ) {
        Ok(crate::hooks::arm64_injection::Arm64InjectionOutcome::Installed) => {
            info!("Installed ARM64 deferred root-filesystem module-loading trampoline");
        }
        Err(status) => {
            error!(
                "Failed to inject the ARM64 kernel trampoline, reason {:?}",
                status
            );
        }
    }
    result
}
