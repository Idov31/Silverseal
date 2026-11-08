#![no_main]
#![no_std]

#[cfg(target_arch = "x86_64")]
use log::LevelFilter;
use log::{debug, error, info};
use uefi::boot::{self};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;

pub mod helpers;
use crate::helpers::{
    file_helper::{increase_fail_attempts, is_faulty_env, load_original_grub},
    printing_constants::LOGO,
};

pub mod hooks;
#[cfg(target_arch = "x86_64")]
use crate::hooks::boot_hooks::{
    GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE, grub_arch_efi_linux_boot_image_hook,
};

#[entry]
fn main() -> Status {
    if let Err(e) = uefi::helpers::init() {
        return e.status();
    }
    setup_logger();
    debug!("{}", LOGO);

    let original_grub_handle = match load_original_grub() {
        Ok(handle) => handle,
        Err(e) => {
            error!("Failed to load original GRUB, reason {:?}", e);
            return e.status();
        }
    };
    let loaded_image = match boot::open_protocol_exclusive::<LoadedImage>(original_grub_handle) {
        Ok(image) => image,
        Err(e) => {
            error!("Failed to open LoadedImage protocol, reason {:?}", e);
            return e.status();
        }
    };
    let (base, size) = loaded_image.info();
    info!("Original GRUB base: {:?}, size: {:?}", base, size);

    if !is_faulty_env()
        && let Err(status) = install_boot_hook(base as usize, size as usize)
    {
        increase_fail_attempts();
        return status;
    }
    info!("Starting GRUB...");

    if let Err(e) = boot::start_image(original_grub_handle) {
        error!("Failed to start original GRUB: {:?}", e);
        return e.status();
    }
    Status::SUCCESS
}

#[cfg(target_arch = "x86_64")]
fn setup_logger() {
    use crate::helpers::printing_constants::COM1_PORT;

    com_logger::builder()
        .base(COM1_PORT)
        .filter(LevelFilter::Debug)
        .setup();
}

#[cfg(target_arch = "aarch64")]
fn setup_logger() {
    crate::helpers::uefi_serial_logger::setup();
}

#[cfg(target_arch = "x86_64")]
fn install_boot_hook(base: usize, size: usize) -> Result<(), Status> {
    use crate::helpers::memory_helper::{LINUX_BOOT_IMAGE_SIGNATURE, binary_search, inline_hook};

    let target = match binary_search(base, size, LINUX_BOOT_IMAGE_SIGNATURE) {
        Some(addr) => addr,
        None => {
            error!("Failed to find target function in original GRUB");
            return Err(Status::NOT_FOUND);
        }
    };
    debug!("Found target function at address: {:#x}", target);

    // Install the hook at the found address
    let linux_boot_image_hook = grub_arch_efi_linux_boot_image_hook as *const () as usize;

    let hook_info = match inline_hook(target, linux_boot_image_hook) {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to install inline hook, reason {:?}", e);
            return Err(e);
        }
    };
    unsafe {
        GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE = hook_info;
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn install_boot_hook(base: usize, size: usize) -> Result<(), Status> {
    match crate::hooks::arm64_hooks::install_grub_hook(base, size) {
        Ok(true) => Ok(()),
        Ok(false) => {
            info!("ARM64 GRUB hook is disabled because no target profile was embedded");
            Ok(())
        }
        Err(status) => {
            error!(
                "ARM64 GRUB signature was missing/non-unique or its detour was rejected: {:?}; continuing original GRUB",
                status
            );
            Ok(())
        }
    }
}
