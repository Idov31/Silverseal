#![no_main]
#![no_std]

use com_logger;
use log::{debug, error, info, LevelFilter};
use uefi::boot::{self};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;

pub mod helpers;
use crate::helpers::{
    file_helper::{increase_fail_attempts, is_faulty_env, load_original_grub},
    memory_helper::{LINUX_BOOT_IMAGE_SIGNATURE, binary_search, inline_hook},
    printing_constants::{COM1_PORT, LOGO},
};

pub mod hooks;
use crate::hooks::hooks::{
    GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE, grub_arch_efi_linux_boot_image_hook,
};

#[entry]
fn main() -> Status {
    if let Err(e) = uefi::helpers::init() {
        return e.status();
    }
    com_logger::builder()
        .base(COM1_PORT)
        .filter(LevelFilter::Debug)
        .setup();
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

    if !is_faulty_env() {
        let target = match binary_search(base as usize, size as usize, LINUX_BOOT_IMAGE_SIGNATURE) {
            Some(addr) => addr,
            None => {
                error!("Failed to find target function in original GRUB");
                increase_fail_attempts();
                return Status::NOT_FOUND;
            }
        };
        debug!("Found target function at address: {:#x}", target);

        // Install the hook at the found address
        let linux_boot_image_hook = grub_arch_efi_linux_boot_image_hook as *const () as usize;

        let hook_info = match inline_hook(target, linux_boot_image_hook) {
            Ok(info) => info,
            Err(e) => {
                error!("Failed to install inline hook, reason {:?}", e);
                increase_fail_attempts();
                return e;
            }
        };
        unsafe {
            GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE = hook_info;
        }
    }
    info!("Starting GRUB...");

    if let Err(e) = boot::start_image(original_grub_handle) {
        error!("Failed to start original GRUB: {:?}", e);
        return e.status();
    }
    Status::SUCCESS
}
