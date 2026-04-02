#![no_main]
#![no_std]

const COM1_PORT: u16 = 0x3f8;

#[allow(dead_code)]
const COM2_PORT: u16 = 0x2f8;

use core::time::Duration;

use com_logger;
use log::{debug, error, info, LevelFilter};
use uefi::boot::{self};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;

pub mod helpers;
use crate::helpers::{
    file_helper::{increase_fail_attempts, is_faulty_env, load_original_grub},
    memory_helper::{LINUX_BOOT_IMAGE_SIGNATURE, binary_search, inline_hook},
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
    info!("Silverseal logo placeholder");

    let original_grub_handle = match load_original_grub() {
        Ok(handle) => handle,
        Err(e) => {
            error!("Failed to load original GRUB, reason {:?}", e);
            boot::stall(Duration::from_secs(5));
            return e.status();
        }
    };
    let loaded_image = match boot::open_protocol_exclusive::<LoadedImage>(original_grub_handle) {
        Ok(image) => image,
        Err(e) => {
            error!("Failed to open LoadedImage protocol, reason {:?}", e);
            boot::stall(Duration::from_secs(5));
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
                boot::stall(Duration::from_secs(5));
                increase_fail_attempts();
                return e;
            }
        };
        unsafe {
            GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE = hook_info;
        }
    }
    debug!("Starting GRUB...");

    if let Err(e) = boot::start_image(original_grub_handle) {
        error!("Failed to start original GRUB: {:?}", e);
        boot::stall(Duration::from_secs(5));
        return e.status();
    }
    Status::SUCCESS
}
