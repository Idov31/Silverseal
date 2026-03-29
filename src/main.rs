#![no_main]
#![no_std]

use core::time::Duration;
use log::info;
use uefi::boot::{self};
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;

pub mod helpers;
use crate::helpers::{
    file_helper::{increase_fail_attempts, is_faulty_env, load_original_grub},
    hooks::{GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE, grub_arch_efi_linux_boot_image_hook},
    memory_helper::{LINUX_BOOT_IMAGE_SIGNATURE, binary_search, inline_hook},
};

fn log_and_stall(msg: &str) {
    info!("{}", msg);
    boot::stall(Duration::from_secs(5));
}

#[entry]
fn main() -> Status {
    if let Err(e) = uefi::helpers::init() {
        return e.status();
    }
    info!("Silverseal logo placeholder");

    let original_grub_handle = match load_original_grub() {
        Ok(handle) => handle,
        Err(e) => {
            log_and_stall("Failed to load original GRUB");
            info!("Reason: {:?}", e);
            return e.status();
        }
    };
    let loaded_image = match boot::open_protocol_exclusive::<LoadedImage>(original_grub_handle) {
        Ok(image) => image,
        Err(e) => {
            log_and_stall("Failed to open LoadedImage protocol");
            info!("Reason: {:?}", e);
            return e.status();
        }
    };
    let (base, size) = loaded_image.info();
    info!("Original GRUB base: {:?}, size: {:?}", base, size);

    if !is_faulty_env() {
        let target = match binary_search(base as usize, size as usize, LINUX_BOOT_IMAGE_SIGNATURE) {
            Some(addr) => addr,
            None => {
                log_and_stall("Failed to find target function in original GRUB");
                increase_fail_attempts();
                return Status::NOT_FOUND;
            }
        };
        info!("Found target function at address: {:#x}", target);

        // Install the hook at the found address
        let linux_boot_image_hook = grub_arch_efi_linux_boot_image_hook as *const () as usize;

        let hook_info = match inline_hook(target, linux_boot_image_hook) {
            Ok(info) => info,
            Err(e) => {
                log_and_stall("Failed to install inline hook");
                info!("Reason: {:?}", e);
                increase_fail_attempts();
                return e;
            }
        };
        unsafe {
            GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE = hook_info;
        }
    }

    if let Err(e) = boot::start_image(original_grub_handle) {
        info!("Failed to start original GRUB: {:?}", e);
        return e.status();
    }
    Status::SUCCESS
}
