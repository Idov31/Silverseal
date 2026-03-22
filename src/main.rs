#![no_main]
#![no_std]

use core::time::Duration;
use log::info;
use uefi::boot::{self};
use uefi::prelude::*;

pub mod helpers;
use crate::helpers::file_helper::{
    load_original_grub
};

#[entry]
fn main() -> Status {
    if let Err(e) = uefi::helpers::init() {
        return e.status();
    }
    info!("Silverseal logo placeholder");
    boot::stall(Duration::from_secs(5));
    let original_grub_handle = match load_original_grub() {
        Ok(handle) => handle,
        Err(e) => {
            info!("Failed to load original GRUB: {:?}", e);
            return e.status();
        }
    };
    info!("Original GRUB handle: {:?}", original_grub_handle);
    boot::stall(Duration::from_secs(5));

    if let Err(e) = boot::start_image(original_grub_handle) {
        info!("Failed to start original GRUB: {:?}", e);
        return e.status();
    }
    Status::SUCCESS
}