use uefi::{CStr16, cstr16, Handle};
use uefi::boot::{self, LoadImageSource};
use uefi::proto::BootPolicy;
use uefi::proto::device_path::{build, DeviceSubType, DeviceType, LoadedImageDevicePath};
use uefi::proto::device_path::build::DevicePathBuilder;

extern crate alloc;
use alloc::vec::Vec;

const GRUB_PATH: &CStr16 = cstr16!("\\EFI\\ubuntu\\grubx64.efi.original");

pub fn load_original_grub() -> uefi::Result<Handle> {
    let loaded_image_device_path =
        boot::open_protocol_exclusive::<LoadedImageDevicePath>(boot::image_handle())?;

    let mut storage = Vec::new();
    let mut builder = DevicePathBuilder::with_vec(&mut storage);

    for node in loaded_image_device_path.node_iter() {
        if node.full_type() == (DeviceType::MEDIA, DeviceSubType::MEDIA_FILE_PATH) {
            break;
        }

        builder = builder
            .push(&node)
            .map_err(|_| uefi::Error::from(uefi::Status::INVALID_PARAMETER))?;
    }

    builder = builder
        .push(&build::media::FilePath {
            path_name: GRUB_PATH,
        })
        .map_err(|_| uefi::Error::from(uefi::Status::INVALID_PARAMETER))?;

    let new_image_path = builder
        .finalize()
        .map_err(|_| uefi::Error::from(uefi::Status::INVALID_PARAMETER))?;

    let new_image = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: new_image_path,
            boot_policy: BootPolicy::ExactMatch,
        },
    )?;

    Ok(new_image)
}