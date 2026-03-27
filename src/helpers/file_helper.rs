use uefi::boot::{self, LoadImageSource};
use uefi::proto::BootPolicy;
use uefi::proto::device_path::build::DevicePathBuilder;
use uefi::proto::device_path::{DeviceSubType, DeviceType, LoadedImageDevicePath, build};
use uefi::{CStr16, Handle, cstr16};

extern crate alloc;
use alloc::vec::Vec;

const GRUB_PATH: &CStr16 = cstr16!("\\EFI\\ubuntu\\grubx64.efi.original");

/*
 * Loads the original GRUB.
 *
 * Args:
 * - None
 *
 * Returns:
 * - Ok(Handle): Handle to the loaded original GRUB image.
 * - Err(uefi::Error): If loading fails, returns the corresponding UEFI error
 */
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
