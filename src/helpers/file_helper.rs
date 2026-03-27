use uefi::boot::{self, LoadImageSource};
use uefi::proto::BootPolicy;
use uefi::proto::device_path::build::DevicePathBuilder;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::device_path::{DeviceSubType, DeviceType, LoadedImageDevicePath, build};
use uefi::proto::media::file::{File, FileMode, FileAttribute, RegularFile};
use uefi::{CStr16, Handle, cstr16};

extern crate alloc;
use alloc::vec::Vec;

const GRUB_PATH: &CStr16 = cstr16!("\\EFI\\ubuntu\\grubx64.efi.original");
const FAILSAFE_PATH: &CStr16 = cstr16!("\\EFI\\ubuntu\\failsafe");
const MAX_FAIL_ATTEMPTS: u16 = 1;

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

/*
* Increases the fail attempts counter in the failsafe file to prevent booting into bad GRUB in case of repeated failures.
*
* Args:
* - None
*
* Returns:
* - None
*/
pub fn increase_fail_attempts() {
    // Read current counter
    let mut counter: u16 = 0;
    
    if let Ok(mut file) = open_failsafe_for_read() {
        let mut buf: [u8; 2] = [0; 2];
        if let Ok(bytes_read) = file.read(&mut buf) {
            if bytes_read >= 2 {
                counter = u16::from_le_bytes(buf);
            }
        }
    }
    
    // Write new counter
    let new_counter = counter.saturating_add(1);
    if let Ok(mut file) = open_failsafe_for_write() {
        let _ = file.set_position(0);
        let _ = file.write(&new_counter.to_le_bytes());
    }
}

/*
* Checks the fail attempts counter in the failsafe file to determine if attempt to hook or restore the original GRUB should be made.
*
* Args:
* - None
*
* Returns:
* - bool: True if the environment is considered faulty, false otherwise.
*/
pub fn is_faulty_env() -> bool {
    match open_failsafe_for_read() {
        Ok(mut file) => {
            let mut buf = [0u8; 2];
            
            match file.read(&mut buf) {
                Ok(bytes_read) if bytes_read >= 2 => {
                    let counter = u16::from_le_bytes(buf);
                    counter >= MAX_FAIL_ATTEMPTS
                }
                _ => false,
            }
        }
        Err(_) => false,
    }
}

fn open_failsafe_for_read() -> uefi::Result<RegularFile> {
    let mut sfs = boot::open_protocol_exclusive::<SimpleFileSystem>(boot::image_handle())?;
    let mut root = sfs.open_volume()?;
    let file_handle = root.open(FAILSAFE_PATH, FileMode::Read, FileAttribute::empty())?;
    Ok(unsafe { RegularFile::new(file_handle) })
}

fn open_failsafe_for_write() -> uefi::Result<RegularFile> {
    let mut sfs = boot::open_protocol_exclusive::<SimpleFileSystem>(boot::image_handle())?;
    let mut root = sfs.open_volume()?;
    let file_handle = root.open(FAILSAFE_PATH, FileMode::ReadWrite, FileAttribute::empty())?;
    Ok(unsafe { RegularFile::new(file_handle) })
}
