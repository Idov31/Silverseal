use uefi::boot::{self, LoadImageSource};
use uefi::proto::BootPolicy;
use uefi::proto::device_path::build::DevicePathBuilder;
use uefi::proto::device_path::{DeviceSubType, DeviceType, LoadedImageDevicePath, build};
use uefi::proto::media::file::{File, FileAttribute, FileMode, RegularFile};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{CStr16, Handle, cstr16};

use core::ops::{BitOr, BitOrAssign};
use elf::ElfBytes;
use elf::abi::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use elf::endian::AnyEndian;
use elf::section::SectionHeader;
use log::debug;

extern crate alloc;
use alloc::vec::Vec;

const GRUB_PATH: &CStr16 = cstr16!("\\EFI\\ubuntu\\grubx64.efi.original");
const FAILSAFE_PATH: &CStr16 = cstr16!("\\EFI\\ubuntu\\failsafe");
const MAX_FAIL_ATTEMPTS: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions(u32);

impl Permissions {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for Permissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Permissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// ## Description
/// cave_finder searches ELF sections whose permissions match the requested mask
/// and returns the first absolute address of a contiguous cave filled with
/// `0x00` and/or `0x90` bytes.
///
/// ## Arguments
/// - `data_address`: Base address of the in-memory ELF image.
/// - `data_size`: Total size of the in-memory ELF image.
/// - `cave_size`: Required contiguous cave size.
/// - `cave_permissions`: Required section permissions.
///
/// ## Returns
/// - `Some(usize)`: Absolute address of the first matching cave.
/// - `None`: If parsing fails or no suitable cave exists.
pub fn cave_finder(
    data_address: usize,
    data_size: usize,
    cave_size: usize,
    cave_permissions: Permissions,
) -> Option<usize> {
    if data_address == 0 || data_size == 0 || cave_size == 0 {
        return None;
    }

    let data = unsafe { core::slice::from_raw_parts(data_address as *const u8, data_size) };
    let elf = ElfBytes::<AnyEndian>::minimal_parse(data).ok()?;
    let sections = elf.section_headers()?;

    for section in sections.iter() {
        if section.sh_size == 0 || !section_matches_permissions(&section, cave_permissions) {
            continue;
        }

        let Some(section_offset) = usize::try_from(section.sh_offset).ok() else {
            continue;
        };
        let Some(section_size) = usize::try_from(section.sh_size).ok() else {
            continue;
        };
        let Some(section_end): Option<usize> = section_offset.checked_add(section_size) else {
            continue;
        };

        if section_end > data.len() {
            continue;
        }

        let section_data = &data[section_offset..section_end];
        let Some(cave_offset) = find_cave_offset(section_data, cave_size) else {
            continue;
        };
        let cave_address = section_offset
            .checked_add(cave_offset)
            .and_then(|offset| data_address.checked_add(offset));
        if let Some(address) = cave_address {
            debug!(
                "Found code cave: section={:#x}, cave_offset={:#x}, address={:#x}",
                section.sh_addr, cave_offset, address
            );
        }
        return cave_address;
    }

    None
}

/// ## Description
/// get_section_address_by_name returns the absolute address of the first byte of the specified section,
/// or None if parsing fails or the section doesn't exist.
///
/// ## Arguments
/// - `data_address`: Base address of the in-memory ELF image.
/// - `data_size`: Total size of the in-memory ELF image.
/// - `section_name`: Exact name of the ELF section to find.
///
/// ## Returns
/// - `Some(usize)`: Absolute address of the first byte of the specified section.
/// - `None`: If parsing fails or the section doesn't exist.
pub fn get_section_address_by_name(
    data_address: usize,
    data_size: usize,
    section_name: &str,
) -> Option<usize> {
    if data_address == 0 || data_size == 0 {
        return None;
    }

    let data = unsafe { core::slice::from_raw_parts(data_address as *const u8, data_size) };
    let elf = ElfBytes::<AnyEndian>::minimal_parse(data).ok()?;
    let (sections_opt, strtab_opt) = elf.section_headers_with_strtab().ok()?;
    let sections = sections_opt?;
    let strtab = strtab_opt?;

    for section in sections.iter() {
        if section.sh_size == 0 {
            continue;
        }

        let name = strtab.get(section.sh_name as usize).unwrap_or("");
        if name == section_name {
            return usize::try_from(section.sh_addr).ok();
        }
    }

    None
}

/// ## Description
/// cave_finder_by_section_name searches a specific named ELF section for a
/// contiguous cave filled with `0x00` and/or `0x90` bytes, regardless of the
/// section's permission flags.
///
/// ## Arguments
/// - `data_address`: Base address of the in-memory ELF image.
/// - `data_size`: Total size of the in-memory ELF image.
/// - `cave_size`: Required contiguous cave size in bytes.
/// - `section_name`: Exact name of the ELF section to search.
///
/// ## Returns
/// - `Some(usize)`: Absolute (physical) address of the first matching cave.
/// - `None`: If parsing fails or no suitable cave exists.
pub fn cave_finder_by_section_name(
    data_address: usize,
    data_size: usize,
    cave_size: usize,
    section_name: &str,
) -> Option<usize> {
    cave_finder_by_section_name_excluding(data_address, data_size, cave_size, section_name, &[])
}

/// ## Description
/// Searches a named ELF section for a cave while excluding address ranges that
/// have already been reserved for other injected blobs.
///
/// ## Arguments
/// - `data_address` - Base address of the in-memory ELF image.
/// - `data_size` - Total size of the in-memory ELF image.
/// - `cave_size` - Required contiguous cave size in bytes.
/// - `section_name` - Exact name of the ELF section to search.
/// - `excluded_ranges` - Absolute physical address ranges to avoid.
///
/// ## Returns
/// - `Some(usize)` - Absolute physical address of the first non-overlapping cave.
/// - `None` - If parsing fails or no suitable cave exists.
pub fn cave_finder_by_section_name_excluding(
    data_address: usize,
    data_size: usize,
    cave_size: usize,
    section_name: &str,
    excluded_ranges: &[(usize, usize)],
) -> Option<usize> {
    cave_finder_by_section_name_excluding_after(
        data_address,
        data_size,
        cave_size,
        section_name,
        excluded_ranges,
        0,
    )
}

/// ## Description
/// Searches a named ELF section for a cave while excluding address ranges and
/// skipping the first `min_section_offset` bytes of that section.
///
/// ## Arguments
/// - `data_address` - Base address of the in-memory ELF image.
/// - `data_size` - Total size of the in-memory ELF image.
/// - `cave_size` - Required contiguous cave size in bytes.
/// - `section_name` - Exact name of the ELF section to search.
/// - `excluded_ranges` - Absolute physical address ranges to avoid.
/// - `min_section_offset` - Minimum offset inside the section to consider.
///
/// ## Returns
/// - `Some(usize)` - Absolute physical address of the first matching cave.
/// - `None` - If parsing fails or no suitable cave exists.
pub fn cave_finder_by_section_name_excluding_after(
    data_address: usize,
    data_size: usize,
    cave_size: usize,
    section_name: &str,
    excluded_ranges: &[(usize, usize)],
    min_section_offset: usize,
) -> Option<usize> {
    if data_address == 0 || data_size == 0 || cave_size == 0 {
        return None;
    }

    let data = unsafe { core::slice::from_raw_parts(data_address as *const u8, data_size) };
    let elf = ElfBytes::<AnyEndian>::minimal_parse(data).ok()?;
    let (sections_opt, strtab_opt) = elf.section_headers_with_strtab().ok()?;
    let sections = sections_opt?;
    let strtab = strtab_opt?;

    for section in sections.iter() {
        if section.sh_size == 0 {
            continue;
        }

        let name = strtab.get(section.sh_name as usize).unwrap_or("");
        if name != section_name {
            continue;
        }

        let Some(section_offset) = usize::try_from(section.sh_offset).ok() else {
            continue;
        };
        let Some(section_size) = usize::try_from(section.sh_size).ok() else {
            continue;
        };
        let Some(section_end): Option<usize> = section_offset.checked_add(section_size) else {
            continue;
        };

        if section_end > data.len() {
            continue;
        }

        let section_data = &data[section_offset..section_end];
        let mut search_start = min_section_offset;
        while search_start <= section_data.len().saturating_sub(cave_size) {
            let Some(relative_offset) = find_cave_offset(&section_data[search_start..], cave_size)
            else {
                break;
            };
            let cave_offset = search_start.checked_add(relative_offset)?;
            let cave_address = section_offset
                .checked_add(cave_offset)
                .and_then(|offset| data_address.checked_add(offset))?;
            let cave_end = cave_address.checked_add(cave_size)?;

            if excluded_ranges
                .iter()
                .all(|(start, end)| cave_end <= *start || cave_address >= *end)
            {
                debug!(
                    "Found code cave in section {}: section_virt={:#x}, cave_offset={:#x}, address={:#x}",
                    section_name, section.sh_addr, cave_offset, cave_address
                );
                return Some(cave_address);
            }

            search_start = cave_offset.checked_add(1)?;
        }
    }

    None
}

/// ## Description
/// cave_finder_by_section_name_after is identical to cave_finder_by_section_name
/// but skips all caves whose physical address is less than `after_phys`.
/// Use this to find a second (or later) cave in the same section.
///
/// ## Arguments
/// - `data_address`: Base address of the in-memory ELF image.
/// - `data_size`: Total size of the in-memory ELF image.
/// - `cave_size`: Required contiguous cave size in bytes.
/// - `section_name`: Exact name of the ELF section to search.
/// - `after_phys`: Only return caves at physical addresses ≥ this value.
///
/// ## Returns
/// - `Some(usize)`: Absolute (physical) address of the first matching cave.
/// - `None`: If parsing fails or no suitable cave exists after `after_phys`.
pub fn cave_finder_by_section_name_after(
    data_address: usize,
    data_size: usize,
    cave_size: usize,
    section_name: &str,
    after_phys: usize,
) -> Option<usize> {
    if data_address == 0 || data_size == 0 || cave_size == 0 {
        return None;
    }

    let data = unsafe { core::slice::from_raw_parts(data_address as *const u8, data_size) };
    let elf = ElfBytes::<AnyEndian>::minimal_parse(data).ok()?;
    let (sections_opt, strtab_opt) = elf.section_headers_with_strtab().ok()?;
    let sections = sections_opt?;
    let strtab = strtab_opt?;

    for section in sections.iter() {
        if section.sh_size == 0 {
            continue;
        }

        let name = strtab.get(section.sh_name as usize).unwrap_or("");
        if name != section_name {
            continue;
        }

        let Some(section_offset) = usize::try_from(section.sh_offset).ok() else {
            continue;
        };
        let Some(section_size) = usize::try_from(section.sh_size).ok() else {
            continue;
        };
        let Some(section_end): Option<usize> = section_offset.checked_add(section_size) else {
            continue;
        };

        if section_end > data.len() {
            continue;
        }

        // Compute the offset within section_data to start searching from.
        let section_phys_start = data_address + section_offset;
        let start_in_section = if after_phys > section_phys_start {
            after_phys - section_phys_start
        } else {
            0
        };

        let section_data = &data[section_offset..section_end];
        if start_in_section >= section_data.len() {
            continue;
        }

        let Some(cave_offset_in_slice) =
            find_cave_offset(&section_data[start_in_section..], cave_size)
        else {
            continue;
        };

        let cave_offset = start_in_section + cave_offset_in_slice;
        let cave_address = section_offset
            .checked_add(cave_offset)
            .and_then(|offset| data_address.checked_add(offset));
        if let Some(address) = cave_address {
            debug!(
                "Found code cave in section {} (after {:#x}): section_virt={:#x}, cave_offset={:#x}, address={:#x}",
                section_name, after_phys, section.sh_addr, cave_offset, address
            );
        }
        return cave_address;
    }

    None
}

fn section_matches_permissions(section: &SectionHeader, requested: Permissions) -> bool {
    if requested.is_empty() {
        return true;
    }

    let flags = section.sh_flags as u32;

    (!requested.contains(Permissions::READ) || (flags & SHF_ALLOC) != 0)
        && (!requested.contains(Permissions::WRITE) || (flags & SHF_WRITE) != 0)
        && (!requested.contains(Permissions::EXECUTE) || (flags & SHF_EXECINSTR) != 0)
}

fn find_cave_offset(section_data: &[u8], cave_size: usize) -> Option<usize> {
    if section_data.len() < cave_size {
        return None;
    }

    for start in 0..=section_data.len() - cave_size {
        let end = start + cave_size;
        if section_data[start..end]
            .iter()
            .all(|byte| *byte == 0x00 || *byte == 0x90)
        {
            return Some(start);
        }
    }

    None
}

/// ## Description
/// load_original_grub attempts to load the original GRUB image from the same device as the current image, using a predefined path.
///
/// ## Arguments
/// - None
///
/// ## Returns
/// - `Ok(Handle)`: Handle to the loaded original GRUB image.
/// - `Err(uefi::Error)`: If loading fails, returns the corresponding U
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

/// ## Description
/// increase_fail_attempts increases the fail attempts counter in the failsafe file to prevent booting into bad GRUB in case of repeated failures.
///
/// ## Arguments
/// - None
///
/// ## Returns
/// - None
pub fn increase_fail_attempts() {
    if let Ok(mut file) = open_failsafe_file(FileMode::ReadWrite) {
        // Read current counter
        let mut buf = [0u8; 2];
        let counter = match file.read(&mut buf) {
            Ok(bytes_read) if bytes_read >= 2 => u16::from_le_bytes(buf),
            _ => 0,
        };

        // Write new counter
        let new_counter = counter.saturating_add(1);
        if file.set_position(0).is_ok() {
            let _ = file.write(&new_counter.to_le_bytes());
        }
    }
}

/// ## Description
/// is_faulty_env checks the fail attempts counter in the failsafe file to determine if the environment is considered faulty.
///
/// ## Arguments
/// - None
///
/// ## Returns
/// - `bool`: True if the environment is considered faulty, false otherwise.
pub fn is_faulty_env() -> bool {
    open_failsafe_file(FileMode::Read)
        .ok()
        .and_then(|mut file| {
            let mut buf = [0u8; 2];
            file.read(&mut buf).ok().and_then(|bytes_read| {
                if bytes_read >= 2 {
                    Some(u16::from_le_bytes(buf) >= MAX_FAIL_ATTEMPTS)
                } else {
                    None
                }
            })
        })
        .unwrap_or(false)
}

/// ## Description
/// open_failsafe_file opens the failsafe file with the specified mode, creating it if necessary.
/// This file is used to track fail attempts and determine if the environment is faulty.
///
/// ## Arguments
/// - `mode`: The mode in which to open the file.
///
/// ## Returns
/// - `Ok(RegularFile)`: The opened failsafe file.
/// - `Err(uefi::Error)`: If opening the file fails, returns the corresponding UEFI error.
fn open_failsafe_file(mode: FileMode) -> uefi::Result<RegularFile> {
    let mut sfs = boot::open_protocol_exclusive::<SimpleFileSystem>(boot::image_handle())?;
    let mut root = sfs.open_volume()?;

    let open_mode = match mode {
        FileMode::Read => FileMode::Read,
        FileMode::ReadWrite | FileMode::CreateReadWrite => FileMode::CreateReadWrite,
    };

    let file_handle = root.open(FAILSAFE_PATH, open_mode, FileAttribute::empty())?;
    Ok(unsafe { RegularFile::new(file_handle) })
}
