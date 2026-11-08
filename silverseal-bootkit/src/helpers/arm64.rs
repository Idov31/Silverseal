//! ARM64 signature, detour, branch, and cache helpers.

#[cfg(target_arch = "aarch64")]
use core::arch::asm;

use elf::ElfBytes;
use elf::abi::{EM_AARCH64, ET_REL, SHT_REL, SHT_RELA};
use elf::endian::AnyEndian;
#[cfg(target_arch = "aarch64")]
use uefi::Status;

#[cfg(all(test, not(target_arch = "aarch64")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Status(u64);

#[cfg(all(test, not(target_arch = "aarch64")))]
impl Status {
    const INVALID_PARAMETER: Self = Self(2);
    const UNSUPPORTED: Self = Self(3);
    const COMPROMISED_DATA: Self = Self(4);
    const NOT_FOUND: Self = Self(14);
}

pub const AARCH64_DETOUR_SIZE: usize = 20;
const AARCH64_INSTRUCTION_SIZE: usize = 4;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Register populated by the detour with its relocated function entry.
pub enum RuntimeEntryRegister {
    X2,
    X3,
    X5,
}

impl RuntimeEntryRegister {
    const fn number(self) -> u32 {
        match self {
            Self::X2 => 2,
            Self::X3 => 3,
            Self::X5 => 5,
        }
    }
}

/// Locates one raw PE/COFF section by its exact eight-byte section name.
///
/// The returned address and size describe the bytes in the staged file image,
/// not the section's eventual virtual mapping. Ambiguous section names fail
/// closed.
pub fn find_unique_pe_section(
    image_base: usize,
    image_size: usize,
    name: &[u8; 8],
) -> Result<(usize, usize), Status> {
    if image_base == 0 || image_size == 0 {
        return Err(Status::INVALID_PARAMETER);
    }
    image_base
        .checked_add(image_size)
        .ok_or(Status::INVALID_PARAMETER)?;
    let image = unsafe { core::slice::from_raw_parts(image_base as *const u8, image_size) };
    if image.get(..2) != Some(b"MZ") {
        return Err(Status::COMPROMISED_DATA);
    }
    let pe_offset = read_u32(image, 0x3c)? as usize;
    let signature_end = pe_offset.checked_add(4).ok_or(Status::COMPROMISED_DATA)?;
    if image.get(pe_offset..signature_end) != Some(b"PE\0\0") {
        return Err(Status::COMPROMISED_DATA);
    }
    let coff = pe_offset.checked_add(4).ok_or(Status::COMPROMISED_DATA)?;
    if read_u16(image, coff)? != 0xaa64 {
        return Err(Status::UNSUPPORTED);
    }
    let section_count = read_u16(image, coff + 2)? as usize;
    let optional_size = read_u16(image, coff + 16)? as usize;
    let optional = coff.checked_add(20).ok_or(Status::COMPROMISED_DATA)?;
    if optional_size < 112 || read_u16(image, optional)? != 0x20b {
        return Err(Status::UNSUPPORTED);
    }
    let section_table = optional
        .checked_add(optional_size)
        .ok_or(Status::COMPROMISED_DATA)?;
    let table_size = section_count
        .checked_mul(40)
        .ok_or(Status::COMPROMISED_DATA)?;
    let table_end = section_table
        .checked_add(table_size)
        .ok_or(Status::COMPROMISED_DATA)?;
    if table_end > image.len() {
        return Err(Status::COMPROMISED_DATA);
    }

    let mut found = None;
    for index in 0..section_count {
        let section = section_table + index * 40;
        if image.get(section..section + 8) != Some(name) {
            continue;
        }
        if found.is_some() {
            return Err(Status::COMPROMISED_DATA);
        }
        let raw_size = read_u32(image, section + 16)? as usize;
        let raw_offset = read_u32(image, section + 20)? as usize;
        if raw_size == 0 {
            return Err(Status::COMPROMISED_DATA);
        }
        let raw_end = raw_offset
            .checked_add(raw_size)
            .ok_or(Status::COMPROMISED_DATA)?;
        if raw_end > image.len() {
            return Err(Status::COMPROMISED_DATA);
        }
        found = Some((
            image_base
                .checked_add(raw_offset)
                .ok_or(Status::INVALID_PARAMETER)?,
            raw_size,
        ));
    }
    found.ok_or(Status::NOT_FOUND)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Relocation format applied after the source image is patched.
pub enum StagedImageKind {
    EmbeddedElfRelocatable,
    PeCoff,
}

#[derive(Clone, Copy)]
/// Original bytes used to remove a detour from its relocated runtime entry.
///
/// The source-buffer address is deliberately not retained: it is never an
/// executable address after the staged image has been loaded.
pub struct Aarch64Detour {
    original_bytes: [u8; AARCH64_DETOUR_SIZE],
}

pub fn find_unique_signature(
    data_address: usize,
    data_size: usize,
    signature: &[u8],
) -> Option<usize> {
    if data_address == 0 || signature.is_empty() || data_size < signature.len() {
        return None;
    }
    let data = unsafe { core::slice::from_raw_parts(data_address as *const u8, data_size) };
    let mut matches = data
        .windows(signature.len())
        .enumerate()
        .filter(|(_, window)| *window == signature);
    let first = matches.next()?.0;
    if matches.next().is_some() {
        return None;
    }
    data_address.checked_add(first)
}

pub fn encode_b(from: usize, to: usize) -> Option<u32> {
    if !from.is_multiple_of(AARCH64_INSTRUCTION_SIZE)
        || !to.is_multiple_of(AARCH64_INSTRUCTION_SIZE)
    {
        return None;
    }
    let delta = (to as i128).checked_sub(from as i128)?;
    let words = delta / AARCH64_INSTRUCTION_SIZE as i128;
    if delta % AARCH64_INSTRUCTION_SIZE as i128 != 0 || !(-(1 << 25)..(1 << 25)).contains(&words) {
        return None;
    }
    Some(0x1400_0000 | ((words as i64 as u32) & 0x03ff_ffff))
}

fn detour_patch(hook: usize, runtime_entry_register: RuntimeEntryRegister) -> [u8; 20] {
    let mut patch = [0u8; AARCH64_DETOUR_SIZE];
    // adr xN, . ; ldr x16, #8 ; br x16 ; .quad hook
    patch[..4].copy_from_slice(&(0x1000_0000 | runtime_entry_register.number()).to_le_bytes());
    patch[4..8].copy_from_slice(&0x5800_0050u32.to_le_bytes());
    patch[8..12].copy_from_slice(&0xd61f_0200u32.to_le_bytes());
    patch[12..].copy_from_slice(&(hook as u64).to_le_bytes());
    patch
}

/// Installs a self-locating detour in an image that will be copied and
/// relocated before execution. Loader relocations may not overlap the patch.
///
/// # Safety
///
/// The image must remain mapped, readable, and writable. `target` must be an
/// executable staged-image entry, `hook` a BTI-compatible AAPCS64 entry, and
/// callers must exclude concurrent access to the patch span.
pub unsafe fn install_detour_in_staged_image(
    image_base: usize,
    image_size: usize,
    target: usize,
    hook: usize,
    runtime_entry_register: RuntimeEntryRegister,
    image_kind: StagedImageKind,
) -> Result<Aarch64Detour, Status> {
    if image_base == 0
        || image_size == 0
        || target == 0
        || hook == 0
        || !target.is_multiple_of(AARCH64_INSTRUCTION_SIZE)
        || !hook.is_multiple_of(AARCH64_INSTRUCTION_SIZE)
    {
        return Err(Status::INVALID_PARAMETER);
    }
    let image_end = image_base
        .checked_add(image_size)
        .ok_or(Status::INVALID_PARAMETER)?;
    let patch_end = target
        .checked_add(AARCH64_DETOUR_SIZE)
        .ok_or(Status::INVALID_PARAMETER)?;
    if target < image_base || patch_end > image_end {
        return Err(Status::INVALID_PARAMETER);
    }

    let image = unsafe { core::slice::from_raw_parts(image_base as *const u8, image_size) };
    let target_offset = target - image_base;
    let overlaps = match image_kind {
        StagedImageKind::EmbeddedElfRelocatable => {
            embedded_elf_relocation_overlaps(image, target_offset, AARCH64_DETOUR_SIZE)?
        }
        StagedImageKind::PeCoff => {
            pe_relocation_overlaps(image, target_offset, AARCH64_DETOUR_SIZE)?
        }
    };
    if overlaps {
        return Err(Status::UNSUPPORTED);
    }

    let mut detour = Aarch64Detour {
        original_bytes: [0; AARCH64_DETOUR_SIZE],
    };
    let patch = detour_patch(hook, runtime_entry_register);
    unsafe {
        core::ptr::copy_nonoverlapping(
            target as *const u8,
            detour.original_bytes.as_mut_ptr(),
            AARCH64_DETOUR_SIZE,
        );
        core::ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, AARCH64_DETOUR_SIZE);
        synchronize_instruction_cache(target, AARCH64_DETOUR_SIZE)?;
    }
    Ok(detour)
}

/// Restores saved bytes at the relocated address produced by the detour's ADR.
///
/// # Safety
///
/// `runtime_entry` must be the writable, executable runtime copy of this
/// detour. Callers must exclude concurrent execution until cache maintenance
/// completes.
pub unsafe fn restore_detour_at_runtime_entry(
    detour: &Aarch64Detour,
    runtime_entry: usize,
) -> Result<(), Status> {
    if runtime_entry == 0 || !runtime_entry.is_multiple_of(AARCH64_INSTRUCTION_SIZE) {
        return Err(Status::INVALID_PARAMETER);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            detour.original_bytes.as_ptr(),
            runtime_entry as *mut u8,
            AARCH64_DETOUR_SIZE,
        );
        synchronize_instruction_cache(runtime_entry, AARCH64_DETOUR_SIZE)?;
    }
    Ok(())
}

fn embedded_elf_relocation_overlaps(
    image: &[u8],
    target_offset: usize,
    patch_len: usize,
) -> Result<bool, Status> {
    let patch_end = target_offset
        .checked_add(patch_len)
        .ok_or(Status::INVALID_PARAMETER)?;
    if patch_end > image.len() {
        return Err(Status::INVALID_PARAMETER);
    }

    for elf_offset in (0..=target_offset.saturating_sub(ELF_MAGIC.len())).rev() {
        if image.get(elf_offset..elf_offset + ELF_MAGIC.len()) != Some(&ELF_MAGIC) {
            continue;
        }
        let Ok(elf) = ElfBytes::<AnyEndian>::minimal_parse(&image[elf_offset..]) else {
            continue;
        };
        if elf.ehdr.e_machine != EM_AARCH64 || elf.ehdr.e_type != ET_REL {
            continue;
        }
        let Some(section_headers) = elf.section_headers() else {
            continue;
        };
        let relative_target = target_offset - elf_offset;
        let relative_patch_end = patch_end - elf_offset;
        let mut target_section = None;
        for (index, section) in section_headers.iter().enumerate() {
            let Ok(section_start) = usize::try_from(section.sh_offset) else {
                continue;
            };
            let Some(section_end) = usize::try_from(section.sh_size)
                .ok()
                .and_then(|size| section_start.checked_add(size))
            else {
                continue;
            };
            if relative_target >= section_start && relative_patch_end <= section_end {
                target_section = Some((index, relative_target - section_start));
                break;
            }
        }
        let Some((target_section_index, patch_in_section)) = target_section else {
            continue;
        };

        for relocation_section in section_headers.iter() {
            if relocation_section.sh_info as usize != target_section_index {
                continue;
            }
            match relocation_section.sh_type {
                SHT_REL => {
                    let relocations = elf
                        .section_data_as_rels(&relocation_section)
                        .map_err(|_| Status::COMPROMISED_DATA)?;
                    for relocation in relocations {
                        if relocation_overlaps(
                            relocation.r_offset,
                            aarch64_relocation_width(relocation.r_type),
                            patch_in_section,
                            patch_len,
                        )? {
                            return Ok(true);
                        }
                    }
                }
                SHT_RELA => {
                    let relocations = elf
                        .section_data_as_relas(&relocation_section)
                        .map_err(|_| Status::COMPROMISED_DATA)?;
                    for relocation in relocations {
                        if relocation_overlaps(
                            relocation.r_offset,
                            aarch64_relocation_width(relocation.r_type),
                            patch_in_section,
                            patch_len,
                        )? {
                            return Ok(true);
                        }
                    }
                }
                _ => {}
            }
        }
        return Ok(false);
    }
    Err(Status::COMPROMISED_DATA)
}

const fn aarch64_relocation_width(relocation_type: u32) -> usize {
    match relocation_type {
        elf::abi::R_AARCH64_ABS64 | elf::abi::R_AARCH64_PREL64 => 8,
        _ => 4,
    }
}

fn relocation_overlaps(
    relocation_offset: u64,
    relocation_width: usize,
    patch_offset: usize,
    patch_len: usize,
) -> Result<bool, Status> {
    let relocation_start =
        usize::try_from(relocation_offset).map_err(|_| Status::COMPROMISED_DATA)?;
    let relocation_end = relocation_start
        .checked_add(relocation_width)
        .ok_or(Status::COMPROMISED_DATA)?;
    let patch_end = patch_offset
        .checked_add(patch_len)
        .ok_or(Status::INVALID_PARAMETER)?;
    Ok(relocation_start < patch_end && patch_offset < relocation_end)
}

fn pe_relocation_overlaps(
    image: &[u8],
    target_offset: usize,
    patch_len: usize,
) -> Result<bool, Status> {
    if image.get(..2) != Some(b"MZ") {
        return Err(Status::COMPROMISED_DATA);
    }
    let pe_offset = read_u32(image, 0x3c)? as usize;
    let signature_end = pe_offset.checked_add(4).ok_or(Status::COMPROMISED_DATA)?;
    if image.get(pe_offset..signature_end) != Some(b"PE\0\0") {
        return Err(Status::COMPROMISED_DATA);
    }
    let coff = pe_offset.checked_add(4).ok_or(Status::COMPROMISED_DATA)?;
    let section_count = read_u16(image, coff + 2)? as usize;
    let optional_size = read_u16(image, coff + 16)? as usize;
    let optional = coff.checked_add(20).ok_or(Status::COMPROMISED_DATA)?;
    if read_u16(image, optional)? != 0x20b || optional_size < 120 {
        return Err(Status::COMPROMISED_DATA);
    }
    let section_table = optional
        .checked_add(optional_size)
        .ok_or(Status::COMPROMISED_DATA)?;
    let patch_rva = raw_range_to_rva(
        image,
        section_table,
        section_count,
        target_offset,
        patch_len,
    )?;

    if read_u32(image, optional + 108)? <= 5 {
        return Ok(false);
    }
    let relocation_rva = read_u32(image, optional + 112 + 5 * 8)?;
    let relocation_size = read_u32(image, optional + 112 + 5 * 8 + 4)? as usize;
    if relocation_rva == 0 || relocation_size == 0 {
        return Ok(false);
    }
    let relocation_offset = rva_to_raw(
        image,
        section_table,
        section_count,
        relocation_rva,
        relocation_size,
    )?;
    let relocation_end = relocation_offset
        .checked_add(relocation_size)
        .ok_or(Status::COMPROMISED_DATA)?;
    let patch_rva_end = patch_rva
        .checked_add(u32::try_from(patch_len).map_err(|_| Status::INVALID_PARAMETER)?)
        .ok_or(Status::INVALID_PARAMETER)?;
    let mut block = relocation_offset;
    while block < relocation_end {
        let page_rva = read_u32(image, block)?;
        let block_size = read_u32(image, block + 4)? as usize;
        if block_size < 8 || !block_size.is_multiple_of(2) {
            return Err(Status::COMPROMISED_DATA);
        }
        let block_end = block
            .checked_add(block_size)
            .ok_or(Status::COMPROMISED_DATA)?;
        if block_end > relocation_end {
            return Err(Status::COMPROMISED_DATA);
        }
        let mut entry_offset = block + 8;
        while entry_offset < block_end {
            let entry = read_u16(image, entry_offset)?;
            if entry >> 12 != 0 {
                let entry_rva = page_rva
                    .checked_add(u32::from(entry & 0x0fff))
                    .ok_or(Status::COMPROMISED_DATA)?;
                let entry_end = entry_rva.checked_add(8).ok_or(Status::COMPROMISED_DATA)?;
                if entry_rva < patch_rva_end && patch_rva < entry_end {
                    return Ok(true);
                }
            }
            entry_offset += 2;
        }
        block = block_end;
    }
    Ok(false)
}

fn raw_range_to_rva(
    image: &[u8],
    section_table: usize,
    section_count: usize,
    raw_offset: usize,
    len: usize,
) -> Result<u32, Status> {
    let raw_end = raw_offset
        .checked_add(len)
        .ok_or(Status::INVALID_PARAMETER)?;
    for index in 0..section_count {
        let section = section_table
            .checked_add(index.checked_mul(40).ok_or(Status::COMPROMISED_DATA)?)
            .ok_or(Status::COMPROMISED_DATA)?;
        let raw_size = read_u32(image, section + 16)? as usize;
        let raw_start = read_u32(image, section + 20)? as usize;
        let section_raw_end = raw_start
            .checked_add(raw_size)
            .ok_or(Status::COMPROMISED_DATA)?;
        if raw_offset >= raw_start && raw_end <= section_raw_end {
            return read_u32(image, section + 12)?
                .checked_add(
                    u32::try_from(raw_offset - raw_start).map_err(|_| Status::COMPROMISED_DATA)?,
                )
                .ok_or(Status::COMPROMISED_DATA);
        }
    }
    Err(Status::COMPROMISED_DATA)
}

fn rva_to_raw(
    image: &[u8],
    section_table: usize,
    section_count: usize,
    rva: u32,
    len: usize,
) -> Result<usize, Status> {
    let rva_end = rva
        .checked_add(u32::try_from(len).map_err(|_| Status::COMPROMISED_DATA)?)
        .ok_or(Status::COMPROMISED_DATA)?;
    for index in 0..section_count {
        let section = section_table
            .checked_add(index.checked_mul(40).ok_or(Status::COMPROMISED_DATA)?)
            .ok_or(Status::COMPROMISED_DATA)?;
        let virtual_size = read_u32(image, section + 8)?;
        let virtual_address = read_u32(image, section + 12)?;
        let raw_size = read_u32(image, section + 16)?;
        let section_end = virtual_address
            .checked_add(virtual_size.max(raw_size))
            .ok_or(Status::COMPROMISED_DATA)?;
        if rva >= virtual_address && rva_end <= section_end {
            return (read_u32(image, section + 20)? as usize)
                .checked_add((rva - virtual_address) as usize)
                .ok_or(Status::COMPROMISED_DATA);
        }
    }
    Err(Status::COMPROMISED_DATA)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, Status> {
    let end = offset.checked_add(2).ok_or(Status::COMPROMISED_DATA)?;
    let bytes: [u8; 2] = data
        .get(offset..end)
        .ok_or(Status::COMPROMISED_DATA)?
        .try_into()
        .map_err(|_| Status::COMPROMISED_DATA)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, Status> {
    let end = offset.checked_add(4).ok_or(Status::COMPROMISED_DATA)?;
    let bytes: [u8; 4] = data
        .get(offset..end)
        .ok_or(Status::COMPROMISED_DATA)?
        .try_into()
        .map_err(|_| Status::COMPROMISED_DATA)?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(target_arch = "aarch64")]
/// Cleans the data cache and invalidates the instruction cache for a code span.
///
/// # Safety
///
/// `address..address + len` must remain mapped for cache maintenance, and the
/// caller must prevent concurrent execution or mutation of the span until the
/// synchronization barriers complete.
pub unsafe fn synchronize_instruction_cache(address: usize, len: usize) -> Result<(), Status> {
    unsafe { synchronize_data_cache(address, len)? };
    const CACHE_LINE_SIZE: usize = 64;
    let start = address & !(CACHE_LINE_SIZE - 1);
    let end = address.checked_add(len).ok_or(Status::INVALID_PARAMETER)?;
    let mut line = start;
    while line < end {
        unsafe { asm!("ic ivau, {line}", line = in(reg) line, options(nostack, preserves_flags)) };
        let Some(next_line) = line.checked_add(CACHE_LINE_SIZE) else {
            break;
        };
        line = next_line;
    }
    unsafe { asm!("dsb ish", "isb", options(nostack, preserves_flags)) };
    Ok(())
}

#[cfg(target_arch = "aarch64")]
/// Cleans a data span to the point of coherency.
///
/// # Safety
///
/// `address..address + len` must remain mapped for cache maintenance, and the
/// caller must prevent concurrent mutation until the data-synchronization
/// barrier completes.
pub unsafe fn synchronize_data_cache(address: usize, len: usize) -> Result<(), Status> {
    const CACHE_LINE_SIZE: usize = 64;
    if address == 0 || len == 0 {
        return Err(Status::INVALID_PARAMETER);
    }
    let start = address & !(CACHE_LINE_SIZE - 1);
    let end = address.checked_add(len).ok_or(Status::INVALID_PARAMETER)?;
    let mut line = start;
    while line < end {
        unsafe { asm!("dc cvac, {line}", line = in(reg) line, options(nostack, preserves_flags)) };
        let Some(next_line) = line.checked_add(CACHE_LINE_SIZE) else {
            break;
        };
        line = next_line;
    }
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };
    Ok(())
}

#[cfg(all(test, not(target_arch = "aarch64")))]
unsafe fn synchronize_instruction_cache(address: usize, len: usize) -> Result<(), Status> {
    if address == 0 || len == 0 || address.checked_add(len).is_none() {
        return Err(Status::INVALID_PARAMETER);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;

    #[test]
    fn detour_bytes_use_requested_runtime_entry_register() {
        let hook = 0x1122_3344_5566_7788usize;
        let x2 = detour_patch(hook, RuntimeEntryRegister::X2);
        let x3 = detour_patch(hook, RuntimeEntryRegister::X3);
        let x5 = detour_patch(hook, RuntimeEntryRegister::X5);
        assert_eq!(&x2[..4], &0x1000_0002u32.to_le_bytes());
        assert_eq!(&x3[..4], &0x1000_0003u32.to_le_bytes());
        assert_eq!(&x5[..4], &0x1000_0005u32.to_le_bytes());
        assert_eq!(&x3[4..8], &0x5800_0050u32.to_le_bytes());
        assert_eq!(&x3[8..12], &0xd61f_0200u32.to_le_bytes());
        assert_eq!(&x3[12..], &(hook as u64).to_le_bytes());
    }

    #[test]
    fn pe_section_lookup_requires_one_bounded_arm64_section() {
        let mut image = vec![0_u8; 0x500];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0xaa64_u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&240_u16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        image[0x188..0x190].copy_from_slice(b".linux\0\0");
        image[0x198..0x19c].copy_from_slice(&0x100_u32.to_le_bytes());
        image[0x19c..0x1a0].copy_from_slice(&0x300_u32.to_le_bytes());

        let base = image.as_ptr() as usize;
        assert_eq!(
            find_unique_pe_section(base, image.len(), b".linux\0\0"),
            Ok((base + 0x300, 0x100))
        );
        assert_eq!(
            find_unique_pe_section(base, image.len(), b".missing"),
            Err(Status::NOT_FOUND)
        );
    }

    #[test]
    fn relocation_overlap_uses_the_entire_write_width() {
        assert!(relocation_overlaps(16, 8, 0, 20).unwrap());
        assert!(!relocation_overlaps(20, 8, 0, 20).unwrap());
        assert!(relocation_overlaps(0, 4, 0, 20).unwrap());
    }

    #[test]
    fn pe_base_relocation_overlap_is_rejected_at_the_patch_boundary() {
        let mut image = vec![0_u8; 0x600];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x86..0x88].copy_from_slice(&2_u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&240_u16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        image[0x104..0x108].copy_from_slice(&16_u32.to_le_bytes());
        image[0x130..0x134].copy_from_slice(&0x2000_u32.to_le_bytes());
        image[0x134..0x138].copy_from_slice(&12_u32.to_le_bytes());

        // .text: RVA 0x1000, raw 0x400. .reloc: RVA 0x2000, raw 0x500.
        image[0x190..0x194].copy_from_slice(&0x100_u32.to_le_bytes());
        image[0x194..0x198].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[0x198..0x19c].copy_from_slice(&0x100_u32.to_le_bytes());
        image[0x19c..0x1a0].copy_from_slice(&0x400_u32.to_le_bytes());
        image[0x1b8..0x1bc].copy_from_slice(&0x100_u32.to_le_bytes());
        image[0x1bc..0x1c0].copy_from_slice(&0x2000_u32.to_le_bytes());
        image[0x1c0..0x1c4].copy_from_slice(&0x100_u32.to_le_bytes());
        image[0x1c4..0x1c8].copy_from_slice(&0x500_u32.to_le_bytes());
        image[0x500..0x504].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[0x504..0x508].copy_from_slice(&12_u32.to_le_bytes());
        image[0x508..0x50a].copy_from_slice(&0xa020_u16.to_le_bytes());

        assert_eq!(pe_relocation_overlaps(&image, 0x420, 20), Ok(true));
        image[0x508..0x50a].copy_from_slice(&0xa034_u16.to_le_bytes());
        assert_eq!(pe_relocation_overlaps(&image, 0x420, 20), Ok(false));
    }

    #[test]
    fn restoration_writes_only_the_relocated_runtime_entry() {
        let original = [
            0xa9, 0xbb, 0x7b, 0xfd, 0x91, 0x00, 0x03, 0xfd, 0xaa, 0x02, 0x03, 0xf3, 0xa9, 0x01,
            0x53, 0xf3, 0xaa, 0x00, 0x03, 0xf5,
        ];
        let detour = Aarch64Detour {
            original_bytes: original,
        };
        let mut source_words = [0x1111_1111_u32; AARCH64_DETOUR_SIZE / 4];
        let mut runtime_words = [0x2222_2222_u32; AARCH64_DETOUR_SIZE / 4];
        let source_before = source_words;

        unsafe {
            restore_detour_at_runtime_entry(
                &detour,
                runtime_words.as_mut_ptr().cast::<u8>() as usize,
            )
            .unwrap();
        }

        let restored = unsafe {
            core::slice::from_raw_parts(runtime_words.as_ptr().cast::<u8>(), AARCH64_DETOUR_SIZE)
        };
        assert_eq!(restored, original);
        assert_eq!(source_words, source_before);
        // Keep the source mutable to model the staged buffer and prove the
        // restoration API has no stored pointer through which to change it.
        source_words[0] = 0x3333_3333;
        assert_ne!(source_words, source_before);
    }
}
