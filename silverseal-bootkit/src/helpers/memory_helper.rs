use elf::ElfBytes;
use elf::abi::PT_LOAD;
use elf::endian::AnyEndian;
use elf::section::SectionHeader;
use uefi::Status;

use log::debug;

/// ## Description
/// Signature unique to find grub_arch_efi_linux_boot_image function which receives:
/// - Kernel entry point
/// - Kernel size
/// - Args
///
/// Signature assembly:
/// ```assembly
/// mov     [rbp+var_48], rsi
/// call    rax
/// ```
pub const LINUX_BOOT_IMAGE_SIGNATURE: &[u8] = &[0x48, 0x89, 0x75, 0xB8, 0xFF, 0xD0];

pub const ZSTD_DECOMPRESS_FUNC_SIGNATURE: &[u8] =
    &[0xF3, 0x0F, 0x1E, 0xFA, 0x53, 0x48, 0x89, 0xFB, 0x48];

pub const INLINE_HOOK_SIZE: usize = 13;

const INITCALL_ARRAY_OFFSET: usize = 0x40;

pub struct InlineHook {
    pub target: usize,
    pub hook: usize,
    pub original_bytes: [u8; INLINE_HOOK_SIZE],
}

pub struct InitcallInfo {
    pub entry_physical_address: usize,
    pub entry_virtual_address: usize,
    pub original_target_virtual_address: usize,
}

#[derive(Debug)]
pub enum InitcallPhase {
    EarlyInitcall,
    CoreInitcall,
    PostCoreInitcall,
    ArchInitcall,
    SubsysInitcall,
    FsInitcall,
    DeviceInitcall,
    LateInitcall,
    ConsoleInitcall,
}

/// ## Description
/// binary_search performs a binary search for the given pattern in the specified memory region.
///
/// ## Arguments
/// - `data_address`: Starting address of the memory region to search.
/// - `data_size`: Size of the memory region to search.
/// - `pattern`: Byte pattern to search for.
///
/// ## Returns
/// - `Some(usize)`: Address where the pattern is found.
/// - `None`: If the pattern is not found in the specified memory region.
pub fn binary_search(data_address: usize, data_size: usize, pattern: &[u8]) -> Option<usize> {
    if data_address == 0 || pattern.is_empty() || data_size < pattern.len() {
        return None;
    }
    let data = unsafe { core::slice::from_raw_parts(data_address as *const u8, data_size) };

    for i in 0..=data.len().saturating_sub(pattern.len()) {
        if &data[i..i + pattern.len()] == pattern {
            return Some(data_address + i);
        }
    }
    None
}

/// ## Description
/// inline_hook installs an inline hook at the specified target address to redirect execution to the hook address.
///
/// ## Arguments
/// - `target`: Address where the hook should be installed.
/// - `hook`: Address of the hook function to redirect execution to.
///
/// ## Returns
/// - `Ok(InlineHook)`: Struct containing the target, hook, and original bytes for restoring later.
/// - `Err(Status)`: If the target or hook address is invalid.
pub fn inline_hook(target: usize, hook: usize) -> Result<InlineHook, Status> {
    if target == 0 || hook == 0 {
        return Err(Status::INVALID_PARAMETER);
    }

    let mut inline_hook = InlineHook {
        target,
        hook,
        original_bytes: [0; INLINE_HOOK_SIZE],
    };

    let mut patch = [0u8; INLINE_HOOK_SIZE];
    patch[0] = 0x49;
    patch[1] = 0xBA;
    patch[2..10].copy_from_slice(&(hook as u64).to_le_bytes());
    patch[10] = 0x41;
    patch[11] = 0xFF;
    patch[12] = 0xD2;

    let target_ptr = target as *mut u8;

    unsafe {
        core::ptr::copy_nonoverlapping(
            target_ptr as *const u8,
            inline_hook.original_bytes.as_mut_ptr(),
            INLINE_HOOK_SIZE,
        );
        core::ptr::copy_nonoverlapping(patch.as_ptr(), target_ptr, INLINE_HOOK_SIZE);
    }

    Ok(inline_hook)
}

/// ## Description
/// inline_jump_hook installs an inline jump hook at the specified target address.
///
/// Unlike `inline_hook`, this detour uses `jmp` instead of `call`, which keeps the
/// original caller's stack layout intact. That is required when replacing a real
/// function entry on x64, where the callee may read stack-passed arguments.
pub fn inline_jump_hook(target: usize, hook: usize) -> Result<InlineHook, Status> {
    if target == 0 || hook == 0 {
        return Err(Status::INVALID_PARAMETER);
    }

    let mut inline_hook = InlineHook {
        target,
        hook,
        original_bytes: [0; INLINE_HOOK_SIZE],
    };

    let mut patch = [0u8; INLINE_HOOK_SIZE];
    patch[0] = 0x49;
    patch[1] = 0xBA;
    patch[2..10].copy_from_slice(&(hook as u64).to_le_bytes());
    patch[10] = 0x41;
    patch[11] = 0xFF;
    patch[12] = 0xE2;

    let target_ptr = target as *mut u8;

    unsafe {
        core::ptr::copy_nonoverlapping(
            target_ptr as *const u8,
            inline_hook.original_bytes.as_mut_ptr(),
            INLINE_HOOK_SIZE,
        );
        core::ptr::copy_nonoverlapping(patch.as_ptr(), target_ptr, INLINE_HOOK_SIZE);
    }

    Ok(inline_hook)
}

/// ## Description
/// restore_inline_hook restores the original bytes at the specified target address to remove the inline hook.
///
/// ## Arguments
/// - `target`: Address where the original bytes should be restored.
/// - `original_bytes`: Byte slice containing the original bytes to restore.
///
/// ## Returns
/// - `Ok(())`: If the original bytes are successfully restored.
/// - `Err(Status)`: If the target address is invalid or the original bytes are empty.
pub fn restore_inline_hook(target: usize, original_bytes: &[u8]) -> Result<(), Status> {
    if target == 0 || original_bytes.len() != INLINE_HOOK_SIZE {
        return Err(Status::INVALID_PARAMETER);
    }

    let target_ptr = target as *mut u8;

    unsafe {
        core::ptr::copy_nonoverlapping(original_bytes.as_ptr(), target_ptr, INLINE_HOOK_SIZE);
    }

    Ok(())
}

/// ## Description
/// get_initcall_phase_address locates the last prel32 initcall entry for the
/// given phase. Linux stores initcall entries as 4-byte signed relative offsets
/// (`entry_addr + i32_value = target_fn`). The `initcall_levels` array in
/// `.init.data` holds absolute pointers that delimit each phase's entry range.
///
/// This function reads `levels[phase]` and `levels[phase+1]`, walks to the last
/// 4-byte entry in that range, decodes its relative offset to recover the
/// original target function address, and returns enough information for the
/// caller to overwrite that entry with a new relative offset.
///
/// ## Arguments
/// - `kernel_base`: Starting address of the kernel in memory.
/// - `kernel_size`: Size of the kernel in memory.
/// - `phase`: The specific initcall phase to search for (e.g., `LateInitcall`).
///
/// ## Returns
/// - `Some(InitcallInfo)`: Entry addresses and original target virtual address.
/// - `None`: If the initcall entries cannot be found or resolved.
pub fn get_initcall_phase_address(
    kernel_base: usize,
    kernel_size: usize,
    phase: InitcallPhase,
) -> Option<InitcallInfo> {
    if kernel_base == 0 || kernel_size == 0 {
        return None;
    }

    let vmlinux = ElfBytes::<AnyEndian>::minimal_parse(unsafe {
        core::slice::from_raw_parts(kernel_base as *const u8, kernel_size)
    })
    .ok()?;

    let init_data_section: SectionHeader = vmlinux.section_header_by_name(".init.data").ok()??;
    let init_data_virtual_address = usize::try_from(init_data_section.sh_addr).ok()?;
    let init_data_offset = usize::try_from(init_data_section.sh_offset).ok()?;
    let init_data_size = usize::try_from(init_data_section.sh_size).ok()?;
    let init_data_end = init_data_offset.checked_add(init_data_size)?;

    if init_data_end > kernel_size {
        return None;
    }

    let init_data_physical_address = kernel_base.checked_add(init_data_offset)?;
    debug!(
        "Found .init.data section: virt={:#x}, phys={:#x}, offset={:#x}, size={:#x}",
        init_data_virtual_address, init_data_physical_address, init_data_offset, init_data_size
    );

    // initcall_levels[] is an array of absolute virtual pointers at
    // .init.data + INITCALL_ARRAY_OFFSET. Each pair levels[i]..levels[i+1]
    // bounds the prel32 entries for phase i.
    let levels_phys = init_data_physical_address.checked_add(INITCALL_ARRAY_OFFSET)?;
    let phase_offset = match phase {
        InitcallPhase::EarlyInitcall => 0usize,
        InitcallPhase::CoreInitcall => 8,
        InitcallPhase::PostCoreInitcall => 0x10,
        InitcallPhase::ArchInitcall => 0x18,
        InitcallPhase::SubsysInitcall => 0x20,
        InitcallPhase::FsInitcall => 0x28,
        InitcallPhase::DeviceInitcall => 0x30,
        InitcallPhase::LateInitcall => 0x38,
        InitcallPhase::ConsoleInitcall => 0x40,
    };

    let kernel_end = kernel_base.checked_add(kernel_size)?;

    // Read levels[phase] (start of this phase's entries).
    let level_start_phys = levels_phys.checked_add(phase_offset)?;
    let level_end_phys = levels_phys.checked_add(phase_offset.checked_add(8)?)?;
    if level_end_phys.checked_add(8)? > kernel_end {
        return None;
    }

    // Safety: bounds checked above.
    let phase_start_virt =
        usize::try_from(unsafe { core::ptr::read(level_start_phys as *const u64) }).ok()?;
    let phase_end_virt =
        usize::try_from(unsafe { core::ptr::read(level_end_phys as *const u64) }).ok()?;

    debug!(
        "Phase {:?} entry range: start_virt={:#x}, end_virt={:#x}",
        phase, phase_start_virt, phase_end_virt
    );

    if phase_end_virt <= phase_start_virt {
        debug!("Phase {:?} has no entries", phase);
        return None;
    }

    let entry_count = (phase_end_virt - phase_start_virt) / 4;
    if entry_count == 0 {
        debug!("Phase {:?} has zero entries", phase);
        return None;
    }

    // Target the last entry: its virtual address is 4 bytes before the end boundary.
    let last_entry_virt = phase_end_virt.checked_sub(4)?;

    // Translate the entry's virtual address to a physical (in-memory) address.
    let last_entry_phys =
        translate_virtual_to_physical(&vmlinux, kernel_base, kernel_size, last_entry_virt)?;

    if last_entry_phys.checked_add(4)? > kernel_end {
        return None;
    }

    // Read the prel32 relative offset at this entry.
    // Safety: bounds checked above.
    let rel_offset = unsafe { core::ptr::read(last_entry_phys as *const i32) };

    // Resolve: original_target = entry_virt + rel_offset (sign-extended).
    let original_target_virt = if rel_offset >= 0 {
        last_entry_virt.checked_add(rel_offset as usize)?
    } else {
        last_entry_virt.checked_sub(rel_offset.unsigned_abs() as usize)?
    };

    debug!(
        "Last entry for phase {:?}: entry_virt={:#x}, entry_phys={:#x}, \
         rel_offset={:#x}, original_target_virt={:#x} (entry_count={})",
        phase, last_entry_virt, last_entry_phys, rel_offset, original_target_virt, entry_count
    );

    Some(InitcallInfo {
        entry_physical_address: last_entry_phys,
        entry_virtual_address: last_entry_virt,
        original_target_virtual_address: original_target_virt,
    })
}

/// ## Description
/// translate_virtual_to_physical converts a kernel virtual address to a physical (in-memory) address by reversing the PT_LOAD segment mapping.
///
/// ## Arguments
/// - `vmlinux`: Parsed ELF image of the kernel.
/// - `kernel_base`: Base address of the in-memory ELF image.
/// - `kernel_size`: Total size of the in-memory ELF image.
/// - `target_virtual_address`: The kernel virtual address to translate.
/// 
/// ## Returns
/// - `Some(usize)`: The corresponding physical address in memory.
/// - `None`: If the virtual address does not fall within any PT_LOAD segment or if the translation fails.
pub fn translate_virtual_to_physical(
    vmlinux: &ElfBytes<AnyEndian>,
    kernel_base: usize,
    kernel_size: usize,
    target_virtual_address: usize,
) -> Option<usize> {
    let segments = vmlinux.segments()?;

    for segment in segments.iter() {
        if segment.p_type != PT_LOAD {
            continue;
        }

        let segment_virtual_start = usize::try_from(segment.p_vaddr).ok()?;
        let segment_offset = usize::try_from(segment.p_offset).ok()?;
        let segment_file_size = usize::try_from(segment.p_filesz).ok()?;
        let segment_memory_size = usize::try_from(segment.p_memsz).ok()?;
        let segment_virtual_end = segment_virtual_start.checked_add(segment_memory_size)?;

        if target_virtual_address < segment_virtual_start
            || target_virtual_address >= segment_virtual_end
        {
            continue;
        }

        let offset_in_segment = target_virtual_address.checked_sub(segment_virtual_start)?;
        if offset_in_segment >= segment_memory_size || offset_in_segment >= segment_file_size {
            return None;
        }

        let target_offset = segment_offset.checked_add(offset_in_segment)?;
        if target_offset >= kernel_size {
            return None;
        }

        let target_physical_address = kernel_base.checked_add(target_offset)?;
        return Some(target_physical_address);
    }

    debug!(
        "Failed to translate target virt={:#x} to a physical PT_LOAD-backed address",
        target_virtual_address
    );
    None
}

/// ## Description
/// translate_physical_to_virtual converts a physical (in-memory) address back
/// to the kernel virtual address by reversing the PT_LOAD segment mapping.
///
/// ## Arguments
/// - `kernel_base`: Base address of the in-memory ELF image.
/// - `kernel_size`: Total size of the in-memory ELF image.
/// - `physical_address`: The physical address to translate.
///
/// ## Returns
/// - `Some(usize)`: The corresponding kernel virtual address.
/// - `None`: If the address does not fall within any PT_LOAD segment.
pub fn translate_physical_to_virtual(
    kernel_base: usize,
    kernel_size: usize,
    physical_address: usize,
) -> Option<usize> {
    if kernel_base == 0 || kernel_size == 0 || physical_address < kernel_base {
        return None;
    }

    let vmlinux = ElfBytes::<AnyEndian>::minimal_parse(unsafe {
        core::slice::from_raw_parts(kernel_base as *const u8, kernel_size)
    })
    .ok()?;

    let file_offset = physical_address.checked_sub(kernel_base)?;
    if file_offset >= kernel_size {
        return None;
    }

    let segments = vmlinux.segments()?;

    for segment in segments.iter() {
        if segment.p_type != PT_LOAD {
            continue;
        }

        let segment_offset = usize::try_from(segment.p_offset).ok()?;
        let segment_file_size = usize::try_from(segment.p_filesz).ok()?;
        let segment_virtual_start = usize::try_from(segment.p_vaddr).ok()?;
        let segment_end = segment_offset.checked_add(segment_file_size)?;

        if file_offset < segment_offset || file_offset >= segment_end {
            continue;
        }

        let offset_in_segment = file_offset.checked_sub(segment_offset)?;
        let virtual_address = segment_virtual_start.checked_add(offset_in_segment)?;
        debug!(
            "Translated phys={:#x} (file_offset={:#x}) via PT_LOAD(offset={:#x}, vaddr={:#x}) to virt={:#x}",
            physical_address, file_offset, segment_offset, segment_virtual_start, virtual_address
        );
        return Some(virtual_address);
    }

    debug!(
        "Failed to translate phys={:#x} to a virtual PT_LOAD-backed address",
        physical_address
    );
    None
}

/// ## Description
/// find_sentinel_4 searches for a 4-byte sentinel value within a given buffer and returns its byte offset if found.
/// 
/// ## Arguments
/// - `buf`: The buffer to search within.
/// - `sentinel`: The 4-byte sentinel value to search for.
/// 
/// ## Returns
/// - `Some(usize)`: The byte offset of the sentinel within the buffer if found.
/// - `None`: If the sentinel is not found in the buffer.
pub fn find_sentinel_4(buf: &[u8], sentinel: &[u8; 4]) -> Option<usize> {
    buf.windows(4).position(|w| w == sentinel)
}

/// ## Description
/// find_sentinel_8 searches for an 8-byte sentinel value within a given buffer and returns its byte offset if found.
/// 
/// ## Arguments
/// - `buf`: The buffer to search within.
/// - `sentinel`: The 8-byte sentinel value to search for.
/// 
/// ## Returns
/// - `Some(usize)`: The byte offset of the sentinel within the buffer if found.
/// - `None`: If the sentinel is not found in the buffer.
pub fn find_sentinel_8(buf: &[u8], sentinel: &[u8; 8]) -> Option<usize> {
    buf.windows(8).position(|w| w == sentinel)
}
