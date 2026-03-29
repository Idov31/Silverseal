use uefi::Status;

extern crate alloc;

/*
* Signature unique to find grub_arch_efi_linux_boot_image function which receives:
* - Kernel entry point
* - Kernel size
* - Args
*
* Signature assembly:
* mov     [rbp+var_48], rsi
* call    rax
*/
pub const LINUX_BOOT_IMAGE_SIGNATURE: &[u8] = &[0x48, 0x89, 0x75, 0xB8, 0xFF, 0xD0];

pub const INLINE_HOOK_SIZE: usize = 13;

pub struct InlineHook {
    pub target: usize,
    pub hook: usize,
    pub original_bytes: [u8; INLINE_HOOK_SIZE],
}

/*
* Performs a binary search for the given pattern in the specified memory region.
*
* Args:
* - data_address: Starting address of the memory region to search.
* - data_size: Size of the memory region to search.
* - pattern: Byte pattern to search for.
*
* Returns:
* - Some(usize): Address where the pattern is found.
* - None: If the pattern is not found in the specified memory region.
*/
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

/*
* Installs an inline hook at the specified target address to redirect execution to the hook address.
*
* Args:
* - target: Address where the hook should be installed.
* - hook: Address of the hook function to redirect execution to.
*
* Returns:
* - Ok(InlineHook): Struct containing the target, hook, and original bytes for restoring later.
* - Err(Status): If the target or hook address is invalid.
*/
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

/*
* Restores the original bytes at the specified target address to remove the inline hook.
*
* Args:
* - target: Address where the original bytes should be restored.
* - original_bytes: Byte slice containing the original bytes to restore.
*
* Returns:
* - Ok(()): If the original bytes are successfully restored.
* - Err(Status): If the target address is invalid or the original bytes are empty.
*/
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
