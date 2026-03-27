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

pub const INLINE_HOOK_SIZE: usize = 12;

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
    let mut inline_hook = InlineHook {
        target,
        hook,
        original_bytes: [0; INLINE_HOOK_SIZE],
    };
    if target == 0 || hook == 0 {
        return Err(Status::INVALID_PARAMETER);
    }
    let target_ptr = target as *mut u8;
    
    unsafe {
        for i in 0..INLINE_HOOK_SIZE {
            inline_hook.original_bytes[i] = core::ptr::read(target_ptr.add(i));
        }

        // mov rax, hook
        core::ptr::write(target_ptr, 0x48);
        core::ptr::write(target_ptr.add(1), 0xB8);
        core::ptr::write_unaligned(target_ptr.add(2) as *mut usize, hook);
        // jmp rax
        core::ptr::write(target_ptr.add(10), 0xFF);
        core::ptr::write(target_ptr.add(11), 0xE0);
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
    if target == 0 || original_bytes.is_empty() {
        return Err(Status::INVALID_PARAMETER);
    }
    let target_ptr = target as *mut u8;

    unsafe {
        for (i, &byte) in original_bytes.iter().enumerate() {
            core::ptr::write(target_ptr.add(i), byte);
        }
    }
    Ok(())
}
