// SPDX-License-Identifier: GPL-2.0
//
// BTI landing pads for staged-image detours. The detours reach these symbols
// with an indirect BR; the veneers then use direct branches into Rust.

    .text
    .p2align 2

    .global silverseal_grub_linux_boot_image_hook_veneer
silverseal_grub_linux_boot_image_hook_veneer:
    // BTI j accepts the detour's BR x16 transfer.
    .inst 0xd503249f
    b silverseal_grub_linux_boot_image_hook_rust

    .global silverseal_zboot_decompress_hook_veneer
silverseal_zboot_decompress_hook_veneer:
    .inst 0xd503249f
    b silverseal_zboot_decompress_hook_rust
