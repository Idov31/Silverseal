import "pe"

rule silverseal_uefi_bootkit_x64 {
    meta:
        description = "Detects the Silverseal x64 UEFI bootkit"
        author = "Ido Veltzman"
        date = "2026-05-01"

    strings:
        $efi_grub = "\\EFI\\ubuntu\\grubx64.efi.original" wide
        $efi_failsafe = "\\EFI\\ubuntu\\failsafe" wide

        $loader_insmod = "/sbin/insmod" ascii
        $loader_module = "/silverseal_rootkit.ko" ascii
        $crate_name = "silverseal_bootkit" ascii

        $hook_log_grub = "grub_arch_efi_linux_boot_image_hook called with kernel_entry" ascii
        $hook_log_zstd = "zstd_decompress_dctx_hook called with dctx" ascii
        $hook_log_late_initcall = "Patched late_initcall entry at virt=" ascii
        $hook_log_caves = "Caves: stager virt=" ascii
        $hook_log_decompressed = "Decompressed linux kernel is at address:" ascii

        $pattern_call_usermodehelper = { E8 5B E3 F8 FF 55 83 F9 01 48 89 E5 41 56 41 89 CE 41 55 48 8B 45 08 }
        $pattern_schedule_work = { 55 48 8B 35 1B 9B D7 02 48 89 FA BF 00 20 00 00 48 89 E5 E8 33 E2 AE FF }
        $pattern_msleep = { E8 CB B7 E7 FF 55 48 89 E5 E8 C2 6B FF FF 48 85 C0 74 10 48 89 C7 }

        $sentinel_argv0 = { AA AA AA AA AA AA AA AA }
        $sentinel_call_umh = { 00 FF EE DD }
        $sentinel_worker_tail = { CC BB AA EE }
        $sentinel_path_disp = { 11 EE DD CC }
        $sentinel_argv_disp = { 22 EE DD CC }

    condition:
        uint16(0) == 0x5A4D and
        pe.machine == 0x8664 and
        pe.subsystem == 10 and
        filesize < 256KB and
        all of ($efi_*) and
        all of ($loader_*) and
        $crate_name and
        2 of ($hook_log_*) and
        2 of ($pattern_*) and
        2 of ($sentinel_*)
}
