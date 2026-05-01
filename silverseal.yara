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

        $pattern_call_usermodehelper = { 81 C6 C0 0D 00 00 48 C1 E8 3C }
        $pattern_schedule_work = { 48 89 FA BF 00 20 00 00 }
        $pattern_msleep = { 48 89 C3 66 90 41 C7 44 24 18 02 }

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
