; lkm_worker.asm
; Kernel work function executed by the system workqueue.
; Sleeps 10 s for userspace to start, then jumps to lkm_worker_tail.asm.
;
; Prototype (work_func_t): void lkm_worker(struct work_struct *work)
; On entry: rsp % 16 == 8 (kernel's workqueue called us as a normal function)
;
; This blob is placed in a .text cave. It deliberately keeps the stack aligned
; for the tail blob by leaving rbp pushed until lkm_worker_tail.asm returns.
;
; Sentinels patched as i32 by Rust before writing blob:
;   MSLEEP_REL_SENTINEL    0x11AABBCC  rel32 for call msleep
;   WORKER_TAIL_REL_SENTINEL 0xEEAABBCC rel32 for jmp lkm_worker_tail

BITS 64

lkm_worker:
    push    rbp

    mov     edi, 10000
    db      0xE8
    dd      0x11AABBCC

    db      0xE9
    dd      0xEEAABBCC
