; lkm_stager.asm
; Minimal 41-byte x64 stager executed as a Linux kernel late_initcall.
;
; Problem: the main lkm_loader shellcode lives in a .data code cave that has
; its NX bit set by the kernel before late_initcall runs. This stager lives in
; .text (always executable), calls set_memory_x to make the .data page
; executable, then tail-calls lkm_loader.
;
; All three kernel addresses are inlined as movabs immediates — no data
; pointer area needed, keeping the blob exactly 41 bytes.
;
; Assemble (flat binary):
;   nasm -f bin -o lkm_stager.bin lkm_stager.asm
;
; Sentinels (patched by Rust before writing blob to cave in .text):
;   0xBADC0FFEE0DDF00D  → page-aligned virt addr of lkm_loader's .data cave
;                          (arg1 to set_memory_x; MUST be 4K-aligned)
;   0xFACEFEEDFACEFEED  → kernel virt addr of set_memory_x
;   0xDEADFACEDEADFACE  → kernel virt addr of lkm_loader inside .data cave

BITS 64

; ── Calling convention ───────────────────────────────────────────────────────
; On entry (late_initcall):  rsp % 16 == 8  (caller ret addr on stack)
; After push rbp:            rsp % 16 == 0  (aligned for call r10)
; After pop rbp:             rsp % 16 == 8  (ready for tail-call)

lkm_stager:
    push    rbp                         ; 55          [1]  align rsp for call
    mov     rdi, 0xBADC0FFEE0DDF00D     ; 48 BF ...  [10] arg1: .data cave page addr
    push    1                           ; 6A 01       [2]  arg2: nrpages = 1
    pop     rsi                         ; 5E          [1]
    mov     r10, 0xFACEFEEDFACEFEED     ; 49 BA ...  [10] set_memory_x virt addr
    call    r10                         ; 41 FF D2    [3]  set_memory_x(cave_page, 1)
    pop     rbp                         ; 5D          [1]  restore frame pointer
    mov     r11, 0xDEADFACEDEADFACE     ; 49 BB ...  [10] lkm_loader virt addr
    jmp     r11                         ; 41 FF E3    [3]  tail-call lkm_loader
                                        ; ─────────────────────────────────────
                                        ; Total bytes: 1+10+2+1+10+3+1+10+3 = 41
