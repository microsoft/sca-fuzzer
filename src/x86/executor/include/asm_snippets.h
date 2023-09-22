/// File: Building blocks for creating macros
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _MACRO_PRIMITIVES_H_
#define _MACRO_PRIMITIVES_H_
// clang-format off

#ifndef VENDOR_ID
#error "VENDOR_ID is not defined! Make sure to include this header late enough."
#endif

/// Accessors to MSRs
///
// clobber: rax, rcx, rdx
#define READ_MSR_START(ID, DEST)                          \
        "mov rcx, "ID"                           \n"      \
        "lfence; rdmsr; lfence                   \n"      \
        "shl rdx, 32; or rdx, rax                \n"      \
        "sub "DEST", rdx                         \n"

// clobber: rax, rcx, rdx
#define READ_MSR_END(ID, DEST)                            \
        "mov rcx, "ID"                           \n"      \
        "lfence; rdmsr; lfence                   \n"      \
        "shl rdx, 32; or rdx, rax                \n"      \
        "add "DEST", rdx                         \n"


/// Accessors to Performance Counters
///
// clobber: rax, rcx, rdx
#define READ_PFC_ONE(ID) \
        "mov rcx, "ID" \n"      \
        "lfence; rdpmc; lfence \n" \
        "shl rdx, 32; or rdx, rax \n"

// clobber: rax, rcx, rdx
#define READ_PFC_START() \
        READ_PFC_ONE("1") \
        "sub r10, rdx \n" \
        READ_PFC_ONE("2") \
        "sub r9, rdx \n" \
        READ_PFC_ONE("3") \
        "sub r8, rdx \n"

// clobber: rax, rcx, rdx
#define READ_PFC_END() \
        READ_PFC_ONE("1") \
        "add r10, rdx \n" \
        READ_PFC_ONE("2") \
        "add r9, rdx \n" \
        READ_PFC_ONE("3") \
        "add r8, rdx \n"


/// Detection of System Management Interrupts (SMIs)
///
#if VENDOR_ID == 1  // Intel
#define READ_SMI_START(DEST) READ_MSR_START("0x00000034", DEST)
#define READ_SMI_END(DEST) READ_MSR_END("0x00000034", DEST)

#elif VENDOR_ID == 2  // AMD
#define READ_SMI_START(DEST) \
    READ_PFC_ONE("5") \
    "sub "DEST", rdx \n"
#define READ_SMI_END(DEST) \
    READ_PFC_ONE("5") \
    "add "DEST", rdx \n"
#endif


/// A sequence of instructions that attempts to set the pipeline to a uniform state,
/// regardless of the code that was executed before it. The idea is that if we execute
/// a whole bunch fences, it will give time for the uops that are currently in
/// the reservation station to get executed, and thus ensure that the test case
/// starts with an empty-ish pipeline
/// clobber: none
#define PIPELINE_RESET() asm volatile(""\
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n" \
    "lfence; lfence; lfence; lfence; lfence \n");

/// Register Loading
#if VENDOR_ID == 1 // Intel
#define SET_REGISTER_FROM_INPUT()\
    asm volatile("\n.intel_syntax noprefix\n" \
    "lea rsp, [r14 + "xstr(REG_INIT_OFFSET)"]\n" \
    "popq rax \n" \
    "popq rbx \n" \
    "popq rcx \n" \
    "popq rdx \n" \
    "popq rsi \n" \
    "popq rdi \n" \
    "popfq \n" \
    "popq rsp \n" \
    "mov rbp, rsp \n" \
    "bndmk bnd0, [r14 + 0x1000]\n" \
    "bndmk bnd1, [r14 + 0x1000]\n" \
    "bndmk bnd2, [r14 + 0x1000]\n" \
    "bndmk bnd3, [r14 + 0x1000]\n" \
    ".att_syntax noprefix");

#elif VENDOR_ID == 2 // AMD
#define SET_REGISTER_FROM_INPUT()\
    asm volatile("\n.intel_syntax noprefix\n" \
    "lea rsp, [r14 + "xstr(REG_INIT_OFFSET)"]\n" \
    "popq rax \n" \
    "popq rbx \n" \
    "popq rcx \n" \
    "popq rdx \n" \
    "popq rsi \n" \
    "popq rdi \n" \
    "popfq \n" \
    "popq rsp \n" \
    "mov rbp, rsp \n" \
    ".att_syntax noprefix");
#endif

// =================================================================================================
// L1D Prime+Probe
// =================================================================================================
// TODO: generate this code dynamically
#if L1D_ASSOCIATIVITY == 8
#define PRIME_ONE_SET(BASE, OFFSET, TMP)                 \
        "mov "TMP", "OFFSET"                ; mfence \n" \
        "add "TMP", ["BASE" + "TMP"]        ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 4096] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 8192] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 12288]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 16384]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 20480]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 24576]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 28672]; mfence \n"

#define PROBE_ONE_SET(BASE, OFFSET)                  \
        "mov rax, "OFFSET"                       \n" \
        "add rax, ["BASE" + rax]        ; mfence \n" \
        "add rax, ["BASE" + rax + 4096] ; mfence \n" \
        "add rax, ["BASE" + rax + 8192] ; mfence \n" \
        "add rax, ["BASE" + rax + 12288]; mfence \n" \
        "add rax, ["BASE" + rax + 16384]; mfence \n" \
        "add rax, ["BASE" + rax + 20480]; mfence \n" \
        "add rax, ["BASE" + rax + 24576]; mfence \n" \
        "add rax, ["BASE" + rax + 28672]; mfence \n"

#elif L1D_ASSOCIATIVITY == 12
#define PRIME_ONE_SET(BASE, OFFSET, TMP)                 \
        "mov "TMP", "OFFSET"                ; mfence \n" \
        "add "TMP", ["BASE" + "TMP"]        ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 4096] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 8192] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 12288]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 16384]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 20480]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 24576]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 28672]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 32768]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 36864]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 40960]; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 45056]; mfence \n"

#define PROBE_ONE_SET(BASE, OFFSET)                  \
        "mov rax, "OFFSET"                       \n" \
        "add rax, ["BASE" + rax]        ; mfence \n" \
        "add rax, ["BASE" + rax + 4096] ; mfence \n" \
        "add rax, ["BASE" + rax + 8192] ; mfence \n" \
        "add rax, ["BASE" + rax + 12288]; mfence \n" \
        "add rax, ["BASE" + rax + 16384]; mfence \n" \
        "add rax, ["BASE" + rax + 20480]; mfence \n" \
        "add rax, ["BASE" + rax + 24576]; mfence \n" \
        "add rax, ["BASE" + rax + 28672]; mfence \n" \
        "add rax, ["BASE" + rax + 32768]; mfence \n" \
        "add rax, ["BASE" + rax + 36864]; mfence \n" \
        "add rax, ["BASE" + rax + 40960]; mfence \n" \
        "add rax, ["BASE" + rax + 45056]; mfence \n"

#endif

// clobber: none
#define PRIME(BASE, OFFSET, TMP, COUNTER, REPS)                 \
        "mfence                                             \n" \
        "mov "COUNTER", "REPS"                              \n" \
        "   1: mov "OFFSET", 0                              \n" \
        "       2: lfence                                   \n" \
                PRIME_ONE_SET(BASE, OFFSET, TMP)                \
        "       add "OFFSET", 64                            \n" \
        "   cmp "OFFSET", 4096; jl 2b                       \n" \
        "dec "COUNTER"; jnz 1b                              \n" \
        "mfence;                                            \n"


// clobber: rax, rcx, rdx
#define PROBE_INTEL(BASE, OFFSET, TMP, DEST)            \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1: lfence                                  \n" \
        "   xor "TMP", "TMP"                        \n" \
            READ_PFC_ONE("0")                           \
        "   sub "TMP", rdx                          \n" \
            PROBE_ONE_SET(BASE, OFFSET)                 \
            READ_PFC_ONE("0")                           \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", "xstr(L1D_ASSOCIATIVITY)"    \n" \
        "   jl 2f                                   \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"

// clobber: rax, rcx, rdx
#define PROBE_AMD(BASE, OFFSET, TMP, DEST)              \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1: lfence                                  \n" \
        "   xor "TMP", "TMP"                        \n" \
            READ_PFC_ONE("0")                           \
        "   sub "TMP", rdx                          \n" \
            PROBE_ONE_SET(BASE, OFFSET)                 \
            READ_PFC_ONE("0")                           \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 0; jg 2f                     \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"

#if VENDOR_ID == 1
#define PROBE(BASE, OFFSET, TMP, DEST) PROBE_INTEL(BASE, OFFSET, TMP, DEST)
#elif VENDOR_ID == 2
#define PROBE(BASE, OFFSET, TMP, DEST) PROBE_AMD(BASE, OFFSET, TMP, DEST)
#endif

// =================================================================================================
// Partial Prime+Probe (P+P applied to a subset of L1D instead the whole cache)
// =================================================================================================
#define PRIME_PARTIAL(BASE, OFFSET, TMP, COUNTER, REPS)         \
        "mfence                                             \n" \
        "mov "COUNTER", "REPS"                              \n" \
        "   1: mov "OFFSET", 0                              \n" \
        "       2: lfence                                   \n" \
                PRIME_ONE_SET(BASE, OFFSET, TMP)                \
        "       add "OFFSET", 64                            \n" \
        "   cmp "OFFSET", 3840; jl 2b                       \n" \
        "dec "COUNTER"; jnz 1b                              \n" \
        "mfence;                                            \n"

// =================================================================================================
// L1D Flush+Reload
// =================================================================================================

// clobber: none
#define FLUSH(BASE, OFFSET) \
        "mfence                                     \n" \
        "mov "OFFSET", 0                            \n" \
        "1: lfence                                  \n" \
        "   clflush qword ptr ["BASE" + "OFFSET"]   \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n" \
        "mfence                                     \n"

// clobber: rax, rcx, rdx
#define RELOAD_INTEL(BASE, OFFSET, TMP, DEST)           \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1:                                         \n" \
        "   xor "TMP", "TMP"                        \n" \
            READ_PFC_ONE("0")                           \
        "   sub "TMP", rdx                          \n" \
        "   mov rax, qword ptr ["BASE" + "OFFSET"]  \n" \
            READ_PFC_ONE("0")                           \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 0; jne 2f                    \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"

// clobber: rax, rcx, rdx
#define RELOAD_AMD(BASE, OFFSET, TMP, DEST)             \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1:                                         \n" \
        "   xor "TMP", "TMP"                        \n" \
            READ_PFC_ONE("0")                           \
        "   sub "TMP", rdx                          \n" \
        "   mov rax, qword ptr ["BASE" + "OFFSET"]  \n" \
            READ_PFC_ONE("0")                           \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 0; je 2f                     \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"

#if VENDOR_ID == 1
#define RELOAD(BASE, OFFSET, TMP, DEST) RELOAD_INTEL(BASE, OFFSET, TMP, DEST)
#elif VENDOR_ID == 2
#define RELOAD(BASE, OFFSET, TMP, DEST) RELOAD_AMD(BASE, OFFSET, TMP, DEST)
#endif

// =================================================================================================
// GPR Tracing
// =================================================================================================
#define GPR_TRACING_START(BASE, OFFSET) ""  // dummy macro

#define GPR_TRACING_END(BASE, OFFSET, TMP, DEST) \
    "" // tbd
    // implement this:
    //
    // // Read GPR values
    // asm_volatile_intel(
    //     // r15 <- &latest_measurement
    //     "lea r15, [r14 + "xstr(MEASUREMENT_OFFSET)"]\n"
    //     "mov qword ptr [r15], rax \n"
    //     "mov qword ptr [r15 + 8], rbx \n"
    //     "mov qword ptr [r15 + 16], rcx \n"
    //     "mov qword ptr [r15 + 24], rdx \n"
    //     "mov qword ptr [r15 + 32], rsi \n"
    //     "mov qword ptr [r15 + 40], rdi \n"

    //     // rsp <- rsp_before_test_case
    //     "mov rsp, qword ptr [r14 + "xstr(RSP_OFFSET)"]\n"

    //     // restore registers
    //     "popfq\n"
    //     "pop r15\n"
    //     "pop r14\n"
    //     "pop r13\n"
    //     "pop r12\n"
    //     "pop r11\n"
    //     "pop r10\n"
    //     "pop rbp\n"
    //     "pop rbx\n"
    // );

// clang-format on
#endif // _MACRO_PRIMITIVES_H_
