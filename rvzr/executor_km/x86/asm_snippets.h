/// File: Building blocks for creating macros; x86-64
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _X86_ASM_SNIPPETS_H_
#define _X86_ASM_SNIPPETS_H_
// clang-format off

#include "hardware_desc.h"
#include "measurement.h"
#include <asm/msr-index.h>

#ifndef VENDOR_ID
#error "VENDOR_ID is not defined! Make sure to include this header late enough."
#endif

/// Reserved registers
#define STATUS_REGISTER        "r12"
#define STATUS_REGISTER_32     "r12d"
#define STATUS_REGISTER_8      "r12b"
#define HTRACE_REGISTER        "r13"

/// State machine of the tracing process
#define SET_SR_STARTED()       "mov "STATUS_REGISTER_8", "xstr(STATUS_STARTED)" \n"
#define SET_SR_ENDED()         "mov "STATUS_REGISTER_8", "xstr(STATUS_ENDED)" \n"


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

/// @brief Clear the upper 32 bits of the STATUS_REGISTER
#define CLEAR_SMI_STATUS() \
   "mov "STATUS_REGISTER_32", "STATUS_REGISTER_32" \n"

#if VENDOR_ID == VENDOR_INTEL_
/// @brief Start monitoring SMIs by reading the current value of the SMI counter (MSR 0x34)
///        and storing it in the STATUS_REGISTER[63:32]
///  clobber: rax, rcx, rdx
#define READ_SMI_START()               \
    "mov rcx, "xstr(MSR_SMI_COUNT)"\n" \
    "lfence; rdmsr; lfence         \n" \
    "mov rcx, 0                    \n" \
    "sub ecx, eax                  \n" \
    "shl rcx, 32                   \n" \
    CLEAR_SMI_STATUS()                 \
    "or "STATUS_REGISTER", rcx     \n"

/// @brief End monitoring SMIs by reading the current value of the SMI counter (MSR 0x34)
///        and storing the difference between the current and the previous value
///        in the STATUS_REGISTER[31:0]
/// clobber: rax, rcx, rdx
#define READ_SMI_END()                 \
    "mov rcx, "xstr(MSR_SMI_COUNT)"\n" \
    "lfence; rdmsr; lfence         \n" \
    "mov rcx, "STATUS_REGISTER"    \n" \
    "shr rcx, 32                   \n" \
    "add ecx, eax                  \n" \
    "shl rcx, 32                   \n" \
    CLEAR_SMI_STATUS()                 \
    "or "STATUS_REGISTER", rcx     \n"
#elif VENDOR_ID == VENDOR_AMD_
/// @brief Start monitoring SMIs by reading the current value of the SMI counter (PMU ID 5)
///        and storing it in the STATUS_REGISTER[63:32]
///  clobber: rax, rcx, rdx
#define READ_SMI_START()            \
    "mov rcx, 5                 \n" \
    "lfence; rdpmc; lfence      \n" \
    "mov rcx, 0                 \n" \
    "sub ecx, eax               \n" \
    "shl rcx, 32                \n" \
    CLEAR_SMI_STATUS()              \
    "or "STATUS_REGISTER", rcx  \n"

/// @brief End monitoring SMIs by reading the current value of the SMI counter (PMU ID 5)
///        and storing the difference between the current and the previous value
///        in the STATUS_REGISTER[31:0]
/// clobber: rax, rcx, rdx
#define READ_SMI_END()              \
    "mov rcx, 5                 \n" \
    "lfence; rdpmc; lfence      \n" \
    "mov rcx, "STATUS_REGISTER" \n" \
    "shr rcx, 32                \n" \
    "add ecx, eax               \n" \
    "shl rcx, 32                \n" \
    CLEAR_SMI_STATUS()              \
    "or "STATUS_REGISTER", rcx  \n"

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
    "pop rax \n" \
    "pop rbx \n" \
    "pop rcx \n" \
    "pop rdx \n" \
    "pop rsi \n" \
    "pop rdi \n" \
    "popfq \n" \
    "lea rsp, [r14 + "xstr(LOCAL_RSP_OFFSET)"]\n" \
    "mov rbp, rsp \n" \
    ".att_syntax noprefix");

#elif VENDOR_ID == 2 // AMD
#define SET_REGISTER_FROM_INPUT()\
    asm volatile("\n.intel_syntax noprefix\n" \
    "lea rsp, [r14 + "xstr(REG_INIT_OFFSET)"]\n" \
    "pop rax \n" \
    "pop rbx \n" \
    "pop rcx \n" \
    "pop rdx \n" \
    "pop rsi \n" \
    "pop rdi \n" \
    "popfq \n" \
    "lea rsp, [r14 + "xstr(LOCAL_RSP_OFFSET)"]\n" \
    "mov rbp, rsp \n" \
    ".att_syntax noprefix");
#endif

// =================================================================================================
// L1D Prime+Probe
// =================================================================================================
// TODO: generate this code dynamically
#if L1D_ASSOCIATIVITY == 2
#define PRIME_ONE_SET(BASE, OFFSET, TMP)                 \
        "mov "TMP", "OFFSET"                ; mfence \n" \
        "add "TMP", ["BASE" + "TMP"]        ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 4096] ; mfence \n"

#define PROBE_ONE_SET(BASE, OFFSET)                  \
        "mov rax, "OFFSET"                       \n" \
        "add rax, ["BASE" + rax]        ; mfence \n" \
        "add rax, ["BASE" + rax + 4096] ; mfence \n"

#elif L1D_ASSOCIATIVITY == 4
#define PRIME_ONE_SET(BASE, OFFSET, TMP)                 \
        "mov "TMP", "OFFSET"                ; mfence \n" \
        "add "TMP", ["BASE" + "TMP"]        ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 4096] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 8192] ; mfence \n" \
        "add "TMP", ["BASE" + "TMP" + 12288]; mfence \n"

#define PROBE_ONE_SET(BASE, OFFSET)                  \
        "mov rax, "OFFSET"                       \n" \
        "add rax, ["BASE" + rax]        ; mfence \n" \
        "add rax, ["BASE" + rax + 4096] ; mfence \n" \
        "add rax, ["BASE" + rax + 8192] ; mfence \n" \
        "add rax, ["BASE" + rax + 12288]; mfence \n"

#elif L1D_ASSOCIATIVITY == 8
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

#else
#error "Unexpected associativity"
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
// Macro stack management
// =================================================================================================
/// @brief A sequence of instructions that switches the stack pointer to the macro stack
///        and pushes the flags and registers RAX, RBX, RCX, RDX
#define MACRO_PROLOGUE()                                                                           \
    "mov qword ptr [r14 - " xstr(MACRO_STACK_TOP_OFFSET) " - 8], rsp\n"                            \
    "lea rsp, [r14 - " xstr(MACRO_STACK_TOP_OFFSET) " - 8]\n"                                      \
    "push rax\n"                                                                                   \
    "push rbx\n"                                                                                   \
    "push rcx\n"                                                                                   \
    "push rdx\n"                                                                                   \
    "pushf\n"

/// @brief A sequence of instructions that pops the flags and registers RDX, RCX, RBX, RAX, RSP
///        and overwrites the popped memory addresses with zeros
#define MACRO_EPILOGUE()                                                                           \
    "popf\n"                                                                                       \
    "pop rdx\n"                                                                                    \
    "pop rcx\n"                                                                                    \
    "pop rbx\n"                                                                                    \
    "pop rax\n"                                                                                    \
    "mov qword ptr [rsp - 0x08], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x10], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x18], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x20], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x28], 0 \n"                                                             \
    "pop rsp\n"

// clang-format on
#endif // _X86_ASM_SNIPPETS_H_
