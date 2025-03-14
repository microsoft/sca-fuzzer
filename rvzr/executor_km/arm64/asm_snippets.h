/// File: Building blocks for creating macros; ARM64 version
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _ARM64_ASM_SNIPPETS_H_
#define _ARM64_ASM_SNIPPETS_H_

#include "hardware_desc.h"
#include "measurement.h"

/// Reserved registers
#define STATUS_REGISTER         "x12"
#define STATUS_REGISTER_32      "w12"
#define HTRACE_REGISTER         "x13"
#define MEMORY_BASE_REGISTER    "x30"
#define MEMORY_BASE_REGISTER_ID 0x1e
#define UTIL_BASE_REGISTER      "x29"
#define UTIL_BASE_REGISTER_ID   0x1d
#define TMP_REG1                "x28"
#define TMP_REG1_ID             0x1c
#define TMP_REG2                "x27"
#define TMP_REG3                "x26"
#define TMP_REG4                "x25"
#define TMP_REG5                "x24"
#define TMP_REG6                "x23"

#define PFC0 "x10"
#define PFC1 "x9"
#define PFC2 "x8"

/// State machine of the tracing process
#define SET_SR_STARTED()                                                                           \
    "and " STATUS_REGISTER_32 ", " STATUS_REGISTER_32 ", #0xFFFFFF00 \n"                           \
    "orr " STATUS_REGISTER_32 ", " STATUS_REGISTER_32 ", " xstr(STATUS_STARTED) " \n"
#define SET_SR_ENDED()                                                                             \
    "and " STATUS_REGISTER_32 ", " STATUS_REGISTER_32 ", #0xFFFFFF00 \n"                           \
    "orr " STATUS_REGISTER_32 ", " STATUS_REGISTER_32 ", " xstr(STATUS_ENDED) " \n"

/// ================================================================================================
/// MSR and Performance Counter accessors
/// ================================================================================================

// clobber: x16
#define READ_MSR_START(ID, DEST)                                                                   \
    "isb; dsb SY \n"                                                                               \
    "mov " DEST ", #0 \n"                                                                          \
    "mrs x16, " ID " \n"                                                                           \
    "sub " DEST ", " DEST ", x16 \n"

// clobber: x16
#define READ_MSR_END(ID, DEST)                                                                     \
    "isb; dsb SY \n"                                                                               \
    "mrs x16, " ID " \n"                                                                           \
    "add " DEST ", " DEST ", x16 \n"

// clobber: x16 (dest)
#define READ_PFC_ONE(ID)                                                                           \
    "mov x16, " ID " \n"                                                                           \
    "msr pmselr_el0, x16 \n"                                                                       \
    "mrs x16, pmxevcntr_el0 \n"

// clobber: x16, PFC0, PFC1, PFC2
// clang-format off
#define READ_PFC_START() \
        "isb; dsb SY \n" \
        "mov " PFC0 ", #0 \n" \
        "mov " PFC1 ", #0 \n" \
        "mov " PFC2 ", #0 \n" \
        READ_PFC_ONE("1") \
        "sub " PFC0 ", " PFC0 ", x16 \n" \
        READ_PFC_ONE("2") \
        "sub " PFC1 ", " PFC1 ", x16 \n" \
        READ_PFC_ONE("3") \
        "sub " PFC2 ", " PFC2 ", x16 \n"

// clobber: rax, rcx, rdx
#define READ_PFC_END() \
        "isb; dsb SY \n" \
        READ_PFC_ONE("1") \
        "add " PFC0 ", " PFC0 ", x16 \n" \
        READ_PFC_ONE("2") \
        "add " PFC1 ", " PFC1 ", x16 \n" \
        READ_PFC_ONE("3") \
        "add " PFC2 ", " PFC2 ", x16 \n"
// clang-format on

/// ================================================================================================
/// Detection of Interrupts
/// ================================================================================================
/// @brief Start monitoring SMIs by reading the current value of the SMI counter (MSR ???)
///        and storing it in the STATUS_REGISTER[63:32]
///  clobber:
#define READ_SMI_START() // FIXME: unimplemented

/// @brief End monitoring SMIs by reading the current value of the SMI counter (MSR ???))
///        and storing the difference between the current and the previous value
///        in the STATUS_REGISTER[31:0]
/// clobber: x1 [dest]
#define READ_SMI_END() // FIXME: unimplemented

/// ================================================================================================
/// Pre- and Post- measurement macros
/// ================================================================================================

/// @brief Loading of register values from the main actor's memory
/// clobber: x0-x7, nzcv, sp
// clang-format off
#define SET_REGISTER_FROM_INPUT() \
    asm volatile("\n"   \
    "mov x0, #"xstr(REG_INIT_OFFSET)" \n" \
    "add sp, "MEMORY_BASE_REGISTER", x0 \n" \
    "ldp x0, x1, [sp], #16\n" \
    "ldp x2, x3, [sp], #16\n" \
    "ldp x4, x5, [sp], #16\n" \
    "ldp x6, x7, [sp], #16\n" \
    "msr nzcv, x6\n" \
    "mov sp, x7\n");
// clang-format on

/// ================================================================================================
/// Measurement primitives
/// ================================================================================================
// clang-format off
#if L1D_ASSOCIATIVITY == 2
#define PRIME_ONE_SET(BASE, OFFSET, TMP, ACC) \
    "mov "TMP", "BASE" \n" \
    "add "TMP", "TMP", "OFFSET" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #4096 \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n"
#elif L1D_ASSOCIATIVITY == 4
#define PRIME_ONE_SET(BASE, OFFSET, TMP, ACC) \
    "mov "TMP", "BASE" \n" \
    "add "TMP", "TMP", "OFFSET" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #4096 \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #4096 \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #4096 \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n"
#elif L1D_ASSOCIATIVITY == 8
#define PRIME_ONE_SET(BASE, OFFSET, TMP, ACC) \
    "mov "TMP", "BASE" \n" \
    "add "TMP", "TMP", "OFFSET" \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #4096 \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #4096 \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #4096 \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #4096 \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #4096 \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #4096 \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n" \
    "add "TMP", "TMP", #4096 \n" \
    "add "TMP", "TMP", "ACC" \n" \
    "ldr "ACC", ["TMP"]\n"
#else
#error "Unsupported L1D_ASSOCIATIVITY"
#endif
// clang-format on

/// @brief Prime part of the Prime+Probe attack
// clobber: none
// clang-format off
#define PRIME(BASE, OFFSET, TMP, ACC, COUNTER, REPS) \
    "isb \n dsb SY \n" \
    "mov "COUNTER", "REPS"\n" \
    "1: \n" \
        "mov "OFFSET", 0 \n" \
        "mov "ACC", 0 \n" \
        "2: \n" \
            "isb \n dsb SY \n" \
            PRIME_ONE_SET(BASE, OFFSET, TMP, ACC) \
            "add "OFFSET", "OFFSET", #64 \n" \
            "mov "TMP", #4096 \n" \
            "cmp "OFFSET", "TMP"; \n" \
            "b.lt 2b \n" \
        "sub "COUNTER", "COUNTER", #1 \n" \
        "cmp "COUNTER", xzr \n" \
        "b.ne 1b \n" \
    "isb \n dsb SY \n"
// clang-format on

/// @brief Probe part of the Prime+Probe attack
// clobber: none
#define PROBE() // FIXME: unimplemented

// #define PROBE(BASE, OFFSET, TMP, TMP2, ACC, DEST) asm volatile("" \
//     "eor "DEST", "DEST", "DEST"                           \n" \
//     "eor "OFFSET", "OFFSET", "OFFSET"                     \n" \
//     "_arm64_executor_probe_loop:                          \n" \
//     "  isb; dsb SY                                        \n" \
//     "  eor "TMP", "TMP", "TMP"                            \n" \
//     "  mrs "TMP", pmevcntr0_el0                           \n" \
//     "  mov "ACC", "TMP"                                   \n" \
//                                                             \
//     "  sub "TMP", "BASE", #"xstr(EVICT_REGION_OFFSET)"    \n" \
//     "  add "TMP", "TMP", "OFFSET"                         \n" \
//     "  ldr "TMP2", ["TMP", #0]                            \n" \
//     "  isb; dsb SY                                        \n" \
//     "  ldr "TMP2", ["TMP", #"xstr(L1D_CONFLICT_DISTANCE)"]\n" \
//     "  isb; dsb SY                                        \n" \
//                                                             \
//     "  mrs "TMP", pmevcntr0_el0                           \n" \
//     "  subs "ACC", "TMP", "ACC"                           \n" \
//     "  b.eq _arm64_executor_probe_failed                  \n" \
//     "  _arm64_executor_probe_success:                     \n" \
//     "    mov "DEST", "DEST", lsl #1                       \n" \
//     "    orr "DEST", "DEST", #1                           \n" \
//     "    b _arm64_executor_probe_loop_check               \n" \
//     "  _arm64_executor_probe_failed:                      \n" \
//     "    mov "DEST", "DEST", lsl #1                       \n" \
//     "  _arm64_executor_probe_loop_check:                  \n" \
//     "  add "OFFSET", "OFFSET", #64                        \n" \
//     "  mov "TMP", #"xstr(L1D_CONFLICT_DISTANCE)"          \n" \
//     "  cmp "TMP", "OFFSET"                                \n" \
//     "  b.gt _arm64_executor_probe_loop                    \n" \
// )

// clang-format on

#endif // _ARM64_ASM_SNIPPETS_H_
