/// File: Test case entry point in the DynamoRIO backend adapter.
///       Responsible for preserving and initializing the registers before calling the test case.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdio.h>

#include "sandbox.h"

#define xstr(s) _str(s)
#define _str(s) str(s)
#define str(s)  #s

void __attribute__((noinline)) test_case_entry(sandbox_t *sandbox)
{
    // clang-format off
    asm volatile(
        ".intel_syntax noprefix\n"
        "pushfq\n"

        "mov r14, %[sandbox]\n"
        "mov r15, %[tc]\n"

        // Initialize FLAGS
        "mov rax, qword ptr [r14 + "xstr(REG_INIT_OFFSET + EFLAGS_INIT_ID * GPR_SIZE)"]\n"
        "push rax\n"
        "popfq\n"

        // Stack pointer
        // "push rsp\n"
        // "mov rax, qword ptr [r14 + "xstr(REG_INIT_OFFSET + RSP_INIT_ID * GPR_SIZE)"]\n"
        // "mov rsp, rax\n"

        // Initialize registers
        "mov rax, qword ptr [r14 + "xstr(REG_INIT_OFFSET + 0x00)"]\n"
        "mov rbx, qword ptr [r14 + "xstr(REG_INIT_OFFSET + 0x08)"]\n"
        "mov rcx, qword ptr [r14 + "xstr(REG_INIT_OFFSET + 0x10)"]\n"
        "mov rdx, qword ptr [r14 + "xstr(REG_INIT_OFFSET + 0x18)"]\n"
        "mov rsi, qword ptr [r14 + "xstr(REG_INIT_OFFSET + 0x20)"]\n"
        "mov rdi, qword ptr [r14 + "xstr(REG_INIT_OFFSET + 0x28)"]\n"

        // Initialize MMX registers
        "movq mm0, qword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x00)"]\n"
        "movq mm1, qword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x08)"]\n"
        "movq mm2, qword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x10)"]\n"
        "movq mm3, qword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x18)"]\n"
        "movq mm4, qword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x20)"]\n"
        "movq mm5, qword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x28)"]\n"
        "movq mm6, qword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x30)"]\n"
        "movq mm7, qword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x38)"]\n"

        // Initialize YMM registers (overlap with MMX init values is intentional)
        "vmovdqa ymm0, ymmword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x00)"]\n"
        "vmovdqa ymm1, ymmword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x20)"]\n"
        "vmovdqa ymm2, ymmword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x40)"]\n"
        "vmovdqa ymm3, ymmword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x60)"]\n"
        "vmovdqa ymm4, ymmword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0x80)"]\n"
        "vmovdqa ymm5, ymmword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0xa0)"]\n"
        "vmovdqa ymm6, ymmword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0xc0)"]\n"
        "vmovdqa ymm7, ymmword ptr [r14 + "xstr(SIMD_INIT_OFFSET + 0xe0)"]\n"

        "callq r15\n"

        // "pop rsp\n"
        "popfq\n"

        ".att_syntax\n"
        :
        : [sandbox] "r"(&sandbox->data->main_area[0]), [tc] "r"(&sandbox->code->code[0])
        : "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r14", "r15");
    // clang-format on
}

