/// File: Multiple variants of test case entry and exit points, for x86-64 architecture
///      used exclusively by code_loader.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// -----------------------------------------------------------------------------------------------
// Note on registers.
// Some of the registers are reserved for a specific purpose and should never be overwritten.
// See ./docs/registers.md and registers.h for more information.

#ifndef _ENTRY_EXIT_H_
#define _ENTRY_EXIT_H_

#include "hardware_desc.h"

#include "asm_snippets.h"
#include "registers.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

#define TEMPLATE_START                     0x0fff379000000000
#define TEMPLATE_INSERT_TC                 0x0fff2f9000000000
#define TEMPLATE_DEFAULT_EXCEPTION_LANDING 0x0fff479000000000
#define TEMPLATE_END                       0x0fff279000000000
#define TEMPLATE_MARKER_SIZE               8

// clang-format off
static inline void prologue(void)
{
    // As we don't use a compiler to track clobbering,
    // we have to save the callee-saved regs
    asm_volatile_intel(
        "push rbx\n"
        "push rbp\n"
        "push r10\n"
        "push r11\n"
        "push r12\n"
        "push r13\n"
        "push r14\n"
        "push r15\n"
        "pushfq\n"

        // MEMORY_BASE_REG = main_area of actor 0
        // (passed in rdi, the first argument of measurement_code)
        "mov "MEMORY_BASE_REG", rdi\n"

        // UTIL_BASE_REG = sandbox->util
        "lea "UTIL_BASE_REG", ["MEMORY_BASE_REG" - "xstr(UTIL_REL_TO_MAIN)"]\n"

        // sandbox->util->stored_rsp = rsp
        "mov qword ptr ["UTIL_BASE_REG" + "xstr(STORED_RSP_OFFSET)"], rsp\n"

        // clear the rest of the registers
        "mov rax, 0\n"
        "mov rbx, 0\n"
        "mov rcx, 0\n"
        "mov rdx, 0\n"
        "mov rsi, 0\n"
        "mov rdi, 0\n"
        "mov r8,  0\n"
        "mov r9,  0\n"
        "mov r10, 0\n"
        "mov r11, 0\n"
        "mov r12, 0\n"
        "mov r13, 0\n"

        // initialize special registers
        "mov "HTRACE_REGISTER", 0\n"
        "mov "STATUS_REGISTER", "xstr(STATUS_UNINITIALIZED)"\n"

        "mov rbp, rsp\n"
        "sub rsp, 0x1000\n"

        // start monitoring interrupts
        READ_SMI_START()
    );

}

static inline void epilogue(void)
{
    asm_volatile_intel(
        // rbx <- SMI counter
        READ_SMI_END()

        // rax <- &latest_measurement
        "lea rax, ["UTIL_BASE_REG" + "xstr(MEASUREMENT_OFFSET)"]\n"

        // Store the results
        "mov qword ptr [rax + 0x00], "HTRACE_REGISTER" \n"  // HTrace
        "mov qword ptr [rax + 0x08], r10 \n"                // PFC0
        "mov qword ptr [rax + 0x10], r9 \n"                 // PFC1
        "mov qword ptr [rax + 0x18], r8 \n"                 // PFC2
        "mov qword ptr [rax + 0x20], 0 \n"                  // PFC3 (unused)
        "mov qword ptr [rax + 0x28], 0 \n"                  // PFC4 (unused)
        "mov qword ptr [rax + 0x30], "STATUS_REGISTER" \n"  // Measurement status

        // rsp = sandbox->util->stored_rsp
        "mov rsp, qword ptr ["UTIL_BASE_REG" + "xstr(STORED_RSP_OFFSET)"]\n"

        // restore registers
        "popfq\n"
        "pop r15\n"
        "pop r14\n"
        "pop r13\n"
        "pop r12\n"
        "pop r11\n"
        "pop r10\n"
        "pop rbp\n"
        "pop rbx\n"

        // return 0
        "mov rax, 0\n"
        "ret\n"
        "int3\n" // Silences objtool warnings about no int3 after ret
    );
}

static inline void epilogue_dbg_gpr(void)
{
    asm_volatile_intel(
        // r14 <- &latest_measurement
        // clobber r14; not in use anymore
        "lea r14, ["UTIL_BASE_REG" + "xstr(MEASUREMENT_OFFSET)"]\n"

        // Store the results
        "mov qword ptr [r14 + 0x00], rax\n"
        "mov qword ptr [r14 + 0x08], rbx\n"
        "mov qword ptr [r14 + 0x10], rcx\n"
        "mov qword ptr [r14 + 0x18], rdx\n"
        "mov qword ptr [r14 + 0x20], rsi\n"
        "mov qword ptr [r14 + 0x28], rdi\n"
        "mov qword ptr [r14 + 0x30], "STATUS_REGISTER"\n"

        // rsp = sandbox->util->stored_rsp
        "mov rsp, qword ptr ["UTIL_BASE_REG" + "xstr(STORED_RSP_OFFSET)"]\n"

        // restore registers
        "popfq\n"
        "pop r15\n"
        "pop r14\n"
        "pop r13\n"
        "pop r12\n"
        "pop r11\n"
        "pop r10\n"
        "pop rbp\n"
        "pop rbx\n"

        // return 0
        "mov rax, 0\n"
        "ret\n"
        "int3\n" // Silences objtool warnings about no int3 after ret
    );
}
// clang-format on

static void main_segment_template(void)
{
    asm volatile(".quad " xstr(TEMPLATE_START));
    prologue();

    SET_REGISTER_FROM_INPUT();
    PIPELINE_RESET();

    // test case placeholder
    asm volatile("\nlfence\n");
    asm volatile(".quad " xstr(TEMPLATE_INSERT_TC) "\n");
    asm volatile("\nmfence\n");

    // fault handler
    asm_volatile_intel(""
                       "jmp 1f\n"
                       ".quad " xstr(TEMPLATE_DEFAULT_EXCEPTION_LANDING) "\n"
                                                                         "1:nop; nop; nop\n");

    epilogue();
    asm volatile(".quad " xstr(TEMPLATE_END));
}

static void main_segment_template_dbg_gpr(void)
{
    asm volatile(".quad " xstr(TEMPLATE_START));
    prologue();

    SET_REGISTER_FROM_INPUT();
    PIPELINE_RESET();

    // test case placeholder
    asm volatile("\nlfence\n");
    asm volatile(".quad " xstr(TEMPLATE_INSERT_TC) "\n");
    asm volatile("\nmfence\n");

    asm_volatile_intel(""
                       "jmp 1f\n"
                       ".quad " xstr(TEMPLATE_DEFAULT_EXCEPTION_LANDING) "\n"
                                                                         "1:nop; nop; nop\n");

    epilogue_dbg_gpr();
    asm volatile(".quad " xstr(TEMPLATE_END));
}

#endif // _ENTRY_EXIT_H_
