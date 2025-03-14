/// File: Test case entry and exit points; used by code_loader.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// -----------------------------------------------------------------------------------------------
// Note on registers.
// Some of the registers are reserved for a specific purpose and should never be overwritten.
// See ./docs/registers.md for more information.

#ifndef _ENTRY_EXIT_H_
#define _ENTRY_EXIT_H_

#define TEMPLATE_START                     0x0000111100001111
#define TEMPLATE_INSERT_TC                 0x0000222200002222
#define TEMPLATE_DEFAULT_EXCEPTION_LANDING 0x0000333300003333
#define TEMPLATE_END                       0x0000444400004444
#define TEMPLATE_MARKER_SIZE               8

// clang-format off
static inline void prologue(void)
{
    // As we don't use a compiler to track clobbering,
    // we have to save the callee-saved regs
    asm volatile("" \
        "stp x16, x17, [sp, #-16]!\n"
        "stp x18, x19, [sp, #-16]!\n"
        "stp x20, x21, [sp, #-16]!\n"
        "stp x22, x23, [sp, #-16]!\n"
        "stp x24, x25, [sp, #-16]!\n"
        "stp x26, x27, [sp, #-16]!\n"
        "stp x28, x29, [sp, #-16]!\n"
        "str x30, [sp, #-16]!\n"

        // x30 = main_area of actor 0 (passed in x0, the first argument of measurement_code)
        "mov "MEMORY_BASE_REGISTER", x0\n"

        // x29 = sandbox->util (x30 - UTIL_REL_TO_MAIN)
        "mov "UTIL_BASE_REGISTER", "MEMORY_BASE_REGISTER"\n"
        "mov x0, "xstr(UTIL_REL_TO_MAIN)"\n"
        "sub "UTIL_BASE_REGISTER", "UTIL_BASE_REGISTER", x0\n"

        // sandbox->util->stored_rsp = sp
        "mov x0, sp\n"
        "str x0, ["UTIL_BASE_REGISTER", #"xstr(STORED_RSP_OFFSET)"]\n"

        // clear the rest of the registers
        "mov x0, 0\n"
        "mov x1, 0\n"
        "mov x2, 0\n"
        "mov x3, 0\n"
        "mov x4, 0\n"
        "mov x5, 0\n"
        "mov x6, 0\n"
        "mov x7, 0\n"
        "mov x8, 0\n"
        "mov x9, 0\n"
        "mov x10, 0\n"
        "mov x11, 0\n"
        "mov x12, 0\n"
        "mov x13, 0\n"
        "mov x14, 0\n"
        "mov x15, 0\n"

        // initialize special registers
        "mov "HTRACE_REGISTER", 0\n"
        "mov "STATUS_REGISTER", "xstr(STATUS_UNINITIALIZED)"\n"

        // create space on stack
        // "mov rbp, rsp\n"
        "sub sp, sp, #0x1000\n"

        // start monitoring interrupts
        READ_SMI_START()
    );


}

static inline void epilogue(void)
{
    asm volatile(""
        READ_SMI_END()

        // x0 = &latest_measurement
        "mov x0, "UTIL_BASE_REGISTER"\n"
        "mov x1, #"xstr(MEASUREMENT_OFFSET)"\n"
        "add x0, x0, x1\n"

        // Store the results
        "str "HTRACE_REGISTER", [x0]\n"     // HTrace
        "str "PFC0", [x0, #8]\n"            // PFC0
        "str "PFC1", [x0, #16]\n"           // PFC1
        "str "PFC2", [x0, #24]\n"           // PFC2
        "str xzr, [x0, #32]\n"              // PFC3 (unused)
        "str xzr, [x0, #40]\n"              // PFC4 (unused)
        "str "STATUS_REGISTER", [x0, #48]\n" // Measurement status

        // rsp = sandbox->util->stored_rsp
        "ldr x0, ["UTIL_BASE_REGISTER", #"xstr(STORED_RSP_OFFSET)"]\n"
        "mov sp, x0\n"

        // restore registers
        "ldr x30, [sp], #16\n"
        "ldp x28, x29, [sp], #16\n"
        "ldp x26, x27, [sp], #16\n"
        "ldp x24, x25, [sp], #16\n"
        "ldp x22, x23, [sp], #16\n"
        "ldp x20, x21, [sp], #16\n"
        "ldp x18, x19, [sp], #16\n"
        "ldp x16, x17, [sp], #16\n"

        // return 0
        "mov x0, 0\n"
        "ret\n"
    );
}

static inline void epilogue_dbg_gpr(void)
{
    asm volatile(""
        READ_SMI_END()

        // x7 = &latest_measurement
        "mov x7, "UTIL_BASE_REGISTER"\n"
        "mov x8, #"xstr(MEASUREMENT_OFFSET)"\n"
        "add x7, x7, x8\n"

        // Store the results
        "str x0, [x7]\n"
        "str x1, [x7, #8]\n"
        "str x2, [x7, #16]\n"
        "str x3, [x7, #24]\n"
        "str x4, [x7, #32]\n"
        "str x5, [x7, #40]\n"
        "str "STATUS_REGISTER", [x7, #48]\n"

        // rsp = sandbox->util->stored_rsp
        "ldr x0, ["UTIL_BASE_REGISTER", #"xstr(STORED_RSP_OFFSET)"]\n"
        "mov sp, x0\n"

        // restore registers
        "ldr x30, [sp], #16\n"
        "ldp x28, x29, [sp], #16\n"
        "ldp x26, x27, [sp], #16\n"
        "ldp x24, x25, [sp], #16\n"
        "ldp x22, x23, [sp], #16\n"
        "ldp x20, x21, [sp], #16\n"
        "ldp x18, x19, [sp], #16\n"
        "ldp x16, x17, [sp], #16\n"

        // return 0
        "mov x0, 0\n"
        "ret\n"
    );
}
// clang-format on

static void main_segment_template(void)
{
    asm volatile(".quad " xstr(TEMPLATE_START));
    prologue();

    SET_REGISTER_FROM_INPUT();

    // test case placeholder
    asm volatile("isb\n dsb SY \n");
    asm volatile(".quad " xstr(TEMPLATE_INSERT_TC) "\n");
    asm volatile("isb\n dsb SY \n");

    // fault handler
    asm volatile("b 1f\n"
                 ".quad " xstr(TEMPLATE_DEFAULT_EXCEPTION_LANDING) "\n"
                                                                   "nop\n"
                                                                   "1:nop\n");

    epilogue();
    asm volatile(".quad " xstr(TEMPLATE_END));
}

static void main_segment_template_dbg_gpr(void)
{
    asm volatile(".quad " xstr(TEMPLATE_START));
    prologue();

    SET_REGISTER_FROM_INPUT();

    // test case placeholder
    asm volatile("isb\n dsb SY \n");
    asm volatile(".quad " xstr(TEMPLATE_INSERT_TC) "\n");
    asm volatile("isb\n dsb SY \n");

    asm volatile("b 1f\n"
                 ".quad " xstr(TEMPLATE_DEFAULT_EXCEPTION_LANDING) "\n"
                                                                   "nop\n"
                                                                   "1:nop\n");

    epilogue_dbg_gpr();
    asm volatile(".quad " xstr(TEMPLATE_END));
}

#endif // _ENTRY_EXIT_H_
