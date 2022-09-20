/// File: Measurement templates for various threat models
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// -----------------------------------------------------------------------------------------------
// Note on registers.
// Some of the registers are reserved for a specific purpose and should never be overwritten.
// These include:
//   * X15 - hardware trace
//   * X20 - performance counter 1
//   * X21 - performance counter 2
//   * X22 - performance counter 3

#include "main.h"
#include <linux/string.h>

#define TEMPLATE_ENTER 0x00001111
#define TEMPLATE_INSERT_TC 0x00002222
#define TEMPLATE_RETURN 0x00003333

#define xstr(s) _str(s)
#define _str(s) str(s)
#define str(s) #s

int load_template(size_t tc_size)
{
    unsigned template_pos = 0;
    unsigned code_pos = 0;

    // skip until the beginning of the template
    for (;; template_pos++)
    {
        if (template_pos >= MAX_MEASUREMENT_CODE_SIZE)
            return -1;

        if (*(uint32_t *)&measurement_template[template_pos] == TEMPLATE_ENTER)
        {
            template_pos += 4;
            break;
        }
    }

    // copy the first part of the template
    for (;; template_pos++, code_pos++)
    {
        if (template_pos >= MAX_MEASUREMENT_CODE_SIZE)
            return -1;

        if (*(uint32_t *)&measurement_template[template_pos] == TEMPLATE_INSERT_TC)
        {
            template_pos += 4;
            break;
        }

        measurement_code[code_pos] = measurement_template[template_pos];
    }

    // copy the test case into the template
    memcpy(&measurement_code[code_pos], test_case, tc_size);
    code_pos += tc_size;

    // write the rest of the template
    for (;; template_pos++, code_pos++)
    {
        if (template_pos >= MAX_MEASUREMENT_CODE_SIZE)
            return -2;

        if (*(uint32_t *)&measurement_template[template_pos] == TEMPLATE_INSERT_TC)
            return -3;

        if (*(uint32_t *)&measurement_template[template_pos] == TEMPLATE_RETURN)
            break;

        measurement_code[code_pos] = measurement_template[template_pos];
    }

    // RET
    measurement_code[code_pos + 0] = '\xc0';
    measurement_code[code_pos + 1] = '\x03';
    measurement_code[code_pos + 2] = '\x5f';
    measurement_code[code_pos + 3] = '\xd6';
    return code_pos + 4;
}

// =================================================================================================
// Template building blocks
// =================================================================================================
// clang-format off
inline void prologue(void)
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

        // x30 <- input base address (stored in x0, the first argument of measurement_code)
        "mov x30, x0\n"

        // stored_rsp <- sp
        // "str sp, [x30, #"xstr(RSP_OFFSET)"]\n"
        "mov x0, sp\n"
        "str x0, [x30, #"xstr(RSP_OFFSET)"]\n"
    );
}

inline void epilogue(void) {
    asm volatile(""
        // store the hardware trace (x15) and pfc readings (x20)
        "mov x16, #"xstr(MEASUREMENT_OFFSET)"\n"
        "add x16, x16, x30\n"
        "stp x15, x20, [x16]\n"
        "str x21, [x16, #16]\n"

        // rsp <- stored_rsp
        "ldr x0, [x30, #"xstr(RSP_OFFSET)"]\n"
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
    );
}

#define SET_REGISTER_FROM_INPUT() asm volatile("" \
    "add sp, x30, #"xstr(REG_INIT_OFFSET)"\n" \
    "ldp x0, x1, [sp], #16\n" \
    "ldp x2, x3, [sp], #16\n" \
    "ldp x4, x5, [sp], #16\n" \
    "ldp x6, x7, [sp], #16\n" \
    "msr nzcv, x6\n" \
    "mov sp, x7\n");


// clobber: -
// dest: x20
#define READ_PFC_START() asm volatile("" \
    "mov x20, #0 \n" \
    "mov x21, #0 \n" \
    "isb; dsb SY \n" \
    "mrs x20, pmevcntr1_el0 \n" \
    "mrs x21, pmevcntr2_el0 \n");

// clobber: x1
// dest: x20
#define READ_PFC_END() asm volatile("" \
    "isb; dsb SY \n" \
    "mrs x1, pmevcntr1_el0 \n" \
    "sub x20, x1, x20 \n" \
    "mrs x1, pmevcntr2_el0 \n" \
    "sub x21, x1, x21 \n");

// =================================================================================================
// L1D Prime+Probe
// =================================================================================================
#if L1D_ASSOCIATIVITY == 2

// clobber:
#define PRIME(BASE, OFFSET, TMP, ACC, COUNTER, REPS) asm volatile("" \
    "isb; dsb SY                                        \n" \
    "mov "COUNTER", "REPS"                              \n" \
    "_arm64_executor_prime_outer:                       \n" \
    "mov "OFFSET", 0                                    \n" \
                                                            \
    "_arm64_executor_prime_inner:                       \n" \
    "sub "TMP", "BASE", #"xstr(EVICT_REGION_OFFSET)"    \n" \
    "isb; dsb SY                                        \n" \
    "add "TMP", "TMP", "OFFSET"                         \n" \
    "ldr "ACC", ["TMP", #0]                             \n" \
    "isb; dsb SY                                        \n" \
    "ldr "ACC", ["TMP", #"xstr(L1D_CONFLICT_DISTANCE)"] \n" \
    "isb; dsb SY                                        \n" \
    "add "OFFSET", "OFFSET", #64                        \n" \
                                                            \
    "mov "ACC", #"xstr(L1D_CONFLICT_DISTANCE)"          \n" \
    "cmp "ACC", "OFFSET"                                \n" \
    "b.gt _arm64_executor_prime_inner                   \n" \
                                                            \
    "sub "COUNTER", "COUNTER", #1                       \n" \
    "cmp "COUNTER", xzr                                 \n" \
    "b.ne _arm64_executor_prime_outer                   \n" \
                                                            \
    "isb; dsb SY                                        \n" \
)

#define PROBE(BASE, OFFSET, TMP, TMP2, ACC, DEST) asm volatile("" \
    "eor "DEST", "DEST", "DEST"                           \n" \
    "eor "OFFSET", "OFFSET", "OFFSET"                     \n" \
    "_arm64_executor_probe_loop:                          \n" \
    "  isb; dsb SY                                        \n" \
    "  eor "TMP", "TMP", "TMP"                            \n" \
    "  mrs "TMP", pmevcntr0_el0                           \n" \
    "  mov "ACC", "TMP"                                   \n" \
                                                            \
    "  sub "TMP", "BASE", #"xstr(EVICT_REGION_OFFSET)"    \n" \
    "  add "TMP", "TMP", "OFFSET"                         \n" \
    "  ldr "TMP2", ["TMP", #0]                            \n" \
    "  isb; dsb SY                                        \n" \
    "  ldr "TMP2", ["TMP", #"xstr(L1D_CONFLICT_DISTANCE)"]\n" \
    "  isb; dsb SY                                        \n" \
                                                            \
    "  mrs "TMP", pmevcntr0_el0                           \n" \
    "  subs "ACC", "TMP", "ACC"                           \n" \
    "  b.eq _arm64_executor_probe_failed                  \n" \
    "  _arm64_executor_probe_success:                     \n" \
    "    mov "DEST", "DEST", lsl #1                       \n" \
    "    orr "DEST", "DEST", #1                           \n" \
    "    b _arm64_executor_probe_loop_check               \n" \
    "  _arm64_executor_probe_failed:                      \n" \
    "    mov "DEST", "DEST", lsl #1                       \n" \
    "  _arm64_executor_probe_loop_check:                  \n" \
    "  add "OFFSET", "OFFSET", #64                        \n" \
    "  mov "TMP", #"xstr(L1D_CONFLICT_DISTANCE)"          \n" \
    "  cmp "TMP", "OFFSET"                                \n" \
    "  b.gt _arm64_executor_probe_loop                    \n" \
)
#endif

void template_l1d_prime_probe(void) {
    asm volatile(".long "xstr(TEMPLATE_ENTER));

    // ensure that we don't crash because of BTI
    asm volatile("bti c");

    prologue();

    PRIME("x30", "x1", "x2", "x3", "x4", "32");

    // Initialize registers
    SET_REGISTER_FROM_INPUT();

    // Execute the test case
    asm("\nisb; dsb SY\n"
        ".long "xstr(TEMPLATE_INSERT_TC)" \n"
        "isb; dsb SY\n");

    // Probe and store the resulting eviction bitmap map into x15
    PROBE("x30", "x0", "x1", "x2", "x3", "x15");

    epilogue();
    asm volatile(".long "xstr(TEMPLATE_RETURN));
}

// =================================================================================================
// Flush+Reload
// =================================================================================================
#define FLUSH(BASE, OFFSET, TMP) asm volatile("" \
    "isb; dsb SY                                        \n" \
    "mov "OFFSET", #0                                   \n" \
    "_arm64_executor_flush_loop:                        \n" \
                                                            \
    "add "TMP", "BASE", "OFFSET"                        \n" \
    "isb; dsb SY                                        \n" \
    "dc ivac, "TMP"                                     \n" \
    "isb; dsb SY                                        \n" \
    "add "OFFSET", "OFFSET", #64                        \n" \
                                                            \
    "mov "TMP", #8192                                   \n" \
    "cmp "TMP", "OFFSET"                                \n" \
    "b.gt _arm64_executor_flush_loop                    \n" \
                                                            \
    "isb; dsb SY                                        \n" \
)

#define RELOAD(BASE, OFFSET, TMP, TMP2, ACC, DEST) asm volatile("" \
    "mov "OFFSET", #0                                   \n" \
    "mov "TMP", #0                                      \n" \
    "mov "TMP2", #0                                     \n" \
    "mov "ACC", #0                                      \n" \
    "mov "DEST", #0                                     \n" \
    "_arm64_executor_reload_loop:                       \n" \
    "  isb; dsb SY                                      \n" \
    "  mov "TMP", #0                                    \n" \
    "  mrs "TMP", pmevcntr0_el0                         \n" \
    "  mov "ACC", "TMP"                                 \n" \
    "  isb; dsb SY                                      \n" \
                                                            \
    "  add "TMP", "BASE", "OFFSET"                      \n" \
    "  ldr "TMP2", ["TMP", #0]                          \n" \
    "  isb; dsb SY                                      \n" \
                                                            \
    "  mrs "TMP", pmevcntr0_el0                         \n" \
    "  subs "ACC", "TMP", "ACC"                         \n" \
    "  b.ne _arm64_executor_reload_failed               \n" \
    "  _arm64_executor_reload_success:                  \n" \
    "    mov "DEST", "DEST", lsl #1                     \n" \
    "    orr "DEST", "DEST", #1                         \n" \
    "    b _arm64_executor_reload_loop_check            \n" \
    "  _arm64_executor_reload_failed:                   \n" \
    "    mov "DEST", "DEST", lsl #1                     \n" \
    "  _arm64_executor_reload_loop_check:               \n" \
    "  add "OFFSET", "OFFSET", #64                      \n" \
    "  mov "TMP", #"xstr(MAIN_REGION_SIZE)"             \n" \
    "  cmp "TMP", "OFFSET"                              \n" \
    "b.gt _arm64_executor_reload_loop                   \n" \
)


void template_l1d_flush_reload(void) {
    asm volatile(".long "xstr(TEMPLATE_ENTER));

    // ensure that we don't crash because of BTI
    asm volatile("bti c");

    prologue();

    FLUSH("x30", "x16", "x17");

    // Initialize registers
    SET_REGISTER_FROM_INPUT();

    READ_PFC_START();

    // Execute the test case
    asm("\nisb; dsb SY\n"
        ".long "xstr(TEMPLATE_INSERT_TC)" \n"
        "isb; dsb SY\n");

    READ_PFC_END();

    // Probe and store the resulting eviction bitmap map into x15
    RELOAD("x30", "x16", "x17", "x18", "x19", "x15");

    epilogue();
    asm volatile(".long "xstr(TEMPLATE_RETURN));
}
