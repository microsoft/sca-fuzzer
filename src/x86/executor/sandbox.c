/// File:
///  - Parsing inputs and test cases
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "sandbox.h"
#include "shortcuts.h"

sandbox_t *sandbox = NULL; // global
void *stack_base = NULL;   // global
static void *_sandbox_unaligned = NULL;

void write_sandbox(uint64_t *current_input)
{
    // Initialize the rest of the memory
    // - sandbox: main and faulty regions
    uint64_t *main_page_values = &current_input[0];
    uint64_t *main_base = (uint64_t *)&sandbox->main_area[0];
    for (int j = 0; j < MAIN_AREA_SIZE / 8; j += 1) {
        ((uint64_t *)main_base)[j] = main_page_values[j];
    }

    uint64_t *faulty_page_values = &current_input[MAIN_AREA_SIZE / 8];
    uint64_t *faulty_base = (uint64_t *)&sandbox->faulty_area[0];
    for (int j = 0; j < FAULTY_AREA_SIZE / 8; j += 1) {
        ((uint64_t *)faulty_base)[j] = faulty_page_values[j];
    }

    // Initial register values (the registers will be set to these values in template.c)
    uint64_t *register_values = &current_input[(MAIN_AREA_SIZE + FAULTY_AREA_SIZE) / 8];
    uint64_t *register_initialization_base = (uint64_t *)&sandbox->overflow_pad[0];

    // - RAX ... RDI
    for (int j = 0; j < 6; j += 1) {
        ((uint64_t *)register_initialization_base)[j] = register_values[j];
    }

    // - flags
    uint64_t masked_flags = (register_values[6] & 2263) | 2;
    ((uint64_t *)register_initialization_base)[6] = masked_flags;

    // - RSP and RBP
    ((uint64_t *)register_initialization_base)[7] = (uint64_t)stack_base;

    // - XMM0 ... XMM15
    asm volatile(""
                 "movdqa 0x00(%0), %%xmm0\n"
                 "movdqa 0x10(%0), %%xmm1\n"
                 "movdqa 0x20(%0), %%xmm2\n"
                 "movdqa 0x30(%0), %%xmm3\n"
                 "movdqa 0x40(%0), %%xmm4\n"
                 "movdqa 0x50(%0), %%xmm5\n"
                 "movdqa 0x60(%0), %%xmm6\n"
                 "movdqa 0x70(%0), %%xmm7\n"
                 "movdqa 0x80(%0), %%xmm8\n"
                 "movdqa 0x90(%0), %%xmm9\n"
                 "movdqa 0xa0(%0), %%xmm10\n"
                 "movdqa 0xb0(%0), %%xmm11\n"
                 "movdqa 0xc0(%0), %%xmm12\n"
                 "movdqa 0xd0(%0), %%xmm13\n"
                 "movdqa 0xe0(%0), %%xmm14\n"
                 "movdqa 0xf0(%0), %%xmm15\n" ::"r"(&register_values[8])
                 : "xmm0");
}

// =================================================================================================
// Allocation and Initialization
// =================================================================================================
int alloc_and_map_sandboxes()
{
    // Under construction
    return 0;
}

/// Constructor
///
int init_sandbox(void)
{
    // allocate working memory
    _sandbox_unaligned = CHECKED_VMALLOC(sizeof(sandbox_t) + 0x1000);

    // align sandbox to 2 pages (vmalloc guarantees 1 page alignment)
    if ((unsigned long)_sandbox_unaligned % 0x2000 == 0)
        sandbox = (sandbox_t *)_sandbox_unaligned;
    else
        sandbox = (sandbox_t *)((unsigned long)_sandbox_unaligned + 0x1000);

    // make sure the fields of the sandbox are aligned as we expect
    ASSERT(&sandbox->main_area[0] - &sandbox->underflow_pad[0] == UNDERFLOW_PAD_OFFSET,
           "init_sandbox");
    ASSERT(&sandbox->faulty_area[0] - &sandbox->main_area[0] == FAULTY_AREA_OFFSET, "init_sandbox");
    ASSERT(&sandbox->overflow_pad[0] - &sandbox->main_area[0] == REG_INIT_OFFSET, "init_sandbox");
    ASSERT(&sandbox->l1d_priming_area[0] - &sandbox->main_area[0] == L1D_PRIMING_OFFSET,
           "init_sandbox");
    ASSERT(&sandbox->macro_stack[64] - &sandbox->main_area[0] == MACRO_STACK_TOP_OFFSET,
           "init_sandbox");
    ASSERT(((char *)&sandbox->stored_rsp - &sandbox->main_area[0]) == RSP_OFFSET, "init_sandbox");
    ASSERT(((char *)&sandbox->latest_measurement - &sandbox->main_area[0]) == MEASUREMENT_OFFSET,
           "init_sandbox");

    // stack pointer for test cases
    stack_base = &(sandbox->main_area[MAIN_AREA_SIZE - 8]);

    // zero-initialize the sandbox
    memset(sandbox, 0, sizeof(sandbox_t));

    return 0;
}

/// Destructor
///
void free_sandbox(void) { SAFE_VFREE(_sandbox_unaligned); }
