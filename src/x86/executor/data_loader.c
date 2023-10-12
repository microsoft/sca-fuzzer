/// File:
///  - Parsing inputs and test cases
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "actor_manager.h"
#include "input_parser.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

/// @brief This function serves a dual purpose:
/// - it initializes the data area of the sandbox with the values from the current input
/// - it (indirectly) sets the microarchitectural state of some of the memory buffers (e.g., the
///   store buffer) to a the state that depends on the current input; hence, we reduce the
///   non-determinism of the measurements
/// @param input_id
/// @return
int load_sandbox_data(int input_id)
{
    // NOTE: this function intentionally does not use memset (with a few exceptions), because
    // we found that direct initialization is more effective at priming the uarch state

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_data_t *dest = &sandbox->data[actor_id];
        input_fragment_t *source = get_input_fragment_unsafe(input_id, actor_id);

        // Zero-initialize the areas surrounding the sandbox
        if (!quick_and_dirty_mode) {
            memset(&dest->underflow_pad[0], 0, UNDERFLOW_PAD_SIZE * sizeof(char));
            for (int j = 0; j < OVERFLOW_PAD_SIZE / 8; j += 1) {
                // ((uint64_t *) sandbox->underflow_pad)[j] = 0;
                ((uint64_t *)dest->overflow_pad)[j] = 0;
            }
        }

        // Initialize the main and faulty areas of the sandbox data
        uint64_t *main_src = (uint64_t *)source->main_area;
        uint64_t *main_dest = (uint64_t *)dest->main_area;
        for (int j = 0; j < MAIN_AREA_SIZE / 8; j += 1) {
            main_dest[j] = main_src[j];
        }

        uint64_t *faulty_src = (uint64_t *)source->faulty_area;
        uint64_t *faulty_dest = (uint64_t *)dest->faulty_area;
        for (int j = 0; j < FAULTY_AREA_SIZE / 8; j += 1) {
            faulty_dest[j] = faulty_src[j];
        }

        // Initial register values
        // (the registers will be set to these values in code_loader template)
        uint64_t *reg_src = (uint64_t *)source->reg_init_region;
        uint64_t *reg_dest = (uint64_t *)dest->reg_init_area;
        for (int j = 0; j < REG_INIT_AREA_SIZE / 8; j += 1) {
            reg_dest[j] = reg_src[j];
        }

        // - Ensure that the flags are valid
        reg_dest[6] = (reg_src[6] & 2263) | 2;

        // - RSP and RBP are do not take a value from the input,
        //   and are rather set to the stack base

        // stack pointer for actor 0
        reg_dest[7] = (uint64_t)sandbox->data[0].main_area + LOCAL_RSP_OFFSET;
    }

    // - Initialize SIMD registers
    // Note: GPRs will be initialized directly by the test case template; see code_loader.c
    uint64_t *simd_src = (uint64_t *)&get_input_fragment_unsafe(input_id, 0)->reg_init_region[64];
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
                 "movdqa 0xf0(%0), %%xmm15\n" ::"r"(&simd_src[0]));

    return 0;
}

// =================================================================================================
int init_data_loader(void) { return 0; }

void free_data_loader(void) {}
