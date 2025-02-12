/// File: Allocation and management of the sandbox memory for test cases
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "rcbf.h"
#include "rdbf.h"
#include "sandbox.h"

static sandbox_t *sandbox;
static const int nop_opcode = 0x90;
static const int ret_opcode = 0xc3;

/// @brief Load a test case code into the sandbox
/// @param rcbf_data Parsed RCBF data
/// @return 0 on success, -1 on failure
int load_code_in_sandbox(rcbf_t *rcbf_data)
{
    for (uint64_t section_id = 0; section_id < rcbf_data->header.n_actors; section_id++) {
        code_section_t *code_section = &sandbox->code[section_id];

        // Copy the code into the sandbox
        int code_size = (int)rcbf_data->section_metadata[section_id].size;
        memcpy(code_section->code, rcbf_data->sections[section_id].code, code_size);

        // Insert a RETQ instruction at the end of the main area of the first section
        if (section_id == 0) {
            code_section->code[code_size] = ret_opcode;
            code_size++;
        }

        // Initialize the remaining space with NOPs
        int uninitialized_size = MAX_EXPANDED_SECTION_SIZE - code_size;
        memset(code_section->code + code_size, nop_opcode, uninitialized_size);
        memset(code_section->unused, nop_opcode, MACRO_AREA_SIZE);
    }

    return 0;
}

/// @brief Load a test case data into the sandbox
/// @param rdbf_data Parsed RDBF data
/// @param input_id Index of the input to load from the RDBF data
/// @return 0 on success, -1 on failure
int load_data_in_sandbox(rdbf_t *input_sequence, int input_id)
{
    rdbf_data_section_t *data = &input_sequence->data[input_id];
    for (uint64_t section_id = 0; section_id < input_sequence->header.n_actors; section_id++) {
        data_section_t *data_section = &sandbox->data[section_id];

        // Zero out underflow and overflow pads
        memset(data_section->macro_stack, 0, MACRO_STACK_SIZE);
        memset(data_section->underflow_pad, 0, UNDERFLOW_PAD_SIZE);
        memset(data_section->overflow_pad, 0, OVERFLOW_PAD_SIZE);

        // Copy the data into the sandbox
        memcpy(data_section->main_area, data[section_id].main_area, MAIN_AREA_SIZE);
        memcpy(data_section->faulty_area, data[section_id].faulty_area, FAULTY_AREA_SIZE);
        memcpy(data_section->reg_init_area, data[section_id].reg_init_region, REG_INIT_AREA_SIZE);

        // Fixup the EFLAGS init value to ensure we don't set invalid flags
        uint64_t eflags_value = ((uint64_t *)data_section->reg_init_area)[EFLAGS_INIT_ID];
        eflags_value = (eflags_value & 2263) | 2;
        ((uint64_t *)data_section->reg_init_area)[EFLAGS_INIT_ID] = eflags_value;
    }

    return 0;
}

/// @brief Accessor for the sandbox
/// @return Pointer to the sandbox
sandbox_t *get_sandbox() { return sandbox; }

// =================================================================================================
// Constructor and destructor
// =================================================================================================
/// @brief Allocate memory for the sandbox
/// @param n_actors Number of actors in the test case
/// @return -1 on failure, 0 on success
int allocate_sandbox(uint64_t n_actors)
{
    sandbox = (sandbox_t *)malloc(sizeof(sandbox_t));
    if (sandbox == NULL) {
        return -1;
    }

    // Allocate memory for the data and code sections, with page alignment
    sandbox->data = (data_section_t *)aligned_alloc(PAGE_SIZE, n_actors * sizeof(data_section_t));
    if (sandbox->data == NULL) {
        free(sandbox);
        return -1;
    }

    sandbox->code = (code_section_t *)aligned_alloc(PAGE_SIZE, n_actors * sizeof(code_section_t));
    if (sandbox->code == NULL) {
        free(sandbox->data);
        free(sandbox);
        return -1;
    }
    mprotect(sandbox->code, n_actors * sizeof(code_section_t), PROT_READ | PROT_WRITE | PROT_EXEC);

    return 0;
}

/// @brief Free the memory allocated for the sandbox
void free_sandbox()
{
    free(sandbox->data);
    free(sandbox->code);
    free(sandbox);
}
