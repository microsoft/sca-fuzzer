/// File: Fault handling and vector table management on ARM64 (i.e., aarch64)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/interrupt.h>

#include "code_loader.h"
#include "main.h"
#include "measurement.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "fault_handler.h"

typedef uint32_t opcode_t; // opcodes in ARM64 are 32-bit

typedef struct {
    opcode_t code[32];
} __attribute__((packed)) vector_table_entry_t;

typedef struct {
    vector_table_entry_t vector_table[16];
} __attribute__((packed)) vector_table_t;

extern vector_table_t outer_vector_table;
extern vector_table_t inner_vector_table;

uint32_t handled_faults = 0;  // global
char *fault_handler = NULL;   // global
uint64_t is_nested_fault = 0; // shared with exception.S

vector_table_t *orig_vector_table_ptr = NULL;

// =================================================================================================
// Vector table management
// =================================================================================================
static inline vector_table_t *vbar_el1_read(void)
{
    vector_table_t *vbar_el1 = NULL;
    asm volatile("mrs %0, vbar_el1" : "=r"(vbar_el1));
    return vbar_el1;
}

static inline void vbar_el1_write(vector_table_t *vbar_el1)
{
    asm volatile("msr vbar_el1, %0" ::"r"(vbar_el1));
}

void set_outer_fault_handlers(void)
{
    // Save the original vector table
    orig_vector_table_ptr = vbar_el1_read();

    // Set VBAR to point to our custom vector table
    vbar_el1_write(&outer_vector_table);
}

void unset_outer_fault_handlers(void)
{
    // Restore the original vector table
    vbar_el1_write(orig_vector_table_ptr);
}

void set_inner_fault_handlers(void)
{
    is_nested_fault = 0;
    vbar_el1_write(&inner_vector_table);
}

void unset_inner_fault_handlers(void) { vbar_el1_write(&outer_vector_table); }

// =================================================================================================
int init_fault_handler(void)
{
    handled_faults = HANDLED_FAULTS_DEFAULT;
    fault_handler = NULL;
    return 0;
}

void free_fault_handler(void) {}
