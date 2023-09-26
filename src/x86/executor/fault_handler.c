/// File:
///  - Fault handling
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang-format off
#include <linux/interrupt.h>
// clang-format on

#include "fault_handler.h"
#include "loader.h"
#include "sandbox.h"
#include "shortcuts.h"
#include "test_case.h"

uint32_t handled_faults = 0; // global
char *fault_handler = NULL;  // global
gate_desc *curr_idt_table;   // global

static char *_default_fault_handler = NULL;
static gate_desc *orig_idt_table;
static struct desc_ptr idtr;

// =================================================================================================
// IDT management
// =================================================================================================
static void inline local_store_idt(void *dtr)
{
    asm volatile("sidt %0" : "=m"(*((struct desc_ptr *)dtr)));
}

static void inline local_load_idt(void *dtr)
{
    asm volatile("lidt %0" ::"m"(*((struct desc_ptr *)dtr)));
}

static void idt_setup_from_table(gate_desc *idt, const struct idt_data *t, int size)
{
    gate_desc desc;

    for (; size > 0; t++, size--) {
        unsigned long addr = (unsigned long)t->addr;

        desc.offset_low = (u16)addr;
        desc.segment = (u16)t->segment;
        desc.bits = t->bits;
        desc.offset_middle = (u16)(addr >> 16);
#ifdef CONFIG_X86_64
        desc.offset_high = (u32)(addr >> 32);
        desc.reserved = 0;
#endif

        write_idt_entry(idt, t->vector, &desc);
    }
}

static void set_intr_gate(unsigned int n, const void *addr)
{
    struct idt_data data;

    memset(&data, 0, sizeof(data));
    data.vector = n;
    data.addr = addr;
    data.segment = __KERNEL_CS;
    data.bits.type = GATE_INTERRUPT;
    data.bits.p = 1;

    idt_setup_from_table(curr_idt_table, &data, 1);
}

static void enable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    asm volatile("mov %0,%%cr0" ::"r"(cr0) : "memory");
}

static void disable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    asm volatile("mov %0,%%cr0" ::"r"(cr0) : "memory");
}

static void idt_copy(void)
{
    for (int entry = 0; entry < 256; entry++) {
        const gate_desc *gate = &orig_idt_table[entry];
        memcpy(&curr_idt_table[entry], gate, sizeof(*gate));
    }
}

void idt_store(void)
{
    // save the current state of IDT
    local_store_idt(&idtr);
    orig_idt_table = (gate_desc *)idtr.address;
    idt_copy();
}

void idt_restore(void)
{
    idtr.address = (unsigned long)orig_idt_table;
    local_load_idt(&idtr);
}

void idt_set_custom_handlers(void)
{
    disable_write_protection();
    uint8_t idx = 0;
    for (idx = 0; idx < 32; idx++) {
        if (BIT_CHECK(handled_faults, idx)) {
            set_intr_gate(idx, (void *)fault_handler);
        } else {
            set_intr_gate(idx, (void *)_default_fault_handler);
        }
    }
    enable_write_protection();
    idtr.address = (unsigned long)curr_idt_table;
    local_load_idt(&idtr);
}

// =================================================================================================
// Handlers
// =================================================================================================

__attribute__((unused)) void default_handler_wrapper(void)
{
    // clang-format off
    asm_volatile_intel(
        ".global default_handler\n"
        "default_handler:\n"

        // rax <- &latest_measurement
        "lea rax, [r14 + "xstr(MEASUREMENT_OFFSET)"]\n"

        // set the trace to 0xFFFF to indicate an unhandled fault
        "mov qword ptr [rax], 0xFFFF \n"

        // set PFC[0] to the error code
        "pop rbx \n"
        "mov qword ptr [rax + 8], rbx \n"

        // set PFC[1] to the faulting address
        "pop rcx \n"
        "mov qword ptr [rax + 16], rcx \n"

        // rsp <- stored_rsp
        "mov rsp, qword ptr [r14 + "xstr(RSP_OFFSET)"]\n"

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
    );
    // clang-format on

    // since most faults happen within the measurement_code, we additionally store
    // a normalized value of the faulting address
    sandbox->latest_measurement.pfc[2] =
        sandbox->latest_measurement.pfc[1] - (uint64_t)loaded_main_section;

    // TODO: make run_experiment exit with an error code upon a n unhandled fault

    PRINT_ERRS("default_handler_wrapper", "Test case triggered an unhandled fault\n");

    asm_volatile_intel("ret\n");
}

// =================================================================================================
// Allocation and Initialization
// =================================================================================================

/// Constructor
///
int init_fault_handler(void)
{
    handled_faults = HANDLED_FAULTS_DEFAULT;
    _default_fault_handler = (char *)default_handler;
    fault_handler = _default_fault_handler;

    return 0;
}

/// Destructor for the measurement module
///
void free_fault_handler(void) {}
