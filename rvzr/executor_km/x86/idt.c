/// File:
///  - Fault handling and IDT management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/interrupt.h>

#include "code_loader.h"
#include "hardware_desc.h"
#include "main.h"
#include "measurement.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "fault_handler.h"

uint32_t handled_faults = 0;          // global
char *fault_handler = NULL;           // global
struct desc_ptr test_case_idtr = {0}; // global

static gate_desc *bubble_idt = NULL;
static gate_desc *test_case_idt = NULL;

static struct desc_ptr orig_idtr = {0};
static struct desc_ptr bubble_idtr = {0};

// Declarations from fault_handlers.S
void test_case_handler(void);
void bubble_handler(void);
void nmi_handler(void);
extern uint64_t is_nested_fault;

#define BIT_CHECK(a, b) (!!((a) & (1ULL << (b))))

// =================================================================================================
// Handler declarations and lists
// =================================================================================================
// The 256 entry stubs for each handler are generated in fault_handlers.S using assembly macros.
// Here we only declare them and create arrays of pointers for IDT initialization.

#define MULTI_ENTRY_HANDLER_DECLARATIONS_ID(name, id) void name##_##id(void);
#define MULTI_ENTRY_HANDLER_DECLARATIONS(name)                                                     \
    CALL_256_TIMES(MULTI_ENTRY_HANDLER_DECLARATIONS_ID, name)

#define MULTI_ENTRY_HANDLER_LIST_ID(name, id) name##_##id,
#define MULTI_ENTRY_HANDLER_LIST(name)        CALL_256_TIMES(MULTI_ENTRY_HANDLER_LIST_ID, name)

MULTI_ENTRY_HANDLER_DECLARATIONS(test_case_handler);
static void *test_case_handlers[] = {
    MULTI_ENTRY_HANDLER_LIST(test_case_handler) NULL,
};

MULTI_ENTRY_HANDLER_DECLARATIONS(bubble_handler);
static void *bubble_handlers[] = {
    MULTI_ENTRY_HANDLER_LIST(bubble_handler) NULL,
};

// =================================================================================================
// IDT management
// =================================================================================================
inline static void native_sidt(void *dtr)
{
    asm volatile("sidt %0\n mfence\n" : "=m"(*((struct desc_ptr *)dtr)));
}

inline static void native_lidt(void *dtr)
{
    asm volatile("lidt %0\n mfence\n" ::"m"(*((struct desc_ptr *)dtr)));
}

static void set_intr_gate_default(gate_desc *idt, int interrupt_id, void *handler)
{
    gate_desc desc = {
        .offset_low = (u16)(unsigned long)handler,
        .segment = __KERNEL_CS,
        .bits = (struct idt_bits){.ist = 0, .zero = 0, .type = GATE_INTERRUPT, .dpl = 0, .p = 1},
        .offset_middle = (u16)((unsigned long)handler >> 16),
        .offset_high = (u32)((unsigned long)handler >> 32),
        .reserved = 0,
    };
    write_idt_entry(idt, interrupt_id, &desc);
}

static void idt_set_custom_handlers(gate_desc *idt, struct desc_ptr *idtr, void *main_handler,
                                    void **secondary_handlers)
{
    for (int idx = 0; idx < 256; idx++) {
        if (idx == X86_TRAP_NMI) {
            set_intr_gate_default(idt, idx, nmi_handler);
            continue;
        }

        if (main_handler != NULL && idx < 32 && BIT_CHECK(handled_faults, idx)) {
            set_intr_gate_default(idt, idx, main_handler);
            continue;
        }

        switch (idx) {
        // if we ever get a machine check exception, the CPU is definitely in a bad state
        // so we should let OS handle it
        case X86_TRAP_DF:
        case X86_TRAP_MC: {
            // case 22 ... 31: {
            gate_desc *org_handler = &((gate_desc *)orig_idtr.address)[idx];
            write_idt_entry(idt, idx, org_handler);
            break;
        }
        default:
            // all other exceptions are dispatched to the secondary handler
            set_intr_gate_default(idt, idx, secondary_handlers[idx]);
            break;
        }
    }
    idtr->address = (unsigned long)idt;
    idtr->size = (sizeof(gate_desc) * 256) - 1;
    native_lidt(idtr);
}

void set_outer_fault_handlers(void)
{
    native_sidt(&orig_idtr); // preserve original IDT
    idt_set_custom_handlers(bubble_idt, &bubble_idtr, NULL, bubble_handlers);
    is_nested_fault = 0;
}

void unset_outer_fault_handlers(void)
{
    if (orig_idtr.address != 0) {
        native_lidt(&orig_idtr); // restore original IDT
    } else {
        PRINT_ERR("unset_outer_fault_handlers: original IDT is not set\n");
    }
}

void set_inner_fault_handlers(void)
{
    idt_set_custom_handlers(test_case_idt, &test_case_idtr, fault_handler, test_case_handlers);
    is_nested_fault = 0;
}

void unset_inner_fault_handlers(void)
{
    if (bubble_idtr.address != 0) {
        native_lidt(&bubble_idtr); // restore bubble IDT
    } else {
        PRINT_ERR("unset_inner_fault_handlers: bubble IDT is not set\n");
    }
}

// =================================================================================================
int init_fault_handler(void)
{
    fault_handler = (void *)test_case_handler;

    bubble_idt = CHECKED_ZALLOC(sizeof(gate_desc) * 256);
    test_case_idt = CHECKED_ZALLOC(sizeof(gate_desc) * 256);
    test_case_idtr.address = (unsigned long)test_case_idt;
    return 0;
}

void free_fault_handler(void)
{
    SAFE_FREE(bubble_idt);
    SAFE_FREE(test_case_idt);
}
