/// File:
///  - Fault handling and IDT management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/interrupt.h>

#include "code_loader.h"
#include "measurement.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "hw_features/fault_handler.h"

uint32_t handled_faults = 0; // global
char *fault_handler = NULL;  // global
uint64_t pre_bubble_rsp = 0; // global

static gate_desc *bubble_idt = NULL;
static gate_desc *test_case_idt = NULL;

static struct desc_ptr orig_idtr = {0};
static struct desc_ptr bubble_idtr = {0};
static struct desc_ptr test_case_idtr = {0};

void fallback_handler(void);
void bubble_handler(void);

// =================================================================================================
// IDT management
// =================================================================================================
static void inline native_sidt(void *dtr)
{
    asm volatile("sidt %0" : "=m"(*((struct desc_ptr *)dtr)));
}

static void inline native_lidt(void *dtr)
{
    asm volatile("lidt %0" ::"m"(*((struct desc_ptr *)dtr)));
}

static void set_intr_gate(gate_desc *idt, int interrupt_id, void *handler)
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

void idt_set_custom_handlers(gate_desc *idt, struct desc_ptr *idtr, void *main_handler,
                             void *secondary_handler, void *nmi_handler)
{
    for (uint8_t idx = 0; idx < 255; idx++) {
        if (idx == 2) {
            set_intr_gate(idt, idx, nmi_handler);
            continue;
        }

        if (BIT_CHECK(handled_faults, idx)) {
            set_intr_gate(idt, idx, main_handler);
        } else {
            set_intr_gate(idt, idx, secondary_handler);
        }
    }
    idtr->address = (unsigned long)idt;
    idtr->size = (sizeof(gate_desc) * 256) - 1;
    native_lidt(idtr);
}

int set_bubble_idt(void)
{
    ASSERT(pre_bubble_rsp != 0, "set_bubble_idt");
    native_sidt(&orig_idtr); // preserve original IDT
    // void *nmi_handler = (void *)(orig_idtr.address + 2 * sizeof(gate_desc));
    idt_set_custom_handlers(bubble_idt, &bubble_idtr, bubble_handler, bubble_handler,
                            bubble_handler);
    return 0;
}

int unset_bubble_idt(void)
{
    native_lidt(&orig_idtr); // restore original IDT
    return 0;
}

int set_test_case_idt(void)
{
    ASSERT(bubble_idtr.address != 0, "set_test_case_idt");
    // void *nmi_handler = (void *)(orig_idtr.address + 2 * sizeof(gate_desc));
    idt_set_custom_handlers(test_case_idt, &test_case_idtr, fault_handler, fallback_handler,
                            fallback_handler);
    return 0;
}

int unset_test_case_idt(void)
{
    // void *nmi_handler = (void *)(orig_idtr.address + 2 * sizeof(gate_desc));
    idt_set_custom_handlers(bubble_idt, &bubble_idtr, bubble_handler, bubble_handler,
                            bubble_handler);
    return 0;
}

// =================================================================================================
// Handlers
// =================================================================================================
__attribute__((unused)) void fallback_handler_wrapper(void)
{
    // clang-format off
    asm_volatile_intel(
        ".global fallback_handler\n"
        "fallback_handler:\n"

        // rax <- &latest_measurement
        "lea rax, [r15 + "xstr(MEASUREMENT_OFFSET)"]\n"

        // set the trace to 0xFFFF to indicate an unhandled fault
        "mov qword ptr [rax], 0xFFFF \n"

        // set PFC[0] to the error code
        "pop rbx \n"
        "mov qword ptr [rax + 8], rbx \n"

        // set PFC[1] to the faulting address
        "pop rcx \n"
        "mov qword ptr [rax + 16], rcx \n"

        // rsp = sandbox->util->stored_rsp
        "mov rsp, qword ptr [r15 + "xstr(STORED_RSP_OFFSET)"]\n"

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
    sandbox->util->latest_measurement.pfc_reading[2] =
        sandbox->util->latest_measurement.pfc_reading[1] - (uint64_t)loaded_test_case_entry;

    // TODO: make run_experiment exit with an error code upon a n unhandled fault

    PRINT_ERRS("fallback_handler",
               "Test case triggered an unhandled fault:\n"
               "  Faulting address: 0x%llx\n"
               "  Error code: 0x%llx\n"
               "  (sandbox code start: 0x%llx; data start: 0x%llx)\n",
               sandbox->util->latest_measurement.pfc_reading[1],
               sandbox->util->latest_measurement.pfc_reading[0], (uint64_t)sandbox->code[0].section,
               (uint64_t)sandbox->data[0].main_area);

    // return 1 to indicate an unhandled fault
    asm_volatile_intel(""
                       "mov rax, 1\n"
                       "ret\n");
}

__attribute__((unused)) void bubble_handler_wrapper(void)
{
    static uint64_t fault_stack[5] = {0};
    asm volatile(""
                 ".global bubble_handler\n"
                 "bubble_handler:\n"
                 "nop\n"

                 "pop %%rax\n"
                 "pop %%rbx\n"
                 "pop %%rcx\n"
                 "pop %%rdx\n"
                 "mov %%rax, %[fault_stack0]\n"
                 "mov %%rbx, %[fault_stack1]\n"
                 "mov %%rcx, %[fault_stack2]\n"
                 "mov %%rdx, %[fault_stack3]\n"
                 "mov %%rsi, %[fault_stack4]\n"
                 : [fault_stack0] "=m"(fault_stack[0]), [fault_stack1] "=m"(fault_stack[1]),
                   [fault_stack2] "=m"(fault_stack[2]), [fault_stack3] "=m"(fault_stack[3]),
                   [fault_stack4] "=m"(fault_stack[4]));

    PRINT_ERRS("bubble_handler", "run_experiment triggered a fault\n");
    PRINT_ERR("Fault stack (applies only to exceptions):\n"
              "  1 [Error]:\t0x%llx\n"
              "  2 [RIP]:\t0x%llx\n"
              "    (run_experiment base: 0x%llx, offset: 0x%llx)\n"
              "  3 [CS]:\t0x%llx\n"
              "  4 [RFLAGS]:\t0x%llx\n"
              "  5 [RSP]:\t0x%llx\n",
              fault_stack[0], fault_stack[1], (uint64_t)run_experiment,
              (fault_stack[1] - (uint64_t)run_experiment), fault_stack[2], fault_stack[3],
              fault_stack[4]);

    // the code below MUST match the epilogue of unsafe_bubble in measurement.c
    unset_bubble_idt();
    asm volatile(""
                 "mov %[rsp_save], %%rsp\n"
                 "pop %%rbp\n"
                 "pop %%r15\n"
                 "pop %%r14\n"
                 "pop %%r13\n"
                 "pop %%r12\n"
                 "pop %%r11\n"
                 "pop %%r10\n"
                 "pop %%r9\n"
                 "pop %%r8\n"
                 "pop %%rdi\n"
                 "pop %%rsi\n"
                 "pop %%rdx\n"
                 "pop %%rcx\n"
                 "pop %%rbx\n"
                 "mov $1, %%rax\n"

                 "ret\n"
                 : [rsp_save] "=m"(pre_bubble_rsp)
                 :);
}

// =================================================================================================
int init_fault_handler(void)
{
    handled_faults = HANDLED_FAULTS_DEFAULT;
    fault_handler = (void *)fallback_handler;

    bubble_idt = CHECKED_ZALLOC(sizeof(gate_desc) * 256);
    test_case_idt = CHECKED_ZALLOC(sizeof(gate_desc) * 256);
    return 0;
}

void free_fault_handler(void)
{
    SAFE_FREE(bubble_idt);
    SAFE_FREE(test_case_idt);
}
