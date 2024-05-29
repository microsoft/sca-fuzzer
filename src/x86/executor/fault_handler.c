/// File:
///  - Fault handling and IDT management
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

uint32_t handled_faults = 0;          // global
char *fault_handler = NULL;           // global
uint64_t pre_bubble_rsp = 0;          // global
struct desc_ptr test_case_idtr = {0}; // global

static gate_desc *bubble_idt = NULL;
static gate_desc *test_case_idt = NULL;

static struct desc_ptr orig_idtr = {0};
static struct desc_ptr bubble_idtr = {0};

void fallback_handler(void);
void bubble_handler(void);
void nmi_handler(void);

MULTI_ENTRY_HANDLER_DECLARATIONS(fallback_handler);
static void *fallback_handlers[] = {
    MULTI_ENTRY_HANDLER_LIST(fallback_handler) NULL,
};

MULTI_ENTRY_HANDLER_DECLARATIONS(bubble_handler);
static void *bubble_handlers[] = {
    MULTI_ENTRY_HANDLER_LIST(bubble_handler) NULL,
};

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

void idt_set_custom_handlers(gate_desc *idt, struct desc_ptr *idtr, void *main_handler,
                             void **secondary_handlers)
{
    for (uint8_t idx = 0; idx < 255; idx++) {
        if (idx == X86_TRAP_NMI) {
            set_intr_gate_default(idt, idx, nmi_handler);
            continue;
        }

        if (idx < 32 && BIT_CHECK(handled_faults, idx)) {
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

int set_bubble_idt(void)
{
    ASSERT(pre_bubble_rsp != 0, "set_bubble_idt");
    sandbox->util->nested_fault = 0;
    native_sidt(&orig_idtr); // preserve original IDT
    idt_set_custom_handlers(bubble_idt, &bubble_idtr, bubble_handler, bubble_handlers);
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
    idt_set_custom_handlers(test_case_idt, &test_case_idtr, fault_handler, fallback_handlers);
    sandbox->util->nested_fault = 0;
    return 0;
}

int unset_test_case_idt(void)
{
    idt_set_custom_handlers(bubble_idt, &bubble_idtr, bubble_handler, bubble_handlers);
    return 0;
}

// =================================================================================================
// Handlers
// =================================================================================================

/// @brief Universal NMI handler. Used by both Bubble and Test Case IDTs.
///        Prints a warning message and terminates the measurement.
///        Returns to the caller of unsafe_bubble_wrapper.
/// @param void
__attribute__((unused)) void nmi_handler_wrapper(void)
{
    asm volatile(".global nmi_handler\n"
                 "nmi_handler:\n"

                 // just in case, disable interrupts
                 "cli\n"

                 // note: NMIs are automatically disabled in this handler,
                 // hence we don't need to check for nested interrupts

                 // get a safe stack
                 "mov %[rsp_save], %%rsp\n"

                 // move the stack pointer down by a page in case the compiler have preallocated
                 // some stack space for the following function calls
                 "sub $0x1000, %%rsp\n"
                 "mov %%rsp, %%rbp\n"

                 : [rsp_save] "=m"(pre_bubble_rsp)::"memory");

    printk(KERN_WARNING "WARN: unhandled NMI\n");
    recover_orig_state();

    // restore the caller's register values and return to the caller of unsafe_bubble_wrapper
    asm volatile(""
                 "add $0x1000, %%rsp\n"
                 "popfq\n"
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
                 "mov $0, %%rax\n"
                 "ret\n"
                 // Silences objtool warnings about no int3 after ret
                 "int3\n"
                 : [rsp_save] "=m"(pre_bubble_rsp)
                 :);
}

__attribute__((unused)) void fallback_handler_wrapper(void)
{
    static uint64_t fault_data[6] = {0};

    // clang-format off
    MULTI_ENTRY_HANDLER(fallback_handler);
    asm volatile(""
        ".global fallback_handler\n"
        "fallback_handler:\n"
    : : : "memory");

    asm volatile(""
        "mov %%r13, %%r14\n"          // r14 <- error code
        "mov %[util_base], %%r15\n"   // r15 <- util_base

        // check for nested faults
        "lea %[nested_flag], %%rax\n"
        "cmpq $0, (%%rax)\n"
        "jne .nested_fault\n"
        "movq $1, (%%rax)\n"

        // store error info
        "lea %[fault_data], %%rax\n"
        "mov %%r14, (%%rax)\n"
        "pop %%rbx\n"
        "movq %%rbx, 8(%%rax)\n"
        "pop %%rbx\n"
        "movq %%rbx, 16(%%rax)\n"
        "pop %%rbx\n"
        "movq %%rbx, 24(%%rax)\n"
        "pop %%rbx\n"
        "movq %%rbx, 32(%%rax)\n"
        "pop %%rbx\n"
        "movq %%rbx, 40(%%rax)\n"

        // rsp = sandbox->util->stored_rsp
        "lea "xstr(STORED_RSP_OFFSET)"(%%r15), %%rax\n"
        "mov (%%rax), %%rsp\n"

        // restore registers
        "popfq\n"
        "pop %%r15\n"
        "pop %%r14\n"
        "pop %%r13\n"
        "pop %%r12\n"
        "pop %%r11\n"
        "pop %%r10\n"
        "pop %%rbp\n"
        "pop %%rbx\n"
        "jmp .fallback_handler_end\n"

        // BUG on nested fault
        ".nested_fault:\n"
        "mov %[recover_orig_state], %%rax\n"
        "call *%%rax\n"
        "sti\n"
#if VENDOR_ID == VENDOR_AMD_
        "stgi\n"
#endif
        "ud2\n"

        ".fallback_handler_end:\n"

        : [util_base] "=m"(sandbox->util),
          [nested_flag] "+m"(sandbox->util->nested_fault),
          [fault_data] "=m"(fault_data[0])
        : [recover_orig_state] "r"(&recover_orig_state)
        : "rax", "rbx", "rcx", "r10", "r11", "r12", "r13", "r14", "r15"
    );
    // clang-format on

    uint64_t cr2 = read_cr2();
    PRINT_ERR("[fallback_handler] Test case triggered an unhandled fault:\n"
              "Exception ID: 0x%llx\n"
              "  1 [Error code]:\t0x%llx\n"
              "  2 [RIP]:\t0x%llx\n"
              "  (sandbox code start: 0x%llx; data start: 0x%llx)\n"
              "  3 [CS]:\t0x%llx\n"
              "  4 [RFLAGS]:\t0x%llx\n"
              "  5 [RSP]:\t0x%llx\n"
              "  CR2:\t\t0x%llx\n",
              fault_data[0], fault_data[1], fault_data[2], (uint64_t)sandbox->code[0].section,
              (uint64_t)sandbox->data[0].main_area, fault_data[3], fault_data[4], fault_data[5],
              cr2);

    recover_orig_state();

    // return 1 to indicate an unhandled fault
    asm_volatile_intel("mov rax, 1\n"
                       "ret\n"
                       "int3\n" // Silences objtool warnings about no int3 after ret
    );
}

__attribute__((unused)) void bubble_handler_wrapper(void)
{
    static uint64_t fault_data[6] = {0};
    MULTI_ENTRY_HANDLER(bubble_handler);
    asm volatile(".global bubble_handler\n"
                 "bubble_handler:\n"
                 :
                 :
                 : "memory");

    asm volatile(""
                 "mov %%r13, %%r14\n" // r14 <- error code

                 // check for nested faults
                 "lea %[nested_flag], %%rax\n"
                 "cmpq $0, (%%rax)\n"
                 "jne .nested_fault_bubble\n"
                 "movq $1, (%%rax)\n"

                 // store error info
                 "lea %[fault_data], %%rax\n"
                 "mov %%r14, (%%rax)\n"
                 "pop %%rbx\n"
                 "movq %%rbx, 8(%%rax)\n"
                 "pop %%rbx\n"
                 "movq %%rbx, 16(%%rax)\n"
                 "pop %%rbx\n"
                 "movq %%rbx, 24(%%rax)\n"
                 "pop %%rbx\n"
                 "movq %%rbx, 32(%%rax)\n"
                 "pop %%rbx\n"
                 "movq %%rbx, 40(%%rax)\n"

                 "jmp .bubble_handler_end\n"

                 // BUG on nested fault
                 ".nested_fault_bubble:\n"
                 "mov %[recover_orig_state], %%rax\n"
                 "call *%%rax\n"
                 "sti\n"
#if VENDOR_ID == VENDOR_AMD_
                 "stgi\n"
#endif
                 "ud2\n"

                 ".bubble_handler_end:\n"
                 : [fault_data] "=m"(fault_data[0]), [nested_flag] "+m"(sandbox->util->nested_fault)
                 : [recover_orig_state] "r"(&recover_orig_state)
                 : "rax", "rbx", "r13");

    uint64_t cr2 = read_cr2();
    PRINT_ERRS("bubble_handler", "run_experiment triggered a fault\n");
    PRINT_ERR("Fault stack (applies only to exceptions):\n"
              "Exception ID: 0x%llx\n"
              "  1 [Error code]:\t0x%llx\n"
              "  2 [RIP]:\t0x%llx\n"
              "    (run_experiment base: 0x%llx, offset: 0x%llx)\n"
              "  3 [CS]:\t0x%llx\n"
              "  4 [RFLAGS]:\t0x%llx\n"
              "  5 [RSP]:\t0x%llx\n"
              "  CR2:\t\t0x%llx\n",
              fault_data[0], fault_data[1], fault_data[2], (uint64_t)run_experiment,
              (fault_data[2] - (uint64_t)run_experiment), fault_data[3], fault_data[4],
              fault_data[5], cr2);

    // the code below MUST match the epilogue of unsafe_bubble in measurement.c
    unset_bubble_idt();
    recover_orig_state();

    asm volatile(""
                 "mov %[rsp_save], %%rsp\n"
                 "popfq\n"
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
                 "int3\n" // Silences objtool warnings about no int3 after ret
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
    test_case_idtr.address = (unsigned long)test_case_idt;
    return 0;
}

void free_fault_handler(void)
{
    SAFE_FREE(bubble_idt);
    SAFE_FREE(test_case_idt);
}
