// File: Low-level exception handling code for ARM64
//
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT
.extern _printk
.extern set_outer_fault_handlers
.extern unset_outer_fault_handlers
.extern run_experiment
.extern orig_vector_table_ptr
.extern loaded_test_case_entry

.extern fault_handler
.extern is_nested_fault


// =================================================================================================
// Global variables
// =================================================================================================
.data

recovery_sp:
.quad 0

.Lunreachable_msg:
.asciz	"ERROR: rvzr_executor: unreachable code\n"
.align

.Lunexpected_fault_msg:
.asciz	"\0013 ERROR: [fallback_handler] Unexpected fault in run_experiment: \n\
1 [Error Syndrome]:\t0x%llx\n\
2 [Fault Address]:\t0x%llx\n\
  (run_experiment start:\t0x%llx)\n\
3 [SP]:\t0x%llx\n"
.align

.Ldefault_fault_msg:
.asciz	"\0013 ERROR: [test_case_handler] Unhandled fault in the test case: \n\
1 [Error Syndrome]:\t0x%llx\n\
2 [Fault Address]:\t0x%llx\n\
  (test case start:\t0x%llx)\n\
3 [SP]:\t0x%llx\n"
.align


// =================================================================================================
// Macros
// =================================================================================================
.macro unreachable
    adr	x0, .Lunreachable_msg
    mov	x2, lr
    b panic
.endm


// =================================================================================================
// Custom vector tables
// =================================================================================================
.text

/// @brief The vector table used for catching bugs in run_experiment function
///        This table exists purely for convenience during the development process and
///        should be unreachable during normal operation
.global outer_vector_table
.balign 2048
outer_vector_table:
    // Interrupts/exceptions from EL1 to EL1; using SP_EL1 as sp
        b fallback_handler
    .balign 0x80
        b fallback_handler
    .balign 0x80
        b fallback_handler
    .balign 0x80
        b fallback_handler
    // Interrupts/exceptions from EL1 to EL1; using SP_ELX as sp
    .balign 0x80
        b fallback_handler
    .balign 0x80
        b fallback_handler
    .balign 0x80
        b fallback_handler
    .balign 0x80
        b fallback_handler
    // Interrupts/exceptions from EL0 to EL1; in AArch64 mode
    .balign 0x80
        b fallback_handler
    .balign 0x80
        b fallback_handler
    .balign 0x80
        b fallback_handler
    .balign 0x80
        b fallback_handler
    // Interrupts/exceptions from EL0 to EL1; in AArch32 mode
    .balign 0x80
        unreachable
    .balign 0x80
        unreachable
    .balign 0x80
        unreachable
    .balign 0x80
        unreachable

/// @brief The vector table used for redirecting exceptions in tests cases to the recovery code
///        In contrast to the outer_vector_table, this table is actively used during normal
///        operation, especially when testing for Meltdown-like vulnerabilities
.global inner_vector_table
.balign 2048
inner_vector_table:
    // Interrupts/exceptions from EL1 to EL1; using SP_EL1 as sp
        b test_case_handler
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    // Interrupts/exceptions from EL1 to EL1; using SP_ELX as sp
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    // Interrupts/exceptions from EL0 to EL1; in AArch64 mode
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    // Interrupts/exceptions from EL0 to EL1; in AArch32 mode
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler
    .balign 0x80
        b test_case_handler

// =================================================================================================
// Handlers
// =================================================================================================
.text

/// @brief The default handler that terminates the tracing process
///        by directly jumping to the exit point of the run_experiment function
.global fallback_handler
fallback_handler:
    mrs x1, esr_el1
    mrs x2, far_el1  // FIXME: this doesn't work for many exception types
    adr x3, run_experiment
    mov x4, sp
    adr x5, .Lunexpected_fault_msg

    adr x0, .run_experiment_recovery
    msr elr_el1, x0
    eret


/// @brief A handler for all exceptions that occur during the test case execution
.global test_case_handler
test_case_handler:
    // check for nested faults
    adr x11, is_nested_fault
    ldr x10, [x11]
    cmp x10, #0
    b.ne .test_case_handler.default
    mov x10, #1
    str x10, [x11]

    // check if a custom handler is registered
    adr x10, fault_handler
    ldr x10, [x10]
    cmp x10, #0
    b.eq .test_case_handler.default

    .test_case_handler.registered_handler:
    msr elr_el1, x10
    eret

    .test_case_handler.default:
    mrs x1, esr_el1
    mrs x2, far_el1  // FIXME: this doesn't work for many exception types
    adr x3, loaded_test_case_entry
    ldr x3, [x3]
    mov x4, sp
    adr x5, .Ldefault_fault_msg

    adr x0, .run_experiment_recovery
    msr elr_el1, x0
    eret


// =================================================================================================
// run_experiment_outer: Fault-tolerant wrapper for run_experiment
// =================================================================================================
.text

/// @brief A wrapper over run_experiment that ensures that any bugs that cause an
///        exception will be handled gracefully and won't crash the system
/// @param void
.global run_experiment_outer
run_experiment_outer:
    // A bug in run_experiment may corrupt the CPU state, so we need to save the current state
    // before calling run_experiment
    stp x1, x2, [sp, -16]!
    stp x3, x4, [sp, -16]!
    stp x5, x6, [sp, -16]!
    stp x7, x8, [sp, -16]!
    stp x9, x10, [sp, -16]!
    stp x11, x12, [sp, -16]!
    stp x13, x14, [sp, -16]!
    stp x15, x16, [sp, -16]!
    stp x17, x18, [sp, -16]!
    stp x19, x20, [sp, -16]!
    stp x21, x22, [sp, -16]!
    stp x23, x24, [sp, -16]!
    stp x25, x26, [sp, -16]!
    stp x27, x28, [sp, -16]!
    stp x29, x30, [sp, -16]!
    mov x29, sp

    // Save the SP into a global variables so that we can recover it after a destructive bug
    mov x0, sp
    adr x1, recovery_sp
    str x0, [x1]

    // Set up a custom vector table
    bl set_outer_fault_handlers

    // Call run_experiment
    bl run_experiment
    b .run_experiment_normal_exit
.run_experiment_recovery:
    // Overwrite SP with recovery_sp
    adr x28, recovery_sp
    ldr x28, [x28]
    mov sp, x28
    mov x29, sp

    // Print an error message
    // x1 already contains the fault code from the fault handler
    mov x0, x5
    bl _printk
    mov x0, #1

.run_experiment_normal_exit:
    // Restore the original vector table
    bl unset_outer_fault_handlers

    // Restore the CPU state in case run_experiment has corrupted it
    ldp x29, x30, [sp], 16
    ldp x27, x28, [sp], 16
    ldp x25, x26, [sp], 16
    ldp x23, x24, [sp], 16
    ldp x21, x22, [sp], 16
    ldp x19, x20, [sp], 16
    ldp x17, x18, [sp], 16
    ldp x15, x16, [sp], 16
    ldp x13, x14, [sp], 16
    ldp x11, x12, [sp], 16
    ldp x9, x10, [sp], 16
    ldp x7, x8, [sp], 16
    ldp x5, x6, [sp], 16
    ldp x3, x4, [sp], 16
    ldp x1, x2, [sp], 16

    ret
