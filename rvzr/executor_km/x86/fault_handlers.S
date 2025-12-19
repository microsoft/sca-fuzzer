// File: Low-level exception handling code for x86-64
//
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT
.intel_syntax noprefix

#include "sandbox_constants.h"
#include "registers.h"

.extern _printk
.extern set_outer_fault_handlers
.extern unset_outer_fault_handlers
.extern run_experiment
.extern recover_orig_state


// =================================================================================================
// Global variables
// =================================================================================================
.data

.global is_nested_fault
is_nested_fault:
.quad 0

fault_recovery_sp:
.quad 0

.Lrecovery_triggered_msg:
.asciz	"\0013[rvzr_executor:run_experiment_outer]\n\
ERROR: Recovery from fault triggered during run_experiment\n"
.align

.Lunreachable_msg:
.asciz	"\0013[rvzr_executor:rvzr_executor]\n\
ERROR: unreachable code\n"
.align

.Ltest_case_handler_msg:
.asciz	"\0013[rvzr_executor:test_case_handler]\n\
ERROR: Unhandled fault in the test case: \n\
    0 [Exception ID]:\t0x%llx\n\
    1 [Error code]:\t0x%llx\n\
    2 [RIP]:\t0x%llx\n\
    3 [CS]:\t0x%llx\n\
    4 [RFLAGS]:\t0x%llx\n\
    5 [RSP]:\t0x%llx\n\
Context:\n\
    R14: \t0x%llx\n\
    R15: \t0x%llx\n"
.align

.Lbubble_handler_msg:
.asciz	"\0013[rvzr_executor:bubble_handler]\n\
ERROR: Unexpected fault in run_experiment: \n\
    0 [Exception ID]:\t0x%llx\n\
    1 [Error code]:\t0x%llx\n\
    2 [RIP]:\t0x%llx\n\
    3 [CS]:\t0x%llx\n\
    4 [RFLAGS]:\t0x%llx\n\
    5 [RSP]:\t0x%llx\n\
Context:\n\
    run_experiment:\t\t0x%llx\n\
    run_experiment_outer:\t0x%llx\n"
.align

.Lnmi_handler_msg:
.asciz	"\0013[rvzr_executor:nmi_handler]\n\
ERROR: Unhandled NMI occurred during run_experiment\n"
.align

.Lnested_fault_msg:
.asciz	"\0013[rvzr_executor:nested_fault]\n\
ERROR: Nested fault detected\n"
.align

// =================================================================================================
// Macros
// =================================================================================================
.macro unreachable
    lea rdi, .Lunreachable_msg
    mov rsi, rcx
    call _printk
    hlt
.endm

// Generate entry stub for exception WITHOUT error code
.macro entry_stub_no_err name, id
.global \name\()_\id
.balign 16
\name\()_\id:
    push 0                // push dummy error code for stack normalization
    mov r13, 0x\id        // set exception ID in r13
    jmp \name             // jump to main handler
.endm

// Generate entry stub for exception WITH error code
.macro entry_stub_err name, id
.global \name\()_\id
.balign 16
\name\()_\id:
    mov r13, 0x\id        // set exception ID in r13 (error code already on stack)
    jmp \name             // jump to main handler
.endm

// C preprocessor macro: Helper to repeat a macro 16 times
#define CALL_16_TIMES(macro, arg, id)                                                              \
    macro arg, id##0; macro arg, id##1; macro arg, id##2; macro arg, id##3;                        \
    macro arg, id##4; macro arg, id##5; macro arg, id##6; macro arg, id##7;                        \
    macro arg, id##8; macro arg, id##9; macro arg, id##a; macro arg, id##b;                        \
    macro arg, id##c; macro arg, id##d; macro arg, id##e; macro arg, id##f;


// =================================================================================================
// Handlers
// =================================================================================================
.text

/// @brief The default handler for interrupts/exceptions that occur during the test case execution.
/// @param r13: error code
.global test_case_handler
.balign 4096
test_case_handler:
    // just in case, disable interrupts
    cli

    // check for nested faults
    lea rax, is_nested_fault
    cmp qword ptr [rax], 0
    jne .run_experiment_recovery  // nested fault detected -> go to recovery
    mov qword ptr [rax], 1        // no nested fault -> set the flag

    // Print error info:
    // Note: this function is called by the generated entry stubs (see entry_stub_* below),
    //       which set r13 to the exception ID
    //       and ensure that the stack layout is:
    //          - error code
    //          - RIP
    //          - CS
    //          - RFLAGS
    //          - RSP
    lea rdi, .Ltest_case_handler_msg  // format string
    mov rsi, r13                      // arg 1: Exception ID
    pop rdx                           // arg 2: Error code
    pop rcx                           // arg 3: RIP
    pop r8                            // arg 4: CS
    pop r9                            // arg 5: RFLAGS
    // arg 6+ are passed on stack
    pop rax
    push r15                          // arg 8: R15
    push r14                          // arg 7: R14
    push rax                          // arg 6: RSP
    xor eax, eax   // no vector registers used
    call _printk

    // ensure that the CPU state is properly restored before we exit
    call recover_orig_state

    jmp .run_experiment_recovery


/// @brief The default handler for interrupts/exceptions that occur inside the code called by
///        run_experiment_outer but outside of the test case itself.
.global bubble_handler
.balign 4096
bubble_handler:
    // just in case, disable interrupts
    cli

    // check for nested faults
    lea rax, is_nested_fault
    cmp qword ptr [rax], 0
    jne .run_experiment_recovery  // nested fault detected -> go to recovery
    mov qword ptr [rax], 1        // no nested fault -> set the flag

    // Print error info:
    // Note: this function is called by the generated entry stubs (see entry_stub_* below),
    //       which set r13 to the exception ID
    //       and ensure that the stack layout is:
    //          - error code
    //          - RIP
    //          - CS
    //          - RFLAGS
    //          - RSP
    lea rdi, .Lbubble_handler_msg     // format string
    mov rsi, r13                      // arg 1: Exception ID
    pop rdx                           // arg 2: Error code
    pop rcx                           // arg 3: RIP
    pop r8                            // arg 4: CS
    pop r9                            // arg 5: RFLAGS
    // arg 6+ are passed on stack
    pop r10                           // get RSP value
    lea r11, run_experiment           // get run_experiment address
    lea r12, run_experiment_outer     // get run_experiment_outer address
    push r12                          // arg 8: run_experiment_outer
    push r11                          // arg 7: run_experiment
    push r10                          // arg 6: RSP
    xor eax, eax   // no vector registers used
    call _printk
    add rsp, 16    // clean up stack (2 arguments)

    // ensure that the CPU state is properly restored before we exit
    call recover_orig_state

    jmp .run_experiment_recovery


/// @brief Universal NMI handler. Used by both Bubble and Test Case IDTs.
///        Prints a warning message and terminates the measurement.
///        Returns to the caller of unsafe_bubble_wrapper.
/// @param void
.global nmi_handler
.balign 4096
nmi_handler:
    // just in case, disable interrupts
    cli

    // flag that we had a fault
    mov qword ptr [is_nested_fault], 1

    // ensure that the stack pointer is valid
    lea rbx, fault_recovery_sp
    mov rbx, [rbx]
    mov rsp, rbx

    // print error message
    lea rdi, .Lnmi_handler_msg
    call _printk

    // go into recovery
    jmp .run_experiment_recovery


/// @brief Handler for nested faults.
///        Note: Revizor currently does not support handling of multiple faults in a single
///        test case execution. Thus, if a nested fault occurs, we simply print an error message
///        and terminate the measurement.
/// @param void
.global nested_fault_handler
.balign 4096
nested_fault_handler:
    // just in case, disable interrupts
    cli

    // print error message
    lea rdi, .Lnested_fault_msg
    call _printk

    // go into recovery
    jmp .run_experiment_recovery


// =================================================================================================
// Multi-entry handler generation
// =================================================================================================
// This section generates 256 individual entry stubs for each handler (test_case_handler and
// bubble_handler). Each stub normalizes the stack layout (ensures error code is present) and
// passes the exception ID in r13 before jumping to the main handler.
//
// Exceptions that push error codes: 0x08, 0x0a-0x0e, 0x11, 0x15, 0x1d, 0x1e
// For exceptions WITHOUT error code, we push a dummy 0 to normalize the stack layout.
.text

// Generate all 256 entry stubs for test_case_handler
entry_stub_no_err test_case_handler, 00
entry_stub_no_err test_case_handler, 01
entry_stub_no_err test_case_handler, 02
entry_stub_no_err test_case_handler, 03
entry_stub_no_err test_case_handler, 04
entry_stub_no_err test_case_handler, 05
entry_stub_no_err test_case_handler, 06
entry_stub_no_err test_case_handler, 07
entry_stub_err test_case_handler, 08
entry_stub_no_err test_case_handler, 09
entry_stub_err test_case_handler, 0a
entry_stub_err test_case_handler, 0b
entry_stub_err test_case_handler, 0c
entry_stub_err test_case_handler, 0d
entry_stub_err test_case_handler, 0e
entry_stub_no_err test_case_handler, 0f
entry_stub_no_err test_case_handler, 10
entry_stub_err test_case_handler, 11
entry_stub_no_err test_case_handler, 12
entry_stub_no_err test_case_handler, 13
entry_stub_no_err test_case_handler, 14
entry_stub_err test_case_handler, 15
entry_stub_no_err test_case_handler, 16
entry_stub_no_err test_case_handler, 17
entry_stub_no_err test_case_handler, 18
entry_stub_no_err test_case_handler, 19
entry_stub_no_err test_case_handler, 1a
entry_stub_no_err test_case_handler, 1b
entry_stub_no_err test_case_handler, 1c
entry_stub_err test_case_handler, 1d
entry_stub_err test_case_handler, 1e
entry_stub_no_err test_case_handler, 1f
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 2)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 3)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 4)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 5)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 6)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 7)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 8)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, 9)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, a)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, b)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, c)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, d)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, e)
CALL_16_TIMES(entry_stub_no_err, test_case_handler, f)

// Generate all 256 entry stubs for bubble_handler
entry_stub_no_err bubble_handler, 00
entry_stub_no_err bubble_handler, 01
entry_stub_no_err bubble_handler, 02
entry_stub_no_err bubble_handler, 03
entry_stub_no_err bubble_handler, 04
entry_stub_no_err bubble_handler, 05
entry_stub_no_err bubble_handler, 06
entry_stub_no_err bubble_handler, 07
entry_stub_err bubble_handler, 08
entry_stub_no_err bubble_handler, 09
entry_stub_err bubble_handler, 0a
entry_stub_err bubble_handler, 0b
entry_stub_err bubble_handler, 0c
entry_stub_err bubble_handler, 0d
entry_stub_err bubble_handler, 0e
entry_stub_no_err bubble_handler, 0f
entry_stub_no_err bubble_handler, 10
entry_stub_err bubble_handler, 11
entry_stub_no_err bubble_handler, 12
entry_stub_no_err bubble_handler, 13
entry_stub_no_err bubble_handler, 14
entry_stub_err bubble_handler, 15
entry_stub_no_err bubble_handler, 16
entry_stub_no_err bubble_handler, 17
entry_stub_no_err bubble_handler, 18
entry_stub_no_err bubble_handler, 19
entry_stub_no_err bubble_handler, 1a
entry_stub_no_err bubble_handler, 1b
entry_stub_no_err bubble_handler, 1c
entry_stub_err bubble_handler, 1d
entry_stub_err bubble_handler, 1e
entry_stub_no_err bubble_handler, 1f
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 2)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 3)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 4)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 5)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 6)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 7)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 8)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, 9)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, a)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, b)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, c)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, d)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, e)
CALL_16_TIMES(entry_stub_no_err, bubble_handler, f)


// =================================================================================================
// run_experiment_outer: Fault-tolerant wrapper for run_experiment
// =================================================================================================
.text

/// @brief A wrapper over run_experiment that ensures that any bugs that cause an
///        exception will be handled gracefully and won't crash the system
/// @param void
.global run_experiment_outer
.balign 4096
run_experiment_outer:
    // A bug in run_experiment may corrupt the CPU state, so we need to save the current state
    // before calling run_experiment
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp, rsp

    // Save the SP into a global variables so that we can recover it after a destructive bug
    lea rax, fault_recovery_sp
    mov [rax], rsp

    // Disable interrupts to avoid nested faults (should already be disabled but just in case)
    cli

    // Set up outer fault handlers
    call set_outer_fault_handlers

    // Run the measurements
    call run_experiment
    jmp .run_experiment_normal_exit

.run_experiment_recovery:
    // START CRITICAL SECTION
    // Note: this section is used to recover from bugs in the executor with possible full corruption
    // of the memory and register state. Thus, the code below has to make as few assumptions
    // as possible, and also be very careful about memory accesses.

    // Overwrite SP with fault_recovery_sp
    lea rbx, fault_recovery_sp
    mov rbx, [rbx]
    mov rsp, rbx

    // Print an error message
    lea rdi, .Lrecovery_triggered_msg
    call _printk

    // Return error code 1
    mov rax, 1

    jmp .run_experiment_normal_exit
    // END CRITICAL SECTION

.run_experiment_normal_exit:
    // preserve err (rax)
    push rax

    // Restore original fault handlers
    call unset_outer_fault_handlers
    pop rax  // restore err

    // Restore the original CPU state
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx

    ret
    unreachable
