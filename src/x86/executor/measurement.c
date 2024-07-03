/// File:
///  - Test case execution
///  - Ensuring an isolated environment
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/spec-ctrl.h>

#include "code_loader.h"
#include "data_loader.h"
#include "input_parser.h"
#include "main.h"
#include "measurement.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "fault_handler.h"
#include "host_page_tables.h"
#include "memory_guest.h"
#include "perf_counters.h"
#include "special_registers.h"
#include "vmx.h"
#include "svm.h"

#include <../arch/x86/include/asm/desc.h>

measurement_t *measurements = NULL; // global

int unsafe_bubble(void);

// =================================================================================================
// CPU configuration
// =================================================================================================

static inline int uarch_flush(void)
{
#if VENDOR_ID == 1 // Intel
    static const u16 ds = __KERNEL_DS;
    asm volatile("verw %[ds]" : : [ds] "m"(ds) : "cc");
#ifndef VMBUILD
    wrmsr64(MSR_IA32_FLUSH_CMD, L1D_FLUSH);
#endif
    asm volatile("wbinvd\n" : : :);
    asm volatile("lfence\n" : : :);
#elif VENDOR_ID == 2 // AMD
    // TBD
#endif
    return 0;
}

static int set_execution_environment(void)
{
    int err = 0;
    err = set_special_registers();
    CHECK_ERR("set_execution_environment:set_special_registers");

    // If necessary, enable VM operation
    if (test_case->features.includes_vm_actors) {
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            err = start_vmx_operation();
            CHECK_ERR("set_execution_environment:start_vmx_operation");

            err = store_orig_vmcs_state();
            CHECK_ERR("set_execution_environment:store_orig_vmcs_state");

            err = set_vmcs_state();
            CHECK_ERR("set_execution_environment:set_vmcs_state");
        } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
            err = start_svm_operation();
            CHECK_ERR("set_execution_environment:start_svm_operation");

            err = store_orig_vmcb_state();
            CHECK_ERR("set_execution_environment:store_orig_vmcb_state");

            err = set_vmcb_state();
            CHECK_ERR("set_execution_environment:set_vmcb_state");
        }
    }
    return 0;
}

/// @brief Restores the CPU state to the state before the test case execution. This function is
/// written in a fail-safe manner, so that it can be called in fault handlers.
/// @param void
void recover_orig_state(void)
{
    // restore VMX state
    if (test_case->features.includes_vm_actors) {
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            // if (vmx_is_on)
            //     print_vmx_exit_info(); // uncomment to debug VMX exits
            restore_orig_vmcs_state();
            stop_vmx_operation();
        } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
            // if (svm_is_on)
            //     print_svm_exit_info(); // uncomment to debug SVM exits
            restore_orig_vmcb_state();
            stop_svm_operation();
        }
    }

    restore_special_registers();
    unset_bubble_idt(); // restores original IDT regardless of the current IDTR value
    restore_orig_sandbox_page_tables();
}

// =================================================================================================
// Measurement
// =================================================================================================
int run_experiment(void)
{
    int err = 0;

    err = set_sandbox_page_tables();
    if (err)
        goto cleanup;

    err = set_execution_environment();
    if (err)
        goto cleanup;

    // Zero-initialize the region of memory used by Prime+Probe
    if (!quick_and_dirty_mode)
        memset(&sandbox->util->l1d_priming_area[0], 0, L1D_PRIMING_AREA_SIZE * sizeof(char));

    // Try to reset the uarch state
    // (we do it here because from this point on the execution is expected to be deterministic
    // and depend solely on the test case and the input to it)
    if (pre_run_flush == 1 && !quick_and_dirty_mode)
        uarch_flush();

    long rounds = (long)n_inputs;
    for (long i = -uarch_reset_rounds; i < rounds; i++) {
        // ignore "warm-up" runs (i<0)uarch_reset_rounds
        long i_ = (i < 0) ? 0 : i;

        // Prepare sandbox
        load_sandbox_data(i_);
        set_faulty_page_permissions();

        // Catch all exceptions
        set_test_case_idt();

        // execute
        char *main_data = &sandbox->data[0].main_area[0];
        err = ((int (*)(char *))loaded_test_case_entry)(main_data);

        unset_test_case_idt();
        restore_faulty_page_permissions();
        if (err)
            goto cleanup;

        // store the measurement
        // printk(KERN_ERR "x86_executor: measurement %llu\n", result.htrace[0]);
        measurement_t result = sandbox->util->latest_measurement;
        measurements[i_].htrace[0] = result.htrace[0];
        memcpy(measurements[i_].pfc_reading, result.pfc_reading, sizeof(uint64_t) * NUM_PFC);
    }

cleanup:
    if (err)
        measurements[0].htrace[0] = 0; // communicate the error up to x86_executor.py
    recover_orig_state();
    CHECK_ERR("run_experiment:cleanup");
    return err;
}

/// @brief A wrapper function that ensures that any bugs in run_experiment that cause an exception
///        will be handled gracefully and won't crash the system
/// @param void
__attribute__((unused)) void unsafe_bubble_wrapper(void)
{
    asm volatile(""
                 ".global unsafe_bubble\n"
                 "unsafe_bubble:\n"
                 "push %%rbx\n"
                 "push %%rcx\n"
                 "push %%rdx\n"
                 "push %%rsi\n"
                 "push %%rdi\n"
                 "push %%r8\n"
                 "push %%r9\n"
                 "push %%r10\n"
                 "push %%r11\n"
                 "push %%r12\n"
                 "push %%r13\n"
                 "push %%r14\n"
                 "push %%r15\n"
                 "push %%rbp\n"
                 "cli\n" // should be already disabled, but just in case
                 "pushfq\n"

                 "mov %%rsp, %[rsp_save]\n"

                 // CRITICAL: keep enough space for the local variables
                 "sub $0x1000, %%rsp\n"
                 "mov %%rsp, %%rbp\n"

                 : [rsp_save] "=m"(pre_bubble_rsp)
                 :);
    uint64_t err = 0;

    set_bubble_idt();
    err = run_experiment();
    unset_bubble_idt();

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
                 "mov %[err], %%rax\n"

                 "ret\n"
                 "int3\n" // Silences objtool warnings about no int3 after ret
                 : [rsp_save] "=m"(pre_bubble_rsp), [err] "+a"(err)
                 :);
    // Unreachable
    asm volatile("UD2\n");
}

/// @brief The outermost wrapper for the test case execution. Sets up performance counters,
///        configures the CPU, disables interrupts, and calls unsafe_bubble
/// @param void
/// @return 0 on success, -1 on failure
int trace_test_case(void)
{
    int err = 0;
    unsigned long flags;

    err = alloc_measurements();
    CHECK_ERR("alloc_measurements");

    // check that all main data structures were allocated
    ASSERT(loaded_test_case_entry, "trace_test_case");
    ASSERT(inputs, "trace_test_case");
    ASSERT(inputs->metadata, "trace_test_case");
    ASSERT(inputs->data, "trace_test_case");

    // check that the test case is executable
    pte_t *tc_pte = get_pte((uint64_t)loaded_test_case_entry);
    ASSERT(tc_pte && pte_present(*tc_pte) && pte_exec(*tc_pte), "trace_test_case");

    // Pre-measurement setup
    err |= pfc_configure();
    CHECK_ERR("trace_test_case:pfc_configure");

    kernel_fpu_begin(); // Enable FPU - just in case, we might use it within the test case

    // prevent preemption
    get_cpu();
    raw_local_irq_save(flags);

    // Measurement
    if (n_inputs) {
        err |= unsafe_bubble();
    }

    // Post-measurement cleanup
#if VENDOR_ID == VENDOR_AMD_
    asm volatile("stgi\n"); // enable interrupts in case they were disabled
#endif
    raw_local_irq_restore(flags);
    put_cpu();

    kernel_fpu_end();
    CHECK_ERR("trace_test_case:cleanup");
    return err;
}

int alloc_measurements(void)
{
    static int old_n_inputs = 0;
    if (n_inputs <= old_n_inputs)
        return 0;
    old_n_inputs = n_inputs;

    SAFE_VFREE(measurements);
    measurements = CHECKED_VMALLOC(n_inputs * sizeof(measurement_t));
    memset(measurements, 0, n_inputs * sizeof(measurement_t));
    return 0;
}

// =================================================================================================
int init_measurements(void)
{
    measurements = CHECKED_VMALLOC(sizeof(measurement_t));
    return 0;
}

/// Destructor for the measurement module
///
void free_measurements(void) { SAFE_VFREE(measurements); }
