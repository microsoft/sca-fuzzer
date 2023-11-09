/// File:
///  - Test case execution
///  - Ensuring an isolated environment
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/msr-index.h>

#include "code_loader.h"
#include "data_loader.h"
#include "input_parser.h"
#include "main.h"
#include "measurement.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "hw_features/fault_handler.h"
#include "hw_features/page_table.h"
#include "hw_features/perf_counters.h"

measurement_t *measurements = NULL; // global
cpu_state_t *orig_cpu_state = NULL; // global

int unsafe_bubble(void);

// =================================================================================================
// CPU configuration
// =================================================================================================

/// @brief Configure the CPU features and extensions
/// @param void
/// @return 0 on success, -1 on failure
static int cpu_configure(void)
{
#if VENDOR_ID == 1 // Intel
    // Configure uarch patches
    wrmsr64(MSR_IA32_SPEC_CTRL, ssbp_patch_control);

    // Configure extensions
    wrmsr64(MSR_IA32_BNDCFGS, mpx_control);

    // Disable prefetchers
    wrmsr64(0x1a4, prefetcher_control);

#elif VENDOR_ID == 2 // AMD
    // ...
#if CPU_FAMILY == 25
    // Configure uarch patches
    wrmsr64(MSR_IA32_SPEC_CTRL, ssbp_patch_control);

    // Disable prefetchers
    wrmsr64(0xc0000108, prefetcher_control);
#elif CPU_FAMILY == 23
    // Disable prefetchers
    uint64_t dc_config = native_read_msr(0xC0011022); // Data Cache Configuration
    dc_config |= (1 << 13);
    dc_config |= (1 << 15);
    wrmsr64(0xC0011022, dc_config);
#endif

#endif
    return 0;
}

/// @brief Restores the CPU features and extensions
/// @param void
/// @return 0 on success, -1 on failure
int cpu_restore(void)
{
#if VENDOR_ID == 1 // Intel
    wrmsr64(MSR_IA32_BNDCFGS, 0ULL);
#endif
    return 0;
}

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

static inline void clear_orig_cpu_state(void) {
    orig_cpu_state->lstar = 0;
}

void restore_orig_cpu_state(void) {
    if (orig_cpu_state->lstar) {
        wrmsr64(MSR_LSTAR, orig_cpu_state->lstar);
        orig_cpu_state->lstar = 0;
    }
    unset_bubble_idt();   // restores original IDT regardless of the current IDTR value
}

// =================================================================================================
// Measurement
// =================================================================================================
int run_experiment(void)
{
    int err = 0;
    clear_orig_cpu_state();

    // If necessary, configure userspace
    if (test_case->features.includes_user_actors) {
#ifdef FORCE_SMAP_OFF
        uint64_t cr4 = __read_cr4();
        cr4 &= ~(X86_CR4_SMAP | X86_CR4_SMEP);
        asm volatile("mov %0, %%cr4" : : "r"(cr4));
#endif

        err = map_user_pages();
        CHECK_ERR("run_experiment:map_user_pages");

        orig_cpu_state->lstar = rdmsr64(MSR_LSTAR);
        wrmsr64(MSR_LSTAR, (uint64_t)fault_handler);
    }

    // Zero-initialize the region of memory used by Prime+Probe
    if (!quick_and_dirty_mode)
        memset(&sandbox->util->l1d_priming_area[0], 0, L1D_PRIMING_AREA_SIZE * sizeof(char));

    long rounds = (long)n_inputs;
    for (long i = -uarch_reset_rounds; i < rounds; i++) {
        // ignore "warm-up" runs (i<0)uarch_reset_rounds
        long i_ = (i < 0) ? 0 : i;

        // Try to reset the uarch state
        // (we do it here because from this point on the execution is expected to be deterministic
        // and depend solely on the test case and the input to it)
        if (pre_run_flush == 1 && !quick_and_dirty_mode)
            uarch_flush();

        // Prepare sandbox
        load_sandbox_data(i_);
        faulty_page_pte_store();
        faulty_page_pte_set();

        // Catch all exceptions
        set_test_case_idt();

        // execute
        char *main_data = &sandbox->data[0].main_area[0];
        err = ((int (*)(char *))loaded_test_case_entry)(main_data);

        unset_test_case_idt();
        faulty_page_pte_restore();
        if (err)
            goto cleanup;

        // store the measurement
        // printk(KERN_ERR "x86_executor: measurement %llu\n", result.htrace[0]);
        measurement_t result = sandbox->util->latest_measurement;
        measurements[i_].htrace[0] = result.htrace[0];
        memcpy(measurements[i_].pfc_reading, result.pfc_reading, sizeof(uint64_t) * NUM_PFC);
    }

cleanup:
    restore_orig_cpu_state();
    if (test_case->features.includes_user_actors) {
        err |= unmap_user_pages();
    }
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

    // ensure that the test case is executable
    pte_t *tc_pte = get_pte((uint64_t)loaded_test_case_entry);
    ASSERT(tc_pte && pte_present(*tc_pte) && pte_exec(*tc_pte), "trace_test_case");

    // Pre-measurement setup
    err |= pfc_configure();
    CHECK_ERR("trace_test_case:pfc_configure");

    err |= faulty_page_prepare();
    CHECK_ERR("trace_test_case:faulty_page_prepare");

    kernel_fpu_begin(); // Enable FPU - just in case, we might use it within the test case
    err |= cpu_configure();
    if (err)
        goto trace_test_case_cleanup;

    // prevent preemption
    get_cpu();
    raw_local_irq_save(flags);

    // Measurement
    if (n_inputs) {
        err |= unsafe_bubble();
    }

    // Post-measurement cleanup
    raw_local_irq_restore(flags);
    put_cpu();

trace_test_case_cleanup:
    cpu_restore();
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
    orig_cpu_state = CHECKED_ZALLOC(sizeof(cpu_state_t));
    return 0;
}

/// Destructor for the measurement module
///
void free_measurements(void)
{
    SAFE_VFREE(measurements);
    SAFE_FREE(orig_cpu_state);
}
