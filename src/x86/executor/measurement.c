/// File:
///  - Test case execution
///  - Ensuring an isolated environment
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "measurement.h"
#include "fault_handler.h"
#include "input.h"
#include "loader.h"
#include "main.h"
#include "page_table.h"
#include "sandbox.h"
#include "shortcuts.h"
#include "test_case.h"

measurement_t *measurements = NULL; // global

static int pfc_write(unsigned int id, char *pfc_code_org, unsigned int usr, unsigned int os);
int unsafe_bubble(void);

// =================================================================================================
// Performance counters and MSRs
// =================================================================================================
static int pfc_configure(void)
{
    int err = 0;
#if VENDOR_ID == 1 // Intel
    // Configure PMU
    // #0:  Htrace collection
    //   MEM_LOAD_RETIRED.L1_HIT: Counts retired load instructions with at least one uop that hit
    //   in the L1 data cache. This event includes all SW prefetches and lock instructions
    //   regardless of the data source.
    err |= pfc_write(0, "D1.01", 1, 1);

    // #1: Fuzzing feedback
    //   UOPS_ISSUED.ANY: Counts the number of uops that the Resource Allocation Table (RAT)
    //   issues to the Reservation Station (RS).
    err |= pfc_write(1, "0E.01", 1, 1); // 0E.01 - uops issued - fuzzing feedback

    // #2: Fuzzing feeback
    //   UOPS_RETIRED.RETIRE_SLOTS: Counts the retirement slots used.
    err |= pfc_write(2, "C2.02", 1, 1); // C2.02 - uops retirement slots - fuzzing feedback

    // #3: Fuzzing feedback
    //   INT_MISC.CLEAR_RESTEER_CYCLES: Cycles the issue-stage is waiting for front-end to fetch
    //   from resteered path following branch misprediction or machine clear events.
    err |= pfc_write(3, "0D.01", 1, 1); // misprediction recovery cycles - fuzzing feedback

    // #4: Interrupt detection
    //    HW_INTERRUPTS.RECEIVED: Counts the number of hardware interruptions received
    //    by the processor.
    err |= pfc_write(4, "CB.01", 1, 1); // detection of interrupts
#elif VENDOR_ID == 2                    // AMD
    // Configure PMU
#if CPU_FAMILY == 25
    err |= pfc_write(0, "044.ff", 1, 1); // Local L2->L1 cache fills - htrace collection
#elif CPU_FAMILY == 23
    err |= pfc_write(0, "043.ff", 1, 1);
#endif
    err |= pfc_write(5, "02c.00", 1, 1); // SMI monitoring

    err |= pfc_write(1, "0AB.88", 1, 1); // dispatched ops - fuzzing feedback
    err |= pfc_write(2, "0C1.00", 1, 1); // retired ops - fuzzing feedback
    err |= pfc_write(3, "091.00", 1, 1); // decode redirects - fuzzing feedback
    // err |= pfc_write(1, "05A.ff", 1, 1); // decode redirects - fuzzing feedback
#endif // VENDOR_ID
    return err;
}

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

    // Ensure SVM is disabled
    unsigned long long int msr_efer = rdmsr64(0xc0000080);
    if (msr_efer & EFER_SVME) {
        printk(KERN_ERR "x86_executor: ERROR: SVME is on. \nThis testing configuration is not "
                        "supported by Revizor yet.");
        return -1;
    }
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

/// @brief  Clears the programmable performance counters and writes the
///         configurations to the corresponding MSRs.
/// @param  void
/// @return 0 on success, -1 on failure
static int pfc_write(unsigned int id, char *pfc_code_org, unsigned int usr, unsigned int os)
{
    // Parse the PFC code name
    struct pfc_config config = {0};

    char pfc_code[50];
    strcpy(pfc_code, pfc_code_org);
    char *pfc_code_p = pfc_code;

    int err = 0;
    char *evt_num = strsep(&pfc_code_p, ".");
    err |= kstrtoul(evt_num, 16, &(config.evt_num));

    char *umask = strsep(&pfc_code_p, ".");
    err |= kstrtoul(umask, 16, &(config.umask));

    char *ce;
    while ((ce = strsep(&pfc_code_p, ".")) != NULL) {
        if (!strcmp(ce, "Any")) {
            config.any = 1;
        } else if (!strcmp(ce, "EDG")) {
            config.edge = 1;
        } else if (!strcmp(ce, "INV")) {
            config.inv = 1;
        } else if (!strncmp(ce, "CMSK=", 5)) {
            err |= kstrtoul(ce + 5, 0, &(config.cmask));
        }
    }

    if (err)
        return err;

    // Configure the counter
    uint64_t perf_configuration;
#if VENDOR_ID == 1
    uint64_t global_ctrl = native_read_msr(0x38F);
    global_ctrl |= ((uint64_t)7 << 32) | 15;
    wrmsr64(0x38F, global_ctrl);

    perf_configuration = native_read_msr(0x186 + id);

    // disable the counter
    perf_configuration &= ~(((uint64_t)1 << 32) - 1);
    wrmsr64(0x186 + id, perf_configuration);

    // clear
    wrmsr64(0x0C1 + id, 0ULL);

    perf_configuration |= ((config.cmask & 0xFF) << 24);
    perf_configuration |= (config.inv << 23);
    perf_configuration |= (1ULL << 22);
    perf_configuration |= (config.any << 21);
    perf_configuration |= (config.edge << 18);
    perf_configuration |= (os << 17);
    perf_configuration |= (usr << 16);
    perf_configuration |= ((config.umask & 0xFF) << 8);
    perf_configuration |= (config.evt_num & 0xFF);
    wrmsr64(0x186 + id, perf_configuration);
#elif VENDOR_ID == 2
    perf_configuration |= ((config.evt_num) & 0xF00) << 24;
    perf_configuration |= (config.evt_num) & 0xFF;
    perf_configuration |= ((config.umask) & 0xFF) << 8;
    perf_configuration |= ((config.cmask) & 0x7F) << 24;
    perf_configuration |= (config.inv << 23);
    perf_configuration |= (1ULL << 22);
    perf_configuration |= (config.edge << 18);
    perf_configuration |= (os << 17);
    perf_configuration |= (usr << 16);
    wrmsr64(0xC0010200 + 2 * id, perf_configuration);
#endif
    return 0;
}

// =================================================================================================
// Measurement
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

int run_experiment(long rounds)
{
    // Zero-initialize the region of memory used by Prime+Probe
    if (!quick_and_dirty_mode)
        memset(&sandbox->l1d_priming_area[0], 0, L1D_PRIMING_AREA_SIZE * sizeof(char));

    for (long i = -uarch_reset_rounds; i < rounds; i++) {
        // ignore "warm-up" runs (i<0)uarch_reset_rounds
        long i_ = (i < 0) ? 0 : i;
        int actor_id = 0; // we don't support multiple actors yet
        uint64_t *current_input = (uint64_t *)get_input_fragment_unsafe(i_, actor_id);

        // Zero-initialize the areas surrounding the sandbox
        if (!quick_and_dirty_mode) {
            memset(&sandbox->underflow_pad[0], 0, OVERFLOW_PAD_SIZE * sizeof(char));
            // NOTE: memset is not used intentionally! somehow, it messes up with P+P measurements
            for (int j = 0; j < OVERFLOW_PAD_SIZE / 8; j += 1) {
                // ((uint64_t *) sandbox->underflow_pad)[j] = 0;
                ((uint64_t *)sandbox->overflow_pad)[j] = 0;
            }
        }

        // Try to reset the uarch state
        // (we do it here because from this point on the execution is expected to be deterministic
        // and depend solely on the test case and the input to it)
        if (pre_run_flush == 1 && !quick_and_dirty_mode)
            uarch_flush();

        // Prepare sandbox
        write_sandbox(current_input);
        faulty_page_pte_store();
        faulty_page_pte_set();

        // Catch all exceptions
        set_test_case_idt();

        // execute
        ((void (*)(char *))loaded_main_section)(&sandbox->main_area[0]);

        unset_test_case_idt();
        faulty_page_pte_restore();

        // store the measurement
        // printk(KERN_ERR "x86_executor: measurement %llu\n", result.htrace[0]);
        measurement_t result = sandbox->latest_measurement;
        measurements[i_].htrace[0] = result.htrace[0];
        memcpy(measurements[i_].pfc, result.pfc, sizeof(uint64_t) * NUM_PFC);
    }
    return 0;
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

    set_bubble_idt();
    uint64_t err = run_experiment((long)n_inputs);
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
                 : [rsp_save] "=m"(pre_bubble_rsp), [err] "=r"(err)
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

    ASSERT(measurements, "trace_test_case");
    ASSERT(loaded_main_section, "trace_test_case");
    ASSERT(inputs, "trace_test_case");
    ASSERT(inputs->metadata, "trace_test_case");
    ASSERT(inputs->data, "trace_test_case");

    // Pre-measurement setup
    kernel_fpu_begin(); // Enable FPU - just in case, we might use it within the test case

    err |= pfc_configure();
    CHECK_ERR("pfc_configure");

    err |= cpu_configure();
    CHECK_ERR("cpu_configure");

    err |= faulty_page_prepare();
    CHECK_ERR("faulty_page_prepare");

    if (err)
        return err;

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
    cpu_restore();
    kernel_fpu_end();

    return err;
}

// =================================================================================================
// Allocation and Initialization
// =================================================================================================

/// Constructor for the measurement module
///
int alloc_measurements(void)
{
    static int old_n_inputs = 0;
    if (n_inputs <= old_n_inputs)
        return 0;
    old_n_inputs = n_inputs;

    SAFE_VFREE(measurements);
    measurements = CHECKED_VMALLOC(n_inputs * sizeof(measurement_t));
    return 0;
}

/// Constructor
///
int init_measurements(void)
{
    measurements = CHECKED_VMALLOC(sizeof(measurement_t));
    return 0;
}

/// Destructor for the measurement module
///
void free_measurements(void) { SAFE_VFREE(measurements); }
