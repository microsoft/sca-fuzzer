/// File: Configuration and use of performance counters
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/kernel.h>
#include <linux/types.h>

#include "shortcuts.h"

#include "hw_features/perf_counters.h"

struct pfc_config {
    unsigned long evt_num;
    unsigned long umask;
    unsigned long cmask;
    unsigned int any;
    unsigned int edge;
    unsigned int inv;
};

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

int pfc_configure(void)
{
    int err = 0;

    // Make sure that PCE bit is set in CR4
    uint64_t cr4 = __read_cr4();
    __write_cr4(cr4 | (1 << 8));

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

// =================================================================================================
int init_perf_counters(void) { return 0; }
void free_perf_counters(void) {}
