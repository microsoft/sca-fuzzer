/// File: Configuration and use of performance counters
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/msr-index.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "main.h"
#include "shortcuts.h"

#include "perf_counters.h"

struct pfc_config {
    unsigned long evt_num;
    unsigned long umask;
    unsigned long cmask;
    unsigned int any;
    unsigned int edge;
    unsigned int inv;
};

typedef enum {
    L1_HITS = 0,
    UOPS_ISSUED_ANY = 1,
    UOPS_RETIRED_ANY = 2,
    MISPREDICTION_RECOVERY_CYCLES = 3,
    HW_INTERRUPTS_RECEIVED = 4,
    SMI_INTERRUPTS_RECEIVED = 5,
    DECODE_REDIRECTS = 6
} pfc_name_e;

static int get_pfc_config_by_name(pfc_name_e pfc_name, struct pfc_config *config)
{
    uint64_t family = cpuinfo->x86;
    uint64_t model = cpuinfo->x86_model;

    // most commonly, the fields cmask, any, edge, and inv are set to 0
    config->cmask = 0;
    config->any = 0;
    config->edge = 0;
    config->inv = 0;

    // Intel PMU
    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        switch (pfc_name) {
        case L1_HITS:
            //   MEM_LOAD_RETIRED.L1_HIT: Counts retired load instructions with at least one uop
            //   that hit in the L1 data cache. This event includes all SW prefetches and lock
            //   instructions regardless of the data source.
            config->evt_num = 0xd1;
            config->umask = 0x01;
            break;
        case UOPS_ISSUED_ANY:
            //   UOPS_ISSUED.ANY: Counts the number of uops that the Resource Allocation Table (RAT)
            //   issues to the Reservation Station (RS).
            if (model == 0xBA || model == 0xB7 || model == 0xBF || model == 0x97 || model == 0x9A) {
                config->evt_num = 0xAE;
                config->umask = 0x01;
            } else {
                config->evt_num = 0x0E;
                config->umask = 0x01;
            }
            break;
        case UOPS_RETIRED_ANY:
            //   UOPS_RETIRED.RETIRE_SLOTS: Counts the retirement slots used.
            config->evt_num = 0xC2;
            config->umask = 0x02;
            break;
        case MISPREDICTION_RECOVERY_CYCLES:
            //   INT_MISC.CLEAR_RESTEER_CYCLES: Cycles the issue-stage is waiting for front-end to
            //   fetch from resteered path following branch misprediction or machine clear events.
            if (model == 0xBA || model == 0xB7 || model == 0xBF || model == 0x97 || model == 0x9A) {
                config->evt_num = 0xAD;
                config->umask = 0x80;
            } else {
                config->evt_num = 0x0D;
                config->umask = 0x01;
            }
            break;
        case HW_INTERRUPTS_RECEIVED:
            //   HW_INTERRUPTS.RECEIVED: Counts the number of hardware interruptions received by the
            //   processor.
            config->evt_num = 0xCB;
            config->umask = 0x01;
            break;
        default:
            return -1;
        }
        return 0;
    }

    // AMD PMU
    if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        switch (pfc_name) {
        case L1_HITS:
            switch (family) {
            case 0x1a:
            case 0x19:
                // Any Data Cache Fills by Data Source
                config->evt_num = 0x44;
                config->umask = 0xff;
                break;
            default:
                config->evt_num = 0x43;
                config->umask = 0xff;
            }
            break;
        case UOPS_ISSUED_ANY:
            // Dispatched ops
            switch (family) {
            case 0x17:
                // there's no reliable counter of dispatched ops on this family (at least that
                // I know of), so we use a dummy counter that always returns zero; this way,
                // we effectively disable the speculation filter
                config->evt_num = 0x00;
                config->umask = 0x00;
                break;
            default:
                config->evt_num = 0xAB;
                config->umask = 0xff;
            }
            break;
        case UOPS_RETIRED_ANY:
            // Retired ops
            config->evt_num = 0xC1;
            config->umask = 0x00;
            break;
        case MISPREDICTION_RECOVERY_CYCLES:
            // Decode redirects
            config->evt_num = 0x91;
            config->umask = 0x00;
            break;
        case SMI_INTERRUPTS_RECEIVED:
            // SMI monitoring
            config->evt_num = 0x2c;
            config->umask = 0x00;
            break;
        default:
            return -1;
        }
        return 0;
    }

    // unsupported vendor
    return -1;
}

/// @brief  Clears the programmable performance counters and writes the
///         configurations to the corresponding MSRs.
/// @param  void
/// @return 0 on success, -1 on failure
static int pfc_write(unsigned int id, struct pfc_config *config, unsigned int usr, unsigned int os)
{
    uint64_t perf_configuration = 0;
#if VENDOR_ID == 1
    uint64_t global_ctrl = native_read_msr(MSR_CORE_PERF_GLOBAL_CTRL);
    global_ctrl |= ((uint64_t)7 << 32) | 15;
    wrmsr64(MSR_CORE_PERF_GLOBAL_CTRL, global_ctrl);

    perf_configuration = native_read_msr(MSR_P6_EVNTSEL0 + id);

    // disable the counter
    perf_configuration &= ~(((uint64_t)1 << 32) - 1);
    wrmsr64(MSR_P6_EVNTSEL0 + id, perf_configuration);

    // clear
    wrmsr64(MSR_IA32_PERFCTR0 + id, 0ULL);

    perf_configuration |= ((config->cmask & 0xFF) << 24);
    perf_configuration |= (config->inv << 23);
    perf_configuration |= (1ULL << 22);
    perf_configuration |= (config->any << 21);
    perf_configuration |= (config->edge << 18);
    perf_configuration |= (os << 17);
    perf_configuration |= (usr << 16);
    perf_configuration |= ((config->umask & 0xFF) << 8);
    perf_configuration |= (config->evt_num & 0xFF);
    wrmsr64(MSR_P6_EVNTSEL0 + id, perf_configuration);
#elif VENDOR_ID == 2
    perf_configuration = 0;
    perf_configuration |= ((config->evt_num) & 0xF00) << 24;
    perf_configuration |= (config->evt_num) & 0xFF;
    perf_configuration |= ((config->umask) & 0xFF) << 8;
    perf_configuration |= ((config->cmask) & 0x7F) << 24;
    perf_configuration |= (config->inv << 23);
    perf_configuration |= (1ULL << 22);
    perf_configuration |= (config->edge << 18);
    perf_configuration |= (os << 17);
    perf_configuration |= (usr << 16);
    wrmsr64(MSR_F15H_PERF_CTL + 2 * id, perf_configuration);
#endif
    return 0;
}

int pfc_configure(void)
{
    int err = 0;
    struct pfc_config config = {0};

    // Configure PMU
    // #0:  Htrace collection
    err |= get_pfc_config_by_name(L1_HITS, &config);
    CHECK_ERR("pfc_configure");
    err |= pfc_write(0, &config, 1, 1);
    CHECK_ERR("pfc_configure");

    // #1: Fuzzing feedback
    err |= get_pfc_config_by_name(UOPS_ISSUED_ANY, &config);
    CHECK_ERR("pfc_configure");
    err |= pfc_write(1, &config, 1, 1);
    CHECK_ERR("pfc_configure");

    // #2: Fuzzing feeback
    err |= get_pfc_config_by_name(UOPS_RETIRED_ANY, &config);
    CHECK_ERR("pfc_configure");
    err |= pfc_write(2, &config, 1, 1);
    CHECK_ERR("pfc_configure");

    // #3: Fuzzing feedback
    err |= get_pfc_config_by_name(MISPREDICTION_RECOVERY_CYCLES, &config);
    CHECK_ERR("pfc_configure");
    err |= pfc_write(3, &config, 1, 1);
    CHECK_ERR("pfc_configure");

    // #4: Interrupt detection
    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        err |= get_pfc_config_by_name(HW_INTERRUPTS_RECEIVED, &config);
        CHECK_ERR("pfc_configure");
        err |= pfc_write(4, &config, 1, 1);
        CHECK_ERR("pfc_configure");
    }

    // #5: SMI monitoring
    if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        err |= get_pfc_config_by_name(SMI_INTERRUPTS_RECEIVED, &config);
        CHECK_ERR("pfc_configure");
        err |= pfc_write(5, &config, 1, 1);
        CHECK_ERR("pfc_configure");
    }

    return err;
}

// =================================================================================================
int init_perf_counters(void) { return 0; }
void free_perf_counters(void) {}
