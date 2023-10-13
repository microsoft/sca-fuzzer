/// File: Kernel module interface
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang-format off
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/version.h>
#include <linux/kobject.h>
// clang-format on

#include "main.h"
#include "actor_manager.h"
#include "code_loader.h"
#include "data_loader.h"
#include "hardware_desc.h"
#include "input_parser.h"
#include "macro_loader.h"
#include "measurement.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "hw_features/fault_handler.h"
#include "hw_features/page_table.h"
#include "hw_features/perf_counters.h"

// Version-dependent includes
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 6)
#include <../arch/x86/include/asm/io.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 12, 0)
#include <asm/cacheflush.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#include <linux/kallsyms.h>
int (*set_memory_x)(unsigned long, int) = 0;
int (*set_memory_nx)(unsigned long, int) = 0;
#else
#include <linux/set_memory.h>
#endif

// =================================================================================================
// Global Variables
bool quick_and_dirty_mode = false;

long uarch_reset_rounds = UARCH_RESET_ROUNDS_DEFAULT;
uint64_t ssbp_patch_control = SSBP_PATH_DEFAULT;
uint64_t prefetcher_control = PREFETCHER_DEFAULT;
uint64_t mpx_control = MPX_DEFAULT; // unused on AMD
char pre_run_flush = PRE_RUN_FLUSH_DEFAULT;
measurement_mode_e measurement_mode = MEASUREMENT_MODE_DEFAULT;
bool dbg_gpr_mode = DBG_GPR_MODE_DEFAULT;

// =================================================================================================
// Local declarations and definitions
#define SYSFS_DIRNAME "x86_executor"
static struct kobject *kobj_interface;

unsigned inputs_top = 0;
bool inputs_ready = false;
bool tc_ready = false;

// =================================================================================================
// SysFS interface to the module

/* warning! need write-all permission so overriding check */
#undef VERIFY_OCTAL_PERMISSIONS
#define VERIFY_OCTAL_PERMISSIONS(perms) (perms)

/// Reading hardware traces and performance counters
///
static ssize_t trace_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static struct kobj_attribute trace_attribute = __ATTR(trace, 0664, trace_show, NULL);

/// Loading a test case
///
static ssize_t test_case_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                               size_t count);
static ssize_t test_case_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static struct kobj_attribute test_case_attribute =
    __ATTR(test_case, 0666, test_case_show, test_case_store);

/// Loading inputs
///
static ssize_t inputs_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                            size_t count);
static ssize_t inputs_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static struct kobj_attribute inputs_attribute = __ATTR(inputs, 0666, inputs_show, inputs_store);

/// Setting the number of warm up rounds
///
static ssize_t warmups_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t warmups_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                             size_t count);
static struct kobj_attribute warmups_attribute = __ATTR(warmups, 0666, warmups_show, warmups_store);

/// Getting the sandbox base address
///
static ssize_t print_sandbox_base_show(struct kobject *kobj, struct kobj_attribute *attr,
                                       char *buf);
static struct kobj_attribute print_sandbox_base_attribute =
    __ATTR(print_sandbox_base, 0664, print_sandbox_base_show, NULL);

/// Getting the base address of the memory region where the test case is loaded
///
static ssize_t print_code_base_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static struct kobj_attribute print_code_base_attribute =
    __ATTR(print_code_base, 0664, print_code_base_show, NULL);

/// Control SSBP patch
///
static ssize_t enable_ssbp_patch_store(struct kobject *kobj, struct kobj_attribute *attr,
                                       const char *buf, size_t count);
static struct kobj_attribute enable_ssbp_patch_attribute =
    __ATTR(enable_ssbp_patch, 0666, NULL, enable_ssbp_patch_store);

/// Control prefetchers
///
static ssize_t enable_prefetcher_store(struct kobject *kobj, struct kobj_attribute *attr,
                                       const char *buf, size_t count);
static struct kobj_attribute enable_prefetcher_attribute =
    __ATTR(enable_prefetcher, 0666, NULL, enable_prefetcher_store);

/// Control flushing
///
static ssize_t enable_pre_run_flush_store(struct kobject *kobj, struct kobj_attribute *attr,
                                          const char *buf, size_t count);
static struct kobj_attribute enable_pre_run_flush_attribute =
    __ATTR(enable_pre_run_flush, 0666, NULL, enable_pre_run_flush_store);

/// Vendor-specific features
#if VENDOR_ID == 1 // Intel
// MPX control
static ssize_t enable_mpx_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                                size_t count);
static struct kobj_attribute enable_mpx_attribute =
    __ATTR(enable_mpx, 0666, NULL, enable_mpx_store);
#endif

/// Bitmask that control which pte bits to flip
//
static ssize_t faulty_pte_mask_store(struct kobject *kobj, struct kobj_attribute *attr,
                                     const char *buf, size_t count);
static struct kobj_attribute pte_mask_attribute =
    __ATTR(faulty_pte_mask, 0666, NULL, faulty_pte_mask_store);

/// Measurement template selector
///
static ssize_t measurement_mode_store(struct kobject *kobj, struct kobj_attribute *attr,
                                      const char *buf, size_t count);
static struct kobj_attribute measurement_mode_attribute =
    __ATTR(measurement_mode, 0666, NULL, measurement_mode_store);

/// Q&D mode selector
///
static ssize_t enable_quick_and_dirty_mode(struct kobject *kobj, struct kobj_attribute *attr,
                                           const char *buf, size_t count);
static struct kobj_attribute enable_quick_and_dirty_mode_attribute =
    __ATTR(enable_quick_and_dirty_mode, 0666, NULL, enable_quick_and_dirty_mode);

/// Debug GPR mode selector
///
static ssize_t enable_dbg_gpr_mode(struct kobject *kobj, struct kobj_attribute *attr,
                                   const char *buf, size_t count);
static struct kobj_attribute enable_dbg_gpr_mode_attribute =
    __ATTR(enable_dbg_gpr_mode, 0666, NULL, enable_dbg_gpr_mode);

/// Debugging interface
///
static ssize_t dbg_dump_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static struct kobj_attribute dbg_dump_attribute = __ATTR(dbg_dump_mode, 0666, dbg_dump_show, NULL);

static struct attribute *sysfs_attributes[] = {
    &trace_attribute.attr,
    &test_case_attribute.attr,
    &inputs_attribute.attr,
    &warmups_attribute.attr,
    &print_sandbox_base_attribute.attr,
    &print_code_base_attribute.attr,
    &enable_ssbp_patch_attribute.attr,
    &enable_prefetcher_attribute.attr,
    &enable_pre_run_flush_attribute.attr,
    &measurement_mode_attribute.attr,
    &enable_quick_and_dirty_mode_attribute.attr,
    &enable_dbg_gpr_mode_attribute.attr,
    &pte_mask_attribute.attr,
    &dbg_dump_attribute.attr,
#if VENDOR_ID == 1 // Intel
    &enable_mpx_attribute.attr,
#endif
    NULL, /* need to NULL terminate the list of attributes */
};

// =================================================================================================
// Implementation of the sysfs attributes

int next_measurement_id = -1;
static ssize_t trace_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int count = 0;
    int retval = 0;

    ASSERT(measurements, "trace_show");
    ASSERT(input_parsing_completed(), "trace_show");
    ASSERT(tc_parsing_completed(), "trace_show");

    // start a new measurement?
    if (next_measurement_id < 0) {
        int err = trace_test_case();
        if (err)
            return -EIO;

        // start printing the results
        next_measurement_id = n_inputs - 1;
    }

    // print the results, but make sure we can continue later if we run out of space in buf
    for (; next_measurement_id >= 0; next_measurement_id--) {
        // check if the output buffer still has space
        if (count >= (4096 - 128))
            return count; // we will continue in the next call of this function

        measurement_t m = measurements[next_measurement_id];
        retval =
            sprintf(&buf[count], "%llu,%llu,%llu,%llu,%llu,%llu\n", m.htrace[0], m.pfc_reading[0],
                    m.pfc_reading[1], m.pfc_reading[2], m.pfc_reading[3], m.pfc_reading[4]);
        if (!retval)
            return -1;
        count += retval;
    }
    count += sprintf(&buf[count], "done\n");
    return count;
}

static ssize_t faulty_pte_mask_store(struct kobject *kobj, struct kobj_attribute *attr,
                                     const char *buf, size_t count)
{
    sscanf(buf, "%lu %lu", &faulty_pte_mask_set, &faulty_pte_mask_clear);
    return count;
}

static ssize_t test_case_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                               size_t count)
{
    bool finished = false;
    ssize_t consumed_bytes = parse_test_case_buffer(buf, count, &finished);
    tc_ready = false;

    if (finished) {
        // prepare sandboxes
        int err = allocate_sandbox();
        CHECK_ERR("allocate_sandbox");

        err = load_sandbox_code();
        CHECK_ERR("load_sandbox_code");

        next_measurement_id = -1;
        tc_ready = true;
    }
    return consumed_bytes;
}

static ssize_t test_case_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    for (int i = 0; i < 0xfff; i++) {
        sprintf(&buf[i], "%c", loaded_test_case_entry[i]);
    }
    return 0xfff;
}

static ssize_t inputs_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                            size_t count)
{
    bool finished = false;
    ssize_t consumed_bytes = parse_input_buffer(buf, count, &finished);
    inputs_ready = false;

    if (finished) {
        inputs_ready = true;
    }
    return consumed_bytes;
}

static ssize_t inputs_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    // FIXME: not implemented yet. See Flavien's branch for a reference implementation
    return sprintf(buf, "%d\n", inputs_ready);
}

static ssize_t warmups_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%ld\n", uarch_reset_rounds);
}

static ssize_t warmups_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                             size_t count)
{
    sscanf(buf, "%ld", &uarch_reset_rounds);
    return count;
}

static ssize_t print_sandbox_base_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%llx\n", (long long unsigned)sandbox->data[0].main_area);
}

static ssize_t print_code_base_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%llx\n", (long long unsigned)loaded_test_case_entry);
}

static ssize_t enable_ssbp_patch_store(struct kobject *kobj, struct kobj_attribute *attr,
                                       const char *buf, size_t count)
{
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    ssbp_patch_control = (value == 0) ? SSBP_PATCH_OFF : SSBP_PATCH_ON;
    return count;
}

static ssize_t enable_prefetcher_store(struct kobject *kobj, struct kobj_attribute *attr,
                                       const char *buf, size_t count)
{
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    prefetcher_control = (value == 0) ? PREFETCHER_OFF : PREFETCHER_ON;
    return count;
}

static ssize_t enable_pre_run_flush_store(struct kobject *kobj, struct kobj_attribute *attr,
                                          const char *buf, size_t count)
{
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    pre_run_flush = (value == 0) ? 0 : 1;
    return count;
}

// This function is unused on AMD
static ssize_t enable_mpx_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                                size_t count)
{
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    mpx_control = (value == 0) ? 0 : 1;
    return count;
}

static ssize_t measurement_mode_store(struct kobject *kobj, struct kobj_attribute *attr,
                                      const char *buf, size_t count)
{
    switch (buf[0]) {
    case 'P':
        if (buf[1] == '+')
            measurement_mode = PRIME_PROBE;
        else
            measurement_mode = PARTIAL_PRIME_PROBE;
        break;
    case 'F':
        measurement_mode = FLUSH_RELOAD;
        break;
    case 'E':
        measurement_mode = EVICT_RELOAD;
        break;
    case 'T':
        measurement_mode = TSC;
        break;
    default:
        PRINT_ERRS("measurement_mode_store", "Invalid measurement mode\n");
        return -1;
    }

    quick_and_dirty_mode = false; // updating the measurement mode resets the Q&D mode
    return count;
}

static ssize_t enable_quick_and_dirty_mode(struct kobject *kobj, struct kobj_attribute *attr,
                                           const char *buf, size_t count)
{

    unsigned value = 0;
    sscanf(buf, "%u", &value);
    if (value == 1 && quick_and_dirty_mode == false) {
        quick_and_dirty_mode = true;
        switch (measurement_mode) {
        case PRIME_PROBE:
            measurement_mode = FAST_PRIME_PROBE;
            break;
        case PARTIAL_PRIME_PROBE:
            measurement_mode = FAST_PARTIAL_PRIME_PROBE;
            break;
        default:
            break;
        }
    } else if (value == 0 && quick_and_dirty_mode == true) {
        quick_and_dirty_mode = false;
        switch (measurement_mode) {
        case FAST_PRIME_PROBE:
            measurement_mode = PRIME_PROBE;
            break;
        case FAST_PARTIAL_PRIME_PROBE:
            measurement_mode = PARTIAL_PRIME_PROBE;
            break;
        default:
            break;
        }
    }
    return count;
}

static ssize_t enable_dbg_gpr_mode(struct kobject *kobj, struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    dbg_gpr_mode = (value == 0) ? false : true;
    return count;
}

/// Dump all global variables into the kernel log
///
static ssize_t dbg_dump_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int len = 0;
    len += sprintf(&buf[len], "n_actors: %lu\n", n_actors);
    len += sprintf(&buf[len], "test_case: 0x%llx\n", (uint64_t)test_case);
    len += sprintf(&buf[len], "loaded_test_case_entry: 0x%llx\n", (uint64_t)loaded_test_case_entry);
    len += sprintf(&buf[len], "measurements: 0x%llx\n", (uint64_t)measurements);
    len += sprintf(&buf[len], "n_inputs: %lu\n", n_inputs);
    len += sprintf(&buf[len], "inputs: %llx\n", (uint64_t)inputs);
    if (inputs) {
        len += sprintf(&buf[len], "inputs->metadata: %llx\n", (uint64_t)inputs->metadata);
        len += sprintf(&buf[len], "inputs->data: %llx\n", (uint64_t)inputs->data);
    }
    len += sprintf(&buf[len], "sandbox: %llx\n", (uint64_t)sandbox);
    len += sprintf(&buf[len], "fault_handler: %llx\n", (uint64_t)fault_handler);
    len += sprintf(&buf[len], "handled_faults: %u\n", handled_faults);
    len += sprintf(&buf[len], "faulty_pte_mask_set: %lu\n", faulty_pte_mask_set);
    len += sprintf(&buf[len], "faulty_pte_mask_clear: %lu\n", faulty_pte_mask_clear);
    len += sprintf(&buf[len], "quick_and_dirty_mode: %d\n", quick_and_dirty_mode);
    len += sprintf(&buf[len], "uarch_reset_rounds: %ld\n", uarch_reset_rounds);
    len += sprintf(&buf[len], "ssbp_patch_control: %llu\n", ssbp_patch_control);
    len += sprintf(&buf[len], "prefetcher_control: %llu\n", prefetcher_control);
    len += sprintf(&buf[len], "pre_run_flush: %d\n", pre_run_flush);
    len += sprintf(&buf[len], "mpx_control: %llu\n", mpx_control);
    return len;
}

// ============================================================================
// Memory Management and Initialization

/// Get symbols for set_memory_x and set_memory_nx
///
static inline void _get_required_kernel_functions(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
#endif // KPROBE_LOOKUP
    set_memory_x = (void *)kallsyms_lookup_name("set_memory_x");
    set_memory_nx = (void *)kallsyms_lookup_name("set_memory_nx");
#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
}

static int __init executor_init(void)
{
    // Check CPU vendor
    struct cpuinfo_x86 *c = &cpu_data(0);
    if (c->x86_vendor != X86_VENDOR_INTEL && c->x86_vendor != X86_VENDOR_AMD) {
        printk(KERN_ERR "x86_executor: This CPU vendor is not supported\n");
        return -1;
    }

    // Make sure that we have all requirements
    _get_required_kernel_functions();

    // Initialize modules
    int err = 0;
    err |= init_measurements();
    err |= init_sandbox_manager();
    err |= init_actor_manager();
    err |= init_code_loader();
    err |= init_data_loader();
    err |= init_macros_loader();
    err |= init_input_parser();
    err |= init_test_case_parser();
    err |= init_fault_handler();
    err |= init_page_table_manager();
    err |= init_perf_counters();
    CHECK_ERR("executor_init");

    // Create a pseudo file system interface
    kobj_interface = kobject_create_and_add(SYSFS_DIRNAME, kernel_kobj->parent);
    if (!kobj_interface) {
        printk(KERN_ERR "x86_executor: Failed to create a sysfs directory for x86-executor\n");
        return -ENOMEM;
    }

    // Create the files associated with this kobject
    // int retval = sysfs_create_group(kobj_interface, &attr_group);
    int i = 0;
    struct attribute *attr;
    for (attr = sysfs_attributes[i]; !err; i++) {
        attr = sysfs_attributes[i];
        if (attr == NULL)
            break;

        err = sysfs_create_file(kobj_interface, attr);
    }
    if (err != 0) {
        printk(KERN_ERR "x86_executor: Failed to create a sysfs group\n");
        kobject_put(kobj_interface);
        return err;
    }

    return 0;
}

static void __exit executor_exit(void)
{
    free_measurements();
    free_sandbox_manager();
    free_actor_manager();
    free_code_loader();
    free_data_loader();
    free_macros_loader();
    free_input_parser();
    free_test_case_parser();
    free_fault_handler();
    free_page_table_manager();
    free_perf_counters();

    if (kobj_interface)
        kobject_put(kobj_interface);
}

module_init(executor_init);
module_exit(executor_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Oleksii Oleksenko");
