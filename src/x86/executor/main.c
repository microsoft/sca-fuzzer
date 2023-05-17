/// File: Kernel module interface
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang-format off
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/kobject.h>
// clang-format on
#include <../arch/x86/include/asm/processor.h>

#include "main.h"

// =================================================================================================
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
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
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
char mpx_control = MPX_DEFAULT; // unused on AMD
char pre_run_flush = PRE_RUN_FLUSH_DEFAULT;
char *measurement_template = (char *)&template_l1d_prime_probe;
char *measurement_code = NULL;

void *sandbox_unaligned = NULL;
sandbox_t *sandbox = NULL;
void *stack_base = NULL;

char *test_case = NULL;
uint64_t *inputs = NULL;
volatile size_t n_inputs = 1;

uint32_t handled_faults = HANDLED_FAULTS_DEFAULT;
pteval_t faulty_pte_mask_set = 0x0;
pteval_t faulty_pte_mask_clear = 0xffffffffffffffff;

measurement_t *measurements;

// =================================================================================================
// Local declarations and definitions
#define SYSFS_DIRNAME "x86_executor"

char tracing_error = 0;

unsigned inputs_top = 0;
static struct kobject *kobj_interface;
char test_case_ready = 0;
char n_inputs_ready = 0;
char inputs_ready = 0;

int loaded_tc_size = 0;

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

/// Changing the number of tested inputs
///
static ssize_t n_inputs_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                              size_t count);
static ssize_t n_inputs_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static struct kobj_attribute n_inputs_attribute =
    __ATTR(n_inputs, 0666, n_inputs_show, n_inputs_store);

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

static struct attribute *sysfs_attributes[] = {
    &trace_attribute.attr,
    &test_case_attribute.attr,
    &inputs_attribute.attr,
    &n_inputs_attribute.attr,
    &warmups_attribute.attr,
    &print_sandbox_base_attribute.attr,
    &print_code_base_attribute.attr,
    &enable_ssbp_patch_attribute.attr,
    &enable_prefetcher_attribute.attr,
    &enable_pre_run_flush_attribute.attr,
    &measurement_mode_attribute.attr,
    &enable_quick_and_dirty_mode_attribute.attr,
    &pte_mask_attribute.attr,
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

    if (!measurements)
    {
        printk(KERN_ERR "x86_executor: Measurements where not initialized\n");
        return -1;
    }

    // start a new measurement?
    if (next_measurement_id < 0)
    {
        if (test_case_ready == 0 || inputs_ready == 0)
        {
            printk(KERN_ERR "x86_executor: Test case is not ready to be tested\n");
            return -1;
        }

        tracing_error = 1; // this variable is used to detect crashes during test case execution
        int err = trace_test_case();
        tracing_error = 0;
        if (err)
            return -1;

        // start printing the results
        next_measurement_id = n_inputs - 1;
    }

    // print the results, but make sure we can continue later if we run out of space in buf
    for (; next_measurement_id >= 0; next_measurement_id--)
    {
        // check if the output buffer still has space
        if (count >= (4096 - 128))
            return count; // we will continue in the next call of this function

        measurement_t m = measurements[next_measurement_id];
        retval = sprintf(&buf[count], "%llu,%llu,%llu,%llu,%llu,%llu\n", m.htrace[0], m.pfc[0],
                         m.pfc[1], m.pfc[2], m.pfc[3], m.pfc[4]);
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
    if (count >= MAX_TEST_CASE_SIZE)
    {
        printk(KERN_ERR "x86_executor: Test case exceeds MAX_TEST_CASE_SIZE\n");
        return -1;
    }

    // check if memory for inputs was allocated
    if (!test_case || !measurement_code)
    {
        printk(KERN_ERR "x86_executor: The memory for the test case was not allocated\n");
        return -1;
    }

    memcpy(test_case, buf, count);
    loaded_tc_size = load_template(count);
    if (loaded_tc_size <= 0)
    {
        printk(KERN_ERR "x86_executor: Failed to load the test case (code %d)\n", loaded_tc_size);
        return -1;
    }

    test_case_ready = 1;
    n_inputs_ready = 0;
    inputs_ready = 0;
    next_measurement_id = -1;
    return count;
}

static ssize_t test_case_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    for (int i = 0; i < loaded_tc_size; i++)
    {
        sprintf(&buf[i], "%c", measurement_code[i]);
    }
    return loaded_tc_size;
}

static ssize_t n_inputs_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                              size_t count)
{
    unsigned long old_n_inputs = n_inputs;
    sscanf(buf, "%ld", &n_inputs);

    if (n_inputs > old_n_inputs)
    {
        // allocate more memory for measurements
        vfree(measurements);
        measurements = vmalloc(n_inputs * sizeof(measurement_t));
        if (!measurements)
        {
            printk(KERN_ERR "x86_executor: Could not allocate memory for measurements\n");
            return -ENOMEM;
        }

        // and for inputs
        vfree(inputs);
        inputs = vmalloc(n_inputs * INPUT_SIZE);
        if (!inputs)
        {
            printk(KERN_ERR "x86_executor: Could not allocate memory for inputs\n");
            return -ENOMEM;
        }
    }
    inputs_top = 0; // restart input loading
    n_inputs_ready = 1;
    return count;
}

static ssize_t n_inputs_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%ld\n", n_inputs);
}

static ssize_t inputs_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
                            size_t count)
{
    if (n_inputs_ready == 0)
    {
        printk(KERN_ERR "x86_executor: Violation of the loading protocol\n");
        return -1;
    }

    // check if memory for inputs was allocated
    if (!inputs)
    {
        printk(KERN_ERR "x86_executor: Input memory was not allocated\n");
        inputs_ready = 0;
        return -1;
    }

    /// Because of buffering in sysfs, this function may be called several times for
    /// the same sequence of inputs
    unsigned batch_size = count / 8; // the count is for uint64

    // first, check for overflows
    if (inputs_top + batch_size > n_inputs * INPUT_SIZE)
    {
        printk(KERN_ERR "x86_executor: Input overflow\n");
        inputs_ready = 0;
        return -1;
    }

    // load the batch
    uint64_t *new_inputs = (uint64_t *)buf;
    for (unsigned i = 0; i < batch_size; i++)
    {
        inputs[inputs_top + i] = new_inputs[i];
    }
    inputs_top += batch_size;
    inputs_ready = 1;
    return count;
}

static ssize_t inputs_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
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
    return sprintf(buf, "%llx\n", (long long unsigned)sandbox->main_region);
}

static ssize_t print_code_base_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%llx\n", (long long unsigned)test_case);
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
static ssize_t enable_mpx_store(struct kobject *kobj, struct kobj_attribute *attr,
                                       const char *buf, size_t count)
{
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    mpx_control = (value == 0) ? 0 : 1;
    return count;
}

static ssize_t measurement_mode_store(struct kobject *kobj, struct kobj_attribute *attr,
                                      const char *buf, size_t count)
{
    if (buf[0] == 'F')
    {
        measurement_template = (char *)&template_l1d_flush_reload;
    }
    else if (buf[0] == 'P')
    {
        if (buf[1] == '+')
            measurement_template = (char *)&template_l1d_prime_probe;
        else
            measurement_template = (char *)&template_l1d_prime_probe_partial;
    }
    else if (buf[0] == 'E')
    {
        measurement_template = (char *)&template_l1d_evict_reload;
    }
    else if (buf[0] == 'G')
    {
        measurement_template = (char *)&template_gpr;
    }

    return count;
}

static ssize_t enable_quick_and_dirty_mode(struct kobject *kobj, struct kobj_attribute *attr,
                                           const char *buf, size_t count)
{

    unsigned value = 0;
    sscanf(buf, "%u", &value);

    if (value == 1)
    {
        quick_and_dirty_mode = true;
        if (measurement_template == (char *)&template_l1d_prime_probe)
        {
            measurement_template = (char *)&template_l1d_prime_probe_fast;
        }
        else if (measurement_template == (char *)&template_l1d_prime_probe_partial)
        {
            measurement_template = (char *)&template_l1d_prime_probe_partial_fast;
        }
    }
    else
    {
        quick_and_dirty_mode = false;
        if (measurement_template == (char *)&template_l1d_prime_probe_fast)
        {
            measurement_template = (char *)&template_l1d_prime_probe;
        }
        else if (measurement_template == (char *)&template_l1d_prime_probe_partial_fast)
        {
            measurement_template = (char *)&template_l1d_prime_probe_partial;
        }
    }
    return count;
}

// ============================================================================
// Memory Management and Initialization
static int __init executor_init(void)
{
    // get set_memory_x and set_memory_nx
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
#endif
    set_memory_x = (void *)kallsyms_lookup_name("set_memory_x");
    set_memory_nx = (void *)kallsyms_lookup_name("set_memory_nx");
#endif

    // Check CPU vendor
    struct cpuinfo_x86 *c = &cpu_data(0);
    if (c->x86_vendor != X86_VENDOR_INTEL && c->x86_vendor != X86_VENDOR_AMD)
    {
        printk(KERN_ERR "x86_executor: This CPU vendor is not supported\n");
        return -1;
    }

    // allocate memory for test cases and make it executable
    test_case = kmalloc(MAX_TEST_CASE_SIZE, GFP_KERNEL);
    measurement_code = kmalloc(MAX_MEASUREMENT_CODE_SIZE, GFP_KERNEL);
    if (!test_case || !measurement_code)
    {
        printk(KERN_ERR "x86_executor: Could not allocate memory for test_case\n");
        return -ENOMEM;
    }
    set_memory_x((unsigned long)measurement_code, MAX_MEASUREMENT_CODE_SIZE / PAGE_SIZE);

    // allocate memory for inputs
    inputs = vmalloc(n_inputs * INPUT_SIZE);
    if (!inputs)
    {
        printk(KERN_ERR "x86_executor: Could not allocate memory for inputs\n");
        return -ENOMEM;
    }

    // allocate working memory
    sandbox_unaligned = vmalloc(sizeof(sandbox_t) + 0x1000);
    if (!sandbox_unaligned)
    {
        printk(KERN_ERR "x86_executor: Could not allocate memory for sandbox\n");
        return -ENOMEM;
    }

    // align sandbox to 2 pages (vmalloc guarantees 1 page alignment)
    if ((unsigned long)sandbox_unaligned % 0x2000 == 0)
        sandbox = (sandbox_t *)sandbox_unaligned;
    else
        sandbox = (sandbox_t *)((unsigned long)sandbox_unaligned + 0x1000);

    // make sure the fields of the sandbox are aligned as we expect
    if ((&sandbox->main_region[0] - &sandbox->eviction_region[0]) != EVICT_REGION_OFFSET ||
        ((char *)&sandbox->stored_rsp - &sandbox->main_region[0]) != RSP_OFFSET ||
        ((char *)&sandbox->latest_measurement - &sandbox->main_region[0]) != MEASUREMENT_OFFSET ||
        (&sandbox->upper_overflow[0] - &sandbox->main_region[0]) != REG_INIT_OFFSET)
    {
        printk(KERN_ERR "x86_executor: Sandbox alignment error\n");
        return -1;
    }

    stack_base = &(sandbox->main_region[MAIN_REGION_SIZE - 8]);

    // zero-initialize the region of memory used by Prime+Probe
    memset(&sandbox->eviction_region[0], 0, EVICT_REGION_SIZE * sizeof(char));

    // allocate memory for measurements
    measurements = vmalloc(n_inputs * sizeof(measurement_t));
    if (!measurements)
    {
        printk(KERN_ERR "x86_executor: Could not allocate memory for measurements\n");
        return -ENOMEM;
    }

    // Create a pseudo file system interface
    kobj_interface = kobject_create_and_add(SYSFS_DIRNAME, kernel_kobj->parent);
    if (!kobj_interface)
    {
        printk(KERN_ERR "x86_executor: Failed to create a sysfs directory for x86-executor\n");
        return -ENOMEM;
    }

    // Create the files associated with this kobject
    // int retval = sysfs_create_group(kobj_interface, &attr_group);
    int i = 0;
    int err = 0;
    struct attribute *attr;
    for (attr = sysfs_attributes[i]; !err; i++)
    {
        attr = sysfs_attributes[i];
        if (attr == NULL)
            break;

        err = sysfs_create_file(kobj_interface, attr);
    }

    if (err != 0)
    {
        printk(KERN_ERR "x86_executor: Failed to create a sysfs group\n");
        kobject_put(kobj_interface);
        return err;
    }

    // Allocate memory for new IDT
    curr_idt_table = kmalloc(sizeof(gate_desc) * 256, GFP_KERNEL);
    if (!curr_idt_table)
    {
        printk(KERN_ERR "x86_executor: Could not allocate memory for IDT\n");
        return -ENOMEM;
    }

    return 0;
}

static void __exit executor_exit(void)
{
    if (tracing_error != 0)
    {
        printk(KERN_ERR "x86_executor: Failed to unload the module due to corrupted state\n");
        return;
    }

    if (measurement_code)
    {
        set_memory_nx((unsigned long)measurement_code, MAX_MEASUREMENT_CODE_SIZE / PAGE_SIZE);
        kfree(measurement_code);
    }

    if (test_case)
        kfree(test_case);

    if (inputs)
        vfree(inputs);

    if (sandbox_unaligned)
        vfree(sandbox_unaligned);

    if (measurements)
        vfree(measurements);

    if (kobj_interface)
        kobject_put(kobj_interface);
}

module_init(executor_init);
module_exit(executor_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Oleksii Oleksenko");
