/// File:
///  - Test case execution
///  - Ensuring an isolated environment
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang-format off
#include <linux/seq_file.h>
#include <linux/irqflags.h>
#include <../arch/x86/include/asm/fpu/api.h>
#include <../arch/x86/include/asm/pgtable.h>
#include <../arch/x86/include/asm/tlbflush.h>
// clang-format on
#include "main.h"

struct pfc_config
{
    unsigned long evt_num;
    unsigned long umask;
    unsigned long cmask;
    unsigned int any;
    unsigned int edge;
    unsigned int inv;
};

struct idt_data
{
    unsigned int vector;
    unsigned int segment;
    struct idt_bits bits;
    const void *addr;
};

unsigned long faulty_page_addr;
pte_t faulty_page_pte;
pte_t *faulty_page_ptep;

gate_desc *orig_idt_table;
gate_desc *curr_idt_table;
struct desc_ptr idtr;

int config_pfc(unsigned int id, char *pfc_code, unsigned int usr, unsigned int os);
pte_t *get_pte(unsigned long address);

inline void wrmsr64(unsigned int msr, uint64_t value)
{
    native_write_msr(msr, (uint32_t)value, (uint32_t)(value >> 32));
}

inline void _native_page_invalidate(void)
{
    asm volatile("invlpg (%0)" ::"r"(faulty_page_addr) : "memory");
}

// =================================================================================================
// Fault Handling
// =================================================================================================
static void inline local_store_idt(void *dtr)
{
    asm volatile("sidt %0" : "=m"(*((struct desc_ptr *)dtr)));
}

static void inline local_load_idt(void *dtr)
{
    asm volatile("lidt %0" ::"m"(*((struct desc_ptr *)dtr)));
}

static void idt_setup_from_table(gate_desc *idt, const struct idt_data *t, int size)
{
    gate_desc desc;

    for (; size > 0; t++, size--)
    {
        unsigned long addr = (unsigned long)t->addr;

        desc.offset_low = (u16)addr;
        desc.segment = (u16)t->segment;
        desc.bits = t->bits;
        desc.offset_middle = (u16)(addr >> 16);
#ifdef CONFIG_X86_64
        desc.offset_high = (u32)(addr >> 32);
        desc.reserved = 0;
#endif

        write_idt_entry(idt, t->vector, &desc);
    }
}

static void set_intr_gate(unsigned int n, const void *addr)
{
    struct idt_data data;

    memset(&data, 0, sizeof(data));
    data.vector = n;
    data.addr = addr;
    data.segment = __KERNEL_CS;
    data.bits.type = GATE_INTERRUPT;
    data.bits.p = 1;

    idt_setup_from_table(curr_idt_table, &data, 1);
}

static void enable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    asm volatile("mov %0,%%cr0" ::"r"(cr0) : "memory");
}

static void disable_write_protection(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    asm volatile("mov %0,%%cr0" ::"r"(cr0) : "memory");
}

static void idt_copy(void)
{
    for (int entry = 0; entry < 256; entry++)
    {
        const gate_desc *gate = &orig_idt_table[entry];
        memcpy(&curr_idt_table[entry], gate, sizeof(*gate));
    }
}

static void setup_idt(void)
{
    disable_write_protection();
    uint8_t idx = 0;
    for (idx = 0; idx < 32; idx++)
    {
        if (BIT_CHECK(handled_faults, idx))
        {
            set_intr_gate(idx, (void *)fault_handler);
        }
    }
    enable_write_protection();
    idtr.address = (unsigned long)curr_idt_table;
    local_load_idt(&idtr);
}

static void reset_idt(void)
{
    idtr.address = (unsigned long)orig_idt_table;
    local_load_idt(&idtr);
}

// =================================================================================================
// Measurement
// =================================================================================================
static inline int pre_measurement_setup(void)
{
    int err = 0;
#if VENDOR_ID == 1 // Intel
    // Configure PMU
    err |= config_pfc(0, "D1.01", 1, 1); // L1 hits - for htrace collection
    err |= config_pfc(1, "0D.01", 1, 1); // misprediction recovery cycles - fuzzing feedback
    err |= config_pfc(2, "C2.02", 1, 1); // C2.02 - uops retirement slots - fuzzing feedback
    err |= config_pfc(3, "0E.01", 1, 1); // 0E.01 - uops issued - fuzzing feedback

    // Configure uarch patches
    wrmsr64(MSR_IA32_SPEC_CTRL, ssbp_patch_control);

    // Disable prefetchers
    wrmsr64(0x1a4, prefetcher_control);

#elif VENDOR_ID == 2 // AMD
    // Configure PMU
    err |= config_pfc(0, "044.ff", 1, 1); // Local L2->L1 cache fills - htrace collection
    err |= config_pfc(5, "02c.00", 1, 1); // SMI monitoring

    err |= config_pfc(1, "091.00", 1, 1); // decode redirects - fuzzing feedback
    // err |= config_pfc(1, "05A.ff", 1, 1); // decode redirects - fuzzing feedback
    err |= config_pfc(2, "0C1.00", 1, 1); // retired ops - fuzzing feedback
    err |= config_pfc(3, "0AB.88", 1, 1); // dispatched ops - fuzzing feedback

    // Configure uarch patches
    wrmsr64(MSR_IA32_SPEC_CTRL, ssbp_patch_control);

    // Disable prefetchers
    wrmsr64(0xc0000108, prefetcher_control);
#endif

    if (err)
        return err;

    faulty_page_addr = (unsigned long)&sandbox->faulty_region[0];
    faulty_page_ptep = get_pte(faulty_page_addr);
    if (faulty_page_ptep == NULL)
    {
        printk(KERN_ERR "x86_executor: Couldn't get the faulty page PTE entry");
        return -1;
    }
    return 0;
}

static inline int uarch_flush(void)
{
#if VENDOR_ID == 1 // Intel
    static const u16 ds = __KERNEL_DS;
    asm volatile("verw %[ds]" : : [ds] "m"(ds) : "cc");
    wrmsr64(MSR_IA32_FLUSH_CMD, L1D_FLUSH);
#elif VENDOR_ID == 2 // AMD
    // TBD
#endif
    return 0;
}

void run_experiment(long rounds)
{
    get_cpu();
    unsigned long flags;
    raw_local_irq_save(flags);

    // save the current state of IDT
    local_store_idt(&idtr);
    orig_idt_table = (gate_desc *)idtr.address;
    idt_copy();

    // save the current value of the faulty page PTE
    pteval_t orig_pte = faulty_page_ptep->pte;

    // Zero-initialize the region of memory used by Prime+Probe
    memset(&sandbox->eviction_region[0], 0, EVICT_REGION_SIZE * sizeof(char));

    for (long i = -uarch_reset_rounds; i < rounds; i++)
    {
        // ignore "warm-up" runs (i<0)uarch_reset_rounds
        long i_ = (i < 0) ? 0 : i;
        uint64_t *current_input = &inputs[i_ * INPUT_SIZE / 8];

        // Initialize memory:
        // NOTE: memset is not used intentionally! somehow, it messes up with P+P measurements
        // - overflows are initialized with zeroes
        memset(&sandbox->lower_overflow[0], 0, OVERFLOW_REGION_SIZE * sizeof(char));
        for (int j = 0; j < OVERFLOW_REGION_SIZE / 8; j += 1)
        {
            // ((uint64_t *) sandbox->lower_overflow)[j] = 0;
            ((uint64_t *)sandbox->upper_overflow)[j] = 0;
        }

        // - sandbox: main and faulty regions
        uint64_t *main_page_values = &current_input[0];
        uint64_t *main_base = (uint64_t *)&sandbox->main_region[0];
        for (int j = 0; j < MAIN_REGION_SIZE / 8; j += 1)
        {
            ((uint64_t *)main_base)[j] = main_page_values[j];
        }

        uint64_t *faulty_page_values = &current_input[MAIN_REGION_SIZE / 8];
        uint64_t *faulty_base = (uint64_t *)&sandbox->faulty_region[0];
        for (int j = 0; j < FAULTY_REGION_SIZE / 8; j += 1)
        {
            ((uint64_t *)faulty_base)[j] = faulty_page_values[j];
        }

        // Initial register values (the registers will be set to these values in template.c)
        uint64_t *register_values = &current_input[(MAIN_REGION_SIZE + FAULTY_REGION_SIZE) / 8];
        uint64_t *register_initialization_base = (uint64_t *)&sandbox->upper_overflow[0];

        // - RAX ... RDI
        for (int j = 0; j < 6; j += 1)
        {
            ((uint64_t *)register_initialization_base)[j] = register_values[j];
        }

        // - flags
        uint64_t masked_flags = (register_values[6] & 2263) | 2;
        ((uint64_t *)register_initialization_base)[6] = masked_flags;

        // - RSP and RBP
        ((uint64_t *)register_initialization_base)[7] = (uint64_t)stack_base;

        // flush some of the uarch state
        if (pre_run_flush == 1)
            uarch_flush();

        // Set page table entry for the faulty region
        if ((faulty_pte_mask_set != 0) || (faulty_pte_mask_clear != 0xffffffffffffffff))
        {
            faulty_page_pte.pte =
                ((faulty_page_ptep->pte | faulty_pte_mask_set) & faulty_pte_mask_clear);
            set_pte_at(current->mm, faulty_page_addr, faulty_page_ptep, faulty_page_pte);
            // asm volatile("clflush (%0)\nlfence\n" ::"r"(faulty_page_addr)
            //  : "memory");
            _native_page_invalidate();
        }

        setup_idt();

        // execute
        ((void (*)(char *))measurement_code)(&sandbox->main_region[0]);

        reset_idt();

        // restore the original value of the faulty page PTE
        if ((faulty_pte_mask_set != 0) || (faulty_pte_mask_clear != 0xffffffffffffffff))
        {
            faulty_page_pte.pte = orig_pte;
            set_pte_at(current->mm, faulty_page_addr, faulty_page_ptep, faulty_page_pte);
            _native_page_invalidate();
        }

        // store the measurement results
        measurement_t result = sandbox->latest_measurement;
        // printk(KERN_ERR "x86_executor: measurement %llu\n", result.htrace[0]);
        measurements[i_].htrace[0] = result.htrace[0];
        measurements[i_].pfc[0] = result.pfc[0];
        measurements[i_].pfc[1] = result.pfc[1];
        measurements[i_].pfc[2] = result.pfc[2];
        measurements[i_].pfc[3] = result.pfc[3];
        measurements[i_].pfc[4] = result.pfc[4];
    }

    raw_local_irq_restore(flags);
    put_cpu();
}

int trace_test_case(void)
{
    // Prepare for the experiment:
    // 1. Ensure that all necessary objects are allocated
    if (!measurements)
    {
        printk(KERN_ERR "Did not allocate memory for measurements\n");
        return -ENOMEM;
    }
    if (!measurement_code)
        return -1;
    if (!inputs)
    {
        printk(KERN_ERR "Did not allocate memory for inputs\n");
        return -ENOMEM;
    }

    // 2. Enable FPU - just in case, we might use it within the test case
    kernel_fpu_begin();

    // 3. Run the measurement
    if (pre_measurement_setup())
        return -1;
    run_experiment((long)n_inputs);

    kernel_fpu_end();
    return 0;
}

// =================================================================================================
// Helper Functions
// =================================================================================================

/// Clears the programmable performance counters and writes the
/// configurations to the corresponding MSRs.
///
int config_pfc(unsigned int id, char *pfc_code_org, unsigned int usr, unsigned int os)
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
    while ((ce = strsep(&pfc_code_p, ".")) != NULL)
    {
        if (!strcmp(ce, "Any"))
        {
            config.any = 1;
        }
        else if (!strcmp(ce, "EDG"))
        {
            config.edge = 1;
        }
        else if (!strcmp(ce, "INV"))
        {
            config.inv = 1;
        }
        else if (!strncmp(ce, "CMSK=", 5))
        {
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
    wrmsr64(0x0C1 + id, 0);

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

pte_t *get_pte(unsigned long address)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    /* Make sure we are in vmalloc area: */
    if (!(address >= VMALLOC_START && address < VMALLOC_END))
        return NULL;

    pgd = pgd_offset(current->mm, address);
    if (pgd_none(*pgd))
        return NULL;

    p4d = p4d_offset(pgd, address);
    pud = pud_offset(p4d, address);
    if (pud_none(*pud))
        return NULL;

    pmd = pmd_offset(pud, address);
    if (pmd_none(*pmd))
        return NULL;

    pte = pte_offset_kernel(pmd, address);
    if (!pte_present(*pte))
        return NULL;

    return pte;
}
