/// File:
///  - Guest page table management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/io.h>
#include <asm/msr.h>

#include "actor.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

#include "hw_features/guest_memory.h"
#include "hw_features/page_tables_common.h"

#define INIT_PTE(PTE, PADDR, P, W, US, PWT, PCD, XD, A)                                            \
    {                                                                                              \
        PTE.present = P;                                                                           \
        PTE.write_access = W;                                                                      \
        PTE.user_supervisor = US;                                                                  \
        PTE.page_write_through = PWT;                                                              \
        PTE.page_cache_disable = PCD;                                                              \
        PTE.paddr = PADDR >> 12;                                                                   \
        PTE.execute_disable = XD;                                                                  \
        PTE.accessed = A;                                                                          \
    }
#define INIT_EPTE(PTE, PADDR, P, W, X, A)                                                          \
    {                                                                                              \
        PTE.read_access = P;                                                                       \
        PTE.write_access = W;                                                                      \
        PTE.execute_access = X;                                                                    \
        PTE.paddr = PADDR >> 12;                                                                   \
        PTE.accessed = A;                                                                          \
    }

#define INIT_PTE_DEFAULT(PTE, PADDR)  INIT_PTE(PTE, PADDR, 1, 1, 0, 0, 0, 0, 1)
#define INIT_EPTE_DEFAULT(PTE, PADDR) INIT_EPTE(PTE, PADDR, 1, 1, 1, 1)

eptp_t *ept_ptr = NULL; // global

static actor_page_table_t *_allocated_page_tables = NULL;
static actor_ept_t *_allocated_extended_page_tables = NULL;
static void *_allocated_guest_gdts = NULL;
static uint8_t *_vmlaunch_page = NULL;
static pte_t_ *faulty_ptes = NULL;
static epte_t_ *faulty_eptes = NULL;

static v2p_t *_v2p_translations = NULL;

// =================================================================================================
// Helper functions
// =================================================================================================
#define N_TRANSLATIONS 2048

/// @brief Interface to record translations between virtual addresses in high memory into physical
/// addresses. This is necessary because kernel does not provide a direct interface to search for
/// a physical address in page tables (or at least I couldn't find one)
/// @param vaddr virtual address in high memory
/// @param paddr physical address
void record_v2p_translation(uint64_t vaddr, uint64_t paddr)
{
    static int top = 0;
    _v2p_translations[top] = (v2p_t){vaddr, paddr};
    top = (top + 1) % N_TRANSLATIONS;
}

static inline uint64_t vmalloc_to_phys_recorded(void *hva)
{
    uint64_t hpa = vmalloc_to_phys(hva);
    record_v2p_translation((uint64_t)hva, hpa);
    return hpa;
}

void *phys_to_vmalloc(uint64_t paddr)
{
    for (int i = 0; i < N_TRANSLATIONS; i++) {
        if (_v2p_translations[i].paddr == paddr) {
            return (void *)_v2p_translations[i].vaddr;
        }
    }
    return 0;
}

static inline void set_last_ept_level(epte_t_ *ept, uint64_t gpa, void *hva)
{
    uint64_t hpa = vmalloc_to_phys_recorded(hva);
    INIT_EPTE_DEFAULT(ept[PT_INDEX(gpa)], hpa);
    ept[PT_INDEX(gpa)].dirty = 1;
    ept[PT_INDEX(gpa)].ept_mem_type = 6;
    ept[PT_INDEX(gpa)].ignore_pat = 1;
}

// =================================================================================================
// Page table management interface
// =================================================================================================

/// @brief Set the guest page tables for all guest actors according to the layout defined in
/// guest_memory_t (see guest_page_tables.h), with the base address GUEST_MEMORY_START
/// @param void
/// @return 0 on success, -1 on failure
int set_guest_page_tables(void)
{
    static int old_n_actors = 0;
    if (n_actors > old_n_actors) {
        SAFE_FREE(faulty_ptes);
        SAFE_FREE(faulty_eptes);
        faulty_ptes = (pte_t_ *)CHECKED_ZALLOC(sizeof(pte_t_) * n_actors);
        faulty_eptes = (epte_t_ *)CHECKED_ZALLOC(sizeof(epte_t_) * n_actors);
    }
    old_n_actors = n_actors;

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-guest actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST) {
            continue;
        }

        // get a type that represents the guest memory
        guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
        guest_memory_t *guest_p_memory = (guest_memory_t *)(GUEST_P_MEMORY_START);

        // set the first three levels of the page table
        // (they are the same for all addresses within the actor memory)
        actor_page_table_t *page_table_hva = &_allocated_page_tables[actor_id];
        actor_page_table_t *page_table_gpa = &guest_p_memory->guest_page_tables;

        size_t pml4_index = PML4_INDEX(GUEST_V_MEMORY_START);
        INIT_PTE_DEFAULT(page_table_hva->pml4[pml4_index], (uint64_t)&page_table_gpa->pdpt);

        size_t pdpt_index = PDPT_INDEX(GUEST_V_MEMORY_START);
        INIT_PTE_DEFAULT(page_table_hva->pdpt[pdpt_index], (uint64_t)&page_table_gpa->pdt);

        size_t pdt_index = PDT_INDEX(GUEST_V_MEMORY_START);
        INIT_PTE_DEFAULT(page_table_hva->pdt[pdt_index], (uint64_t)&page_table_gpa->pt);

        // set the last level of the page table for each area of the actor sandbox
        for (int i = 0; i < sizeof(util_t); i += 4096) {
            uint64_t vaddr = ((uint64_t)&guest_v_memory->util) + i;
            uint64_t paddr = ((uint64_t)&guest_p_memory->util) + i;
            size_t pt_index = PT_INDEX(vaddr);
            INIT_PTE_DEFAULT(page_table_hva->pt[pt_index], paddr);
            page_table_hva->pt[pt_index].dirty = 1;
        }
        for (int i = 0; i < sizeof(actor_data_t); i += 4096) {
            uint64_t vaddr = ((uint64_t)&guest_v_memory->data) + i;
            uint64_t paddr = ((uint64_t)&guest_p_memory->data) + i;
            size_t pt_index = PT_INDEX(vaddr);
            INIT_PTE_DEFAULT(page_table_hva->pt[pt_index], paddr);
            page_table_hva->pt[pt_index].dirty = 1;
        }
        for (int i = 0; i < sizeof(actor_code_t); i += 4096) {
            uint64_t vaddr = ((uint64_t)&guest_v_memory->code) + i;
            uint64_t paddr = ((uint64_t)&guest_p_memory->code) + i;
            size_t pt_index = PT_INDEX(vaddr);
            INIT_PTE_DEFAULT(page_table_hva->pt[pt_index], paddr);
            page_table_hva->pt[pt_index].dirty = 1;
        }
        { // GDT (indentation is for readability)
            uint64_t vaddr = (uint64_t)&guest_v_memory->gdt[0];
            uint64_t paddr = (uint64_t)&guest_p_memory->gdt[0];
            size_t pt_index = PT_INDEX(vaddr);
            INIT_PTE_DEFAULT(page_table_hva->pt[pt_index], paddr);
            page_table_hva->pt[pt_index].dirty = 1;
        }
        { // VMLAUNCH page (indentation is for readability)
            uint64_t vaddr = (uint64_t)&guest_v_memory->vmlaunch_page[0];
            uint64_t paddr = (uint64_t)&guest_p_memory->vmlaunch_page[0];
            size_t pt_index = PT_INDEX(vaddr);
            INIT_PTE_DEFAULT(page_table_hva->pt[pt_index], paddr);
            page_table_hva->pt[pt_index].dirty = 1;
        }
    }
    return 0;
}

/// @brief Map sandbox_t from host memory into the guest memory of each guest actor, according to
/// the layout defined in guest_memory_t (see guest_memory.h), with the base address equal to
/// GUEST_MEMORY_START
/// @param void
/// @return 0 on success, -1 on failure
int set_extended_page_tables(void)
{
    ASSERT(actors != NULL, "set_extended_page_tables");
    ASSERT(sandbox != NULL, "set_extended_page_tables");
    guest_memory_t *guest_memory = (guest_memory_t *)(GUEST_P_MEMORY_START);

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-guest actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST) {
            continue;
        }
        actor_ept_t *actor_ept_base = &_allocated_extended_page_tables[actor_id];

        // set the first three levels of EPT
        size_t l4_index = PML4_INDEX(GUEST_P_MEMORY_START);
        uint64_t l3_hpa = vmalloc_to_phys_recorded((void *)actor_ept_base->l3);
        INIT_EPTE_DEFAULT(actor_ept_base->l4[l4_index], l3_hpa);

        size_t l3_index = PDPT_INDEX(GUEST_P_MEMORY_START);
        uint64_t l2_hpa = vmalloc_to_phys_recorded((void *)actor_ept_base->l2);
        INIT_EPTE_DEFAULT(actor_ept_base->l3[l3_index], l2_hpa);

        size_t l2_index = PDT_INDEX(GUEST_P_MEMORY_START);
        uint64_t l1_hpa = vmalloc_to_phys_recorded((void *)actor_ept_base->l1);
        INIT_EPTE_DEFAULT(actor_ept_base->l2[l2_index], l1_hpa);

        // map util_t into guest memory (the same phys range for all actors, i.e., shared)
        epte_t_ *l1 = actor_ept_base->l1;
        for (int i = 0; i < sizeof(util_t); i += 4096) {
            set_last_ept_level(l1, ((uint64_t)&guest_memory->util) + i,
                               ((void *)sandbox->util) + i);
        }

        // map actor_data_t, actor_code_t, and GDT into guest memory (each actor has its own)
        for (int i = 0; i < sizeof(actor_data_t); i += 4096) {
            set_last_ept_level(l1, ((uint64_t)&guest_memory->data) + i,
                               ((void *)&sandbox->data[actor_id]) + i);
        }
        for (int i = 0; i < sizeof(actor_code_t); i += 4096) {
            set_last_ept_level(l1, ((uint64_t)&guest_memory->code) + i,
                               ((void *)&sandbox->code[actor_id]) + i);
        }
        { // indent for readability
            set_last_ept_level(l1, (uint64_t)&guest_memory->gdt[0],
                               (void *)_allocated_guest_gdts + actor_id * PAGE_SIZE);
        }
        { // indent for readability
            set_last_ept_level(l1, (uint64_t)&guest_memory->vmlaunch_page[0],
                               (void *)_vmlaunch_page);
        }

        // map guest page tables
        for (int i = 0; i < sizeof(actor_page_table_t); i += 4096) {
            set_last_ept_level(l1, ((uint64_t)&guest_memory->guest_page_tables) + i,
                               ((void *)&_allocated_page_tables[actor_id]) + i);
        }
    }
    return 0;
}

/// @brief Store a pointer to the EPT of actor 1 (default) in ept_ptr after updating extended page
/// tables
/// @param void
/// @return 0 on success, -1 on failure
int update_eptp(void)
{
    SAFE_FREE(ept_ptr);
    ept_ptr = CHECKED_ZALLOC(sizeof(eptp_t) * n_actors);
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_ept_t *actor_ept_base = &_allocated_extended_page_tables[actor_id];
        ept_ptr[actor_id].memory_type = VMX_BASIC_MEM_TYPE_WB;
        ept_ptr[actor_id].page_walk_length = 3;
        ept_ptr[actor_id].ad_enabled = 1; // native_read_msr(MSR_IA32_VMX_EPT_VPID_CAP) &0x00200000;
        ept_ptr[actor_id].superv_sdw_stack = 0;
        ept_ptr[actor_id].paddr = vmalloc_to_phys_recorded(actor_ept_base->l4) >> 12;
    }

    return 0;
}

int map_sandbox_to_guest_memory(void)
{
    int err = 0;
    ASSERT(_allocated_page_tables != NULL, "map_sandbox_to_guest_memory");
    ASSERT(_allocated_extended_page_tables != NULL, "map_sandbox_to_guest_memory");
    ASSERT(_allocated_guest_gdts != NULL, "map_sandbox_to_guest_memory");

    err = set_guest_page_tables();
    CHECK_ERR("set_guest_page_tables");

    err = set_extended_page_tables();
    CHECK_ERR("set_extended_page_tables");

    err = update_eptp();
    CHECK_ERR("update_eptp");

    return 0;
}

/// @brief Set permissions on the faulty page based on the actor's metadata (for each actor)
/// @param void
void set_faulty_page_guest_permissions(void)
{
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    uint64_t vaddr = ((uint64_t)&guest_v_memory->data.faulty_area[0]);
    size_t index = PT_INDEX(vaddr);

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        uint64_t pte_mask = actor->data_permissions;
        uint64_t mask_set = pte_mask & MODIFIABLE_PTE_BITS;
        uint64_t mask_clear = pte_mask | ~MODIFIABLE_PTE_BITS;

        if ((mask_set != 0) || (mask_clear != NO_CLEAR_MASK)) {
            pte_t_ *ptep = &_allocated_page_tables[actor_id].pt[index];
            uint64_t pte = *(uint64_t *)ptep;

            faulty_ptes[actor_id] = *ptep;
            *(uint64_t *)ptep = (pte | mask_set) & mask_clear;
            // native_page_invalidate(vaddr);
        }
    }
}

void restore_faulty_page_guest_permissions(void)
{
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    uint64_t vaddr = ((uint64_t)&guest_v_memory->data.faulty_area[0]);
    size_t index = PT_INDEX(vaddr);

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        _allocated_page_tables[actor_id].pt[index] = faulty_ptes[actor_id];
    }
}

/// @brief Set EPT permissions on the faulty page based on the actor's metadata (for each actor)
/// @param void
void set_faulty_page_ept_permissions(void)
{
    guest_memory_t *guest_p_memory = (guest_memory_t *)(GUEST_P_MEMORY_START);
    uint64_t gpa = ((uint64_t)&guest_p_memory->data.faulty_area[0]);
    size_t index = PT_INDEX(gpa);

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        uint64_t pte_mask = actor->data_ept_properties;
        uint64_t mask_set = pte_mask & MODIFIABLE_EPTE_BITS;
        uint64_t mask_clear = pte_mask | ~MODIFIABLE_EPTE_BITS;

        if ((mask_set != 0) || (mask_clear != NO_CLEAR_MASK_EPT)) {
            epte_t_ *ptep = &_allocated_extended_page_tables[actor_id].l1[index];
            faulty_eptes[actor_id] = *ptep;
            *(uint64_t *)ptep = (*(uint64_t *)ptep | mask_set) & mask_clear;
            // native_page_invalidate(vaddr);
        }
    }
}

void restore_faulty_page_ept_permissions(void)
{
    guest_memory_t *guest_p_memory = (guest_memory_t *)(GUEST_P_MEMORY_START);
    uint64_t gpa = ((uint64_t)&guest_p_memory->data.faulty_area[0]);
    size_t index = PT_INDEX(gpa);

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        _allocated_extended_page_tables[actor_id].l1[index] = faulty_eptes[actor_id];
    }
}

// =================================================================================================
// Debugging Interfaces
// =================================================================================================

/// @brief Dump the guest page tables for a given actor
/// @param actor_id
/// @return 0 on success, -1 on failure
int dbg_dump_guest_page_tables(int actor_id)
{
    // NOTE: the implementation below traverses page tables as if they were unbounded (i.e.,
    //   contained an unlimited number of PTEs, PDs, etc). This is not the case for the guest page
    //   tables as we have only one PT per actor. However, this implementation is more future-proof,
    //   so we have a traditional page walk, and just check the number of entries with asserts
    printk(KERN_INFO "------- Page table dump for actor %d ---------------\n", actor_id);
    actor_page_table_t *page_table = &_allocated_page_tables[actor_id];
    void *page_table_hva = (void *)page_table;
    uint64_t page_table_gpa =
        (uint64_t) & ((guest_memory_t *)(GUEST_P_MEMORY_START))->guest_page_tables;

    pml4e_t *l4 = page_table->pml4;
    for (uint64_t curr_l4_id = 0; curr_l4_id < ENTRIES_PER_PAGE; curr_l4_id += 1) {
        // L4
        pml4e_t l4e = l4[curr_l4_id];
        if (!l4e.present)
            continue;
        ASSERT(curr_l4_id == 0, "dbg_dump_guest_page_tables");

        uint64_t l3_gpa_offset = ((uint64_t)l4e.paddr << 12) - page_table_gpa;
        pdpte_t *l3 = (pdpte_t *)(page_table_hva + l3_gpa_offset);
        ASSERT(l3 == page_table->pdpt, "dbg_dump_guest_page_tables");

        // L3
        for (uint64_t curr_l3_id = 0; curr_l3_id < ENTRIES_PER_PAGE; curr_l3_id += 1) {
            pdpte_t l3e = l3[curr_l3_id];
            if (!l3e.present)
                continue;
            ASSERT(curr_l3_id == 0, "dbg_dump_guest_page_tables");

            uint64_t l2_gpa_offset = ((uint64_t)l3e.paddr << 12) - page_table_gpa;
            pdte_t *l2 = (pdte_t *)(page_table_hva + l2_gpa_offset);
            ASSERT(l2 == page_table->pdt, "dbg_dump_guest_page_tables");

            // L2
            for (uint64_t curr_l2_id = 0; curr_l2_id < ENTRIES_PER_PAGE; curr_l2_id += 1) {
                pdte_t l2e = l2[curr_l2_id];
                if (!l2e.present)
                    continue;
                ASSERT(curr_l2_id == 0, "dbg_dump_guest_page_tables");

                uint64_t l1_gpa_offset = ((uint64_t)l2e.paddr << 12) - page_table_gpa;
                pte_t_ *l1 = (pte_t_ *)(page_table_hva + l1_gpa_offset);
                ASSERT(l1 == page_table->pt, "dbg_dump_guest_page_tables");

                // L1
                for (uint64_t curr_l1_id = 0; curr_l1_id < ENTRIES_PER_PAGE; curr_l1_id += 1) {
                    pte_t_ l1e = l1[curr_l1_id];
                    if (!l1e.present)
                        continue;
                    uint64_t paddr = ((uint64_t)l1e.paddr << 12);
                    uint64_t vaddr = (curr_l4_id << PML4_SHIFT) | (curr_l3_id << PDPT_SHIFT) |
                                     (curr_l2_id << PDT_SHIFT) | (curr_l1_id << PT_SHIFT);
                    char p = l1e.present ? 'P' : '-';
                    char w = l1e.write_access ? 'W' : '-';
                    char us = l1e.user_supervisor ? 'U' : '-';
                    char pwt = l1e.page_write_through ? 'T' : '-';
                    char pcd = l1e.page_cache_disable ? 'C' : '-';
                    char a = l1e.accessed ? 'A' : '-';
                    char d = l1e.dirty ? 'D' : '-';
                    char pat = l1e.page_attribute_table ? 'T' : '-';
                    char g = l1e.global_page ? 'G' : '-';
                    char x = l1e.execute_disable ? '-' : 'X';
                    printk(KERN_INFO "V: 0x%-16llx -> P: 0x%-16llx; %c%c%c%c%c%c%c%c%c%c\n", vaddr,
                           paddr, p, w, us, pwt, pcd, a, d, pat, g, x);
                }
            }
        }
    }
    return 0;
}

int dbg_dump_ept(int actor_id)
{
    printk(KERN_INFO "------- EPT dump -----------------------------------\n");
    actor_ept_t *actor_ept_base = &_allocated_extended_page_tables[actor_id];

    epml4e_t *l4 = actor_ept_base->l4;
    for (uint64_t curr_l4_id = 0; curr_l4_id < ENTRIES_PER_PAGE; curr_l4_id += 1) {
        // L4
        epml4e_t l4e = l4[curr_l4_id];
        if (!l4e.read_access)
            continue;
        epdpte_t *l3 = phys_to_vmalloc(((uint64_t)l4e.paddr << 12));
        ASSERT(l3 == actor_ept_base->l3, "dbg_dump_ept");

        // L3
        for (uint64_t curr_l3_id = 0; curr_l3_id < ENTRIES_PER_PAGE; curr_l3_id += 1) {
            epdpte_t l3e = l3[curr_l3_id];
            if (!l3e.read_access)
                continue;
            epdte_t *l2 = phys_to_vmalloc(((uint64_t)l3e.paddr << 12));
            ASSERT(l2 == actor_ept_base->l2, "dbg_dump_ept");

            // L2
            for (uint64_t curr_l2_id = 0; curr_l2_id < ENTRIES_PER_PAGE; curr_l2_id += 1) {
                epdte_t l2e = l2[curr_l2_id];
                if (!l2e.read_access)
                    continue;
                epte_t_ *l1 = phys_to_vmalloc(((uint64_t)l2e.paddr << 12));

                void *ept_hva_min = &actor_ept_base->l1[0];
                void *ept_hva_max = &actor_ept_base->l1[ENTRIES_PER_PAGE];
                ASSERT((void *)l1 >= ept_hva_min && (void *)l1 < ept_hva_max, "dbg_dump_ept");

                // L1
                for (uint64_t curr_l1_id = 0; curr_l1_id < ENTRIES_PER_PAGE; curr_l1_id += 1) {
                    epte_t_ l1e = l1[curr_l1_id];
                    if (!l1e.read_access)
                        continue;
                    uint64_t hpa = ((uint64_t)l1e.paddr << 12);
                    void *hva = phys_to_vmalloc(hpa);
                    uint64_t gpa = (curr_l4_id << PML4_SHIFT) | (curr_l3_id << PDPT_SHIFT) |
                                   (curr_l2_id << PDT_SHIFT) | (curr_l1_id << PT_SHIFT);
                    char r = l1e.read_access ? 'R' : '-';
                    char w = l1e.write_access ? 'W' : '-';
                    char x = l1e.execute_access ? 'X' : '-';
                    char a = l1e.accessed ? 'A' : '-';
                    char d = l1e.dirty ? 'D' : '-';
                    char us = l1e.user_ex_access ? 'U' : '-';
                    printk(KERN_INFO
                           "GP: 0x%-16llx -> HP: 0x%-16llx (HV: 0x%-16llx); %c%c%c%c%c%c\n",
                           gpa, hpa, (uint64_t)hva, r, w, x, a, d, us);
                }
            }
        }
    }
    return 0;
}

// =================================================================================================
int allocate_guest_page_tables()
{
    ASSERT(n_actors < 64, "allocate_guest_page_tables");

    static int old_n_actors = 0;
    if (n_actors <= old_n_actors) {
        return 0;
    }
    old_n_actors = n_actors;
    SAFE_VFREE(_allocated_page_tables);
    SAFE_VFREE(_allocated_extended_page_tables);
    SAFE_VFREE(_allocated_guest_gdts);
    SAFE_FREE(_vmlaunch_page);
    SAFE_FREE(_v2p_translations);

    // Guest page tables
    _allocated_page_tables =
        (actor_page_table_t *)CHECKED_VMALLOC(n_actors * sizeof(actor_page_table_t));
    memset(_allocated_page_tables, 0, n_actors * sizeof(actor_page_table_t));

    // EPTs
    _allocated_extended_page_tables =
        (actor_ept_t *)CHECKED_VMALLOC(n_actors * sizeof(actor_ept_t));
    memset(_allocated_extended_page_tables, 0, n_actors * sizeof(actor_ept_t));

    _allocated_guest_gdts = CHECKED_VMALLOC(n_actors * PAGE_SIZE);

    // A page with a single VMCALL instruction; used to put the VM into launched state
    _vmlaunch_page = CHECKED_ZALLOC(PAGE_SIZE);
    _vmlaunch_page[0] = 0x0f;
    _vmlaunch_page[1] = 0x01;
    _vmlaunch_page[2] = 0xc1;

    _v2p_translations = CHECKED_ZALLOC(N_TRANSLATIONS * sizeof(v2p_t));

    faulty_ptes = (pte_t_ *)CHECKED_ZALLOC(sizeof(pte_t_));
    faulty_eptes = (epte_t_ *)CHECKED_ZALLOC(sizeof(epte_t_));
    return 0;
}

void free_guest_page_tables(void)
{
    SAFE_VFREE(_allocated_page_tables);
    SAFE_VFREE(_allocated_extended_page_tables);
    SAFE_VFREE(_allocated_guest_gdts);
    SAFE_FREE(ept_ptr);
    SAFE_FREE(_vmlaunch_page);
    SAFE_FREE(_v2p_translations);
    SAFE_FREE(faulty_ptes);
    SAFE_FREE(faulty_eptes);
}
