/// File:
///  - Guest page table management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/io.h>
#include <asm/msr.h>

#include "actor.h"
#include "hardware_desc.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

#include "page_tables_common.h"
#include "page_tables_guest.h"

#define INIT_PTE(PTE, PADDR, P, W, US, PWT, PCD, XD, A)                                            \
    {                                                                                              \
        (PTE).present = P;                                                                         \
        (PTE).write_access = W;                                                                    \
        (PTE).user_supervisor = US;                                                                \
        (PTE).page_write_through = PWT;                                                            \
        (PTE).page_cache_disable = PCD;                                                            \
        (PTE).paddr = (PADDR) >> 12;                                                               \
        (PTE).execute_disable = XD;                                                                \
        (PTE).accessed = A;                                                                        \
    }

#if VENDOR_ID == VENDOR_INTEL_
#define INIT_EPTE(PTE, PADDR, P, W, X, A)                                                          \
    {                                                                                              \
        (PTE).read_access = P;                                                                     \
        (PTE).write_access = W;                                                                    \
        (PTE).execute_access = X;                                                                  \
        (PTE).paddr = (PADDR) >> 12;                                                               \
        (PTE).accessed = A;                                                                        \
    }
#else // AMD
#define INIT_EPTE(PTE, PADDR, P, W, X, A)                                                          \
    {                                                                                              \
        (PTE).present = P;                                                                         \
        (PTE).write_access = W;                                                                    \
        (PTE).user_supervisor = 1;                                                                 \
        (PTE).page_write_through = 0;                                                              \
        (PTE).page_cache_disable = 0;                                                              \
        (PTE).paddr = (PADDR) >> 12;                                                               \
        (PTE).execute_disable = X ^ 1;                                                             \
        (PTE).accessed = A;                                                                        \
    }
#endif

#define INIT_PTE_DEFAULT(PTE, PADDR)  INIT_PTE(PTE, PADDR, 1, 1, 0, 0, 0, 0, 1)
#define INIT_EPTE_DEFAULT(PTE, PADDR) INIT_EPTE(PTE, PADDR, 1, 1, 1, 1)

#if VENDOR_ID == VENDOR_INTEL_
#define EPTE_IS_PRESENT(EPT) EPT.read_access
#else
#define EPTE_IS_PRESENT(EPT) EPT.present
#endif

#if VENDOR_ID == VENDOR_INTEL_
#define EPTE_IS_EXECUTABLE(EPT) EPT.execute_access
#else
#define EPTE_IS_EXECUTABLE(EPT) (EPT.execute_disable ^ 1)
#endif

#if VENDOR_ID == VENDOR_INTEL_
#define EPTE_IS_USER_ACCESSIBLE(EPT) EPT.user_ex_access
#else
#define EPTE_IS_USER_ACCESSIBLE(EPT) EPT.user_supervisor
#endif

eptp_t *ept_ptr = NULL; // global

static actor_page_table_t *allocated_page_tables = NULL;
static actor_ept_t *allocated_extended_page_tables = NULL;
static actor_gdt_t *allocated_guest_gdts = NULL;
static guest_memory_translations_t *guest_memory_translations = NULL;
static uint8_t *vmlaunch_page = NULL;
static pte_t_ *faulty_ptes = NULL;
static epte_t_ *faulty_eptes = NULL;

static bool guest_pt_is_set = false;
static bool ept_is_set = false;

// =================================================================================================
// Helper functions
// =================================================================================================
/// @brief Translate a host physical address to a virtual address in high memory.
/// Note: This function is necessary because kernel does not provide a direct interface to search
/// for a physical address in page tables (or at least I couldn't find one)
/// @param hpa Host physical address to translate
/// @return Host virtual address in high memory
static void *phys_to_vmalloc(uint64_t hpa, int actor_id)
{
    hgpa_t *flat_translations = (hgpa_t *)&guest_memory_translations[actor_id];
    for (int i = 0; i < sizeof(guest_memory_translations_t) / sizeof(hgpa_t); i++) {
        if (flat_translations[i].hpa == hpa) {
            return flat_translations[i].hva;
        }
    }
    return 0;
}

static inline bool gpa_is_valid(hgpa_t *translations, uint64_t gpa)
{
    for (int i = 0; i < sizeof(guest_memory_translations_t) / sizeof(hgpa_t); i++) {
        if (translations[i].gpa == gpa) {
            return true;
        }
    }
    return false;
}

static inline int set_last_pt_level(pte_t_ *pt, hgpa_t *translation, uint64_t paddr, uint64_t vaddr)
{
    size_t pt_index = PT_INDEX(vaddr);
    ASSERT(pt[pt_index].present == 0, "set_last_pt_level");
    INIT_PTE_DEFAULT(pt[pt_index], paddr);
    pt[pt_index].dirty = 1;

    translation->gpa = paddr;
    translation->gva = (void *)vaddr;
    return 0;
}

static inline int set_ept_entry(actor_ept_t *actor_ept_base, hgpa_t *translation, uint64_t l3_hpa,
                                uint64_t l2_hpa, uint64_t l1_hpa, void *hva)
{
    // get the addresses to map
    uint64_t gpa = translation->gpa;
    uint64_t hpa = vmalloc_to_phys(hva);

    // check for collisions
    // (the way we allocate page could, with very low likelihood, cause a collision)
    ASSERT(actor_ept_base->l1[PT_INDEX(gpa)].paddr == 0, "set_extended_page_tables");
    ASSERT(hpa, "set_extended_page_tables");

    translation->hpa = hpa;
    translation->hva = hva;

    // set all page table levels
    INIT_EPTE_DEFAULT(actor_ept_base->l4[PML4_INDEX(gpa)], l3_hpa);
    INIT_EPTE_DEFAULT(actor_ept_base->l3[PDPT_INDEX(gpa)], l2_hpa);
    INIT_EPTE_DEFAULT(actor_ept_base->l2[PDT_INDEX(gpa)], l1_hpa);
    INIT_EPTE_DEFAULT(actor_ept_base->l1[PT_INDEX(gpa)], hpa);

    // set additional properties for the last level
    actor_ept_base->l1[PT_INDEX(gpa)].dirty = 1;

#if VENDOR_ID == VENDOR_INTEL_
    actor_ept_base->l1[PT_INDEX(gpa)].ept_mem_type = 6;
    actor_ept_base->l1[PT_INDEX(gpa)].ignore_pat = 1;
#else
    actor_ept_base->l1[PT_INDEX(gpa)].page_attribute_table = 1;
#endif

    return 0;
}

// =================================================================================================
// Page table management interface
// =================================================================================================

/// @brief Set the guest page tables for all guest actors according to the layout defined in
/// guest_memory_t (see guest_page_tables.h), with the base address GUEST_MEMORY_START
/// @param void
/// @return 0 on success, -1 on failure
static int set_guest_page_tables(void)
{
    int err = 0;
    uint64_t vaddr = 0;
    uint64_t paddr = 0;

    static size_t old_n_actors = 0;
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
        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];

        // Set the first three levels of the page table
        // For convenience, we set GPA of the page tables to the same value as their GVA
        // Also, since the actor's sandbox is fairly small, the first three levels are identical
        // for all addresses within the actor memory
        actor_page_table_t *page_table = &allocated_page_tables[actor_id];
        actor_page_table_t *page_table_gpa = &guest_p_memory->guest_page_tables;
        translations->guest_page_tables[3].gpa = (uint64_t)&page_table_gpa->l4;

        size_t l4_index = PML4_INDEX(GUEST_V_MEMORY_START);
        uint64_t l3_gpa = (uint64_t)&page_table_gpa->l3;
        INIT_PTE_DEFAULT(page_table->l4[l4_index], l3_gpa);
        translations->guest_page_tables[2].gpa = l3_gpa;

        size_t l3_index = PDPT_INDEX(GUEST_V_MEMORY_START);
        uint64_t l2_gpa = (uint64_t)&page_table_gpa->l2;
        INIT_PTE_DEFAULT(page_table->l3[l3_index], l2_gpa);
        translations->guest_page_tables[1].gpa = l2_gpa;

        size_t l2_index = PDT_INDEX(GUEST_V_MEMORY_START);
        uint64_t l1_gpa = (uint64_t)&page_table_gpa->l1;
        INIT_PTE_DEFAULT(page_table->l2[l2_index], l1_gpa);
        translations->guest_page_tables[0].gpa = l1_gpa;

        // set the last level of the page table for each area of the actor sandbox
        for (int i = 0; i < sizeof(util_t); i += 4096) {
            vaddr = ((uint64_t)&guest_v_memory->util) + i;
            paddr = ((uint64_t)&guest_p_memory->util) + i;
            err = set_last_pt_level(page_table->l1, &translations->util[i / 4096], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }
        for (int i = 0; i < sizeof(actor_data_t); i += 4096) {
            uint64_t vaddr = ((uint64_t)&guest_v_memory->data) + i;
            if (enable_hpa_gpa_collisions) {
                uint64_t aliased_vaddr = ((uint64_t)&sandbox->data[0]) + i;
                paddr = vmalloc_to_phys((void *)aliased_vaddr);
            } else {
                paddr = ((uint64_t)&guest_p_memory->data) + i;
            }
            err = set_last_pt_level(page_table->l1, &translations->data[i / 4096], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }
        for (int i = 0; i < sizeof(actor_code_t); i += 4096) {
            vaddr = ((uint64_t)&guest_v_memory->code) + i;
            if (enable_hpa_gpa_collisions) {
                uint64_t aliased_vaddr = ((uint64_t)&sandbox->code[0]) + i;
                paddr = vmalloc_to_phys((void *)aliased_vaddr);
            } else {
                paddr = ((uint64_t)&guest_p_memory->code) + i;
            }
            err = set_last_pt_level(page_table->l1, &translations->code[i / 4096], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }
        { // GDT (indentation is for readability)
            vaddr = (uint64_t)&guest_v_memory->gdt;
            paddr = (uint64_t)&guest_p_memory->gdt;
            err = set_last_pt_level(page_table->l1, &translations->gdt[0], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }
        { // VMLAUNCH page (indentation is for readability)
            vaddr = (uint64_t)&guest_v_memory->vmlaunch_page[0];
            paddr = (uint64_t)&guest_p_memory->vmlaunch_page[0];
            err = set_last_pt_level(page_table->l1, &translations->vmlaunch_page[0], paddr, vaddr);
            CHECK_ERR("set_guest_page_tables");
        }
    }

    guest_pt_is_set = true;
    return 0;
}

/// @brief Map sandbox_t from host memory into the guest memory of each guest actor, according to
/// the layout defined in guest_memory_t (see page_tables_guest.h), with the base address equal to
/// GUEST_MEMORY_START
/// @param void
/// @return 0 on success, -1 on failure
static int set_extended_page_tables(void)
{
    int err = 0;

    ASSERT(actors != NULL, "set_extended_page_tables");
    ASSERT(sandbox != NULL, "set_extended_page_tables");
    ASSERT(guest_pt_is_set, "set_extended_page_tables");

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-guest actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST) {
            continue;
        }
        actor_ept_t *ept_base = &allocated_extended_page_tables[actor_id];
        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];

        // get addresses of the last three levels
        uint64_t l3_hpa = vmalloc_to_phys((void *)ept_base->l3);
        uint64_t l2_hpa = vmalloc_to_phys((void *)ept_base->l2);
        uint64_t l1_hpa = vmalloc_to_phys((void *)ept_base->l1);

        // map util_t into guest memory (the same phys range for all actors, i.e., shared)
        for (int i = 0; i < sizeof(util_t) / PAGE_SIZE; i += 1) {
            void *hva = (void *)&sandbox->util[0] + (i * PAGE_SIZE);
            err = set_ept_entry(ept_base, &translations->util[i], l3_hpa, l2_hpa, l1_hpa, hva);
            CHECK_ERR("set_extended_page_tables");
        }

        // map actor_data_t, actor_code_t, and GDT into guest memory (each actor has its own)
        for (int i = 0; i < sizeof(actor_data_t) / PAGE_SIZE; i += 1) {
            void *hva = (void *)&sandbox->data[actor_id] + (i * PAGE_SIZE);
            err = set_ept_entry(ept_base, &translations->data[i], l3_hpa, l2_hpa, l1_hpa, hva);
            CHECK_ERR("set_extended_page_tables");
        }
        for (int i = 0; i < sizeof(actor_code_t) / PAGE_SIZE; i += 1) {
            void *hva = (void *)&sandbox->code[actor_id] + (i * PAGE_SIZE);
            err = set_ept_entry(ept_base, &translations->code[i], l3_hpa, l2_hpa, l1_hpa, hva);
            CHECK_ERR("set_extended_page_tables");
        }
        { // indent for readability
            void *hva = (void *)&allocated_guest_gdts[actor_id];
            err = set_ept_entry(ept_base, &translations->gdt[0], l3_hpa, l2_hpa, l1_hpa, hva);
            CHECK_ERR("set_extended_page_tables");
        }
        { // indent for readability
            void *hva = (void *)&vmlaunch_page[0];
            err = set_ept_entry(ept_base, &translations->vmlaunch_page[0], l3_hpa, l2_hpa, l1_hpa,
                                hva);
            CHECK_ERR("set_extended_page_tables");
        }

        // map guest page tables
        for (int i = 0; i < sizeof(actor_page_table_t) / PAGE_SIZE; i += 1) {
            void *hva = (void *)&allocated_page_tables[actor_id] + (i * PAGE_SIZE);
            err = set_ept_entry(ept_base, &translations->guest_page_tables[i], l3_hpa, l2_hpa,
                                l1_hpa, hva);
            CHECK_ERR("set_extended_page_tables");
        }
    }

    ept_is_set = true;
    return 0;
}

/// @brief Store a pointer to the EPT of actor 1 (default) in ept_ptr after updating extended page
/// tables
/// @param void
/// @return 0 on success, -1 on failure
static int update_eptp(void)
{
    ASSERT(ept_is_set, "update_eptp");
    SAFE_FREE(ept_ptr);
    ept_ptr = CHECKED_ZALLOC(sizeof(eptp_t) * n_actors);
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_ept_t *actor_ept_base = &allocated_extended_page_tables[actor_id];
        ept_ptr[actor_id].memory_type = VMX_BASIC_MEM_TYPE_WB;
        ept_ptr[actor_id].page_walk_length = 3;
        ept_ptr[actor_id].ad_enabled = 1; // native_read_msr(MSR_IA32_VMX_EPT_VPID_CAP) &0x00200000;
        ept_ptr[actor_id].superv_sdw_stack = 0;
        ept_ptr[actor_id].paddr = vmalloc_to_phys(actor_ept_base->l4) >> 12;
    }

    return 0;
}

int map_sandbox_to_guest_memory(void)
{
    int err = 0;
    ASSERT(allocated_page_tables != NULL, "map_sandbox_to_guest_memory");
    ASSERT(allocated_extended_page_tables != NULL, "map_sandbox_to_guest_memory");
    ASSERT(allocated_guest_gdts != NULL, "map_sandbox_to_guest_memory");

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

        pte_t_ *ptep = &allocated_page_tables[actor_id].l1[index];
        faulty_ptes[actor_id] = *ptep;

        uint64_t org_pte = *(uint64_t *)ptep;
        uint64_t pte = (org_pte | mask_set) & mask_clear;
        if (pte != org_pte) {
            *(uint64_t *)ptep = pte;
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

        allocated_page_tables[actor_id].l1[index] = faulty_ptes[actor_id];
    }
}

/// @brief Set EPT permissions on the faulty page based on the actor's metadata (for each actor)
/// @param void
void set_faulty_page_ept_permissions(void)
{
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];
        uint64_t gpa = translations->data[FAULTY_PAGE_ID].gpa;
        size_t index = PT_INDEX(gpa);

        uint64_t pte_mask = actor->data_ept_properties;
        uint64_t mask_set = pte_mask & MODIFIABLE_EPTE_BITS;
        uint64_t mask_clear = pte_mask | ~MODIFIABLE_EPTE_BITS;

        epte_t_ *ptep = &allocated_extended_page_tables[actor_id].l1[index];
        faulty_eptes[actor_id] = *ptep;

        uint64_t org_pte = *(uint64_t *)ptep;
        uint64_t pte = (org_pte | mask_set) & mask_clear;
        if (pte != org_pte) {
            *(uint64_t *)ptep = pte;
            // native_page_invalidate(vaddr);
        }
    }
}

void restore_faulty_page_ept_permissions(void)
{
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        guest_memory_translations_t *translations = &guest_memory_translations[actor_id];
        uint64_t gpa = translations->data[FAULTY_PAGE_ID].gpa;
        size_t index = PT_INDEX(gpa);

        allocated_extended_page_tables[actor_id].l1[index] = faulty_eptes[actor_id];
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
    actor_page_table_t *page_table = &allocated_page_tables[actor_id];
    guest_memory_translations_t *translations = &guest_memory_translations[actor_id];

    // L4 traversal
    pml4e_t *l4 = page_table->l4;
    for (uint64_t curr_l4_id = 0; curr_l4_id < ENTRIES_PER_PAGE; curr_l4_id += 1) {
        pml4e_t l4e = l4[curr_l4_id]; // current L4 entry
        if (!l4e.present)
            continue;
        // we allocate memory such that only the first L4 entry is used
        ASSERT(curr_l4_id == 0, "dbg_dump_guest_page_tables");

        uint64_t l3_gpa = ((uint64_t)l4e.paddr << 12);
        ASSERT_MSG(l3_gpa == translations->guest_page_tables[2].gpa, "dbg_dump_guest_page_tables",
                   "0x%llx != 0x%llx\n", l3_gpa, translations->guest_page_tables[2].gpa);
        pdpte_t *l3 = (pdpte_t *)translations->guest_page_tables[2].hva;

        // L3 traversal
        for (uint64_t curr_l3_id = 0; curr_l3_id < ENTRIES_PER_PAGE; curr_l3_id += 1) {
            pdpte_t l3e = l3[curr_l3_id]; // current L3 entry
            if (!l3e.present)
                continue;
            // we allocate memory such that only the first L3 entry is used
            ASSERT(curr_l3_id == 0, "dbg_dump_guest_page_tables");

            uint64_t l2_gpa = ((uint64_t)l3e.paddr << 12);
            ASSERT(l2_gpa == translations->guest_page_tables[1].gpa, "dbg_dump_guest_page_tables");
            pdte_t *l2 = (pdte_t *)translations->guest_page_tables[1].hva;

            // L2 traversal
            for (uint64_t curr_l2_id = 0; curr_l2_id < ENTRIES_PER_PAGE; curr_l2_id += 1) {
                pdte_t l2e = l2[curr_l2_id]; // current L2 entry
                if (!l2e.present)
                    continue;
                ASSERT(curr_l2_id == 0, "dbg_dump_guest_page_tables");

                uint64_t l1_gpa = ((uint64_t)l2e.paddr << 12);
                ASSERT(l1_gpa == translations->guest_page_tables[0].gpa,
                       "dbg_dump_guest_page_tables");
                pte_t_ *l1 = (pte_t_ *)translations->guest_page_tables[0].hva;

                // L1 traversal
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
    actor_ept_t *actor_ept_base = &allocated_extended_page_tables[actor_id];

    // L4 traversal
    epml4e_t *l4 = actor_ept_base->l4;
    for (uint64_t curr_l4_id = 0; curr_l4_id < ENTRIES_PER_PAGE; curr_l4_id += 1) {
        epml4e_t l4e = l4[curr_l4_id];
        if (!EPTE_IS_PRESENT(l4e))
            continue;
        uint64_t l3_hpa = ((uint64_t)l4e.paddr << 12);
        epdpte_t *l3 = actor_ept_base->l3;
        ASSERT((l3_hpa & ~0xFFF) == vmalloc_to_phys(l3), "dbg_dump_ept");

        // L3 traversal
        for (uint64_t curr_l3_id = 0; curr_l3_id < ENTRIES_PER_PAGE; curr_l3_id += 1) {
            epdpte_t l3e = l3[curr_l3_id];
            if (!EPTE_IS_PRESENT(l3e))
                continue;
            uint64_t l2_hpa = ((uint64_t)l3e.paddr << 12);
            epdte_t *l2 = actor_ept_base->l2;
            ASSERT((l2_hpa & ~0xFFF) == vmalloc_to_phys(l2), "dbg_dump_ept");

            // L2 traversal
            for (uint64_t curr_l2_id = 0; curr_l2_id < ENTRIES_PER_PAGE; curr_l2_id += 1) {
                epdte_t l2e = l2[curr_l2_id];
                if (!EPTE_IS_PRESENT(l2e))
                    continue;
                uint64_t l1_hpa = ((uint64_t)l2e.paddr << 12);
                epte_t_ *l1 = actor_ept_base->l1;
                ASSERT((l1_hpa & ~0xFFF) == vmalloc_to_phys(l1), "dbg_dump_ept");

                // L1 traversal
                for (uint64_t curr_l1_id = 0; curr_l1_id < ENTRIES_PER_PAGE; curr_l1_id += 1) {
                    epte_t_ l1e = l1[curr_l1_id];
                    if (!EPTE_IS_PRESENT(l1e))
                        continue;
                    uint64_t gpa = (curr_l4_id << PML4_SHIFT) | (curr_l3_id << PDPT_SHIFT) |
                                   (curr_l2_id << PDT_SHIFT) | (curr_l1_id << PT_SHIFT);

                    // if HPA-GPA collisions are enabled, we will have multiple translations per
                    // physical address; hence, filter out the unused GPAs
                    if (enable_hpa_gpa_collisions &&
                        !gpa_is_valid((hgpa_t *)&guest_memory_translations[actor_id], gpa)) {
                        continue;
                    }

                    uint64_t hpa = ((uint64_t)l1e.paddr << 12);
                    void *hva = phys_to_vmalloc(hpa, actor_id);
                    char r = EPTE_IS_PRESENT(l1e) ? 'R' : '-';
                    char w = l1e.write_access ? 'W' : '-';
                    char x = EPTE_IS_EXECUTABLE(l1e) ? 'X' : '-';
                    char a = l1e.accessed ? 'A' : '-';
                    char d = l1e.dirty ? 'D' : '-';
                    char us = EPTE_IS_USER_ACCESSIBLE(l1e) ? 'U' : '-';
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

    static size_t old_n_actors = 0;
    if (n_actors <= old_n_actors) {
        memset(allocated_page_tables, 0, n_actors * sizeof(actor_page_table_t));
        memset(allocated_extended_page_tables, 0, n_actors * sizeof(actor_ept_t));
        memset(allocated_guest_gdts, 0, n_actors * sizeof(actor_gdt_t));
        memset(guest_memory_translations, 0, n_actors * sizeof(guest_memory_translations_t));
        return 0;
    }
    old_n_actors = n_actors;
    SAFE_VFREE(allocated_page_tables);
    SAFE_VFREE(allocated_extended_page_tables);
    SAFE_VFREE(allocated_guest_gdts);
    SAFE_FREE(guest_memory_translations);
    SAFE_FREE(vmlaunch_page);

    // Guest page tables
    allocated_page_tables =
        (actor_page_table_t *)CHECKED_VMALLOC(n_actors * sizeof(actor_page_table_t));
    memset(allocated_page_tables, 0, n_actors * sizeof(actor_page_table_t));

    // EPTs
    allocated_extended_page_tables = (actor_ept_t *)CHECKED_VMALLOC(n_actors * sizeof(actor_ept_t));
    memset(allocated_extended_page_tables, 0, n_actors * sizeof(actor_ept_t));

    allocated_guest_gdts = CHECKED_VMALLOC(n_actors * sizeof(actor_gdt_t));

    // Fast translations
    guest_memory_translations = CHECKED_ZALLOC(n_actors * sizeof(guest_memory_translations_t));

    // A page with a single VMCALL instruction; used to put the VM into launched state
    vmlaunch_page = CHECKED_ZALLOC(PAGE_SIZE);
    vmlaunch_page[0] = 0x0f;
    vmlaunch_page[1] = 0x01;
    vmlaunch_page[2] = 0xc1;

    faulty_ptes = (pte_t_ *)CHECKED_ZALLOC(sizeof(pte_t_));
    faulty_eptes = (epte_t_ *)CHECKED_ZALLOC(sizeof(epte_t_));

    guest_pt_is_set = false;
    ept_is_set = false;
    return 0;
}

void free_guest_page_tables(void)
{
    SAFE_VFREE(allocated_page_tables);
    SAFE_VFREE(allocated_extended_page_tables);
    SAFE_VFREE(allocated_guest_gdts);
    SAFE_FREE(guest_memory_translations);
    SAFE_FREE(ept_ptr);
    SAFE_FREE(vmlaunch_page);
    SAFE_FREE(faulty_ptes);
    SAFE_FREE(faulty_eptes);
}
