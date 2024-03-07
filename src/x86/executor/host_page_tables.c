/// File:
///  - Page Table management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/kernel.h>
#include <linux/mm.h>

#include "actor.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

#include "host_page_tables.h"
#include "page_tables_common.h"

static sandbox_ptes_t *orig_ptes;
static sandbox_pteps_t *sandbox_pteps;
static pte_t_ *faulty_ptes = NULL;

pte_t *get_pte(uint64_t address)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    /* Make sure we are in vmalloc area: */
    ASSERT_ENULL(address >= VMALLOC_START && address < VMALLOC_END, "get_pte");

    pgd = pgd_offset(current->mm, address);
    ASSERT_ENULL(!pgd_none(*pgd), "get_pte");

    p4d = p4d_offset(pgd, address);
    pud = pud_offset(p4d, address);
    ASSERT_ENULL(!pud_none(*pud), "get_pte");

    pmd = pmd_offset(pud, address);
    ASSERT_ENULL(!pmd_none(*pmd), "get_pte");

    pte = pte_offset_kernel(pmd, address);
    ASSERT_ENULL(pte_present(*pte), "get_pte");

    return pte;
}

// =================================================================================================
// Manipulation of Host Page Tables
// =================================================================================================
/// @brief Cache the PTE pointers for all sandbox pages.
/// @param void
/// @return 0 on success, -1 on failure
int cache_host_pteps(void)
{
    ASSERT(sandbox_pteps != NULL, "cache_host_pteps");
    ASSERT(sandbox != NULL, "cache_host_pteps");

    static int old_n_actors = 1;
    if (n_actors > old_n_actors) {
        SAFE_FREE(sandbox_pteps->data_pteps);
        SAFE_FREE(sandbox_pteps->code_pteps);
        sandbox_pteps->data_pteps =
            CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_ *));
        sandbox_pteps->code_pteps =
            CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_ *));
    }
    old_n_actors = n_actors;

    // cache the PTE pointers for the util pages
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        uint64_t va = (uint64_t)sandbox->util + i * 4096;
        pte_t *ptep = get_pte(va);
        ASSERT(ptep != NULL, "cache_host_pteps");
        sandbox_pteps->util_pteps[i] = (pte_t_ *)&ptep->pte;
    }

    // cache the PTE pointers for the code and data pages of the sandbox
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // cache the PTE pointers for the data pages of the actor
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            uint64_t va = ((uint64_t)&sandbox->data[actor_id]) + i * 4096;
            pte_t *ptep = get_pte(va);
            ASSERT(ptep != NULL, "cache_host_pteps");
            sandbox_pteps->data_pteps[actor_id * N_DATA_PAGES_PER_ACTOR + i] = (pte_t_ *)&ptep->pte;
        }
        // cache the PTE pointers for the code pages of the actor
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            uint64_t va = ((uint64_t)&sandbox->code[actor_id]) + i * 4096;
            pte_t *ptep = get_pte(va);
            ASSERT(ptep != NULL, "cache_host_pteps");
            sandbox_pteps->code_pteps[actor_id * N_CODE_PAGES_PER_ACTOR + i] = (pte_t_ *)&ptep->pte;
        }
    }
    return 0;
}

/// @brief Preserve the original PTEs for all sandbox pages.
/// @param void
/// @return 0 on success, -1 on failure
int store_orig_host_permissions(void)
{
    ASSERT(sandbox_pteps->util_pteps[0] != NULL, "store_orig_host_permissions");
    ASSERT(sandbox_pteps->data_pteps[0] != NULL, "store_orig_host_permissions");
    ASSERT(sandbox_pteps->code_pteps[0] != NULL, "store_orig_host_permissions");

    static int old_n_actors = 1;
    if (n_actors > old_n_actors) {
        SAFE_FREE(orig_ptes->data_ptes);
        SAFE_FREE(orig_ptes->code_ptes);
        orig_ptes->data_ptes = CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_));
        orig_ptes->code_ptes = CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * n_actors * sizeof(pte_t_));

        SAFE_FREE(faulty_ptes);
        faulty_ptes = CHECKED_ZALLOC(sizeof(pte_t_) * n_actors);
    }
    old_n_actors = n_actors;

    // save the original PTEs for the util pages
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        orig_ptes->util_ptes[i] = *sandbox_pteps->util_pteps[i];
    }

    // save the original PTEs for the code and data pages of the sandbox
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // save the original PTEs for the data pages of the actor
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + i;
            orig_ptes->data_ptes[page_id] = *sandbox_pteps->data_pteps[page_id];
        }
        // save the original PTEs for the code pages of the actor
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_CODE_PAGES_PER_ACTOR + i;
            orig_ptes->code_ptes[page_id] = *sandbox_pteps->code_pteps[page_id];
        }
    }
    return 0;
}

/// @brief A shortcut to restore the original PTEs for a single page.
/// @param ptep
/// @param old_pte
/// @param vaddr
void restore_pte(pte_t_ *ptep, pte_t_ old_pte, uint64_t vaddr)
{
    uint64_t curr_pte_val = *(uint64_t *)ptep;
    uint64_t old_pte_val = *(uint64_t *)&old_pte;

    if (curr_pte_val != old_pte_val) {
        *ptep = old_pte;
        native_page_invalidate(vaddr);
    }
}

/// @brief Restore the original PTEs for all sandbox pages.
/// @param void
/// @return
int restore_orig_host_permissions(void)
{
    ASSERT(sandbox_pteps->util_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->data_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->code_pteps[0] != NULL, "restore_orig_host_permissions");

    // restore the original PTEs for the util pages
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        restore_pte(sandbox_pteps->util_pteps[i], orig_ptes->util_ptes[i],
                    (uint64_t)sandbox->util + i * 4096);
    }

    // restore the original PTEs for the code and data pages of the sandbox
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // restore the original PTEs for the data pages of the actor
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + i;
            restore_pte(sandbox_pteps->data_pteps[page_id], orig_ptes->data_ptes[page_id],
                        (uint64_t)&sandbox->data[actor_id] + i * 4096);
        }
        // restore the original PTEs for the code pages of the actor
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_CODE_PAGES_PER_ACTOR + i;
            restore_pte(sandbox_pteps->code_pteps[page_id], orig_ptes->code_ptes[page_id],
                        (uint64_t)&sandbox->code[actor_id] + i * 4096);
        }
    }
    return 0;
}

/// @brief Configures the page table entries for those sandbox pages that are mapped into
/// user-type actors
/// @param void
/// @return 0 on success, -1 on failure
int set_user_pages(void)
{
    ASSERT(sandbox_pteps->util_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->data_pteps[0] != NULL, "restore_orig_host_permissions");
    ASSERT(sandbox_pteps->code_pteps[0] != NULL, "restore_orig_host_permissions");

    // enable user access to util pages so that the actors can store measurement results
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        sandbox_pteps->util_pteps[i]->user_supervisor = 1;
        native_page_invalidate((uint64_t)sandbox->util + i * 4096);
    }

    // enable user access to code and data pages of the sandbox that belong to user actors
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-user actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->pl != PL_USER) {
            continue;
        }

        // configure PTEs for each area of the actor sandbox
        for (int i = 0; i < N_DATA_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + i;
            sandbox_pteps->data_pteps[page_id]->user_supervisor = 1;
            native_page_invalidate((uint64_t)&sandbox->data[actor_id] + i * 4096);
        }
        for (int i = 0; i < N_CODE_PAGES_PER_ACTOR; i++) {
            int page_id = actor_id * N_CODE_PAGES_PER_ACTOR + i;
            sandbox_pteps->code_pteps[page_id]->user_supervisor = 1;
            native_page_invalidate((uint64_t)&sandbox->code[actor_id] + i * 4096);
        }
    }

    return 0;
}

/// @brief Fast modification of the faulty page host PTE; sets the permissions according to
/// actor_t->data_permissions
/// @param void
void set_faulty_page_host_permissions(void)
{
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        uint64_t pte_mask = actors[actor_id].data_permissions;
        uint64_t mask_set = pte_mask & MODIFIABLE_PTE_BITS;
        uint64_t mask_clear = pte_mask | ~MODIFIABLE_PTE_BITS;

        int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + FAULTY_PAGE_ID;
        pte_t_ *ptep = sandbox_pteps->data_pteps[page_id];
        faulty_ptes[actor_id] = *ptep;
        uint64_t org_value = *(uint64_t *)ptep;
        uint64_t pte = (org_value | mask_set) & mask_clear;

        if (pte != org_value) {
            *(uint64_t *)ptep = (pte | mask_set) & mask_clear;
            native_page_invalidate((uint64_t)&sandbox->data[actor_id] + FAULTY_PAGE_ID * 4096);
        }
    }
}

/// @brief Fast recovery of original permissions of the faulty page host PTE
/// @param void
void restore_faulty_page_host_permissions(void)
{
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        int page_id = actor_id * N_DATA_PAGES_PER_ACTOR + FAULTY_PAGE_ID;
        *sandbox_pteps->data_pteps[page_id] = faulty_ptes[actor_id];
        native_page_invalidate((uint64_t)&sandbox->data[actor_id] + FAULTY_PAGE_ID * 4096);
    }
}

// =================================================================================================
int init_page_table_manager(void)
{
    orig_ptes = CHECKED_ZALLOC(sizeof(sandbox_ptes_t));
    orig_ptes->data_ptes = CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * sizeof(pte_t));
    orig_ptes->code_ptes = CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * sizeof(pte_t));
    orig_ptes->util_ptes = CHECKED_ZALLOC(N_UTIL_PAGES * sizeof(pte_t));

    sandbox_pteps = CHECKED_ZALLOC(sizeof(sandbox_pteps_t));
    sandbox_pteps->data_pteps = CHECKED_ZALLOC(N_DATA_PAGES_PER_ACTOR * sizeof(pte_t *));
    sandbox_pteps->code_pteps = CHECKED_ZALLOC(N_CODE_PAGES_PER_ACTOR * sizeof(pte_t *));
    sandbox_pteps->util_pteps = CHECKED_ZALLOC(N_UTIL_PAGES * sizeof(pte_t *));

    faulty_ptes = (pte_t_ *)CHECKED_ZALLOC(sizeof(pte_t_));
    return 0;
}

void free_page_table_manager(void)
{
    SAFE_FREE(sandbox_pteps->data_pteps);
    SAFE_FREE(sandbox_pteps->code_pteps);
    SAFE_FREE(sandbox_pteps->util_pteps);
    SAFE_FREE(sandbox_pteps);

    SAFE_FREE(orig_ptes->data_ptes);
    SAFE_FREE(orig_ptes->code_ptes);
    SAFE_FREE(orig_ptes->util_ptes);
    SAFE_FREE(orig_ptes);

    SAFE_FREE(faulty_ptes);
}
