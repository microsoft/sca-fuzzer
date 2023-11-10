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

#include "hw_features/page_table.h"

#define MODIFIABLE_PTE_BITS                                                                        \
    (_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_PWT | _PAGE_PCD | _PAGE_ACCESSED |              \
     _PAGE_DIRTY | _PAGE_PKEY_BIT0 | _PAGE_PKEY_BIT1 | _PAGE_PKEY_BIT2 | _PAGE_PKEY_BIT3 |         \
     _PAGE_NX)
#define NO_CLEAR_MASK (0xffffffffffffffff & ~MODIFIABLE_PTE_BITS)

typedef struct {
    pteval_t data_ptes[N_DATA_PAGES_PER_ACTOR];
    pteval_t code_ptes[N_CODE_PAGES_PER_ACTOR];
} actor_orig_ptes_t;

static pteval_t *orig_ptes;

// the three variables below duplicate orig_ptes; kept for compatibility, and to be removed soon
static unsigned long faulty_page_addr = 0;
static pte_t *faulty_page_ptep = NULL;
static pteval_t orig_pte;

static inline void _native_page_invalidate(uint64_t va)
{
    asm volatile("invlpg (%0)" ::"r"(va) : "memory");
}

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
// Faulty page management
// =================================================================================================
int faulty_page_prepare(void)
{
    ASSERT(sandbox != NULL, "faulty_page_prepare");
    ASSERT(sandbox->data[0].faulty_area != NULL, "faulty_page_prepare");
    faulty_page_addr = (unsigned long)&(sandbox->data[0].faulty_area[0]);
    faulty_page_ptep = get_pte(faulty_page_addr);
    ASSERT(faulty_page_ptep != NULL, "faulty_page_prepare");
    return 0;
}

void faulty_page_pte_store(void) { orig_pte = faulty_page_ptep->pte; }

void faulty_page_pte_set(void)
{
    uint64_t pte_mask = actors[0].data_permissions;
    uint64_t mask_set = pte_mask & MODIFIABLE_PTE_BITS;
    uint64_t mask_clear = pte_mask | ~MODIFIABLE_PTE_BITS;
    pte_t new_pte = (pte_t){0};
    if ((mask_set != 0) || (mask_clear != NO_CLEAR_MASK)) {
        new_pte.pte = ((orig_pte | mask_set) & mask_clear);
        set_pte_at(current->mm, faulty_page_addr, faulty_page_ptep, new_pte);
        // When testing for #PF flushing the faulty page causes a 'soft
        // lookup' kernel error on certain CPUs.
        // asm volatile("clflush (%0)\nlfence\n" ::"r"(faulty_page_addr)
        // : "memory");
        _native_page_invalidate(faulty_page_addr);
    }
}

void faulty_page_pte_restore(void)
{
    uint64_t pte_mask = actors[0].data_permissions;
    uint64_t mask_set = pte_mask & MODIFIABLE_PTE_BITS;
    uint64_t mask_clear = ~pte_mask | ~MODIFIABLE_PTE_BITS;
    pte_t new_pte = (pte_t){0};
    if ((mask_set != 0) || (mask_clear != NO_CLEAR_MASK)) {
        new_pte.pte = orig_pte;
        set_pte_at(current->mm, faulty_page_addr, faulty_page_ptep, new_pte);
        _native_page_invalidate(faulty_page_addr);
    }
}

// =================================================================================================
// Management of User Pages
// =================================================================================================
static int preserve_and_set_user(uint64_t va, pteval_t *orig_pte)
{
    pte_t *ptep = get_pte(va);
    ASSERT(ptep != NULL, "preserve_and_set_user");
    *orig_pte = ptep->pte;
    ptep->pte |= _PAGE_USER;
    _native_page_invalidate(va);
    return 0;
}

static int restore_user(uint64_t va, pteval_t *orig_pte)
{
    pte_t *ptep = get_pte(va);
    ASSERT(ptep != NULL, "restore_user");
    ptep->pte = *orig_pte;
    _native_page_invalidate(va);
    return 0;
}

/// @brief Configures the page table entries for those sandbox pages that are mapped into
/// user-type actors
/// @param void
/// @return 0 on success, -1 on failure
int map_user_pages(void)
{
    int err = 0;

    static int old_n_actors = 0;
    if (n_actors > old_n_actors) {
        // the number of actors has increased, so we need to allocate more space for preserving PTEs
        SAFE_FREE(orig_ptes);
        orig_ptes = CHECKED_ZALLOC(sizeof(pteval_t) * get_sandbox_size_pages());
    }
    old_n_actors = n_actors;

    // enable user access to util pages so that the actors can store measurement results
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        uint64_t va = (uint64_t)sandbox->util + i * 4096;
        pteval_t *orig_pte = &orig_ptes[i];
        err = preserve_and_set_user(va, orig_pte);
        CHECK_ERR("preserve_and_set_user");
    }

    // enable user access to code and data pages of the sandbox that belong to user actors
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-user actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->pl != PL_USER) {
            continue;
        }
        int org_ptes_offset =
            N_UTIL_PAGES + actor_id * (N_CODE_PAGES_PER_ACTOR + N_DATA_PAGES_PER_ACTOR);
        actor_orig_ptes_t *actor_orig_ptes = (actor_orig_ptes_t *)&orig_ptes[org_ptes_offset];

        // configure PTEs for each area of the actor sandbox while preserving the old values
        for (int i = 0; i < sizeof(actor_data_t); i += 4096) {
            uint64_t va = ((uint64_t)&sandbox->data[actor_id]) + i;
            pteval_t *orig_pte = &actor_orig_ptes->data_ptes[i / 4096];
            err = preserve_and_set_user(va, orig_pte);
            CHECK_ERR("preserve_and_set_user");
        }
        for (int i = 0; i < sizeof(actor_code_t); i += 4096) {
            uint64_t va = ((uint64_t)&sandbox->code[actor_id]) + i;
            pteval_t *orig_pte = &actor_orig_ptes->code_ptes[i / 4096];
            err = preserve_and_set_user(va, orig_pte);
            CHECK_ERR("preserve_and_set_user");
        }
    }
    return 0;
}

int unmap_user_pages(void)
{
    int err = 0;

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-user actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->pl != PL_USER) {
            continue;
        }
        int org_ptes_offset =
            N_UTIL_PAGES + actor_id * (N_CODE_PAGES_PER_ACTOR + N_DATA_PAGES_PER_ACTOR);
        actor_orig_ptes_t *actor_orig_ptes = (actor_orig_ptes_t *)&orig_ptes[org_ptes_offset];

        // configure PTEs for each area of the actor sandbox while preserving the old values
        for (int i = 0; i < sizeof(actor_data_t); i += 4096) {
            uint64_t va = ((uint64_t)&sandbox->data[actor_id]) + i;
            pteval_t *orig_pte = &actor_orig_ptes->data_ptes[i / 4096];
            err = restore_user(va, orig_pte);
            CHECK_ERR("restore_user");
        }
        for (int i = 0; i < sizeof(actor_code_t); i += 4096) {
            uint64_t va = ((uint64_t)&sandbox->code[actor_id]) + i;
            pteval_t *orig_pte = &actor_orig_ptes->code_ptes[i / 4096];
            err = restore_user(va, orig_pte);
            CHECK_ERR("restore_user");
        }
    }

    // restore PTE for util pages
    for (int i = 0; i < N_UTIL_PAGES; i++) {
        uint64_t va = (uint64_t)sandbox->util + i * 4096;
        pteval_t *orig_pte = &orig_ptes[i];
        err = restore_user(va, orig_pte);
        CHECK_ERR("restore_user");
    }

    return 0;
}

// =================================================================================================
int init_page_table_manager(void)
{
    orig_pte = 0;
    faulty_page_ptep = NULL;
    orig_ptes = CHECKED_ZALLOC(sizeof(pteval_t) * get_sandbox_size_pages());
    return 0;
}

void free_page_table_manager(void) { SAFE_FREE(orig_ptes); }
