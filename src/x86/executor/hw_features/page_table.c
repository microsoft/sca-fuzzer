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

static unsigned long faulty_page_addr = 0;
static pte_t *faulty_page_ptep = NULL;
static pteval_t orig_pte;

inline void _native_page_invalidate(void)
{
    asm volatile("invlpg (%0)" ::"r"(faulty_page_addr) : "memory");
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
        _native_page_invalidate();
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
        _native_page_invalidate();
    }
}

// =================================================================================================
int init_page_table_manager(void)
{
    orig_pte = 0;
    faulty_page_ptep = NULL;
    return 0;
}

void free_page_table_manager(void) {}
