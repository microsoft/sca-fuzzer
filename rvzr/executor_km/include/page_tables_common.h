/// File: Dispatch header that includes the correct page tables definitions for the architecture
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _PAGE_TABLES_COMMON_H_
#define _PAGE_TABLES_COMMON_H_

#include "hardware_desc.h"
#include <linux/slab.h> // PAGE_SIZE
#include <linux/types.h>

#define ENTRIES_PER_PAGE (PAGE_SIZE / sizeof(uint64_t))

// =================================================================================================
// X86
// =================================================================================================
#if defined(ARCH_X86_64)

#define MODIFIABLE_PTE_BITS                                                                        \
    (_PAGE_PRESENT | _PAGE_RW | _PAGE_PWT | _PAGE_PCD | _PAGE_ACCESSED | _PAGE_DIRTY |             \
     _PAGE_PKEY_BIT0 | _PAGE_PKEY_BIT1 | _PAGE_PKEY_BIT2 | _PAGE_PKEY_BIT3 | _PAGE_NX |            \
     (1ULL << 51))

#define _E_PAGE_PRESENT  (1 << 0)
#define _E_PAGE_RW       (1 << 1)
#define _E_PAGE_X        (1 << 2)
#define _E_PAGE_ACCESSED (1 << 8)
#define _E_PAGE_DIRTY    (1 << 9)
#define _E_PAGE_USER     (1 << 10)

#if VENDOR_ID == VENDOR_INTEL_ // Intel
#define MODIFIABLE_EPTE_BITS                                                                       \
    (_E_PAGE_PRESENT | _E_PAGE_RW | _E_PAGE_X | _E_PAGE_ACCESSED | _E_PAGE_DIRTY | _E_PAGE_USER |  \
     (1ULL << 51))
#else
#define MODIFIABLE_EPTE_BITS MODIFIABLE_PTE_BITS
#endif

// -------------------------------------------------------------------------------------------------
// Normal page tables
// -------------------------------------------------------------------------------------------------
#define PML4_SHIFT     39
#define PDPT_SHIFT     30
#define PDT_SHIFT      21
#define PT_SHIFT       12
#define MAX_VADDR_BITS 48

#define PML4_INDEX(vaddr) (((uint64_t)(vaddr) >> PML4_SHIFT) & 0x1FF)
#define PDPT_INDEX(vaddr) (((uint64_t)(vaddr) >> PDPT_SHIFT) & 0x1FF)
#define PDT_INDEX(vaddr)  (((uint64_t)(vaddr) >> PDT_SHIFT) & 0x1FF)
#define PT_INDEX(vaddr)   (((uint64_t)(vaddr) >> PT_SHIFT) & 0x1FF)

// Table 4-15. Format of a PML4 Entry (PML4E) that References a Page-Directory-Pointer Table
typedef struct {
    uint64_t present : 1;
    uint64_t write_access : 1;
    uint64_t user_supervisor : 1;
    uint64_t page_write_through : 1;
    uint64_t page_cache_disable : 1;
    uint64_t accessed : 1;
    uint64_t ignored : 1;
    uint64_t reserved_zero : 1;
    uint64_t ignored_11_8 : 4;
    uint64_t paddr : (PHYSICAL_WIDTH - 12);
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_62_52 : 11;
    uint64_t execute_disable : 1;
} __attribute__((packed)) pml4e_t;

// Table 4-17. Format of a Page-Directory-Pointer-Table Entry (PDPTE) that
// References a Page Directory
typedef struct {
    uint64_t present : 1;
    uint64_t write_access : 1;
    uint64_t user_supervisor : 1;
    uint64_t page_write_through : 1;
    uint64_t page_cache_disable : 1;
    uint64_t accessed : 1;
    uint64_t ignored : 1;
    uint64_t reserved_zero : 1;
    uint64_t ignored_11_8 : 4;
    uint64_t paddr : (PHYSICAL_WIDTH - 12);
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_62_52 : 11;
    uint64_t execute_disable : 1;
} __attribute__((packed)) pdpte_t;

// Table 4-19. Format of a Page-Directory Entry that References a Page Table
typedef struct {
    uint64_t present : 1;
    uint64_t write_access : 1;
    uint64_t user_supervisor : 1;
    uint64_t page_write_through : 1;
    uint64_t page_cache_disable : 1;
    uint64_t accessed : 1;
    uint64_t ignored : 1;
    uint64_t reserved_zero : 1;
    uint64_t ignored_11_8 : 4;
    uint64_t paddr : (PHYSICAL_WIDTH - 12);
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_62_52 : 11;
    uint64_t execute_disable : 1;
} __attribute__((packed)) pdte_t;

// Table 4-20. Format of a Page-Table Entry that Maps a 4-KByte Page
typedef struct {
    uint64_t present : 1;
    uint64_t write_access : 1;
    uint64_t user_supervisor : 1;
    uint64_t page_write_through : 1;
    uint64_t page_cache_disable : 1;
    uint64_t accessed : 1;
    uint64_t dirty : 1;
    uint64_t page_attribute_table : 1;
    uint64_t global_page : 1;
    uint64_t ignored_11_9 : 3;
    uint64_t paddr : (PHYSICAL_WIDTH - 12);
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_58_52 : 7;
    uint64_t protection_key : 4;
    uint64_t execute_disable : 1;
} __attribute__((packed)) pte_t_; // using pte_t_ as pte_t is already defined in linux/types.h

// -------------------------------------------------------------------------------------------------
// Extended page tables
// -------------------------------------------------------------------------------------------------

// Figure 29-1. Formats of EPTP and EPT Paging-Structure Entries
typedef struct {
    uint64_t memory_type : 3;
    uint64_t page_walk_length : 3;
    uint64_t ad_enabled : 1;
    uint64_t superv_sdw_stack : 1;
    uint64_t reserved_11_08 : 4;
    uint64_t paddr : (PHYSICAL_WIDTH - 12);
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t reserved_63_52 : 12;
} __attribute__((packed)) eptp_t;

#if VENDOR_ID == 1 // Intel
// Table 28-1. Format of an EPT PML4E
typedef struct {
    uint64_t read_access : 1;
    uint64_t write_access : 1;
    uint64_t execute_access : 1;
    uint64_t reserved_7_3 : 5;
    uint64_t accessed : 1;
    uint64_t ignored_9 : 1;
    uint64_t user_ex_access : 1;
    uint64_t ignored_11 : 1;
    uint64_t paddr : (PHYSICAL_WIDTH - 12);
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_63_52 : 12;
} __attribute__((packed)) epml4e_t;
#else
typedef pml4e_t epml4e_t;
#endif

#if VENDOR_ID == 1 // Intel
// Table 28-3. Format of an EPT Page-Directory-Pointer-Table Entry (EPT PDPTE)
typedef struct {
    uint64_t read_access : 1;
    uint64_t write_access : 1;
    uint64_t execute_access : 1;
    uint64_t reserved_6_3 : 4;
    uint64_t reserved_7 : 1;
    uint64_t accessed : 1;
    uint64_t ignored_9 : 1;
    uint64_t user_ex_access : 1;
    uint64_t ignored_11 : 1;
    uint64_t paddr : (PHYSICAL_WIDTH - 12);
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_63_52 : 12;
} __attribute__((packed)) epdpte_t;
#else
typedef pdpte_t epdpte_t;
#endif

#if VENDOR_ID == 1 // Intel
typedef struct {
    uint64_t read_access : 1;
    uint64_t write_access : 1;
    uint64_t execute_access : 1;
    uint64_t reserved_6_3 : 4;
    uint64_t reserved_7 : 1;
    uint64_t accessed : 1;
    uint64_t ignored_9 : 1;
    uint64_t user_ex_access : 1;
    uint64_t ignored_11 : 1;
    uint64_t paddr : (PHYSICAL_WIDTH - 12);
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_63_52 : 12;
} __attribute__((packed)) epdte_t;
#else
typedef pdte_t epdte_t;
#endif

#if VENDOR_ID == 1 // Intel
typedef struct {
    uint64_t read_access : 1;
    uint64_t write_access : 1;
    uint64_t execute_access : 1;
    uint64_t ept_mem_type : 3;
    uint64_t ignore_pat : 1;
    uint64_t ignored_7 : 1;
    uint64_t accessed : 1;
    uint64_t dirty : 1;
    uint64_t user_ex_access : 1;
    uint64_t ignored_11 : 1;
    uint64_t paddr : (PHYSICAL_WIDTH - 12);
#if PHYSICAL_WIDTH < 52
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
#endif
    uint64_t ignored_56_52 : 5;
    uint64_t verif_guest_pag : 1;
    uint64_t pag_write_access : 1;
    uint64_t ignored_59 : 1;
    uint64_t superv_sdw_stack : 1;
    uint64_t subpg_write_perm : 1;
    uint64_t ignored_62 : 1;
    uint64_t suppress_ve : 1;
} __attribute__((packed)) epte_t_;
#else
typedef pte_t_ epte_t_;
#endif

static inline void set_user_bit(pte_t_ *pte) { pte->user_supervisor = 1; }

// =================================================================================================
// ARM
// =================================================================================================
#elif defined(ARCH_ARM)

// NOTE: All definitions below assume 4KB pages
//
// NOTE: The formats are described in the ARMv8-A Architecture Reference Manual
//       see D8.3.1 VMSAv8-64 descriptor formats

#define MODIFIABLE_PTE_BITS (PTE_VALID | PTE_USER | PTE_RDONLY)

typedef struct {
    uint64_t valid : 1;
    uint64_t type : 1;
    uint64_t ignored_2_7 : 6;
    uint64_t nlta_high : 2;
    uint64_t access_flag : 1;
    uint64_t ignored_11 : 1;
    uint64_t nlta_low : 38;
    uint64_t reserved_50 : 1;
    uint64_t ignored_51_58 : 8;
    uint64_t pxn_table : 1;
    uint64_t uxn_table : 1;
    uint64_t ap_table : 2;
    uint64_t ns_table : 1;
} __attribute__((packed)) l1_descr_t;

typedef struct {
    uint64_t valid : 1;
    uint64_t type : 1;
    uint64_t ignored_2_7 : 6;
    uint64_t nlta_high : 2;
    uint64_t access_flag : 1;
    uint64_t ignored_11 : 1;
    uint64_t nlta_low : 38;
    uint64_t reserved_50 : 1;
    uint64_t ignored_51_58 : 8;
    uint64_t reserved_59_63 : 5;
} __attribute__((packed)) l2_descr_t;

typedef struct {
    uint64_t valid : 1;
    uint64_t type : 1;
    uint64_t attr_index : 3;
    uint64_t non_secure : 1;
    uint64_t access_permissions : 2;
    uint64_t shareability : 2;
    uint64_t access_flag : 1;
    uint64_t not_global : 1;
    uint64_t paddr : 38;
    uint64_t guarded : 1;
    uint64_t dirty : 1;
    uint64_t contiguous : 1;
    uint64_t privileged_execute_never : 1;
    uint64_t execute_never : 1;
    uint64_t reserved_58_55 : 4;
    uint64_t ignored_63_59 : 5;
} __attribute__((packed)) l3_descr_t;

static inline void set_user_bit(l3_descr_t *pte)
{
    // pte->user_supervisor = 1;  // TODO
}

typedef l3_descr_t pte_t_;

#endif // ARCH_X86_64

#endif // _PAGE_TABLES_COMMON_H_
