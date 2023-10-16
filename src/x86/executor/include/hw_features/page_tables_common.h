/// File: Common definitions for page tables
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _PAGE_TABLES_COMMON_H_
#define _PAGE_TABLES_COMMON_H_

#include <linux/slab.h> // PAGE_SIZE
#include <linux/types.h>

#define ENTRIES_PER_PAGE (PAGE_SIZE / sizeof(uint64_t))

#ifndef PHYSICAL_WIDTH
#define PHYSICAL_WIDTH 40 // unused in the build; used only for syntax highlighting
#error "PHYSICAL_WIDTH must be defined by the makefile"
#endif

// =================================================================================================
// Normal page tables
// =================================================================================================
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
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
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
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
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
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
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
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
    uint64_t ignored_58_52 : 7;
    uint64_t protection_key : 4;
    uint64_t execute_disable : 1;
} __attribute__((packed)) pte_t_; // using pte_t_ as pte_t is already defined in linux/types.h

// =================================================================================================
// Extended page tables
// =================================================================================================

// Figure 29-1. Formats of EPTP and EPT Paging-Structure Entries
typedef struct {
    uint64_t memory_type : 3;
    uint64_t page_walk_length : 3;
    uint64_t ad_enabled : 1;
    uint64_t superv_sdw_stack : 1;
    uint64_t reserved_11_08 : 4;
    uint64_t paddr : 40;
    uint64_t reserved_63_52 : 12;
} __attribute__((packed)) eptp_t;

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
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
    uint64_t ignored_63_52 : 12;
} __attribute__((packed)) ept_pml4_pte;

// Table 28-3. Format of an EPT Page-Directory-Pointer-Table Entry (EPT PDPTE)
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
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
    uint64_t ignored_63_52 : 12;
} __attribute__((packed)) ept_pdpt_pte;

typedef struct {
    uint64_t read_access : 1;
    uint64_t write_access : 1;
    uint64_t execute_access : 1;
    uint64_t reserved_6_3 : 5;
    uint64_t ignored_7 : 1;
    uint64_t accessed : 1;
    uint64_t ignored_9 : 1;
    uint64_t user_ex_access : 1;
    uint64_t ignored_11 : 1;
    uint64_t paddr : (PHYSICAL_WIDTH - 12);
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
    uint64_t ignored_63_52 : 12;
} __attribute__((packed)) ept_pdt_pte;

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
    uint64_t reserved_51_M : (52 - PHYSICAL_WIDTH);
    uint64_t ignored_56_52 : 5;
    uint64_t verif_guest_pag : 1;
    uint64_t pag_write_access : 1;
    uint64_t ignored_59 : 1;
    uint64_t superv_sdw_stack : 1;
    uint64_t subpg_write_perm : 1;
    uint64_t ignored_62 : 1;
    uint64_t suppress_ve : 1;
} __attribute__((packed)) ept_pt_pte;

#endif // _PAGE_TABLES_COMMON_H_
