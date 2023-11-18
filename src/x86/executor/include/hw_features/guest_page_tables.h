/// File: Header for guest page table functions
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _GUEST_PAGE_TABLES_H_
#define _GUEST_PAGE_TABLES_H_

#include "hw_features/page_tables_common.h"
#include "sandbox_manager.h"

// start of guest's physical memory; this is an arbitrary large aligned number
#define GUEST_P_MEMORY_START 0
#define GUEST_V_MEMORY_START 0x8000000000ULL
#define GUEST_MEMORY_SIZE    (64 * 4096)          // max size that could be mapped by a single PTE

// Memory layout within the guest memory
typedef struct {
    pml4e_t pml4[ENTRIES_PER_PAGE];
    pdpte_t pdpt[ENTRIES_PER_PAGE];
    pdte_t pdt[ENTRIES_PER_PAGE];
    pte_t_ pt[ENTRIES_PER_PAGE];
} actor_page_table_t;

// Guest memory layout; it is identical for both physical and virtual memory
typedef struct {
    util_t util;
    actor_data_t data;
    actor_code_t code;
    uint8_t gdt[PAGE_SIZE];
    actor_page_table_t guest_page_tables;
} __attribute__((packed)) guest_memory_t;

typedef struct {
    uint64_t vaddr;
    uint64_t paddr;
} __attribute__((packed)) v2p_t;

extern eptp_t *ept_ptr;

int dbg_dump_guest_page_tables(int actor_id);
int dbg_dump_ept(void);

int map_sandbox_to_guest_memory(void);
int allocate_guest_page_tables(void);
void free_guest_page_tables(void);

#endif // _GUEST_PAGE_TABLES_H_
