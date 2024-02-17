/// File: Header for guest page table functions
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _GUEST_PAGE_TABLES_H_
#define _GUEST_PAGE_TABLES_H_

#include "page_tables_common.h"
#include "sandbox_manager.h"

// start of guest's physical memory; this is an arbitrary large aligned number
#define GUEST_P_MEMORY_START 0
#define GUEST_V_MEMORY_START 0x0ULL
#define GUEST_MEMORY_SIZE    (512 * 4096) // max size that could be mapped by a single last-level PT

// Memory layout within the guest memory
typedef struct {
    pml4e_t pml4[ENTRIES_PER_PAGE];
    pdpte_t pdpt[ENTRIES_PER_PAGE];
    pdte_t pdt[ENTRIES_PER_PAGE];
    pte_t_ pt[ENTRIES_PER_PAGE];
} actor_page_table_t;

typedef struct {
    epml4e_t l4[ENTRIES_PER_PAGE];
    epdpte_t l3[ENTRIES_PER_PAGE];
    epdte_t l2[ENTRIES_PER_PAGE];
    epte_t_ l1[ENTRIES_PER_PAGE];
} actor_ept_t;

// Guest memory layout; it is identical for both physical and virtual memory
typedef struct {
    util_t util;
    actor_data_t data;
    actor_code_t code;
    uint8_t vmlaunch_page[PAGE_SIZE];
    uint8_t gdt[PAGE_SIZE];
    actor_page_table_t guest_page_tables;
} __attribute__((packed)) guest_memory_t;

typedef struct {
    uint64_t vaddr;
    uint64_t paddr;
} __attribute__((packed)) v2p_t;

extern eptp_t *ept_ptr;

int dbg_dump_guest_page_tables(int actor_id);
int dbg_dump_ept(int actor_id);

int map_sandbox_to_guest_memory(void);

void set_faulty_page_guest_permissions(void);
void restore_faulty_page_guest_permissions(void);

void set_faulty_page_ept_permissions(void);
void restore_faulty_page_ept_permissions(void);

int allocate_guest_page_tables(void);
void free_guest_page_tables(void);

#endif // _GUEST_PAGE_TABLES_H_
