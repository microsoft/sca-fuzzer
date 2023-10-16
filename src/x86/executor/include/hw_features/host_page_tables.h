/// File: Header for page table functions
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _PAGE_TABLE_H_
#define _PAGE_TABLE_H_

#include <linux/kernel.h>

pte_t *get_pte(uint64_t address);

int faulty_page_prepare(void);
void faulty_page_pte_store(void);
void faulty_page_pte_restore(void);
void faulty_page_pte_set(void);

int map_user_pages(void);
int unmap_user_pages(void);

int init_page_table_manager(void);
void free_page_table_manager(void);

#endif // _PAGE_TABLE_H_
