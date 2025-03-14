/// File: Header for guest page table functions
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _GUEST_PAGE_TABLES_H_
#define _GUEST_PAGE_TABLES_H_

#include "../arm64/page_tables_common.h"
#include "sandbox_manager.h"

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
