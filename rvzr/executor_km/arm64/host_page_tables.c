/// File:
///  - Page Table management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/kernel.h>
#include <linux/mm.h>

#include "actor.h"
#include "hardware_desc.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

#include "host_page_tables.h"
#include "page_tables_common.h"

sandbox_pteps_t *sandbox_pteps;

pte_t *get_pte(uint64_t address) { return NULL; }

// =================================================================================================
// Manipulation of Host Page Tables
// =================================================================================================
/// @brief Cache the PTE pointers for all sandbox pages.
/// @param void
/// @return 0 on success, -1 on failure
int cache_host_pteps(void) { return 0; }

/// @brief Preserve the original PTEs for all sandbox pages.
/// @param void
/// @return 0 on success, -1 on failure
int store_orig_host_permissions(void) { return 0; }

/// @brief Restore the original PTEs for all sandbox pages.
/// @param void
/// @return
int restore_orig_host_permissions(void) { return 0; }

/// @brief Configures the page table entries for those sandbox pages that are mapped into
/// user-type actors
/// @param void
/// @return 0 on success, -1 on failure
int set_user_pages(void) { return 0; }

/// @brief Fast modification of the faulty page host PTE; sets the permissions according to
/// actor_t->data_permissions
/// @param void
void set_faulty_page_host_permissions(void) {}

/// @brief Fast recovery of original permissions of the faulty page host PTE
/// @param void
void restore_faulty_page_host_permissions(void) {}

// =================================================================================================
int init_page_table_manager(void) { return 0; }

void free_page_table_manager(void) {}
