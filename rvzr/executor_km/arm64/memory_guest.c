/// File:
///  - Guest page table management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// #include <asm/io.h>
// #include <asm/msr.h>

#include "memory_guest.h"
#include "actor.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "memory_guest.h"

// eptp_t *ept_ptr = NULL; // global

// =================================================================================================
// Page table management interface
// =================================================================================================

int map_sandbox_to_guest_memory(void)
{
    int err = 0;
    UNIMPLEMENTED("map_sandbox_to_guest_memory");
    return err;
}

/// @brief Set permissions on the faulty page based on the actor's metadata (for each actor)
/// @param void
void set_faulty_page_guest_permissions(void) { return; }

void restore_faulty_page_guest_permissions(void) { return; }

/// @brief Set EPT permissions on the faulty page based on the actor's metadata (for each actor)
/// @param void
void set_faulty_page_ept_permissions(void) { return; }

void restore_faulty_page_ept_permissions(void) { return; }

// =================================================================================================
// Debugging Interfaces
// =================================================================================================

/// @brief Dump the guest page tables for a given actor
/// @param actor_id
/// @return 0 on success, -1 on failure
int dbg_dump_guest_page_tables(int actor_id) { return 0; }

int dbg_dump_ept(int actor_id) { return 0; }

// =================================================================================================
int allocate_guest_page_tables(void) { return 0; }

void free_guest_page_tables(void) {}
