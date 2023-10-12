/// File: Actor management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "actor_manager.h"
#include "shortcuts.h"

size_t n_actors = 1;             // global
actor_metadata_t *actors = NULL; // global

int allocate_actor_metadata(void)
{
    SAFE_FREE(actors);
    actors = CHECKED_ZALLOC(n_actors * sizeof(actor_metadata_t));
    return 0;
}

// =================================================================================================
int init_actor_manager(void)
{
    actors = CHECKED_ZALLOC(sizeof(actor_metadata_t));
    n_actors = 1;
    return 0;
}

void free_actor_manager(void) { SAFE_FREE(actors); }
