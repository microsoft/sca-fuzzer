/// File: Header describing actor metadata
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _ACTOR_MANAGER_H_
#define _ACTOR_MANAGER_H_

#include <linux/types.h>

typedef uint64_t actor_id_t;
typedef uint64_t actor_type_t;

typedef struct {
    actor_id_t id;
    actor_type_t type;
    uint64_t data_permissions;
    uint64_t code_permissions;
} actor_metadata_t;

extern size_t n_actors;
extern actor_metadata_t *actors;

int allocate_actor_metadata(void);

int init_actor_manager(void);
void free_actor_manager(void);

#endif // _ACTOR_MANAGER_H_
