/// File: Header for the input parser
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _INPUT_PARSER_H_
#define _INPUT_PARSER_H_

#include "sandbox_manager.h"

#define REG_INIT_AREA_SIZE_ALIGNED 4096

typedef uint64_t input_fragment_size_t;
typedef uint64_t input_fragment_permissions_field_t;
typedef uint64_t input_fragment_reserved_field_t;

typedef struct {
    input_fragment_size_t size;
    input_fragment_permissions_field_t permission;
    input_fragment_reserved_field_t reserved;
} input_fragment_metadata_entry_t;

typedef struct {
    char main_area[MAIN_AREA_SIZE];
    char faulty_area[FAULTY_AREA_SIZE];
    char reg_init_region[REG_INIT_AREA_SIZE_ALIGNED];
} input_fragment_t;

typedef struct {
    size_t metadata_size;
    size_t data_size;
    input_fragment_metadata_entry_t *metadata;
    input_fragment_t *data;
} input_batch_t;

#define MAX_INPUTS        (1024 * 1024)
#define BATCH_HEADER_SIZE 16 // sizeof(n_actors) + sizeof(n_inputs)
#define FRAGMENT_SIZE_ALIGNED                                                                      \
    (MAIN_AREA_SIZE + FAULTY_AREA_SIZE + REG_INIT_AREA_SIZE_ALIGNED)

extern input_batch_t *inputs;
extern size_t n_inputs;

input_fragment_t *get_input_fragment(uint64_t input_id, uint64_t actor_id);
input_fragment_t *get_input_fragment_unsafe(uint64_t input_id, uint64_t actor_id);
ssize_t parse_input_buffer(const char *buf, size_t count, bool *finished);
bool input_parsing_completed(void);

int init_input_parser(void);
void free_input_parser(void);

#endif // _INPUT_PARSER_H_
