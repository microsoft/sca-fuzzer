/// File: Representation of a RCBF binary
/// (see docs/devel/binary-formats.md for format description)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef RCBF_H
#define RCBF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    MODE_HOST = 0,
    MODE_GUEST = 1,
};

enum {
    PL_KERNEL = 0,
    PL_USER = 1,
};

#define MAX_SECTION_SIZE 4096

typedef struct {
    uint64_t n_actors;
    uint64_t n_symbols;
} rcbf_header_t;

typedef struct {
    uint64_t actor_id;
    uint64_t mode;
    uint64_t pl;
    uint64_t data_permissions;
    uint64_t data_ept_properties;
    uint64_t code_permissions;
} actor_metadata_t;

typedef struct {
    uint64_t section_id;
    uint64_t offset;
    uint64_t symbol_id;
    uint64_t args;
} symbol_entry_t;

typedef struct {
    uint64_t section_id;
    uint64_t size;
    uint64_t reserved;
} code_section_metadata_t;

typedef struct {
    char code[MAX_SECTION_SIZE];
} rcbf_code_section_t;

typedef struct {
    rcbf_header_t header;
    actor_metadata_t *actor_table;
    symbol_entry_t *symbol_table;
    code_section_metadata_t *section_metadata;
    rcbf_code_section_t *sections;
} rcbf_t;

extern rcbf_t *test_case_code;

#endif // RCBF_H
