/// File: Header for the test case parser and manager
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _TEST_CASE_PARSER_H_
#define _TEST_CASE_PARSER_H_

#include "actor.h"

#define MAX_SECTIONS            MAX_ACTORS
#define MAX_SYMBOLS             128
#define MAX_SECTION_SIZE        4096 // NOTE: must be exactly 1 page to detect sysfs buffering
#define MAX_LOADED_SECTION_SIZE (4096 * 2)
#define TC_HEADER_SIZE          (2 * sizeof(uint64_t))

typedef uint64_t section_size_t;
typedef uint64_t section_metadata_reserved_t;
typedef uint64_t section_id_t;
typedef uint64_t symbol_offset_t;
typedef uint64_t symbol_id_t;
typedef uint64_t symbol_args_t;

typedef struct {
    actor_id_t owner;
    section_size_t size;
    section_metadata_reserved_t reserved;
} tc_section_metadata_entry_t;

typedef struct {
    char code[MAX_SECTION_SIZE];
} tc_section_t;

typedef struct {
    actor_id_t owner;
    symbol_offset_t offset;
    symbol_id_t id;
    symbol_args_t args;
} tc_symbol_entry_t;

typedef struct {
    bool includes_vm_actors;
    bool includes_user_actors;
    bool has_explicit_fault_handler;
} tc_features_t;

typedef struct {
    tc_features_t features;
    size_t actor_table_size;
    size_t symbol_table_size;
    size_t metadata_size;
    size_t sections_size;
    actor_metadata_t *actor_table;
    tc_symbol_entry_t *symbol_table;
    tc_section_metadata_entry_t *metadata;
    tc_section_t *sections;
} test_case_t;

extern test_case_t *test_case;

ssize_t parse_test_case_buffer(const char *buf, size_t count, bool *finished);
bool tc_parsing_completed(void);
int init_test_case_parser(void);
void free_test_case_parser(void);

#endif // _TEST_CASE_PARSER_H_
