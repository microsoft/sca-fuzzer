/// File: Representation of a RDBF binary
/// (see docs/devel/binary-formats.md for format description)
///
/// Copyright (C) Microsoft Corporation
/// SPDX-License-Identifier: MIT

#ifndef RDBF_H
#define RDBF_H

#include <stdint.h>

#define RDBF_AREA_SIZE 4096

typedef struct {
    uint64_t n_actors;
    uint64_t n_inputs;
} rdbf_header_t;

typedef struct {
    uint64_t size;
    uint64_t reserved;
} data_section_metadata_t;

typedef struct {
    char main_area[RDBF_AREA_SIZE];
    char faulty_area[RDBF_AREA_SIZE];
    char reg_init_region[RDBF_AREA_SIZE];
} rdbf_data_section_t;

typedef struct {
    rdbf_header_t header;
    data_section_metadata_t *metadata;
    rdbf_data_section_t *data;
} rdbf_t;

extern rdbf_t *input_sequence;

#endif // RDBF_H
