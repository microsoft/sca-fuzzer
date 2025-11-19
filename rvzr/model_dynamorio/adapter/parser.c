///
/// File: RCBF and RDBF parsing functions for the DynamoRIO backend adapter
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <stdlib.h>

#include "rcbf.h"
#include "rdbf.h"
#include "sandbox_const.h"

/// @brief Parse the file in RCBF format and return
///        pointer to the parsed data
/// @param filename The name of the file to parse
/// @return Pointer to the parsed data
rcbf_t *parse_rcbf(const char *filename)
{
    // Open the file in binary mode
    FILE *rdbf_fp = fopen(filename, "rb");
    if (rdbf_fp == NULL) {
        perror("fopen:parse_rcbf");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the RCBF structure
    rcbf_t *rcbf = (rcbf_t *)malloc(sizeof(rcbf_t));
    if (rcbf == NULL) {
        perror("malloc:rcbf");
        exit(EXIT_FAILURE);
    }

    // Read the header
    if (fread(&rcbf->header, sizeof(rcbf_header_t), 1, rdbf_fp) != 1) {
        perror("fread:rcbf->header");
        exit(EXIT_FAILURE);
    }
    uint64_t n_actors = rcbf->header.n_actors;
    if (n_actors <= 0 || n_actors > MAX_ACTORS) {
        fprintf(stderr, "ERROR: invalid number of actors in the RCBF file\n");
        exit(EXIT_FAILURE);
    }
    uint64_t n_symbols = rcbf->header.n_symbols;
    if (n_symbols <= 0) {
        fprintf(stderr, "ERROR: invalid number of symbols in the RCBF file\n");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the actor table and read it
    rcbf->actor_table = (actor_metadata_t *)malloc(n_actors * sizeof(actor_metadata_t));
    if (rcbf->actor_table == NULL) {
        perror("malloc:rcbf->actor_table");
        exit(EXIT_FAILURE);
    }
    if (fread(rcbf->actor_table, sizeof(actor_metadata_t), n_actors, rdbf_fp) != n_actors) {
        perror("fread:rcbf->actor_table");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the symbol table and read it
    rcbf->symbol_table = (symbol_entry_t *)malloc(n_symbols * sizeof(symbol_entry_t));
    if (rcbf->symbol_table == NULL) {
        perror("malloc:rcbf->symbol_table");
        exit(EXIT_FAILURE);
    }
    if (fread(rcbf->symbol_table, sizeof(symbol_entry_t), n_symbols, rdbf_fp) != n_symbols) {
        perror("fread:rcbf->symbol_table");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the section metadata and read it
    rcbf->section_metadata =
        (code_section_metadata_t *)malloc(n_actors * sizeof(code_section_metadata_t));
    if (rcbf->section_metadata == NULL) {
        perror("malloc:rcbf->section_metadata");
        exit(EXIT_FAILURE);
    }
    if (fread(rcbf->section_metadata, sizeof(code_section_metadata_t), n_actors, rdbf_fp) !=
        n_actors) {
        perror("fread:rcbf->section_metadata");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the code sections and read it
    rcbf->sections = (rcbf_code_section_t *)malloc(n_actors * sizeof(rcbf_code_section_t));
    if (rcbf->sections == NULL) {
        perror("malloc:rcbf->sections");
        exit(EXIT_FAILURE);
    }
    for (uint64_t i = 0; i < n_actors; i++) {
        if (fread(rcbf->sections[i].code, 1, rcbf->section_metadata[i].size, rdbf_fp) !=
            rcbf->section_metadata[i].size) {
            perror("fread:rcbf->sections");
            exit(EXIT_FAILURE);
        }
    }

    // Close the file
    fclose(rdbf_fp);

    return rcbf;
}

/// @brief Free the memory allocated for the RCBF structure
/// @param rcbf The RCBF structure to free
void free_rcbf(rcbf_t *rcbf)
{
    free(rcbf->actor_table);
    free(rcbf->symbol_table);
    free(rcbf->section_metadata);
    free(rcbf->sections);
    free(rcbf);
}

/// @brief Parse the file in RDBF format and return pointer to the parsed data
/// @param filename The name of the file to parse
/// @return Pointer to the parsed data
rdbf_t *parse_rdbf(const char *filename)
{
    // Open the file in binary mode
    FILE *rdbf_fp = fopen(filename, "rb");
    if (rdbf_fp == NULL) {
        perror("fopen:parse_rdbf");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the RDBF structure
    rdbf_t *rdbf = (rdbf_t *)malloc(sizeof(rdbf_t));
    if (rdbf == NULL) {
        perror("malloc:rdbf");
        exit(EXIT_FAILURE);
    }

    // Read the header
    if (fread(&rdbf->header, sizeof(rdbf_header_t), 1, rdbf_fp) != 1) {
        perror("fread:rdbf->header");
        exit(EXIT_FAILURE);
    }
    uint64_t n_actors = rdbf->header.n_actors;
    uint64_t n_inputs = rdbf->header.n_inputs;

    // Allocate memory for the data section metadata and read it
    rdbf->metadata = (data_section_metadata_t *)malloc(n_actors * sizeof(data_section_metadata_t));
    if (rdbf->metadata == NULL) {
        perror("malloc:rdbf->metadata");
        exit(EXIT_FAILURE);
    }
    if (fread(rdbf->metadata, sizeof(data_section_metadata_t), n_actors, rdbf_fp) != n_actors) {
        perror("fread:rdbf->metadata");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the data sections and read them
    uint64_t data_size = n_inputs * n_actors * sizeof(rdbf_data_section_t);
    rdbf->data = (rdbf_data_section_t *)malloc(data_size);
    if (rdbf->data == NULL) {
        perror("malloc:rdbf->data");
        exit(EXIT_FAILURE);
    }
    if (fread(rdbf->data, 1, data_size, rdbf_fp) != data_size) {
        perror("fread:rdbf->data");
        exit(EXIT_FAILURE);
    }

    // By this point the whole file should be read
    if (fgetc(rdbf_fp) != EOF) {
        fprintf(stderr, "ERROR: unexpected file format of the RDBF file\n");
        exit(EXIT_FAILURE);
    }

    // Close the file
    fclose(rdbf_fp);

    return rdbf;
}

/// @brief Free the memory allocated for the RDBF structure
/// @param rdbf The RDBF structure to free
void free_rdbf(rdbf_t *rdbf)
{
    free(rdbf->metadata);
    free(rdbf->data);
    free(rdbf);
}
