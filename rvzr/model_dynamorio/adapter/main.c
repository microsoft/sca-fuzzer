///
/// File: Module responsible for loading binary test cases produced by
///       the Revizor generator, and executing them in a sandboxed environment
///       that mirrors the one used by x86 executor.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "parser.h"
#include "rcbf.h"
#include "rdbf.h"
#include "sandbox.h"

static const char *rcbf_file = NULL;
static const char *rdbf_file = NULL;
static const char *bases_file = NULL;

// Defined in test_case_entry.asm
void test_case_entry_outer(uint8_t *main_area_base, uint8_t *code_base);

static int parse_args(int argc, char const *argv[])
{
    // Check usage
    if (argc != 4) {
        printf("Usage: %s <RCBF file> <RDBF file> <bases_file>\n", argv[0]);
        return -1;
    }
    rcbf_file = argv[1];
    rdbf_file = argv[2];
    bases_file = argv[3];

    // Check if files exist
    if (access(rcbf_file, F_OK) == -1) {
        fprintf(stderr, "ERROR: RCBF file %s does not exist\n", rcbf_file);
        return -1;
    }
    if (access(rdbf_file, F_OK) == -1) {
        fprintf(stderr, "ERROR: RDBF file %s does not exist\n", rdbf_file);
        return -1;
    }
    if (access(bases_file, F_OK) == -1) {
        fprintf(stderr, "ERROR: Bases file %s does not exist\n", bases_file);
        return -1;
    }

    return 0;
}

/// @brief Free all resources allocated by the module
/// @param rcbf Allocated RCBF structure
/// @param rdbf Allocated RDBF structure
/// @return void
static void cleanup(rcbf_t *rcbf, rdbf_t *rdbf)
{
    free_rcbf(rcbf);
    free_rdbf(rdbf);
}

int main(int argc, char const *argv[])
{
    // Parse CLI arguments
    if (parse_args(argc, argv) != 0) {
        return -1;
    }

    // Parse input files
    rcbf_t *rcbf_data = parse_rcbf(rcbf_file);
    rdbf_t *rdbf_data = parse_rdbf(rdbf_file);
    if (rcbf_data->header.n_actors != rdbf_data->header.n_actors) {
        fprintf(stderr, "ERROR: RCBF and RDBF files have different number of actors\n");
        cleanup(rcbf_data, rdbf_data);
        return -1;
    }

    // Allocate memory for the sandbox and load code
    if (allocate_sandbox(rcbf_data->header.n_actors) != 0) {
        fprintf(stderr, "ERROR: Failed to allocate memory for the sandbox\n");
        cleanup(rcbf_data, rdbf_data);
        return -1;
    }
    if (load_code_in_sandbox(rcbf_data) != 0) {
        fprintf(stderr, "ERROR: Failed to load code into the sandbox\n");
        cleanup(rcbf_data, rdbf_data);
        return -1;
    }

    // Communicate sandbox base addresses to the python model, in binary format
    sandbox_t *sandbox = get_sandbox();
    FILE *bases_fp = fopen(bases_file, "wb");
    if (bases_fp == NULL) {
        perror("fopen:bases_file");
        cleanup(rcbf_data, rdbf_data);
        return -1;
    }
    fwrite((const void *)&sandbox->code, sizeof(uint8_t *), 1, bases_fp);
    fwrite((const void *)&sandbox->data, sizeof(uint8_t *), 1, bases_fp);
    fflush(bases_fp);
    fclose(bases_fp);

    // Load data into the sandbox and execute the test case
    for (int i = 0; i < rdbf_data->header.n_inputs; i++) {
        if (load_data_in_sandbox(rdbf_data, i) != 0) {
            fprintf(stderr, "ERROR: Failed to load data into the sandbox\n");
            cleanup(rcbf_data, rdbf_data);
            return -1;
        }
        sandbox_t *sandbox = get_sandbox();
        test_case_entry_outer(&sandbox->data->main_area[0], &sandbox->code->code[0]);
    }

    cleanup(rcbf_data, rdbf_data);
    return 0;
}
