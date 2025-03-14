/// File: Header for the measurement manager
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _MEASUREMENT_H_
#define _MEASUREMENT_H_

#include <linux/types.h>
#include <linux/version.h>

#define HTRACE_WIDTH 1
#define NUM_PFC      5

#define STATUS_UNINITIALIZED 0
#define STATUS_STARTED       1
#define STATUS_ENDED         2

typedef struct measurement_status {
    uint8_t measurement_state;
    uint8_t reserved[3];
    uint32_t smi_count;
} __attribute__((packed)) measurement_status_t;

typedef struct Measurement {
    uint64_t htrace[HTRACE_WIDTH];
    uint64_t pfc_reading[NUM_PFC];
    measurement_status_t status;
} __attribute__((packed)) measurement_t;

extern measurement_t *measurements;

int trace_test_case(void);
int run_experiment(void);

void recover_orig_state(void);

int alloc_measurements(void);
int init_measurements(void);
void free_measurements(void);

#endif // _MEASUREMENT_H_
