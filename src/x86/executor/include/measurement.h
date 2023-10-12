/// File: Header for the measurement manager
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _MEASUREMENT_H_
#define _MEASUREMENT_H_

#include <linux/types.h>
#include <linux/version.h>

#define HTRACE_WIDTH 1
#define NUM_PFC 5

typedef struct Measurement {
    uint64_t htrace[HTRACE_WIDTH];
    uint64_t pfc_reading[NUM_PFC];
} __attribute__((packed)) measurement_t;

extern measurement_t *measurements;

int trace_test_case(void);
int run_experiment(void);
int alloc_measurements(void);
int init_measurements(void);
void free_measurements(void);

#endif // _MEASUREMENT_H_
