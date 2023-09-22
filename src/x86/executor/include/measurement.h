/// File: Header for the measurement manager
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _X86_EXECUTOR_MEASUREMENT_H_
#define _X86_EXECUTOR_MEASUREMENT_H_

#include <linux/types.h>
#include <linux/version.h>

#define HTRACE_WIDTH 1
#define NUM_PFC      5

typedef struct Measurement
{
    uint64_t htrace[HTRACE_WIDTH];
    uint64_t pfc[NUM_PFC];
} measurement_t;

struct pfc_config
{
    unsigned long evt_num;
    unsigned long umask;
    unsigned long cmask;
    unsigned int any;
    unsigned int edge;
    unsigned int inv;
};

extern measurement_t *measurements;

int trace_test_case(void);
int alloc_measurements(void);
int init_measurements(void);
void free_measurements(void);

#endif // _X86_EXECUTOR_MEASUREMENT_H_
