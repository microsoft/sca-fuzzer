/// File: Header for perf_counters.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _PERF_COUNTERS_H_
#define _PERF_COUNTERS_H_

int pfc_configure(void);

int init_perf_counters(void);
void free_perf_counters(void);

#endif // _PERF_COUNTERS_H_
