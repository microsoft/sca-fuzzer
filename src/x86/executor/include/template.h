/// File: Header for managing templates
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _X86_EXECUTOR_TEMPLATE_H_
#define _X86_EXECUTOR_TEMPLATE_H_

#include <linux/types.h>

int load_template(size_t tc_size);
void template_l1d_prime_probe(void);
void template_l1d_prime_probe_fast(void);
void template_l1d_prime_probe_partial(void);
void template_l1d_prime_probe_partial_fast(void);
void template_l1d_flush_reload(void);
void template_l1d_evict_reload(void);
void template_gpr(void);

#endif // _X86_EXECUTOR_TEMPLATE_H_
