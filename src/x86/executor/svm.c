/// File: Configuration and use of AMD SVM
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/types.h>

#include "actor.h"
#include "shortcuts.h"

#include "fault_handler.h"
#include "memory_guest.h"
#include "special_registers.h"
#include "svm.h"
#include "svm_config.h"

int svm_check_cpu_compatibility(void) { return 0; }

int start_svm_operation(void) { return 0; }
void stop_svm_operation(void) {}
int store_orig_vmcb_state(void) { return 0; }
void restore_orig_vmcb_state(void) {}
int set_vmcb_state(void) { return 0; }
int print_svm_exit_info(void) { return 0; }

// =================================================================================================
int init_svm(void)
{
    int err = 0;

    return err;
}

void free_svm(void) {}
