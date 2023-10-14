/// File: Sandbox memory management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "sandbox_manager.h"
#include "actor.h"
#include "code_loader.h" // loaded_test_case_entry
#include "main.h"        // set_memory_x, set_memory_nx
#include "shortcuts.h"

sandbox_t *sandbox = NULL; // global

static void *_util_n_data_unaligned = NULL;
static void *util_n_data = NULL;
static void *code = NULL;

static int old_n_actors = 0;
static size_t old_x_size = 0;

static int allocate_util_and_data(size_t n_actors)
{
    SAFE_VFREE(_util_n_data_unaligned);

    // allocate working memory
    size_t mem_size = sizeof(util_t) + n_actors * sizeof(actor_data_t);
    _util_n_data_unaligned = CHECKED_VMALLOC(mem_size + 0x1000);
    memset(_util_n_data_unaligned, 0, mem_size);

    // align memory to 2 pages (vmalloc guarantees 1 page alignment)
    if ((unsigned long)_util_n_data_unaligned % 0x2000 == 0)
        util_n_data = (sandbox_t *)_util_n_data_unaligned;
    else
        util_n_data = (sandbox_t *)((unsigned long)_util_n_data_unaligned + 0x1000);

    return 0;
}

static int allocate_code(size_t n_actors)
{
    // release old space for sections
    if (code) {
        set_memory_nx((unsigned long)code, old_x_size);
        SAFE_VFREE(code);
        loaded_test_case_entry = NULL;
    }

    // create new space for sections
    code = CHECKED_VMALLOC(n_actors * sizeof(actor_code_t));
    memset(code, 0x90, n_actors * sizeof(actor_code_t)); // pad with nops

    // make it executable
    size_t size_pages = n_actors * sizeof(actor_code_t) / PAGE_SIZE;
    if (n_actors * sizeof(actor_code_t) % PAGE_SIZE != 0)
        size_pages++;
    set_memory_x((unsigned long)code, size_pages);
    old_x_size = size_pages;

    // initialize the main section with a single ret instruction
    ((uint8_t *)code)[0] = '\xC3';
    return 0;
}

int allocate_sandbox(void)
{
    if (old_n_actors >= n_actors)
        return 0;

    int err = 0;
    err = allocate_util_and_data(n_actors);
    CHECK_ERR("allocate_sandbox");

    err = allocate_code(n_actors);
    CHECK_ERR("allocate_sandbox");

    // initialize pointers
    sandbox = CHECKED_MALLOC(sizeof(sandbox_t));
    sandbox->data = (actor_data_t *)((unsigned long)util_n_data + sizeof(util_t));
    sandbox->code = (actor_code_t *)code;
    sandbox->util = (util_t *)util_n_data;

    // point to the main section of the first actor
    loaded_test_case_entry = code;

    old_n_actors = n_actors;
    return 0;
}

// =================================================================================================
int init_sandbox_manager(void)
{
    int err = allocate_sandbox();
    CHECK_ERR("allocate_sandbox");
    int offset = (unsigned long)sandbox->data[0].main_area % 0x2000;
    ASSERT(offset == 0, "init_sandbox_manager");

    // self-test: make sure the fields of the sandbox are aligned as we expect
    actor_data_t *data = &sandbox->data[0];
    util_t *util = sandbox->util;
    ASSERT(&util->l1d_priming_area[0] - (uint8_t *)util == L1D_PRIMING_OFFSET, "init_sandbox");
    ASSERT((uint8_t *)&util->stored_rsp - (uint8_t *)util == STORED_RSP_OFFSET, "init_sandbox");
    ASSERT((uint8_t *)&util->latest_measurement - (uint8_t *)util == MEASUREMENT_OFFSET,
           "init_sandbox");

    ASSERT(&data->main_area[0] - (uint8_t *)util == UTIL_REL_TO_MAIN, "init_sandbox");

    ASSERT(&data->main_area[0] - &data->macro_stack[64] == MACRO_STACK_TOP_OFFSET, "init_sandbox");
    ASSERT(&data->faulty_area[0] - &data->main_area[0] == FAULTY_AREA_OFFSET, "init_sandbox");
    ASSERT(&data->reg_init_area[0] - &data->main_area[0] == REG_INIT_OFFSET, "init_sandbox");
    ASSERT(&data->overflow_pad[0] - &data->main_area[0] == OVERFLOW_PAD_OFFSET, "init_sandbox");

    return 0;
}

void free_sandbox_manager(void)
{
    SAFE_VFREE(_util_n_data_unaligned);
    SAFE_VFREE(code);
    util_n_data = NULL;

    if (code) {
        set_memory_nx((unsigned long)code, old_x_size);
        SAFE_VFREE(code);
        loaded_test_case_entry = NULL;
    }
}
