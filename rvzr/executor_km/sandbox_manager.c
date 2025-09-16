/// File: Sandbox memory management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "hardware_desc.h"

#include "actor.h"
#include "code_loader.h" // loaded_test_case_entry
#include "main.h"        // set_memory_x, set_memory_nx
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "page_tables_guest.h"
#include "page_tables_host.h"

sandbox_t *sandbox = NULL; // global

static void *_util_n_data_unaligned = NULL;
static void *util_n_data = NULL;
static void *code = NULL;

static size_t old_x_size = 0;

static int allocate_util_and_data(size_t n_actors)
{
    SAFE_FREE(_util_n_data_unaligned);

    // allocate working memory
    size_t mem_size = sizeof(util_t) + n_actors * sizeof(actor_data_t);
    _util_n_data_unaligned = CHECKED_MALLOC(mem_size + 0x1000);
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

    // initialize
    reset_code_area();

    // make it executable
    size_t size_pages = n_actors * sizeof(actor_code_t) / PAGE_SIZE;
    if (n_actors * sizeof(actor_code_t) % PAGE_SIZE != 0)
        size_pages++;
    set_memory_x((unsigned long)code, size_pages);
    old_x_size = size_pages;

    return 0;
}

/// @brief Clears out the code from previous executions and fills the area with NOPs
/// @param void
/// @return void
void reset_code_area(void)
{
    // fill the code area with NOPs
#if defined(ARCH_X86_64)
    memset(code, 0x90, sizeof(actor_code_t) * n_actors);
#elif defined(ARCH_ARM)
    for (int i = 0; i < n_actors * sizeof(actor_code_t) / 4; i += 1)
        ((uint32_t *)code)[i] = 0xd503201f;
#endif

    // initialize the main section with a single ret instruction
#if defined(ARCH_X86_64)
    ((uint8_t *)code)[0] = '\xC3';
#elif defined(ARCH_ARM)
    ((uint32_t *)code)[0] = 0xd65f03c0;
#endif
}

int allocate_sandbox(void)
{
    int err = 0;
    static int old_n_actors = 1;

    // Allocate sandbox in host memory
    if (old_n_actors < n_actors) {
        err = allocate_util_and_data(n_actors);
        CHECK_ERR("allocate_util_and_data");

        err = allocate_code(n_actors);
        CHECK_ERR("allocate_code");

        // initialize pointers
        sandbox = CHECKED_MALLOC(sizeof(sandbox_t));
        sandbox->data = (actor_data_t *)((unsigned long)util_n_data + sizeof(util_t));
        sandbox->code = (actor_code_t *)code;
        sandbox->util = (util_t *)util_n_data;

        // point to the main section of the first actor
        loaded_test_case_entry = code;
    }

    // Make sure that everything is property initialized
    memset(util_n_data, 0, sizeof(util_t) + n_actors * sizeof(actor_data_t));

    err = cache_host_pteps();
    CHECK_ERR("cache_host_pteps");

    // when necessary, map the sandbox into guest memory and allocate VM management data structures
    if (test_case->features.includes_vm_actors) {
        err = allocate_guest_page_tables();
        CHECK_ERR("allocate_guest_page_tables");

        err = map_sandbox_to_guest_memory();
        CHECK_ERR("map_sandbox_to_guest_memory");
    }
    old_n_actors = n_actors;

    return err;
}

/// @brief Returns the number of pages allocated for the sandbox, including util area, code and data
/// @param void
/// @return number of pages; -1 on error
int get_sandbox_size_pages(void)
{
    if (sandbox == NULL) {
        return -1;
    }

    int n_pages = 0;
    n_pages += sizeof(util_t) / PAGE_SIZE;
    n_pages += sizeof(actor_data_t) / PAGE_SIZE * n_actors;
    n_pages += sizeof(actor_code_t) / PAGE_SIZE * n_actors;

    return n_pages;
}

/// @brief Sets PTE values for the sandbox based on the current test case configuration
/// @param void
/// @return 0 on success; -1 on error
int set_sandbox_page_tables(void)
{
    int err = 0;

    err = store_orig_host_permissions();
    CHECK_ERR("store_orig_host_permissions");

    if (test_case->features.includes_user_actors) {
        err = set_user_pages();
        CHECK_ERR("set_user_pages");
    }
    return 0;
}

void restore_orig_sandbox_page_tables(void) { restore_orig_host_permissions(); }

/// @brief Fast modification of the faulty page PTE; sets the permissions according to
/// actor_t->data_permissions
void set_faulty_page_permissions(void)
{
    set_faulty_page_host_permissions();
    set_faulty_page_guest_permissions();
    set_faulty_page_ept_permissions();
}

/// @brief Fast recovery of original permissions of the faulty page PTE
void restore_faulty_page_permissions(void)
{
    restore_faulty_page_host_permissions();
    restore_faulty_page_guest_permissions();
    restore_faulty_page_ept_permissions();
}

// =================================================================================================
int init_sandbox_manager(void)
{
    int err = 0;
    err = allocate_util_and_data(1);
    CHECK_ERR("allocate_util_and_data");

    err = allocate_code(1);
    CHECK_ERR("allocate_code");

    // initialize pointers
    sandbox = CHECKED_MALLOC(sizeof(sandbox_t));
    sandbox->data = (actor_data_t *)((unsigned long)util_n_data + sizeof(util_t));
    sandbox->code = (actor_code_t *)code;
    sandbox->util = (util_t *)util_n_data;
    loaded_test_case_entry = code;

    // ensure that the main_area of the first actor is aligned as expected
    int offset = (unsigned long)sandbox->data[0].main_area % 0x2000;
    ASSERT(offset == 0, "init_sandbox_manager");

    // self-test: To enable offset-based accesses in assembly code, we have to hardcode
    //            the layout of the data structures in sandbox_constants.h;
    //            This naturally creates a risk of mismatches, so we perform sanity checks here
    //            to ensure that the layout is as expected.
    util_t *util = sandbox->util;
    ASSERT(&util->l1d_priming_area[0] - (uint8_t *)util == L1D_PRIMING_OFFSET, "init_sandbox");
    ASSERT((uint8_t *)&util->vars.stored_rsp - (uint8_t *)util == STORED_RSP_OFFSET,
           "init_sandbox");
    ASSERT((uint8_t *)&util->vars.latest_measurement - (uint8_t *)util == MEASUREMENT_OFFSET,
           "init_sandbox");
    actor_data_t *data = &sandbox->data[0];
    ASSERT(&data->main_area[0] - (uint8_t *)util == UTIL_REL_TO_MAIN, "init_sandbox");
    ASSERT(&data->main_area[0] - &data->macro_stack[64] == MACRO_STACK_TOP_OFFSET, "init_sandbox");
    ASSERT(&data->faulty_area[0] - &data->main_area[0] == FAULTY_AREA_OFFSET, "init_sandbox");
    ASSERT(&data->reg_init_area[0] - &data->main_area[0] == REG_INIT_OFFSET, "init_sandbox");
    ASSERT(&data->overflow_pad[0] - &data->main_area[0] == OVERFLOW_PAD_OFFSET, "init_sandbox");
    ASSERT(sizeof(measurement_t) == MEASUREMENT_SIZE, "init_sandbox");

    return 0;
}

void free_sandbox_manager(void)
{
    SAFE_FREE(_util_n_data_unaligned);
    util_n_data = NULL;

    if (code) {
        set_memory_nx((unsigned long)code, old_x_size);
        SAFE_VFREE(code);
        loaded_test_case_entry = NULL;
    }

    // since sandbox manager called allocators, it is responsible for also freeing the memory
    // note that the below calls are safe even if the corresponding allocations were not made
    free_guest_page_tables();
}
