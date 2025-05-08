///
/// File: Collection of types describing an instruction
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>

typedef uint64_t opcode_t;
typedef uint64_t pc_t;

/// @brief Structure describing observable information of an instruction
typedef struct {
    uint64_t opcode;
    uint64_t pc;
    bool has_mem_access;
} instr_obs_t;

/// @brief Structure describing observable information of a memory access
typedef struct {
    uint64_t addr;
    uint64_t size;
} mem_access_obs_t;
