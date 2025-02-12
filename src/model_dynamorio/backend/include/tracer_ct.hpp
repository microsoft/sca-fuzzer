///
/// File: Header for the CT Tracer and its variants
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <dr_api.h> // NOLINT
#include <dr_defines.h>

#include "tracer_abc.hpp"

/// @brief "Constant-Time" (CT) Tracer;
/// This tracer collects addresses of memory accesses and PCs of the executed instructions
class TracerCT : public TracerABC
{
  public:
    using TracerABC::TracerABC;

    /// @brief Record the PC of the executed instruction on the contract trace
    /// @param opcode unused
    /// @param pc The program counter of the executed instruction
    /// @param mc unused
    /// @return void
    void observe_instruction(uint64_t opcode, uint64_t pc, dr_mcontext_t *mc) override;

    /// @brief Record the memory access
    /// @param type The type of the memory access (read or write)
    /// @param address The address of the memory access
    /// @param size The size of the memory access
    /// @param value The value of the memory access
    /// @return void
    void observe_mem_access(bool is_write, void *address, uint64_t size) override;
};
