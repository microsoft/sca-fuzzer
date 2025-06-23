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
    /// @param instr the observed instruction
    /// @param mc unused
    /// @param dc unused
    /// @return void
    void observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc) override;

    /// @brief Record the memory access
    /// @param type The type of the memory access (read or write)
    /// @param address The address of the memory access
    /// @param size The size of the memory access
    /// @param value The value of the memory access
    /// @return void
    void observe_mem_access(bool is_write, void *address, uint64_t size) override;
};
