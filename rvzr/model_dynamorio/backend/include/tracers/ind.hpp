///
/// File: Header for the Indirect Call Tracer
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <dr_api.h> // NOLINT
#include <dr_defines.h>

#include "tracer_abc.hpp"

/// @brief Indirect Tracer;
/// This tracer collects target addresses of indirect calls, indirect branches and returns
class TracerInd : public TracerABC
{
  public:
    using TracerABC::TracerABC;

    /// @brief Record the target of the executed indirect call (or branch or ret) on the contract
    /// trace
    /// @param instr the instruction being observed
    /// @param mc the instructions's memory context
    /// @param dc the instructions's DR context
    /// @return void
    void observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc) override;
};
