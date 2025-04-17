///
/// File: Header for the COND Speculator
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <dr_api.h> // NOLINT

#include "speculator_abc.hpp"

/// @brief Conditional Branch Misprediction (COND) Speculator;
///        This speculator implements a conditional branch misprediction
///        by flipping the conditions for all conditional branches.
class SpeculatorCond : public SpeculatorABC
{
  public:
    using SpeculatorABC::SpeculatorABC;

    /// @brief If the current instruction is a branch, then the speculator will
    ///        checkpoint the process state and emulate a branch misprediction
    ///        by jumping to the opposite branch target (e.g., will take the branch if it
    ///        was supposed to fall though).
    ///
    /// @param opcode The opcode of the instruction
    /// @param pc The program counter (address) of the instruction
    /// @param mc The machine context of the instruction
    /// @param dc The current DR context
    /// @return 0 if no speculation was triggered or no redirection is needed;
    ///         otherwise, the PC of the instruction to which the execution should be redirected
    virtual pc_t handle_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc);
};
