///
/// File: Header for the Seq (Sequential) Speculator
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "speculator_abc.hpp"

/// @brief Sequential (SEQ) Speculator;
///        This speculator implements a sequential execution model with no speculation
///        It is the simplest form of a speculator and it used to test the parts of the instruction
///        set where no speculation is expected
class SpeculatorSeq : public SpeculatorABC
{
  public:
    using SpeculatorABC::SpeculatorABC;
};
