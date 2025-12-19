/// File: Symbolic names for pre-allocated registers; x86-64 version
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef X86_REGISTERS_H_
#define X86_REGISTERS_H_

/// Reserved registers
#define STATUS_REGISTER    "r12"
#define STATUS_REGISTER_32 "r12d"
#define STATUS_REGISTER_8  "r12b"

#define HTRACE_REGISTER "r13"
#define MEMORY_BASE_REG "r14"
#define UTIL_BASE_REG   "r15"

// NOTE: x16 is used internally by some of the code in asm_snippets.h; avoid using it

/// Performance counter registers
#define PFC0 "r10"
#define PFC1 "r9"
#define PFC2 "r8"

#endif // X86_REGISTERS_H_
