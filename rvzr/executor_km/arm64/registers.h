/// File: Symbolic names for pre-allocated registers; ARM64 version
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _ARM64_REGISTERS_H_
#define _ARM64_REGISTERS_H_

/// Reserved registers
#define STATUS_REGISTER         "x12"
#define STATUS_REGISTER_32      "w12"

#define HTRACE_REGISTER         "x13"

#define MEMORY_BASE_REGISTER    "x20"
#define MEMORY_BASE_REGISTER_ID 0x14

#define UTIL_BASE_REGISTER      "x21"
#define UTIL_BASE_REGISTER_     x21
#define UTIL_BASE_REGISTER_ID   0x15

#define TMP_REG1                "x28"
#define TMP_REG1_               x28
#define TMP_REG1_ID             0x1c

#define TMP_REG2                "x27"
#define TMP_REG2_               x27
#define TMP_REG2_ID             0x1b

#define TMP_REG3                "x26"
#define TMP_REG3_               x26

#define TMP_REG4                "x25"
#define TMP_REG4_               x25

#define TMP_REG5                "x24"
#define TMP_REG5_               x24

#define TMP_REG6                "x23"
#define TMP_REG6_               x23

// NOTE: x16 is used internally by some of the code in asm_snippets.h; avoid using it

/// Performance counter registers
#define PFC0 "x10"
#define PFC1 "x9"
#define PFC2 "x8"

#endif // _ARM64_REGISTERS_H_
