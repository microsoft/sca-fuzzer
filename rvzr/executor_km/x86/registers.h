/// File: Symbolic names for pre-allocated registers; x86-64 version
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef X86_REGISTERS_H_
#define X86_REGISTERS_H_

// Register IDs
#define RAX_REG_ID 0x0
#define RCX_REG_ID 0x1
#define RDX_REG_ID 0x2
#define RBX_REG_ID 0x3
#define RSP_REG_ID 0x4
#define RBP_REG_ID 0x5
#define RSI_REG_ID 0x6
#define RDI_REG_ID 0x7

#define REX_BOUNDARY 0x8
#define R8_REG_ID    0x8
#define R9_REG_ID    0x9
#define R10_REG_ID   0xa
#define R11_REG_ID   0xb
#define R12_REG_ID   0xc
#define R13_REG_ID   0xd
#define R14_REG_ID   0xe
#define R15_REG_ID   0xf

/// Reserved registers
#define STATUS_REGISTER    "r12"
#define STATUS_REGISTER_32 "r12d"
#define STATUS_REGISTER_8  "r12b"

#define HTRACE_REGISTER "r13"
#define MEMORY_BASE_REG "r14"
#define UTIL_BASE_REG   "r15"

#define TMP_REG    "r11" // temporary register for various uses
#define TMP_REG_ID (R11_REG_ID)

/// Performance counter registers
#define PFC0 "r10"
#define PFC1 "r9"
#define PFC2 "r8"

#endif // X86_REGISTERS_H_
