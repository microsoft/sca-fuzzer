/// File:
///   - Functions and macros used for debugging.
///     Should be included temporary where needed, and removed before committing.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <linux/kernel.h>

#define GDB_LOOP                                                                                   \
    __asm__ __volatile__(".globl gdb_loop\n"                                                       \
                         "gdb_loop:\n"                                                             \
                         "xchg %bx, %bx\n"                                                         \
                         "jmp gdb_loop\n")

#endif // _DEBUG_H_
