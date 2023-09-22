/// File: Header for common macros
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _X86_EXECUTOR_MACRO_H_
#define _X86_EXECUTOR_MACRO_H_

#include <../arch/x86/include/asm/desc.h>

// Strings and assembly
#define STRINGIFY(...) #__VA_ARGS__

#define xstr(s) _str(s)
#define _str(s) str(s)
#define str(s)  #s

// clang-format off
#define asm_volatile_intel(ASM)                                                                    \
    asm volatile("\n.intel_syntax noprefix\n"                                                      \
                    ASM                                                                            \
                 ".att_syntax noprefix\n")
// clang-format on

// MSR access
#define wrmsr64(msr, value) native_write_msr(msr, (uint32_t)value, (uint32_t)(value >> 32))
#define rdmsr64(msr)        native_read_msr(msr)

// Bit manipulation
#define BIT_SET(a, b)   ((a) |= (1ULL << (b)))
#define BIT_CLEAR(a, b) ((a) &= ~(1ULL << (b)))
#define BIT_FLIP(a, b)  ((a) ^= (1ULL << (b)))
#define BIT_CHECK(a, b) (!!((a) & (1ULL << (b))))

// Printing
#define PRINT_ERR(msg, ...)       printk(KERN_ERR "[x86_executor] " msg, ##__VA_ARGS__);
#define PRINT_ERRS(src, msg, ...) printk(KERN_ERR "[x86_executor:" src "] " msg, ##__VA_ARGS__);

// Error handling
#define ASSERT(condition, src)                                                                     \
    if (!(condition)) {                                                                            \
        PRINT_ERRS(src, "Assertion failed: " xstr(condition) "\n");                                \
        return -EIO;                                                                               \
    }

#define ASSERT_MSG(condition, src, msg, ...)                                                       \
    if (!(condition)) {                                                                            \
        PRINT_ERRS(src, "Assertion failed: " xstr(condition) ";\n" msg, ##__VA_ARGS__);            \
        return -EIO;                                                                               \
    }

#define ASSERT_ENULL(condition, src)                                                               \
    if (!(condition)) {                                                                            \
        PRINT_ERRS(src, "Assertion failed: " xstr(condition) "\n");                                \
        return NULL;                                                                               \
    }

#define ASSERT_MSG_ENULL(condition, src, ...)                                                      \
    if (!(condition)) {                                                                            \
        PRINT_ERRS(src, "Assertion failed: " xstr(condition) ";" msg, ##__VA_ARGS__);              \
        return NULL;                                                                               \
    }

#define CHECK_ERR(msg)                                                                             \
    if (err) {                                                                                     \
        PRINT_ERR(" Error [" msg "]\n");                                                           \
        return err;                                                                                \
    }

// Memory management
#define CHECKED_MALLOC(x)                                                                          \
    ({                                                                                             \
        void *ptr = kmalloc(x, GFP_KERNEL);                                                        \
        if (!ptr) {                                                                                \
            PRINT_ERR(" Error allocating memory\n");                                               \
            return -EIO;                                                                           \
        }                                                                                          \
        ptr;                                                                                       \
    })
#define CHECKED_ZALLOC(x)                                                                          \
    ({                                                                                             \
        void *ptr = kzalloc(x, GFP_KERNEL);                                                        \
        if (!ptr) {                                                                                \
            PRINT_ERR(" Error zero-allocating memory\n");                                          \
            return -EIO;                                                                           \
        }                                                                                          \
        ptr;                                                                                       \
    })
#define SAFE_FREE(x)                                                                               \
    if (x) {                                                                                       \
        kfree(x);                                                                                  \
        x = NULL;                                                                                  \
    }

#define CHECKED_VMALLOC(x)                                                                         \
    ({                                                                                             \
        void *ptr = vmalloc(x);                                                                    \
        if (!ptr) {                                                                                \
            PRINT_ERR(" Error allocating memory\n");                                               \
            return -EIO;                                                                           \
        }                                                                                          \
        ptr;                                                                                       \
    })
#define SAFE_VFREE(x)                                                                              \
    if (x) {                                                                                       \
        vfree(x);                                                                                  \
        x = NULL;                                                                                  \
    }

#endif // _X86_EXECUTOR_MACRO_H_
