/// File: Header for common macros
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef KM_SHORTCUTS_H
#define KM_SHORTCUTS_H

#include "hardware_desc.h"
#include <asm/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>    // kfree, kmalloc
#include <linux/vmalloc.h> // vfree, vmalloc

#ifdef ARCH_X86_64
#include <../arch/x86/include/asm/desc.h>
#endif

// =================================================================================================
// Strings and assembly
// =================================================================================================
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

// =================================================================================================
// MSR access
// =================================================================================================
#ifdef ARCH_X86_64
// Kernel 6.16+ changed native_write_msr signature from (msr, low, high) to (msr, val)
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
#define wrmsr64(msr, value) native_write_msr(msr, value)
#else
#define wrmsr64(msr, value) native_write_msr(msr, (uint32_t)(value), (uint32_t)((value) >> 32))
#endif
#define rdmsr64(msr) native_read_msr(msr)
#elif defined(ARCH_ARM)
#define write_msr(NAME, VALUE) asm volatile("msr " NAME ", %0\n isb\n" ::"r"(VALUE));
#define read_msr(NAME, VAR)    asm volatile("mrs %0, " NAME "\n isb\n" : "=r"(VAR));
#endif

// =================================================================================================
// Bit manipulation
// =================================================================================================
#define BIT_(x) (1ULL << (x))

// =================================================================================================
// Logging and error handling
// =================================================================================================
#define PRINT_ERR(msg, ...)                                                                        \
    do {                                                                                           \
        printk(KERN_ERR "[rvzr_executor] " msg, ##__VA_ARGS__);                                    \
    } while (0)
#define PRINT_ERRS(src, msg, ...)                                                                  \
    do {                                                                                           \
        printk(KERN_ERR "[rvzr_executor:" src "] " msg, ##__VA_ARGS__);                            \
    } while (0)

#define PRINT_WARN(msg, ...) printk(KERN_WARNING "[rvzr_executor] " msg, ##__VA_ARGS__);
#define PRINT_WARNS(src, msg, ...)                                                                 \
    printk(KERN_WARNING "[rvzr_executor:" src "] " msg, ##__VA_ARGS__);

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
        return -EIO;                                                                               \
    }

#define UNIMPLEMENTED(src)                                                                         \
    PRINT_ERRS(src, "Unimplemented\n");                                                            \
    return -ENOSYS;

// =================================================================================================
// Memory management
// =================================================================================================
// NOLINTBEGIN(bugprone-macro-parentheses)

#define CHECKED_MALLOC(x)                                                                          \
    ({                                                                                             \
        void *ptr = kmalloc(x, GFP_KERNEL);                                                        \
        if (!ptr) {                                                                                \
            PRINT_ERR(" Error allocating memory\n");                                               \
            return -ENOMEM;                                                                        \
        }                                                                                          \
        ptr;                                                                                       \
    })
#define CHECKED_ZALLOC(x)                                                                          \
    ({                                                                                             \
        void *ptr = kzalloc(x, GFP_KERNEL);                                                        \
        if (!ptr) {                                                                                \
            PRINT_ERR(" Error zero-allocating memory\n");                                          \
            return -ENOMEM;                                                                        \
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
            return -ENOMEM;                                                                        \
        }                                                                                          \
        ptr;                                                                                       \
    })
#define SAFE_VFREE(x)                                                                              \
    if (x) {                                                                                       \
        vfree(x);                                                                                  \
        x = NULL;                                                                                  \
    }

#define CHECKED_ALLOC_PAGES(size)                                                                  \
    ({                                                                                             \
        struct page *ptr = alloc_pages(GFP_KERNEL, get_order(size));                               \
        if (!ptr) {                                                                                \
            PRINT_ERR(" Error allocating pages\n");                                                \
            return -ENOMEM;                                                                        \
        }                                                                                          \
        ptr;                                                                                       \
    })

#define SAFE_PAGES_FREE(x, size)                                                                   \
    if (x) {                                                                                       \
        __free_pages(x, get_order(size));                                                          \
        x = NULL;                                                                                  \
    }

// NOLINTEND(bugprone-macro-parentheses)

// =================================================================================================
// Call sequences
// =================================================================================================
#define CALL_16_TIMES(macro, arg, id)                                                              \
    macro(arg, id##0) macro(arg, id##1) macro(arg, id##2) macro(arg, id##3) macro(arg, id##4)      \
        macro(arg, id##5) macro(arg, id##6) macro(arg, id##7) macro(arg, id##8) macro(arg, id##9)  \
            macro(arg, id##a) macro(arg, id##b) macro(arg, id##c) macro(arg, id##d)                \
                macro(arg, id##e) macro(arg, id##f)
#define CALL_256_TIMES(macro, arg)                                                                 \
    CALL_16_TIMES(macro, arg, 0)                                                                   \
    CALL_16_TIMES(macro, arg, 1)                                                                   \
    CALL_16_TIMES(macro, arg, 2)                                                                   \
    CALL_16_TIMES(macro, arg, 3)                                                                   \
    CALL_16_TIMES(macro, arg, 4)                                                                   \
    CALL_16_TIMES(macro, arg, 5)                                                                   \
    CALL_16_TIMES(macro, arg, 6)                                                                   \
    CALL_16_TIMES(macro, arg, 7)                                                                   \
    CALL_16_TIMES(macro, arg, 8)                                                                   \
    CALL_16_TIMES(macro, arg, 9)                                                                   \
    CALL_16_TIMES(macro, arg, a)                                                                   \
    CALL_16_TIMES(macro, arg, b)                                                                   \
    CALL_16_TIMES(macro, arg, c)                                                                   \
    CALL_16_TIMES(macro, arg, d)                                                                   \
    CALL_16_TIMES(macro, arg, e)                                                                   \
    CALL_16_TIMES(macro, arg, f)

// =================================================================================================
// Address translation
// =================================================================================================

static inline uint64_t vmalloc_to_phys(void *hva)
{
    struct page *page = vmalloc_to_page(hva);
    if (!page)
        return 0;
    uint64_t hpa = page_to_phys(page);
    return hpa;
}

static inline void native_page_invalidate(uint64_t hva)
{
#ifdef ARCH_X86_64
    asm volatile("invlpg (%0)" ::"r"(hva) : "memory");
#elif defined(ARCH_ARM)
    hva >>= 12;
    hva &= 0xfffffffffffULL;
    asm volatile("dsb ishst\n tlbi vale1is, %0\n dsb ish\n" ::"r"(hva) : "memory");
#endif
}

#endif // KM_SHORTCUTS_H
