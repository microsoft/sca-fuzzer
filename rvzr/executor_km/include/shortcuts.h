/// File: Header for common macros
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _SHORTCUTS_H_
#define _SHORTCUTS_H_

#include "hardware_desc.h"
#include <asm/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>    // kfree, kmalloc
#include <linux/vmalloc.h> // vfree, vmalloc

#if defined(ARCH_X86_64)
#include <../arch/x86/include/asm/desc.h>
#endif

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
#if defined(ARCH_X86_64)
#define wrmsr64(msr, value) native_write_msr(msr, (uint32_t)value, (uint32_t)(value >> 32))
#define rdmsr64(msr)        native_read_msr(msr)
#elif defined(ARCH_ARM)
#define write_msr(NAME, VALUE) asm volatile("msr " NAME ", %0\n isb\n" ::"r"(VALUE));
#define read_msr(NAME, VAR)    asm volatile("mrs %0, " NAME "\n isb\n" : "=r"(VAR));
#endif

// Bit manipulation
#define BIT_(x) (1ULL << x)

// Printing
#define PRINT_ERR(msg, ...)       printk(KERN_ERR "[rvzr_executor] " msg, ##__VA_ARGS__);
#define PRINT_ERRS(src, msg, ...) printk(KERN_ERR "[rvzr_executor:" src "] " msg, ##__VA_ARGS__);

#define PRINT_WARN(msg, ...) printk(KERN_WARNING "[rvzr_executor] " msg, ##__VA_ARGS__);
#define PRINT_WARNS(src, msg, ...)                                                                 \
    printk(KERN_WARNING "[rvzr_executor:" src "] " msg, ##__VA_ARGS__);

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
        return -EIO;                                                                               \
    }

#define UNIMPLEMENTED(src)                                                                         \
    PRINT_ERRS(src, "Unimplemented\n");                                                            \
    return -ENOSYS;

// Memory management
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

// Fault handling
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

#define MULTI_ENTRY_HANDLER_ID(name, id)                                                           \
    asm volatile(".global " #name "_" #id "\n"                                                     \
                 "" #name "_" #id ":\n"                                                            \
                 "mov $0x" #id ", %%r13\n"                                                         \
                 "jmp " #name "\n" ::                                                              \
                     : "memory");
#define MULTI_ENTRY_HANDLER(name) CALL_256_TIMES(MULTI_ENTRY_HANDLER_ID, name)

#define MULTI_ENTRY_HANDLER_DECLARATIONS_ID(name, id) void name##_##id(void);
#define MULTI_ENTRY_HANDLER_DECLARATIONS(name)                                                     \
    CALL_256_TIMES(MULTI_ENTRY_HANDLER_DECLARATIONS_ID, name)

#define MULTI_ENTRY_HANDLER_LIST_ID(name, id) name##_##id,
#define MULTI_ENTRY_HANDLER_LIST(name)        CALL_256_TIMES(MULTI_ENTRY_HANDLER_LIST_ID, name)

// Address translation
static inline uint64_t vmalloc_to_phys(void *hva)
{
    struct page *page = vmalloc_to_page(hva);
    if (!page)
        return 0;
    uint64_t hpa = page_to_phys(page);
    return hpa;
}

static inline void native_page_invalidate(uint64_t va)
{
    asm volatile("invlpg (%0)" ::"r"(va) : "memory");
}

#endif // _SHORTCUTS_H_
