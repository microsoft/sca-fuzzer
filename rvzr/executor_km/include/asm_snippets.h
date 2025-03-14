/// File: Building blocks for creating macros;
///       This file re-directs to the correct architecture-specific file.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _ASM_SNIPPETS_H_
#define _ASM_SNIPPETS_H_

#include "hardware_desc.h"

#if defined(ARCH_X86_64)
#include "../x86/asm_snippets.h"
#elif defined(ARCH_ARM)
#include "../arm64/asm_snippets.h"
#endif

#endif // _ASM_SNIPPETS_H_