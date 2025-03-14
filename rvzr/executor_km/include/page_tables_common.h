/// File: Dispatch header that includes the correct page tables definitions for the architecture
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "hardware_desc.h"

#if defined(ARCH_X86_64)
#include "../x86/page_tables_common.h"
#elif defined(ARCH_ARM)
#include "../arm64/page_tables_common.h"
#endif
