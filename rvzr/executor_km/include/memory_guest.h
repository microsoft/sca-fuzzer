/// File: Dispatch header that includes the guest page table definitions for the architecture
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "hardware_desc.h"

#if defined(ARCH_X86_64)
#include "../x86/memory_guest.h"
#elif defined(ARCH_ARM)
#include "../arm64/memory_guest.h"
#endif
