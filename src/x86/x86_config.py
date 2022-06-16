"""
File: x86-specific Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List

x86_supported_categories: List[str] = [
    # Base x86
    "BASE-BINARY",
    "BASE-BITBYTE",
    "BASE-CMOV",
    "BASE-COND_BR",
    "BASE-CONVERT",
    "BASE-DATAXFER",
    "BASE-FLAGOP",
    "BASE-LOGICAL",
    "BASE-MISC",
    "BASE-NOP",
    "BASE-POP",
    "BASE-PUSH",
    "BASE-SEMAPHORE",
    "BASE-SETCC",
    "BASE-STRINGOP",

    # "BASE-ROTATE",      # Unknown bug in Unicorn - emulated incorrectly
    # "BASE-SHIFT",       # Unknown bug in Unicorn - emulated incorrectly

    # "BASE-UNCOND_BR",   # Not supported: Complex control flow
    # "BASE-CALL",        # Not supported: Complex control flow
    # "BASE-RET",         # Not supported: Complex control flow

    # "BASE-SEGOP",       # Not supported: System instructions
    # "BASE-INTERRUPT",   # Not supported: System instructions
    # "BASE-IO",          # Not supported: System instructions
    # "BASE-IOSTRINGOP",  # Not supported: System instructions
    # "BASE-SYSCALL",     # Not supported: System instructions
    # "BASE-SYSRET",      # Not supported: System instructions
    # "BASE-SYSTEM",      # Not supported: System instructions

    # Extensions
    "SSE-MISC",  # SFENCE
    "SSE2-MISC",  # LFENCE, MFENCE
    "CLFLUSHOPT-CLFLUSHOPT",
    "CLFSH-MISC",
    # "BMI1",
]
x86_instruction_blocklist: List[str] = [
    # Hard to fix:
    # - STI - enables interrupts, thus corrupting the measurements; CLI - just in case
    "STI", "CLI",
    # - CMPXCHG8B - Unicorn doesn't execute the mem. access hook
    #   bug: https://github.com/unicorn-engine/unicorn/issues/990
    "CMPXCHG8B", "LOCK CMPXCHG8B",
    # - Undefined instructions are, well, undefined
    "UD", "UD2",
    # - Incorrect emulation
    "CPUID",
    # - Requires support of segment registers
    "XLAT", "XLATB",
    # - Requires special instrumentation to avoid #DE faults
    "IDIV", "REX IDIV",
    # - Requires complex instrumentation
    "ENTERW", "ENTER", "LEAVEW", "LEAVE",

    # Stringops - under construction
    "LODSB", "LODSD", "LODSW", "LODSQ",
    "SCASB", "SCASD", "SCASW", "SCASQ",
    "STOSB", "STOSD", "STOSW", "STOSQ",
    "CMPSB", "CMPSD", "CMPSW", "CMPSQ",
    "MOVSB", "MOVSD", "MOVSW", "MOVSQ",

    "REPE LODSB", "REPE LODSD", "REPE LODSW", "REPE LODSQ",
    "REPE SCASB", "REPE SCASD", "REPE SCASW", "REPE SCASQ",
    "REPE STOSB", "REPE STOSD", "REPE STOSW", "REPE STOSQ",
    "REPE CMPSB", "REPE CMPSD", "REPE CMPSW", "REPE CMPSQ",
    "REPE MOVSB", "REPE MOVSD", "REPE MOVSW", "REPE MOVSQ",

    "REPNE LODSB", "REPNE LODSD", "REPNE LODSW", "REPNE LODSQ",
    "REPNE SCASB", "REPNE SCASD", "REPNE SCASW", "REPNE SCASQ",
    "REPNE STOSB", "REPNE STOSD", "REPNE STOSW", "REPNE STOSQ",
    "REPNE CMPSB", "REPNE CMPSD", "REPNE CMPSW", "REPNE CMPSQ",
    "REPNE MOVSB", "REPNE MOVSD", "REPNE MOVSW", "REPNE MOVSQ",

    # - not supported
    "LFENCE", "MFENCE", "SFENCE", "CLFLUSH", "CLFLUSHOPT",
]  # yapf: disable

# x86 executor internally uses R15, R14, RSP, RBP and, thus, they are excluded
# segment registers are also excluded as we don't support their handling so far
# same for CR* and DR*
x86_gpr_blocklist: List[str] = [
    # free - rax, rbx, rcx, rdx, rdi, rsi
    'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'RSP', 'RBP',
    'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D', 'ESP', 'EBP',
    'R8W', 'R9W', 'R10W', 'R11W', 'R12W', 'R13W', 'R14W', 'R15W', 'SP', 'BP',
    'R8B', 'R9B', 'R10B', 'R11B', 'R12B', 'R13B', 'R14B', 'R15B', 'SPL', 'BPL',
    'ES', 'CS', 'SS', 'DS', 'FS', 'GS',
    'CR0', 'CR2', 'CR3', 'CR4', 'CR8',
    'DR0', 'DR1', 'DR2', 'DR3', 'DR4', 'DR5', 'DR6', 'DR7'
]  # yapf: disable
