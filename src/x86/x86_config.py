"""
File: x86-specific Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List

# x86_option_values attribute MUST be the first attribute in the file
x86_option_values = {
    'executor': [
        'x86-64-intel',
        'x86-64-amd',
    ],
    'executor_mode': [
        'P+P',
        'F+R',
        'E+R',
        'PP+P',
        # 'GPR' is intentionally left out
    ],
    'permitted_faults': [
        'DE-zero',
        'DE-overflow',
        'UD',
        'UD-vtx',
        'UD-svm',
        'PF-present',
        'PF-writable',
        'PF-smap',
        'GP-noncanonical',
        'BP',
        'BR',
        'DB-instruction',
        'assist-accessed',
        'assist-dirty',
    ],
    'instruction_categories': [
        # Base x86 - user instructions
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
        "BASE-WIDENOP",

        # Base x86 - system instructions
        "BASE-INTERRUPT",
        # "BASE-ROTATE",      # Unknown bug in Unicorn - emulated incorrectly
        # "BASE-SHIFT",       # Unknown bug in Unicorn - emulated incorrectly
        # "BASE-UNCOND_BR",   # Not supported: Complex control flow
        # "BASE-CALL",        # Not supported: Complex control flow
        # "BASE-RET",         # Not supported: Complex control flow
        # "BASE-SEGOP",       # Not supported: System instructions
        # "BASE-IO",          # Not supported: System instructions
        # "BASE-IOSTRINGOP",  # Not supported: System instructions
        # "BASE-SYSCALL",     # Not supported: System instructions
        # "BASE-SYSRET",      # Not supported: System instructions
        # "BASE-SYSTEM",      # Not supported: System instructions

        # Extensions
        "SSE-SSE",
        "SSE-DATAXFER",
        "SSE-MISC",
        "SSE2-DATAXFER",
        "SSE2-MISC",
        "CLFLUSHOPT-CLFLUSHOPT",
        "CLFSH-MISC",
        "SGX-SGX",
        "VTX-VTX",
        "SVM-SYSTEM",
        "MPX-MPX",
    ]
}

x86_executor_enable_prefetcher: bool = False
""" x86_executor_enable_prefetcher: enable all prefetchers"""
x86_executor_enable_ssbp_patch: bool = True
""" x86_executor_enable_ssbp_patch: enable a patch against Speculative Store Bypass"""
x86_disable_div64: bool = True

x86_instruction_categories: List[str] = ["BASE-BINARY", "BASE-BITBYTE", "BASE-COND_BR"]
""" x86_instruction_categories: a default list of tested instruction categories """

x86_instruction_blocklist: List[str] = [
    # Hard to fix:
    # - STI - enables interrupts, thus corrupting the measurements; CLI - just in case
    "STI", "CLI",
    # - CMPXCHG8B - Unicorn doesn't execute the mem. access hook
    #   bug: https://github.com/unicorn-engine/unicorn/issues/990
    "CMPXCHG8B", "LOCK CMPXCHG8B",
    # - Incorrect emulation
    "CPUID", "RCPPS", "RCPSS",
    # - Requires support of segment registers
    "XLAT", "XLATB",
    # - Requires complex instrumentation
    "ENTERW", "ENTER", "LEAVEW", "LEAVE",
    # - requires support of all possible interrupts
    "INT",
    # - system management instruction
    "ENCLS", "VMXON", "STGI", "SKINIT", "LDMXCSR", "STMXCSR",

    # - not supported
    "LFENCE", "MFENCE", "SFENCE", "CLFLUSH", "CLFLUSHOPT",

    # - under construction
    "CMPPS", "CMPSS", "COMISS", "UCOMISS", "DIVPS", "DIVSS", "MULSS", "MULPS", "MAXPS", "MAXSS",
    "MINPS", "MINSS", "RSQRTPS", "RSQRTSS", "SHUFPS", "SQRTPS", "SQRTSS", "SUBPS", "SUBSS",
    "UNPCKHPS", "UNPCKLPS", "UNPCKLP", "MOVAPS", "MOVHLPS", "MOVHPS", "MOVLHPS", "MOVLPS",
    "MOVMSKPS", "MOVNTPS", "MOVSS", "MOVUP", "MOVUPS", "MASKMOVDQU", "MOVAPD", "MOVDQ2Q", "MOVDQA",
    "MOVDQU", "MOVHPD", "MOVLPD", "MOVMSKPD", "MOVNTDQ", "MOVNTI", "MOVNTPD", "MOVQ2DQ", "MOVSD",
    "MOVUPD",
]  # yapf: disable

# x86 executor internally uses R15, R14, RSP, RBP and, thus, they are excluded
# segment registers are also excluded as we don't support their handling so far
# same for CR* and DR*
x86_register_blocklist: List[str] = [
    # free - rax, rbx, rcx, rdx, rdi, rsi
    'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'RSP', 'RBP',
    'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D', 'ESP', 'EBP',
    'R8W', 'R9W', 'R10W', 'R11W', 'R12W', 'R13W', 'R14W', 'R15W', 'SP', 'BP',
    'R8B', 'R9B', 'R10B', 'R11B', 'R12B', 'R13B', 'R14B', 'R15B', 'SPL', 'BPL',
    'ES', 'CS', 'SS', 'DS', 'FS', 'GS',
    'CR0', 'CR2', 'CR3', 'CR4', 'CR8',
    'DR0', 'DR1', 'DR2', 'DR3', 'DR4', 'DR5', 'DR6', 'DR7',
    # XMM8-15 are somehow broken in Unicorn
    "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15",
]  # yapf: disable
