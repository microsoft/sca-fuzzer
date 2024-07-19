"""
File: x86-specific Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List


def try_get_cpu_vendor():
    with open('/proc/cpuinfo', 'r') as f:
        for line in f:
            if 'AuthenticAMD' in line:
                return 'x86-64-amd'
            if 'GenuineIntel' in line:
                return 'x86-64-intel'
        else:
            return 'x86-64-intel'


_option_values = {
    'executor': [
        'x86-64-intel',
        'x86-64-amd',
    ],
    'executor_mode': [
        'P+P',
        'F+R',
        'E+R',
        'PP+P',
        'TSC',
        # 'GPR' is intentionally left out
    ],
    'generator_faults_allowlist': [
        'div-by-zero',
        'div-overflow',
        'opcode-undefined',
        'bounds-range-exceeded',
        'breakpoint',
        'debug-register',
        'non-canonical-access',
        'user-to-kernel-access',
    ],
    'actor': [
        'name',
        'mode',
        'privilege_level',
        'data_properties',
        'data_ept_properties',
        'observer',
        'instruction_blocklist',
        'fault_blocklist',
    ],
    "actor_mode": [
        'host',
        'guest',
    ],
    "actor_privilege_level": [
        'kernel',
        'user',
    ],
    "actor_data_properties": [
        'present',
        'writable',
        'user',
        'write-through',
        'cache-disable',
        'accessed',
        'dirty',
        'executable',
        'reserved_bit',
        'randomized',
    ],
    "actor_data_ept_properties": [
        "present",
        "writable",
        "executable",
        "accessed",
        "dirty",
        'reserved_bit',
        'randomized',
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
        "BASE-SYSTEM",
        "LONGMODE-CONVERT",
        "LONGMODE-DATAXFER",
        "LONGMODE-SEMAPHORE",
        "LONGMODE-SYSCALL",
        "LONGMODE-SYSRET",

        # SIMD extensions
        "SSE-SSE",
        "SSE-DATAXFER",
        "SSE-MISC",
        "SSE-LOGICAL_FP",
        # "SSE-CONVERT",  # require MMX
        # "SSE-PREFETCH",  # prefetch does not trigger a mem access in unicorn
        "SSE2-SSE",
        "SSE2-DATAXFER",
        "SSE2-MISC",
        "SSE2-LOGICAL_FP",
        "SSE2-LOGICAL",
        # "SSE2-CONVERT",  # require MMX
        # "SSE2-MMX",   # require MMX
        "SSE3-SSE",
        "SSE3-DATAXFER",
        # "SSE4-SSE",  # not tested yet
        "SSE4-LOGICAL",
        "SSE4a-BITBYTE",
        "SSE4a-DATAXFER",

        # Misc
        "CLFLUSHOPT-CLFLUSHOPT",
        "CLFSH-MISC",
        "MPX-MPX",
        "SMX-SYSTEM",
        "VTX-VTX",
        "XSAVE-XSAVE",
    ],
}

# by default, we always handle page faults
_handled_faults: List[str] = ["PF"]

x86_executor_enable_prefetcher: bool = False
""" x86_executor_enable_prefetcher: enable all prefetchers"""
x86_executor_enable_ssbp_patch: bool = True
""" x86_executor_enable_ssbp_patch: enable a patch against Speculative Store Bypass"""
x86_enable_hpa_gpa_collisions: bool = False
""" x86_enable_hpa_gpa_collisions: enable collisions between HPA and GPA;
useful for testing Foreshadow-like leaks"""
x86_disable_div64: bool = True
""" x86_disable_div64: do not generate 64-bit division instructions """
x86_generator_align_locks: bool = True
""" x86_generator_align_locks: align all generated locks to 8 bytes """

# Overwrite executor
executor: str = try_get_cpu_vendor()
""" executor: the default executor depending on the current platform """

instruction_categories: List[str] = ["BASE-BINARY", "BASE-BITBYTE", "BASE-COND_BR"]
""" instruction_categories: a default list of tested instruction categories """

_buggy_instructions: List[str] = [
    "sti",  # enables interrupts
    "cli",  # disables interrupts; blocked just in case
    "xlat",  # requires support of segment registers
    "xlatb",  # requires support of segment registers
    "cmpxchg8b",  # known bug: doesn't execute the mem. access hook
    "lock cmpxchg8b",  # https://github.com/unicorn-engine/unicorn/issues/990
    "cmpxchg16b",  # known bug: doesn't execute the mem. access hook
    "lock cmpxchg16b",  # https://github.com/unicorn-engine/unicorn/issues/990
    "cpuid",  # causes false positives: the model and the CPU will likely have different values
    "cmpps",  # causes crash
    "cmpss",  # causes crash
    'cmppd',  # causes crash
    'cmpsd',  # causes crash
    "movq2dq",  # requires MMX
    'movdq2q',  # requires MMX
    "rcpps",  # incorrect emulation
    "rcpss",  # incorrect emulation
    "maskmovdqu",  # incorrect emulation
]

instruction_blocklist: List[str] = [
    # Hard to fix:
    # - Requires complex instrumentation
    "enterw", "enter", "leavew", "leave",
    # - requires support of all possible interrupts
    "int",
    # - system management instruction
    "encls", "vmxon", "stgi", "skinit", "ldmxcsr", "stmxcsr",

    # - not supported
    "lfence", "mfence", "sfence", "clflush", "clflushopt",

    # - under construction
    # -- trigger FPVI (we have neither a contract nor an instrumentation for it yet)
    "divps", "divss", 'divpd', 'divsd',
    "mulss", "mulps", 'mulpd', 'mulsd',
    "rsqrtps", "rsqrtss", "sqrtps", "sqrtss", 'sqrtpd', 'sqrtsd',
    'addps', 'addss', 'addpd', 'addsd',
    'subps', 'subss', 'subpd', 'subsd',
    'addsubpd', 'addsubps', 'haddpd', 'haddps', 'hsubpd', 'hsubps',
]  # yapf: disable
instruction_blocklist.extend(_buggy_instructions)

# x86 executor internally uses R8...R15, RSP, RBP and, thus, they are excluded
# segment registers are also excluded as we don't support their handling so far
# same for CR* and DR*
register_blocklist: List[str] = [
    # free - rax, rbx, rcx, rdx, rdi, rsi
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rsp', 'rbp',
    'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d', 'esp', 'ebp',
    'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w', 'sp', 'bp',
    'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b', 'spl', 'bpl',
    'es', 'cs', 'ss', 'ds', 'fs', 'gs',
    'cr0', 'cr2', 'cr3', 'cr4', 'cr8',
    'dr0', 'dr1', 'dr2', 'dr3', 'dr4', 'dr5', 'dr6', 'dr7',
    "xcr0", "gdtr", "ldtr", "idtr", "tr", "fsbase", "gsbase", "msrs", "x87control", "tsc", "tscaux",

    # XMM8-15 are somehow broken in Unicorn
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
]  # yapf: disable


_generator_fault_to_fault_name = {
    'div-by-zero': "DE",
    'div-overflow': "DE",
    'opcode-undefined': "UD",
    'bounds-range-exceeded': "BR",
    'breakpoint': "BP",
    'debug-register': "DB",
    'non-canonical-access': "GP",
    'user-to-kernel-access': "PF",
}

_actor_default = {
    'name': "main",
    'mode': "host",
    'privilege_level': "kernel",
    'observer': False,
    'data_properties': {
        'present': True,
        'writable': True,
        'user': False,
        'write-through': False,
        'cache-disable': False,
        'accessed': True,
        'dirty': True,
        'executable': False,
        'reserved_bit': False,
        'randomized': False,
    },
    'data_ept_properties': {
        'present': True,
        'writable': True,
        'executable': False,
        'accessed': True,
        'dirty': True,
        'user': False,
        'reserved_bit': False,
        'randomized': False,
    },
    'instruction_blocklist': set(),
    'fault_blocklist': set(),
}
