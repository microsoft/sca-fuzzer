"""
File: x86 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from fuzzer import Fuzzer
from x86.x86_executor import X86IntelExecutor
class X86Fuzzer(Fuzzer):
    executor: X86IntelExecutor
