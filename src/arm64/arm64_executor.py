"""
File:

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List, Tuple
from interfaces import Input, Executor, CombinedHTrace


class ARMDummyExecutor(Executor):

    def load_test_case(self, _):
        pass

    def trace_test_case(self, inputs: List[Input], _) -> List[CombinedHTrace]:
        return [0 for _ in inputs]

    def read_base_addresses(self) -> Tuple[int, int]:
        return (0x10000, 0x0)

    def get_last_feedback(self):
        pass
