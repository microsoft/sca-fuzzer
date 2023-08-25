"""
File: Various helper functions used by multiple parts of the project

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from .interfaces import Coverage


# ==================================================================================================
# Coverage Disabled
# ==================================================================================================
class NoCoverage(Coverage):
    """
    A dummy class with empty functions.
    Used when fuzzing without coverage
    """

    def load_test_case(self, test_case):
        pass

    def generator_hook(self, feedback):
        pass

    def model_hook(self, feedback):
        pass

    def executor_hook(self, feedback):
        pass

    def analyser_hook(self, feedback):
        pass

    def get(self) -> int:
        return 0
